# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Controller-only official ARVO and OSS-Fuzz image execution for scored tasks.

The task family fixes the command; neither the solver nor an asset manifest may
choose it. This module leaves the historical practice runner unchanged so its
previously frozen evidence can still be interpreted against its original code.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
from pathlib import Path
from uuid import uuid4

from .practice_arvo_runner import (
    _MAX_CANDIDATE_BYTES,
    _MAX_OUTPUT_BYTES,
    _OUTPUT_PREFIX_BYTES,
    _candidate_identity,
)

_IMAGE = re.compile(r"sha256:[a-f0-9]{64}\Z")
_HASH = re.compile(r"[a-f0-9]{64}\Z")
_TASK = re.compile(r"(?:arvo|oss-fuzz):[0-9]+\Z")
_COMMAND = {
    "arvo": "/bin/arvo",
    "oss-fuzz": "/usr/local/bin/run_poc",
}


def run_official_image(
    docker_client,
    *,
    task_id: str,
    image_id: str,
    candidate: Path,
    snapshot_dir: Path,
    expected_sha256: str,
) -> dict[str, str | int | bool]:
    """Execute one pinned image using only the official task-family command."""
    if type(task_id) is not str or _TASK.fullmatch(task_id) is None:
        raise ValueError("official task family required")
    if (
        type(image_id) is not str
        or _IMAGE.fullmatch(image_id) is None
        or type(expected_sha256) is not str
        or _HASH.fullmatch(expected_sha256) is None
    ):
        raise ValueError("pinned image and candidate identities required")
    candidate = Path(candidate)
    snapshot_dir = Path(snapshot_dir)
    if (
        not snapshot_dir.is_absolute()
        or snapshot_dir.is_symlink()
        or not snapshot_dir.is_dir()
        or snapshot_dir.resolve() != snapshot_dir
        or snapshot_dir.is_relative_to(candidate.parent)
        or candidate.is_relative_to(snapshot_dir)
        or (os.name == "posix" and snapshot_dir.stat().st_mode & 0o077)
    ):
        raise ValueError("private controller snapshot directory required")
    before, size = _candidate_identity(candidate)
    if before != expected_sha256:
        raise RuntimeError("candidate changed before official execution")
    snapshot = snapshot_dir / f"poc-{uuid4().hex}"
    copied = hashlib.sha256()
    copied_bytes = 0
    with candidate.open("rb") as source, snapshot.open("xb") as destination:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            destination.write(block)
            copied.update(block)
            copied_bytes += len(block)
            if copied_bytes > _MAX_CANDIDATE_BYTES:
                raise RuntimeError("candidate exceeds controller snapshot limit")
        destination.flush()
        os.fsync(destination.fileno())
    if os.name == "posix":
        snapshot.chmod(0o400)
    if copied.hexdigest() != before or copied_bytes != size:
        raise RuntimeError("candidate changed during controller snapshot")
    if _candidate_identity(candidate) != (before, size):
        raise RuntimeError("candidate changed during controller snapshot")
    if docker_client.images.get(image_id).id != image_id:
        raise RuntimeError("official image pin changed")
    command = [
        "/bin/bash",
        "-c",
        f"timeout -s SIGKILL 10 {_COMMAND[task_id.split(':', 1)[0]]} 2>&1",
    ]
    container = None
    try:
        container = docker_client.containers.create(
            image=image_id,
            command=command,
            network_mode="none",
            volumes={str(snapshot): {"bind": "/tmp/poc", "mode": "ro"}},
        )
        container.start()
        status = container.wait(timeout=60)
        raw_exit = status.get("StatusCode") if type(status) is dict else None
        if type(raw_exit) is not int or not 0 <= raw_exit <= 255:
            raise RuntimeError("official Docker exit is invalid")
        digest = hashlib.sha256()
        prefix = bytearray()
        output_bytes = 0
        if raw_exit != 137:
            for chunk in container.logs(stdout=True, stderr=False, stream=True, follow=False):
                if type(chunk) is not bytes:
                    raise RuntimeError("official output is not bytes")
                output_bytes += len(chunk)
                if output_bytes > _MAX_OUTPUT_BYTES:
                    raise RuntimeError("official output exceeds controller limit")
                digest.update(chunk)
                if len(prefix) < _OUTPUT_PREFIX_BYTES:
                    prefix.extend(chunk[: _OUTPUT_PREFIX_BYTES - len(prefix)])
        after, after_size = _candidate_identity(candidate)
        snapshot_hash, snapshot_size = _candidate_identity(snapshot)
        if (
            after != before
            or after_size != size
            or snapshot_hash != before
            or snapshot_size != size
        ):
            raise RuntimeError("candidate changed during official execution")
        return {
            "task_id": task_id,
            "image_id": image_id,
            "candidate_sha256": before,
            "candidate_bytes": size,
            "snapshot_sha256": snapshot_hash,
            "raw_exit_code": 300 if raw_exit == 137 else raw_exit,
            "output_sha256": digest.hexdigest(),
            "output_bytes": output_bytes,
            "output_prefix_base64": base64.b64encode(prefix).decode("ascii"),
            "output_truncated": output_bytes > len(prefix),
            "network_disabled": True,
        }
    finally:
        if container is not None:
            container.remove(force=True)
