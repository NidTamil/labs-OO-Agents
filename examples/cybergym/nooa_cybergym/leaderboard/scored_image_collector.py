# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Bounded, resumable collection of public scored-image manifest metadata.

This writes candidate observations only. It does not sign a full-cohort freeze,
pull image layers, or establish that registry tags will remain stable.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path

from nooa_cybergym.leaderboard.scored_image_registry import (
    verify_docker_manifest_observation,
)

_SHA = re.compile(r"[a-f0-9]{64}\Z")
_TASK = re.compile(r"(?:arvo|oss-fuzz):[0-9]+\Z")


def _atomic_write(path: Path, content: bytes) -> None:
    if path.exists() or path.is_symlink():
        raise ValueError("registry checkpoint already exists")
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".manifest-", delete=False) as tmp:
        temporary = Path(tmp.name)
        tmp.write(content)
        tmp.flush()
        os.fsync(tmp.fileno())
    try:
        if path.exists() or path.is_symlink():
            raise ValueError("registry checkpoint appeared during write")
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()
    if os.name == "posix":
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def _references(task_ids: tuple[str, ...]):
    if (
        type(task_ids) is not tuple
        or len(task_ids) != 1507
        or len(set(task_ids)) != 1507
        or any(type(task) is not str or _TASK.fullmatch(task) is None for task in task_ids)
    ):
        raise ValueError("exact signed cohort task IDs required")
    for task in task_ids:
        family, number = task.split(":", 1)
        repository = "n132/arvo" if family == "arvo" else "cybergym/oss-fuzz"
        for mode in ("vul", "fix"):
            yield f"{repository}:{number}-{mode}"


def _checkpoint_name(ref: str) -> str:
    return ref.replace("/", "-").replace(":", "-") + ".json"


def collect_batch(
    task_ids: tuple[str, ...],
    cohort_sha256: str,
    output_dir: Path,
    *,
    limit: int,
    fetch: Callable[[str], bytes],
) -> int:
    """Verify every existing checkpoint and collect at most ``limit`` new refs."""
    refs = tuple(_references(task_ids))
    if (
        type(cohort_sha256) is not str
        or _SHA.fullmatch(cohort_sha256) is None
        or type(limit) is not int
        or not 0 <= limit <= 20
        or not callable(fetch)
    ):
        raise ValueError("bounded collector inputs required")
    root = Path(output_dir)
    if not root.is_absolute() or root.is_symlink():
        raise ValueError("absolute unlinked checkpoint directory required")
    root.mkdir(parents=True, exist_ok=True)
    metadata = root / "cohort.sha256.json"
    expected = json.dumps({"cohort_sha256": cohort_sha256}, sort_keys=True).encode()
    if metadata.exists() or metadata.is_symlink():
        if metadata.is_symlink() or not metadata.is_file() or metadata.read_bytes() != expected:
            raise ValueError("registry checkpoint cohort identity differs")
    else:
        _atomic_write(metadata, expected)

    pending = []
    for ref in refs:
        path = root / _checkpoint_name(ref)
        if path.exists() or path.is_symlink():
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
                raise ValueError("registry observation checkpoint is invalid")
            verify_docker_manifest_observation(path.read_bytes(), expected_ref=ref)
        else:
            pending.append((ref, path))
    for ref, path in pending[:limit]:
        raw = fetch(ref)
        verify_docker_manifest_observation(raw, expected_ref=ref)
        _atomic_write(path, raw)
    return min(limit, len(pending))


def fetch_docker_manifest(ref: str) -> bytes:
    """Read public manifest metadata without pulling layers or printing it."""
    result = subprocess.run(
        ["docker", "manifest", "inspect", "--verbose", ref],
        check=True,
        capture_output=True,
        timeout=60,
    )
    return result.stdout


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cohort", type=Path, required=True)
    parser.add_argument("--cohort-sha256", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--limit", type=int, default=8)
    args = parser.parse_args()
    raw = args.cohort.read_bytes()
    if hashlib.sha256(raw).hexdigest() != args.cohort_sha256:
        raise ValueError("cohort lock digest differs")
    task_ids = tuple(json.loads(raw)["task_ids"])
    count = collect_batch(
        task_ids, args.cohort_sha256, args.output_dir, limit=args.limit, fetch=fetch_docker_manifest
    )
    print(f"verified and collected {count} new public manifest observations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
