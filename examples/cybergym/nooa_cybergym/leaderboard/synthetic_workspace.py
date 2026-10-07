# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Fresh toy-task staging, separate from official cohort launch admission."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import re
import tarfile
from dataclasses import dataclass
from pathlib import Path

from .certification import FIXTURE_IDS
from .runtime_config import NativeRuntimeConfig

SYNTHETIC_README = (
    b"Synthetic native certification fixture; this is not an official benchmark task.\n"
    b"Use the frozen /workspace/CLAUDE.md contract and vulnerable MCP test route.\n"
)
SYNTHETIC_SUBMIT = (
    b"#!/bin/sh\n"
    b"printf '%s\\n' 'Synthetic fixture: select the final through the controller.' >&2\n"
    b"exit 1\n"
)


@dataclass(frozen=True)
class SyntheticWorkspace:
    task_id: str
    run_id: str
    root: Path
    evidence: Path
    file_hashes: dict[str, str]
    manifest_bytes: bytes


def write_new(path: Path, data: bytes, mode=0o600):
    if path.is_symlink() or path.parent.resolve() != path.parent:
        raise ValueError("new unlinked file required")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def _archive(source: bytes):
    destination = io.BytesIO()
    with gzip.GzipFile(fileobj=destination, mode="wb", mtime=0, filename="") as zipped:
        with tarfile.open(fileobj=zipped, mode="w") as archive:
            member = tarfile.TarInfo("parser.c")
            member.size, member.mode, member.mtime = len(source), 0o644, 0
            archive.addfile(member, io.BytesIO(source))
    return destination.getvalue()


def stage_synthetic(config: NativeRuntimeConfig, *, run_id: str, task_id: str) -> SyntheticWorkspace:
    """Copy only verified vulnerable bytes and the frozen generic task template.

    The fixed fixture reference stays in the controller config for later oracle
    evaluation. It is never an input to the archive or workspace file list.
    """
    if type(config) is not NativeRuntimeConfig or run_id not in config.run_ids or task_id not in FIXTURE_IDS:
        raise ValueError("declared synthetic run and fixture required")
    config.verify_unchanged()
    fixture = next(item for item in config.fixtures if item.task_id == task_id)
    slug = run_id + "-" + task_id.replace(":", "-")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,255}", slug):
        raise ValueError("invalid staged task identity")
    root, evidence = config.staging_root / slug, config.evidence_root / slug
    root.mkdir(mode=0o755)
    evidence.mkdir(mode=0o700)
    for directory in (root / "src", root / "output", root / ".sunchaser"):
        directory.mkdir(mode=0o755)
    if os.name == "posix" and os.geteuid() == 0:
        # The pinned native image's agent UID/GID is 1001. The output bind is
        # agent-writable without making candidate bytes world-writable.
        os.chown(root / "output", 1001, 1001)
        (root / "output").chmod(0o700)
    files = {
        "description.txt": fixture.description.read_bytes(),
        "repo-vul.tar.gz": _archive(fixture.vulnerable.read_bytes()),
        "README.md": SYNTHETIC_README,
        "submit.sh": SYNTHETIC_SUBMIT,
    }
    template = config.repo_root / "examples/cybergym/leaderboard/agent-template"
    for artifact in config.harness_files:
        if artifact.path.is_relative_to(template):
            name = artifact.path.relative_to(template).as_posix()
            if name in files or name.startswith(("output/", "src/", ".sunchaser/")):
                raise ValueError("task template collides with staged task data")
            files[name] = artifact.read_bytes()
    if "CLAUDE.md" not in files:
        raise ValueError("frozen native task contract absent from harness manifest")
    for name, data in sorted(files.items()):
        path = root.joinpath(*name.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        write_new(path, data, 0o444)
    hashes = {name: hashlib.sha256(data).hexdigest() for name, data in sorted(files.items())}
    manifest = json.dumps({"schema_version": 1, "scope": "synthetic_native", "run_id": run_id,
        "task_id": task_id, "configuration_sha256": config.freeze_sha256, "file_hashes": hashes},
        sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    write_new(evidence / "task-manifest.json", manifest)
    return SyntheticWorkspace(task_id, run_id, root, evidence, hashes, manifest)
