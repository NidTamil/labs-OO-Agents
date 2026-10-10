# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Overlay pinned native instructions on one locked scored Level-1 workspace.

The historical practice overlay remains unchanged. This scored manifest binds
the current task to both the new freeze and exact committed cohort digest.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .practice_native_workspace import _hash_file
from .synthetic_workspace import write_new
from .workspace import PreparedWorkspace

_HASH = re.compile(r"[a-f0-9]{64}\Z")
_RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_TASK = re.compile(r"(?:arvo|oss-fuzz):[0-9]+\Z")


@dataclass(frozen=True)
class CohortNativeWorkspace:
    task_id: str
    run_id: str
    root: Path
    evidence: Path
    file_hashes: dict[str, str]
    manifest_bytes: bytes


def overlay_cohort_template(
    prepared: PreparedWorkspace,
    *,
    cohort_task_ids: tuple[str, ...],
    template_files: Mapping[str, tuple[Path, str]],
    evidence: Path,
    run_id: str,
    freeze_sha256: str,
    cohort_sha256: str,
) -> CohortNativeWorkspace:
    """Preserve official files and add only independently pinned native bytes."""
    if (
        type(prepared) is not PreparedWorkspace
        or type(cohort_task_ids) is not tuple
        or not cohort_task_ids
        or len(set(cohort_task_ids)) != len(cohort_task_ids)
        or any(type(item) is not str or _TASK.fullmatch(item) is None for item in cohort_task_ids)
        or prepared.task_id not in cohort_task_ids
        or type(run_id) is not str
        or _RUN_ID.fullmatch(run_id) is None
        or any(
            type(value) is not str or _HASH.fullmatch(value) is None
            for value in (freeze_sha256, cohort_sha256)
        )
        or not isinstance(template_files, Mapping)
        or not template_files
    ):
        raise ValueError("one signed cohort workspace and frozen template required")
    root, evidence = Path(prepared.root), Path(evidence)
    official_manifest = Path(prepared.task_manifest)
    if (
        not root.is_absolute()
        or root.is_symlink()
        or not root.is_dir()
        or root.resolve() != root
        or not evidence.is_absolute()
        or evidence.exists()
        or evidence.is_symlink()
        or evidence.is_relative_to(root)
        or root.is_relative_to(evidence)
        or official_manifest.is_symlink()
        or not official_manifest.is_file()
    ):
        raise ValueError("separate fresh scored workspace and evidence required")
    manifest_bytes = official_manifest.read_bytes()
    try:
        official = json.loads(manifest_bytes)
    except (ValueError, UnicodeDecodeError):
        raise RuntimeError("official Level-1 task manifest is malformed") from None
    if (
        type(official) is not dict
        or official.get("schema_version") != 1
        or official.get("task_id") != prepared.task_id
        or official.get("difficulty", "level1") != "level1"
        or official.get("file_hashes") != prepared.file_hashes
        or type(prepared.file_hashes) is not dict
    ):
        raise RuntimeError("official Level-1 task identity differs")
    actual = {}
    for path in root.rglob("*"):
        if path.is_symlink():
            raise RuntimeError("official workspace contains a linked path")
        if path.is_file():
            actual[path.relative_to(root).as_posix()] = _hash_file(path)
    if actual != prepared.file_hashes:
        raise RuntimeError("official workspace files differ from task manifest")
    copied = {}
    for name, item in sorted(template_files.items()):
        if (
            type(name) is not str
            or not name
            or "\\" in name
            or ":" in name
            or str(PurePosixPath(name)) != name
            or PurePosixPath(name).is_absolute()
            or any(part in {".", ".."} for part in name.split("/"))
            or name.startswith(("output/", "src/", "harness/", ".sunchaser/"))
            or name in actual
        ):
            raise RuntimeError("native template collides with official task input")
        if (
            type(item) is not tuple
            or len(item) != 2
            or type(item[1]) is not str
            or _HASH.fullmatch(item[1]) is None
        ):
            raise ValueError("frozen native template identity required")
        source = Path(item[0])
        if (
            not source.is_absolute()
            or source.is_symlink()
            or not source.is_file()
            or source.stat().st_size > 1024 * 1024
            or source.is_relative_to(root)
        ):
            raise ValueError("separate pinned native template source required")
        content = source.read_bytes()
        if hashlib.sha256(content).hexdigest() != item[1]:
            raise RuntimeError("native template differs from frozen digest")
        copied[name] = content
    if "CLAUDE.md" not in copied:
        raise RuntimeError("frozen native task contract is missing")
    evidence.mkdir(mode=0o700)
    for name, content in copied.items():
        destination = root.joinpath(*name.split("/"))
        destination.parent.mkdir(parents=True, exist_ok=True)
        write_new(destination, content, 0o444)
        actual[name] = hashlib.sha256(content).hexdigest()
    (root / ".sunchaser").mkdir(mode=0o755, exist_ok=False)
    frozen_manifest = json.dumps(
        {
            "schema_version": 1,
            "scope": "scored_native",
            "run_id": run_id,
            "task_id": prepared.task_id,
            "difficulty": "level1",
            "freeze_sha256": freeze_sha256,
            "cohort_sha256": cohort_sha256,
            "official_task_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "file_hashes": actual,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    write_new(evidence / "task-manifest.json", frozen_manifest)
    return CohortNativeWorkspace(prepared.task_id, run_id, root, evidence, actual, frozen_manifest)
