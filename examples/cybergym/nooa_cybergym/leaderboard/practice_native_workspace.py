# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Overlay pinned native Claude instructions on one official Level-1 workspace."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .practice_campaign import PRACTICE_TASK_IDS
from .synthetic_workspace import write_new
from .workspace import PreparedWorkspace

_HASH = re.compile(r"[a-f0-9]{64}\Z")
_RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")


def _hash_file(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("native practice file must be regular")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class PracticeNativeWorkspace:
    task_id: str
    run_id: str
    root: Path
    evidence: Path
    file_hashes: dict[str, str]
    manifest_bytes: bytes


def overlay_native_template(
    prepared: PreparedWorkspace,
    *,
    template_files: Mapping[str, tuple[Path, str]],
    evidence: Path,
    run_id: str,
    practice_freeze_sha256: str,
) -> PracticeNativeWorkspace:
    """Preserve official task files and add only frozen native template bytes."""
    if (
        type(prepared) is not PreparedWorkspace
        or prepared.task_id not in PRACTICE_TASK_IDS
        or type(run_id) is not str
        or _RUN_ID.fullmatch(run_id) is None
        or type(practice_freeze_sha256) is not str
        or _HASH.fullmatch(practice_freeze_sha256) is None
        or not isinstance(template_files, Mapping)
        or not template_files
    ):
        raise ValueError("one selected practice workspace and frozen template required")
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
        raise ValueError("separate fresh practice workspace and evidence required")
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
            "scope": "practice_native",
            "run_id": run_id,
            "task_id": prepared.task_id,
            "difficulty": "level1",
            "practice_freeze_sha256": practice_freeze_sha256,
            "official_task_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "file_hashes": actual,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    write_new(evidence / "task-manifest.json", frozen_manifest)
    return PracticeNativeWorkspace(
        prepared.task_id, run_id, root, evidence, actual, frozen_manifest
    )
