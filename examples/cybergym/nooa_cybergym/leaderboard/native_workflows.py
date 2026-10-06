# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Frozen native Workflow scripts and their reviewed child declarations.

Scripts use the observed Claude Code 2.1.289 agent/parallel/phase API. This
module pins source bytes, not a claim that a native workflow has executed.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from .child_capacity import ChildCapacity


@dataclass(frozen=True, slots=True)
class FrozenWorkflow:
    script_path: str
    source: Path
    sha256: str
    child_types: tuple[str, ...]


def frozen_workflows(source_root: Path | None = None) -> tuple[FrozenWorkflow, ...]:
    root = (
        source_root or Path(__file__).resolve().parents[2] / "leaderboard/native-launcher/workflows"
    )
    root = Path(root)
    if not root.is_absolute() or root.resolve() != root or not root.is_dir():
        raise ValueError("canonical frozen workflow source root required")
    result = []
    for name, children in (("recon", 2), ("debug", 1), ("review", 1)):
        path = root / f"{name}.js"
        if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
            raise ValueError("frozen workflow source must be an ordinary file")
        raw = path.read_bytes()
        if len(raw) > 32768 or not raw.startswith(b"export const meta = "):
            raise ValueError("frozen workflow source malformed")
        result.append(
            FrozenWorkflow(
                f"/workspace/.claude/workflows/{name}.js",
                path,
                hashlib.sha256(raw).hexdigest(),
                (f"cybergym-{name}",) * children,
            )
        )
    return tuple(result)


def reserve_workflow(
    capacity: ChildCapacity,
    tool_use_id: str,
    arguments: dict,
    definitions: tuple[FrozenWorkflow, ...],
    *,
    observed_sha256: str,
    vulnerable_failure_observed: bool = False,
) -> None:
    """After capability authorization, reserve the pinned script's child batch.

    observed_sha256 is from the controller's safe actual container file read.
    Only this known script executes: inline overrides, resume, and nested
    unreviewed scripts cannot modify its declared tools or child count.
    """
    if type(arguments) is not dict or set(arguments) - {"scriptPath", "args"}:
        raise ValueError("Workflow requires frozen scriptPath and optional args only")
    match = next(
        (item for item in definitions if item.script_path == arguments.get("scriptPath")), None
    )
    if match is None or match.sha256 != observed_sha256:
        raise ValueError("Workflow script identity differs from frozen definition")
    supplied = arguments.get("args")
    if (
        type(supplied) is not dict
        or set(supplied) - {"question", "context"}
        or type(supplied.get("question")) is not str
        or not supplied["question"].strip()
    ):
        raise ValueError("Workflow args require a question and optional context")
    if match.child_types == ("cybergym-debug",) and not vulnerable_failure_observed:
        raise ValueError("Workflow debug requires controller-observed vulnerable failure")
    capacity.reserve_workflow(tool_use_id, match.sha256, match.child_types)
