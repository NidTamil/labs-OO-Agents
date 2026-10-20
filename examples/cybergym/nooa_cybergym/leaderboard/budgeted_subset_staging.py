# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Create-once subset material with durable preparation ownership.

The returned material is not launch authority. Checks around synchronous
staging are admission boundaries, not a hard process deadline: an owned-process
supervisor must still enforce termination and attest eventual cleanup.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

from .budgeted_subset_runtime import BudgetedSubsetRuntimeBinding
from .campaign import _json_bytes
from .cohort_native_workspace import CohortNativeWorkspace, overlay_cohort_template
from .synthetic_workspace import write_new
from .workspace import (
    _assert_controller_path_separation,
    _validate_preparation_id,
    prepare_workspace,
)


@dataclass(frozen=True, slots=True)
class StagedBudgetedSubsetTask:
    workspace: CohortNativeWorkspace
    runtime: BudgetedSubsetRuntimeBinding
    preparation_marker: Path
    preparation_marker_sha256: str


def _fsync_directory(path: Path) -> None:
    if os.name != "posix":
        return
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _canonical(path: Path) -> None:
    if not path.is_absolute() or path.is_symlink() or path.resolve() != path:
        raise RuntimeError("canonical unlinked subset preparation paths required")


def _overlap(left: Path, right: Path) -> bool:
    return left == right or left.is_relative_to(right) or right.is_relative_to(left)


def _verify_marker(path: Path, expected: bytes) -> None:
    _canonical(path)
    if not path.is_file() or path.read_bytes() != expected:
        raise RuntimeError("durable subset preparation marker changed")


def stage_current_budgeted_subset_task(
    runtime: BudgetedSubsetRuntimeBinding,
) -> StagedBudgetedSubsetTask:
    """Stage once after signed preparation commitment, without signing or Send."""
    if type(runtime) is not BudgetedSubsetRuntimeBinding:
        raise TypeError("exact verified subset runtime required")
    runtime.verify_current()
    state, material = runtime.state, runtime.material
    paths = material.verify_current(runtime.task_id)
    preparation = state.preparation_binding(runtime.task_id)
    if preparation["preparation_id"] != runtime.preparation_id:
        raise RuntimeError("subset preparation ownership differs")
    preparation_id = _validate_preparation_id(runtime.preparation_id)
    slug = f"{state.run_id}-{runtime.task_id.replace(':', '-')}"
    root = paths.staging_root.parent / slug
    evidence = paths.evidence_root / slug
    stage = paths.staging_root / preparation_id
    raw = paths.evidence_root / f"workspace-{preparation_id}"
    marker_root = paths.evidence_root / "subset-preparations"
    marker = marker_root / f"{preparation_id}.json"
    owned = (root, evidence, stage, raw)
    _assert_controller_path_separation(paths, root)
    protected = (
        paths.data_dir,
        paths.mask_map_path,
        paths.harness_dir,
        paths.harness_manifest_path,
        paths.generator_source,
        material.asset_manifest_path,
        material.image_manifest_path,
        runtime._donor.repo_root,
        runtime._donor.source.path,
        runtime._bindings_path,
    )
    for path in (*owned, marker_root, marker):
        _canonical(path)
    if (
        any(
            _overlap(left, right)
            for index, left in enumerate(owned)
            for right in owned[index + 1 :]
        )
        or any(_overlap(marker_root, path) for path in owned)
        or any(_overlap(path, trusted) for path in (*owned, marker_root) for trusted in protected)
    ):
        raise RuntimeError("subset preparation paths overlap protected material")
    if any(path.exists() or path.is_symlink() for path in (*owned, marker)):
        raise RuntimeError("subset preparation path already exists; never restage")
    if marker_root.exists() and not marker_root.is_dir():
        raise RuntimeError("subset preparation marker directory is unavailable")
    marker_bytes = _json_bytes(
        {
            "schema_version": 1,
            "artifact_kind": "subset_preparation_ownership",
            "run_id": state.run_id,
            "epoch": state.epoch,
            "task_id": runtime.task_id,
            "preparation_id": preparation_id,
            "preparation_started_event_sha256": preparation["preparation_started_event_sha256"],
            "attempt_id": runtime.attempt_id,
            "budget_sha256": state.preview.budget.envelope_sha256,
            "admission_sha256": state.preview.admission_sha256,
            "freeze_sha256": state.preview.freeze_sha256,
            "cohort_sha256": state.preview.cohort_sha256,
            "source_commit": runtime.source_commit,
            "donor_configuration_sha256": runtime.donor_configuration_sha256,
            "bindings_sha256": runtime.bindings_sha256,
            "capability_registry_sha256": runtime.registry.digest,
            "paths": {
                "task_root": str(root),
                "overlay_evidence": str(evidence),
                "controller_stage": str(stage),
                "raw_manifest_directory": str(raw),
                "raw_manifest": str(raw / "task-manifest.json"),
            },
        }
    )
    marker_root.mkdir(mode=0o700, exist_ok=True)
    _canonical(marker_root)
    _fsync_directory(paths.evidence_root)
    write_new(marker, marker_bytes)
    _fsync_directory(marker_root)
    runtime.verify_current()
    _verify_marker(marker, marker_bytes)
    prepared = prepare_workspace(
        task_id=runtime.task_id,
        agent_id=slug,
        controller_paths=paths,
        task_root=root,
        preparation_id=preparation_id,
    )
    runtime.verify_current()
    _verify_marker(marker, marker_bytes)
    if (
        prepared.root != root
        or prepared.task_id != runtime.task_id
        or prepared.task_manifest != raw / "task-manifest.json"
    ):
        raise RuntimeError("staged subset workspace differs from recorded ownership")
    workspace = overlay_cohort_template(
        prepared,
        cohort_task_ids=material.cohort.task_ids,
        template_files=runtime.template_files,
        evidence=evidence,
        run_id=state.run_id,
        freeze_sha256=state.preview.freeze_sha256,
        cohort_sha256=state.preview.cohort_sha256,
    )
    runtime.verify_current()
    _verify_marker(marker, marker_bytes)
    return StagedBudgetedSubsetTask(
        workspace, runtime, marker, hashlib.sha256(marker_bytes).hexdigest()
    )
