# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Controller-side staging entrypoint for one currently signed scored task.

The native model/container driver must call this only after observing its
immutable image. This function composes existing admission, cohort-asset and
workspace checks; it does not submit a model request or certify a task.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from pathlib import Path

from .campaign import CampaignAction, CampaignState
from .capabilities import CapabilityRegistry
from .cohort_native_workspace import CohortNativeWorkspace, overlay_cohort_template
from .scored_capability_admission import ScoredCapabilityAdmission
from .workspace import ControllerPaths, prepare_workspace

_TASK = re.compile(r"(?:arvo|oss-fuzz):[0-9]+\Z")
_RUN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")


def stage_current_cohort_task(
    *,
    state: CampaignState,
    task_id: str,
    controller_paths: ControllerPaths,
    asset_manifest: Path,
    template_files: Mapping[str, tuple[Path, str]],
    admission: ScoredCapabilityAdmission,
    registry: CapabilityRegistry,
    observed_image_id: str,
) -> CohortNativeWorkspace:
    """Admit, hydrate and overlay only the current signed Level-1 task."""
    if (
        type(state) is not CampaignState
        or type(task_id) is not str
        or _TASK.fullmatch(task_id) is None
        or task_id not in state.task_ids
        or type(state.run_id) is not str
        or _RUN.fullmatch(state.run_id) is None
        or state.next_action() != CampaignAction("prepare", task_id)
        or type(controller_paths) is not ControllerPaths
        or type(admission) is not ScoredCapabilityAdmission
        or admission._state is not state
        or type(registry) is not CapabilityRegistry
        or controller_paths.staging_root.parent != controller_paths.evidence_root.parent
    ):
        raise RuntimeError("current signed scored cohort task and controller paths required")
    # This replays the signed decision, live certification, exact capability
    # registry and observed image before any task asset is materialized.
    admission.verify_current(
        task_id=task_id, registry=registry, observed_image_id=observed_image_id
    )
    verified_paths = state.verified_staging_paths(task_id, controller_paths, asset_manifest)
    slug = f"{state.run_id}-{task_id.replace(':', '-')}"
    root = verified_paths.staging_root.parent / slug
    evidence = verified_paths.evidence_root / slug
    prepared = prepare_workspace(
        task_id=task_id,
        agent_id=slug,
        controller_paths=verified_paths,
        task_root=root,
    )
    return overlay_cohort_template(
        prepared,
        cohort_task_ids=state.task_ids,
        template_files=template_files,
        evidence=evidence,
        run_id=state.run_id,
        freeze_sha256=hashlib.sha256(admission._harness_lock).hexdigest(),
        cohort_sha256=state.cohort_sha256,
    )
