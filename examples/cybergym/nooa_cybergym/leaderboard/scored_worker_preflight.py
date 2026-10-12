# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Bind scored worker dependencies before creating the durable campaign ledger.

The resulting plan has no task-dispatch method. A later binding step must use the
admitted state and repeat the signed checks before constructing a live worker.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import docker

from .capabilities import CapabilityRegistry
from .scored_campaign_inputs import ScoredLaunchPreview
from .scored_launch_config import (
    ScoredControllerMaterial,
    ScoredSignerPreflight,
    load_previewed_scored_capabilities,
    load_previewed_scored_controller_material,
    load_previewed_scored_signers,
)
from .scored_ui_preflight import (
    ScoredUiPreflight,
    prepare_previewed_scored_ui,
    require_previewed_scored_ui_client,
)


@dataclass(frozen=True, slots=True, repr=False)
class ScoredWorkerPlan:
    preview: ScoredLaunchPreview
    launch_config_path: Path
    signers: ScoredSignerPreflight
    material: ScoredControllerMaterial
    registry: CapabilityRegistry
    ui: ScoredUiPreflight
    observed_image_id: str


def prepare_previewed_scored_worker(
    preview: ScoredLaunchPreview, launch_config_path: Path
) -> ScoredWorkerPlan:
    """Require frozen controller inputs, native image and live UI ack pre-admission."""
    if type(preview) is not ScoredLaunchPreview or preview.state.authority is not preview.authority:
        raise RuntimeError("independently verified signed scored preview required")
    signers = load_previewed_scored_signers(preview, launch_config_path)
    material = load_previewed_scored_controller_material(preview, launch_config_path)
    registry = load_previewed_scored_capabilities(preview, launch_config_path)
    if (
        type(signers) is not ScoredSignerPreflight
        or type(material) is not ScoredControllerMaterial
        or type(registry) is not CapabilityRegistry
        or signers.config != material.config
        or signers.config.get("run_id") != preview.state.run_id
        or signers.config.get("epoch") != preview.state.epoch
        or signers.config.get("paths", {}).get("evidence_root") != str(preview.state.evidence_root)
        or type(signers.config.get("timeout_seconds")) is not int
        or signers.config["timeout_seconds"] > signers.donor.budgets.task_wall_timeout_sec
        or not callable(getattr(signers.donor, "verify_unchanged", None))
    ):
        raise RuntimeError("scored worker inputs differ from signed launch preview")
    signers.donor.verify_unchanged()
    expected_image = signers.donor.image_id
    if (
        type(expected_image) is not str
        or re.fullmatch(r"sha256:[a-f0-9]{64}", expected_image) is None
    ):
        raise RuntimeError("immutable scored native image required")
    try:
        actual_image = docker.from_env().images.get(expected_image).id
    except Exception:
        raise RuntimeError("scored native image unavailable before admission") from None
    if actual_image != expected_image:
        raise RuntimeError("scored native image differs from signed freeze")
    ui = prepare_previewed_scored_ui(preview, signers)
    require_previewed_scored_ui_client(ui)
    return ScoredWorkerPlan(
        preview,
        Path(launch_config_path),
        signers,
        material,
        registry,
        ui,
        actual_image,
    )
