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

from .campaign import CampaignState
from .capabilities import CapabilityRegistry
from .cohort_native_worker import CohortNativeWorker
from .model_gateway import (
    PRIMARY_CODING_PLAN_BASE_URL,
    PRIMARY_MODEL,
    PRIMARY_WIRE_MODEL,
    ModelPolicy,
)
from .native_campaign_executor import NativeCampaignTaskExecutor
from .scored_campaign_inputs import ScoredLaunchPreview
from .scored_capability_admission import verify_scored_capability_admission
from .scored_launch_config import (
    ScoredControllerMaterial,
    ScoredSignerPreflight,
    load_previewed_scored_capabilities,
    load_previewed_scored_controller_material,
    load_previewed_scored_launch_config,
    load_previewed_scored_signers,
)
from .scored_native_driver import run as run_scored_native
from .scored_terminal_recovery import CohortTerminalRecovery
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
    model_policy_sha256: str


@dataclass(frozen=True, slots=True, repr=False)
class ScoredWorkerBinding:
    state: CampaignState
    worker: CohortNativeWorker
    executor: NativeCampaignTaskExecutor
    ui: object


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
    model_policy = ModelPolicy(
        PRIMARY_MODEL,
        signers.donor.alternate_policy,
        registry.digest,
        PRIMARY_CODING_PLAN_BASE_URL,
        primary_takeover=signers.donor.primary_takeover_policy,
    )
    harness = preview.authority.attest_signed("harness_lock", preview.inputs.harness_lock)
    if type(harness) is not dict or harness.get("model_policy_sha256") != model_policy.digest:
        raise RuntimeError("scored model policy differs from signed harness lock")
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
        model_policy.digest,
    )


def bind_admitted_scored_worker(
    plan: ScoredWorkerPlan, state: CampaignState
) -> ScoredWorkerBinding:
    """Bind the genuinely created ledger to one serial driver and replay verifier."""
    if (
        type(plan) is not ScoredWorkerPlan
        or type(state) is not CampaignState
        or state is plan.preview.state
        or state != plan.preview.state
        or state.authority is not plan.preview.authority
        or plan.ui.mailbox.run_id != state.run_id
        or plan.ui.ui.mailbox is not plan.ui.mailbox
    ):
        raise RuntimeError("scored worker requires the exact admitted state")
    # Recheck every signed file after the durable creation step; no mutable
    # preflight object can become a new authority for a different campaign.
    config = load_previewed_scored_launch_config(plan.preview, plan.launch_config_path)
    if config != plan.signers.config or config != plan.material.config:
        raise RuntimeError("scored worker configuration changed after admission")
    plan.signers.donor.verify_unchanged()
    policy = ModelPolicy(
        PRIMARY_MODEL,
        plan.signers.donor.alternate_policy,
        plan.registry.digest,
        PRIMARY_CODING_PLAN_BASE_URL,
        primary_takeover=plan.signers.donor.primary_takeover_policy,
    )
    harness = state.authority.attest_signed("harness_lock", plan.preview.inputs.harness_lock)
    if (
        type(harness) is not dict
        or policy.digest != plan.model_policy_sha256
        or harness.get("model_policy_sha256") != policy.digest
    ):
        raise RuntimeError("scored worker model policy changed after admission")
    try:
        observed_image = docker.from_env().images.get(plan.observed_image_id).id
    except Exception:
        raise RuntimeError("scored native image unavailable after admission") from None
    if observed_image != plan.observed_image_id or observed_image != plan.signers.donor.image_id:
        raise RuntimeError("scored native image changed after admission")
    admission = verify_scored_capability_admission(
        state=state,
        decision=plan.preview.inputs.decision,
        certification=plan.preview.inputs.certification,
        harness_lock=plan.preview.inputs.harness_lock,
        registry=plan.registry,
        observed_image_id=observed_image,
    )
    recovery = CohortTerminalRecovery(
        state=state,
        evidence_root=state.evidence_root,
        public_keys=plan.preview.public_keys,
        controller_verifier=plan.signers.controller_verifier,
        evaluator_verifier=plan.signers.evaluator_verifier,
        expected_policy_sha256=policy.digest,
        expected_model=PRIMARY_WIRE_MODEL,
    )
    files = config["files"]

    def driver(current_task: str, *, on_prepared, stop):
        return run_scored_native(
            config_path=Path(files["donor_config"]["path"]),
            bindings_path=Path(files["bindings"]["path"]),
            public_ssh_key=Path(files["public_ssh_key"]["path"]),
            state=state,
            task_id=current_task,
            ssh_port=config["ssh_port"],
            timeout=config["timeout_seconds"],
            controller_paths=plan.material.paths,
            asset_manifest=Path(files["asset_manifest"]["path"]),
            image_manifest=Path(files["image_manifest"]["path"]),
            scored_registry=plan.registry,
            admission=admission,
            official_verifier_source=Path(files["official_verifier"]["path"]),
            official_verifier_sha256=files["official_verifier"]["sha256"],
            evaluator_signer=plan.signers.evaluator_signer,
            evaluator_verifier=plan.signers.evaluator_verifier,
            remote_alias=config["remote_alias"],
            on_prepared=on_prepared,
            stop=stop,
        )

    worker = CohortNativeWorker(
        state=state, driver=driver, terminal_timeout_seconds=config["timeout_seconds"]
    )
    executor = NativeCampaignTaskExecutor(
        state=state,
        worker=worker,
        mailbox=plan.ui.mailbox,
        signer=plan.signers.controller_signer,
        verifier=plan.signers.controller_verifier,
        remote_alias=config["remote_alias"],
        terminal_recovery=recovery,
    )
    return ScoredWorkerBinding(state, worker, executor, plan.ui.ui)
