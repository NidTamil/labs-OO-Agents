# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Bind a certified scored epoch to the already observed native runtime.

The existing runtime configuration is a synthetic donor. Its registry digest
must never be reused as the scored model policy or capability authority.
This module rechecks the signed scored admission and the separately pinned
image manifest before exposing controller-only runtime inputs to a driver.
It does not launch, evaluate or certify a task.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .capabilities import CapabilityRegistry
from .capability_inventory import load_captured_native_schemas, load_scored_binding_provenance
from .model_gateway import PRIMARY_CODING_PLAN_BASE_URL, PRIMARY_MODEL, ModelPolicy
from .runtime_config import RuntimeConfigError, VerifiedFile
from .scored_capability_admission import ScoredCapabilityAdmission
from .scored_image_registry import ScoredImageRegistry

_SHA = re.compile(r"[a-f0-9]{64}\Z")


@dataclass(frozen=True, slots=True)
class ScoredRuntimeBinding:
    registry: CapabilityRegistry
    bindings: tuple
    captured_schemas: dict[str, str]
    images: ScoredImageRegistry
    model_policy: ModelPolicy


def bind_scored_runtime(
    *,
    donor,
    state,
    task_id: str,
    admission,
    registry: CapabilityRegistry,
    bindings_path: Path,
    image_manifest: Path,
    observed_image_id: str,
) -> ScoredRuntimeBinding:
    """Rebind donor tools and model policy only after exact scored admission."""
    if (
        type(registry) is not CapabilityRegistry
        or type(admission) is not ScoredCapabilityAdmission
        or task_id not in state.task_ids
        or admission._state is not state
        or admission.registry_sha256 != registry.digest
        or observed_image_id != donor.image_id
        or observed_image_id != admission.image_id
    ):
        raise RuntimeError("scored task, registry or observed native image differs")
    donor.verify_unchanged()
    admission.verify_current(
        task_id=task_id, registry=registry, observed_image_id=observed_image_id
    )
    policy = ModelPolicy(
        PRIMARY_MODEL,
        donor.alternate_policy,
        registry.digest,
        PRIMARY_CODING_PLAN_BASE_URL,
        primary_takeover=donor.primary_takeover_policy,
    )
    harness = state.authority.attest_signed("harness_lock", admission._harness_lock)
    if (
        type(harness) is not dict
        or harness.get("epoch") != state.epoch
        or type(harness.get("scored_images_sha256")) is not str
        or _SHA.fullmatch(harness["scored_images_sha256"]) is None
        or harness.get("donor_configuration_sha256") != donor.freeze_sha256
        or harness.get("model_policy_sha256") != policy.digest
    ):
        raise RuntimeError("signed scored image manifest pin is absent")
    binding_sha = harness.get("capability_bindings_sha256")
    if type(binding_sha) is not str or _SHA.fullmatch(binding_sha) is None:
        raise RuntimeError("signed scored binding pin is absent")
    try:
        source = Path(bindings_path)
        binding_pin = VerifiedFile(source, binding_sha, source.stat().st_size)
        binding_pin.verify()
    except (OSError, RuntimeConfigError):
        raise RuntimeError("scored binding differs from signed harness lock") from None
    images = ScoredImageRegistry.load(
        image_manifest,
        expected_sha256=harness["scored_images_sha256"],
        task_ids=state.task_ids,
    )
    bindings = load_scored_binding_provenance(
        bindings_path, component_registry=donor.registry, scored_registry=registry
    )
    schemas = load_captured_native_schemas(bindings_path, donor.registry)
    try:
        binding_pin.verify()
    except RuntimeConfigError:
        raise RuntimeError("scored binding changed during native runtime binding") from None
    return ScoredRuntimeBinding(registry, bindings, schemas, images, policy)
