# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Inert comparisons for a future one-preparation manager release.

All pins, manager observations and clock values here are caller supplied. A
future authority must independently persist/verify them and atomically consume
one release claim. This module has no manager backend, OS or file access, worker
entrypoint, effect permission, or cleanup assertion. Its positive result is
only a candidate for those still-missing checks.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from typing import Literal

from .budgeted_subset_preparation_plan import OnePreparationPlan
from .subset_worker_contract import BoundSubsetTaskInputs, WorkerContractError

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_NAME = re.compile(r"[a-z][a-z0-9_.-]{0,127}\Z")
_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_MAX_NS = 2**63 - 1
_MAX_SEALED_BYTES = 64 * 1024 * 1024
_MAX_RUNTIME_BYTES = 128 * 1024 * 1024 * 1024


class ReleasePrerequisiteError(ValueError):
    """Supplied one-preparation facts are malformed or disagree."""


def _sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode()
    ).hexdigest()


def _digest(value: object) -> bool:
    return type(value) is str and _DIGEST.fullmatch(value) is not None


def _bounded_ns(value: object, *, positive: bool = True) -> bool:
    return type(value) is int and (0 < value <= _MAX_NS if positive else 0 <= value <= _MAX_NS)


@dataclass(frozen=True, slots=True)
class ReleasePrerequisitePins:
    """Claims a future independent authority must read from durable state.

    ``persisted_release_claim_sha256`` is a comparison pin, not evidence this
    claim was uniquely written or has not already been consumed.
    This version chooses the exact durable ``preparation_started`` event digest
    as its manager preparation binding. That equality is a source-contract
    comparison, not verification of a signed event or manager intent.
    """

    preparation_binding_sha256: str
    worker_inputs_sha256: str
    preparation_started_event_sha256: str
    worker_material_manifest_sha256: str
    one_preparation_plan_sha256: str
    planned_request_id: str
    full_cohort_ordinal: int
    preparation_action: str
    staging_started: bool
    intent_file_sha256: str
    armed_file_sha256: str
    manager_boot_sha256: str
    manager_invocation_sha256: str
    manager_cgroup_sha256: str
    armed_readback_sha256: str
    material_resolution_sha256: str
    release_nonce: str
    release_ordinal: int
    persisted_release_claim_sha256: str


@dataclass(frozen=True, slots=True)
class ManagerArmedReadback:
    """Claimed exact held-manager property readback, not platform proof."""

    intent_file_sha256: str
    armed_file_sha256: str
    manager_boot_sha256: str
    manager_invocation_sha256: str
    manager_cgroup_sha256: str
    phase: str
    observed_at_ns: int
    hard_stop_deadline_ns: int
    stop_grace_ns: int
    manager_owned: bool
    worker_held: bool
    enumeration_complete: bool
    migration_prevented: bool
    hard_timeout_armed: bool
    member_count: int


@dataclass(frozen=True, slots=True)
class HeldReleaseMaterial:
    """Claimed held identity for one classified worker dependency.

    A ``pinned_runtime`` worker reference requires a separately held runtime
    handle and through-use pin. The current held all-sealed manager contract
    cannot supply that class reconciliation. Paths and raw FD numbers are
    deliberately absent; neither class proves actual immutable bytes here.
    """

    name: str
    worker_delivery: Literal["sealed_fd", "pinned_runtime"]
    manager_hold_kind: Literal["sealed_memfd", "held_runtime_handle"]
    sha256: str
    size_bytes: int
    held_identity_sha256: str
    through_use_pin_sha256: str | None


@dataclass(frozen=True, slots=True)
class ClaimedReleaseDeadline:
    """Residual durations, with manager ticks and controller time kept apart."""

    manager_boot_sha256: str
    manager_now_ns: int
    manager_readback_max_age_ns: int
    startup_bound_ns: int
    claimed_controller_remaining_ns: int
    claimed_cleanup_reserve_ns: int


@dataclass(frozen=True, slots=True)
class ReleaseCandidateAssessment:
    """Arithmetic and identity facts only; no release or readiness decision."""

    release_claim_sha256: str
    one_preparation_plan_sha256: str
    planned_request_id: str
    full_cohort_ordinal: int
    armed_readback_sha256: str
    material_resolution_sha256: str
    manager_runtime_residual_ns: int
    claimed_controller_remaining_ns: int
    unresolved: tuple[str, ...]


def _check_material(
    items: tuple[HeldReleaseMaterial, ...],
    inputs: BoundSubsetTaskInputs,
    expected_sha256: str,
) -> str:
    if (
        type(items) is not tuple
        or not 2 <= len(items) <= 512
        or any(type(item) is not HeldReleaseMaterial for item in items)
        or any(type(item.name) is not str for item in items)
        or tuple(item.name for item in items) != tuple(sorted({item.name for item in items}))
        or {item.name: item.worker_delivery for item in items}.get("entrypoint") != "sealed_fd"
        or {item.name: item.worker_delivery for item in items}.get("interpreter")
        != "pinned_runtime"
    ):
        raise ReleasePrerequisiteError("exact sorted held worker material required")
    sealed_total = 0
    for item in items:
        if (
            type(item.name) is not str
            or _NAME.fullmatch(item.name) is None
            or type(item.worker_delivery) is not str
            or type(item.manager_hold_kind) is not str
            or not _digest(item.sha256)
            or not _digest(item.held_identity_sha256)
            or type(item.size_bytes) is not int
            or item.size_bytes <= 0
        ):
            raise ReleasePrerequisiteError("bounded held material identity required")
        if item.worker_delivery == "sealed_fd":
            if (
                item.manager_hold_kind != "sealed_memfd"
                or item.through_use_pin_sha256 is not None
                or item.size_bytes > _MAX_SEALED_BYTES
            ):
                raise ReleasePrerequisiteError("sealed worker material requires exact held class")
            sealed_total += item.size_bytes
        elif item.worker_delivery == "pinned_runtime":
            if (
                item.manager_hold_kind != "held_runtime_handle"
                or not _digest(item.through_use_pin_sha256)
                or item.size_bytes > _MAX_RUNTIME_BYTES
            ):
                raise ReleasePrerequisiteError(
                    "runtime material requires a held through-use identity, not a path"
                )
        else:
            raise ReleasePrerequisiteError("unknown material delivery class")
    if sealed_total > _MAX_SEALED_BYTES:
        raise ReleasePrerequisiteError("aggregate sealed material exceeds declared boundary")
    if any(type(reference.delivery) is not str for reference in inputs.material):
        raise ReleasePrerequisiteError("exact worker material delivery classes required")
    if tuple(
        (item.name, item.worker_delivery, item.sha256, item.size_bytes) for item in items
    ) != tuple(
        (reference.name, reference.delivery, reference.sha256, reference.size_bytes)
        for reference in inputs.material
    ):
        raise ReleasePrerequisiteError("held material differs from exact worker references")
    material_sha256 = _sha([asdict(item) for item in items])
    if material_sha256 != expected_sha256:
        raise ReleasePrerequisiteError("held material differs from independently supplied pin")
    return material_sha256


def assess_release_prerequisite(
    pins: ReleasePrerequisitePins,
    worker_inputs: BoundSubsetTaskInputs,
    readback: ManagerArmedReadback,
    material: tuple[HeldReleaseMaterial, ...],
    deadline: ClaimedReleaseDeadline,
    *,
    plan: OnePreparationPlan,
) -> ReleaseCandidateAssessment:
    """Compare one claimed release against exact supplied pins; perform no effect."""
    if (
        type(pins) is not ReleasePrerequisitePins
        or type(worker_inputs) is not BoundSubsetTaskInputs
        or type(plan) is not OnePreparationPlan
        or type(readback) is not ManagerArmedReadback
        or type(deadline) is not ClaimedReleaseDeadline
    ):
        raise ReleasePrerequisiteError("exact release fact types required")
    if (
        not all(
            _digest(value)
            for value in (
                pins.preparation_binding_sha256,
                pins.worker_inputs_sha256,
                pins.preparation_started_event_sha256,
                pins.worker_material_manifest_sha256,
                pins.one_preparation_plan_sha256,
                pins.intent_file_sha256,
                pins.armed_file_sha256,
                pins.manager_boot_sha256,
                pins.manager_invocation_sha256,
                pins.manager_cgroup_sha256,
                pins.armed_readback_sha256,
                pins.material_resolution_sha256,
                pins.release_nonce,
                pins.persisted_release_claim_sha256,
            )
        )
        or type(pins.release_ordinal) is not int
        or pins.release_ordinal != 1
        or type(pins.planned_request_id) is not str
        or _IDENTITY.fullmatch(pins.planned_request_id) is None
        or type(pins.full_cohort_ordinal) is not int
        or not 1 <= pins.full_cohort_ordinal <= 1507
        or type(pins.preparation_action) is not str
        or pins.preparation_action != "observe_preparing"
        or type(pins.staging_started) is not bool
        or pins.staging_started is not False
    ):
        raise ReleasePrerequisiteError("exact one-shot release claim and pins required")
    try:
        worker_inputs.__post_init__()
    except WorkerContractError as error:
        raise ReleasePrerequisiteError(
            "worker inputs have a changed material declaration"
        ) from error
    if (
        worker_inputs.identity_sha256 != pins.worker_inputs_sha256
        or pins.preparation_binding_sha256 != worker_inputs.preparation_started_event_sha256
        or worker_inputs.preparation_started_event_sha256 != pins.preparation_started_event_sha256
        or worker_inputs.material_manifest_sha256 != pins.worker_material_manifest_sha256
    ):
        raise ReleasePrerequisiteError("pre-staging worker identity differs from supplied pins")
    if (
        type(plan.schema_version) is not int
        or plan.schema_version != 1
        or plan.plan_sha256 != pins.one_preparation_plan_sha256
        or any(
            type(value) is not str
            for value in (
                plan.run_id,
                plan.epoch,
                plan.task_id,
                plan.preparation_id,
                plan.attempt_id,
                plan.request_id,
                plan.preparation_started_event_sha256,
                plan.worker_inputs_sha256,
                plan.source_commit,
                plan.cohort_sha256,
                plan.admission_sha256,
                plan.freeze_sha256,
                plan.certification_sha256,
                plan.budget_sha256,
                plan.model_policy_sha256,
                plan.metering_policy_sha256,
                plan.launch_config_sha256,
            )
        )
        or (
            plan.run_id,
            plan.epoch,
            plan.task_id,
            plan.preparation_id,
            plan.attempt_id,
            plan.preparation_started_event_sha256,
            plan.worker_inputs_sha256,
            plan.source_commit,
            plan.cohort_sha256,
            plan.admission_sha256,
            plan.freeze_sha256,
            plan.certification_sha256,
            plan.budget_sha256,
            plan.model_policy_sha256,
            plan.metering_policy_sha256,
            plan.launch_config_sha256,
        )
        != (
            worker_inputs.run_id,
            worker_inputs.epoch,
            worker_inputs.task_id,
            worker_inputs.preparation_id,
            worker_inputs.attempt_id,
            worker_inputs.preparation_started_event_sha256,
            worker_inputs.identity_sha256,
            worker_inputs.source_commit,
            worker_inputs.cohort_sha256,
            worker_inputs.admission_sha256,
            worker_inputs.freeze_sha256,
            worker_inputs.certification_sha256,
            worker_inputs.budget_sha256,
            worker_inputs.model_policy_sha256,
            worker_inputs.metering_policy_sha256,
            worker_inputs.launch_config_sha256,
        )
        or plan.request_id != pins.planned_request_id
        or type(plan.full_cohort_ordinal) is not int
        or plan.full_cohort_ordinal != pins.full_cohort_ordinal
        or plan.request_id in {worker_inputs.preparation_id, worker_inputs.attempt_id}
    ):
        raise ReleasePrerequisiteError("one-preparation plan or planned request differs")
    release_claim = {"schema_version": 1, **asdict(pins)}
    release_claim.pop("persisted_release_claim_sha256")
    if _sha(release_claim) != pins.persisted_release_claim_sha256:
        raise ReleasePrerequisiteError("one-shot release claim differs from persisted pin")
    if (
        not all(
            _digest(value)
            for value in (
                readback.intent_file_sha256,
                readback.armed_file_sha256,
                readback.manager_boot_sha256,
                readback.manager_invocation_sha256,
                readback.manager_cgroup_sha256,
            )
        )
        or (
            readback.intent_file_sha256,
            readback.armed_file_sha256,
            readback.manager_boot_sha256,
            readback.manager_invocation_sha256,
            readback.manager_cgroup_sha256,
        )
        != (
            pins.intent_file_sha256,
            pins.armed_file_sha256,
            pins.manager_boot_sha256,
            pins.manager_invocation_sha256,
            pins.manager_cgroup_sha256,
        )
        or type(readback.phase) is not str
        or readback.phase != "armed_paused"
        or any(
            type(value) is not bool or value is not True
            for value in (
                readback.manager_owned,
                readback.worker_held,
                readback.enumeration_complete,
                readback.migration_prevented,
                readback.hard_timeout_armed,
            )
        )
        or type(readback.member_count) is not int
        or not 2 <= readback.member_count <= 1_000_000
        or not _bounded_ns(readback.observed_at_ns)
        or not _bounded_ns(readback.hard_stop_deadline_ns)
        or not _bounded_ns(readback.stop_grace_ns)
        or readback.stop_grace_ns != worker_inputs.stop_grace_ns
        or readback.hard_stop_deadline_ns <= readback.observed_at_ns
        or readback.hard_stop_deadline_ns + readback.stop_grace_ns > _MAX_NS
    ):
        raise ReleasePrerequisiteError("armed manager identity or properties differ")
    readback_sha256 = _sha(asdict(readback))
    if readback_sha256 != pins.armed_readback_sha256:
        raise ReleasePrerequisiteError("manager readback differs from independently supplied pin")
    material_sha256 = _check_material(material, worker_inputs, pins.material_resolution_sha256)
    if (
        not _digest(deadline.manager_boot_sha256)
        or deadline.manager_boot_sha256 != pins.manager_boot_sha256
        or not _bounded_ns(deadline.manager_now_ns)
        or not _bounded_ns(deadline.manager_readback_max_age_ns)
        or not _bounded_ns(deadline.startup_bound_ns)
        or not _bounded_ns(deadline.claimed_controller_remaining_ns)
        or not _bounded_ns(deadline.claimed_cleanup_reserve_ns)
        or deadline.manager_now_ns < readback.observed_at_ns
        or deadline.manager_now_ns - readback.observed_at_ns > deadline.manager_readback_max_age_ns
        or deadline.manager_now_ns >= readback.hard_stop_deadline_ns
    ):
        raise ReleasePrerequisiteError("fresh same-boot manager deadline observation required")
    runtime_residual = readback.hard_stop_deadline_ns - deadline.manager_now_ns
    if (
        runtime_residual <= deadline.startup_bound_ns
        or runtime_residual + readback.stop_grace_ns + deadline.claimed_cleanup_reserve_ns
        > deadline.claimed_controller_remaining_ns
    ):
        raise ReleasePrerequisiteError("claimed residual lacks startup, stop or cleanup reserve")
    return ReleaseCandidateAssessment(
        release_claim_sha256=pins.persisted_release_claim_sha256,
        one_preparation_plan_sha256=plan.plan_sha256,
        planned_request_id=plan.request_id,
        full_cohort_ordinal=plan.full_cohort_ordinal,
        armed_readback_sha256=readback_sha256,
        material_resolution_sha256=material_sha256,
        manager_runtime_residual_ns=runtime_residual,
        claimed_controller_remaining_ns=deadline.claimed_controller_remaining_ns,
        unresolved=(
            "independent_pin_authority",
            "durable_single_use_consumption",
            "manager_platform_and_material_through_use",
            "fresh_signed_pre_staging_state",
            "independent_full_cohort_and_planned_request_provenance",
            "trusted_boot_clock_and_calibrated_cleanup",
            "fresh_effect_lease_and_accounting",
        ),
    )
