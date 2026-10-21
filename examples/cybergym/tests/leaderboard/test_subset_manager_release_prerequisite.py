# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Synthetic comparisons only; these facts never release a worker."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, replace
from enum import StrEnum

import pytest
from nooa_cybergym.leaderboard.budgeted_subset_preparation_plan import OnePreparationPlan
from nooa_cybergym.leaderboard.subset_manager_release_prerequisite import (
    ClaimedReleaseDeadline,
    HeldReleaseMaterial,
    ManagerArmedReadback,
    ReleasePrerequisiteError,
    ReleasePrerequisitePins,
)
from nooa_cybergym.leaderboard.subset_manager_release_prerequisite import (
    assess_release_prerequisite as _candidate_assess,
)
from nooa_cybergym.leaderboard.subset_worker_contract import (
    BoundSubsetTaskInputs,
    MaterialReference,
)


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()


def _repin(pins: ReleasePrerequisitePins, **updates: object) -> ReleasePrerequisitePins:
    changed = replace(pins, **updates)
    claim = {"schema_version": 1, **asdict(changed)}
    claim.pop("persisted_release_claim_sha256")
    return replace(changed, persisted_release_claim_sha256=_digest(claim))


def _plan(worker_inputs: BoundSubsetTaskInputs) -> OnePreparationPlan:
    return OnePreparationPlan(
        schema_version=1,
        run_id=worker_inputs.run_id,
        epoch=worker_inputs.epoch,
        task_id=worker_inputs.task_id,
        preparation_id=worker_inputs.preparation_id,
        preparation_started_event_sha256=worker_inputs.preparation_started_event_sha256,
        attempt_id=worker_inputs.attempt_id,
        request_id="request-101",
        full_cohort_ordinal=751,
        worker_inputs_sha256=worker_inputs.identity_sha256,
        dependency_declaration_sha256="0" * 64,
        source_commit=worker_inputs.source_commit,
        cohort_sha256=worker_inputs.cohort_sha256,
        admission_sha256=worker_inputs.admission_sha256,
        freeze_sha256=worker_inputs.freeze_sha256,
        certification_sha256=worker_inputs.certification_sha256,
        budget_sha256=worker_inputs.budget_sha256,
        model_policy_sha256=worker_inputs.model_policy_sha256,
        metering_policy_sha256=worker_inputs.metering_policy_sha256,
        launch_config_sha256=worker_inputs.launch_config_sha256,
        donor_configuration_sha256="1" * 64,
        bindings_sha256="2" * 64,
        capability_registry_sha256="3" * 64,
        scored_images_sha256="4" * 64,
        observed_native_image_id="sha256:" + "5" * 64,
        resource_boot_domain_sha256="6" * 64,
        resource_accounting_sha256="7" * 64,
        resource_event_ordinal=3,
        resource_observed_ns=2000,
        material_pins_sha256="8" * 64,
        runtime_pins_sha256="9" * 64,
    )


def assess_release_prerequisite(
    pins: ReleasePrerequisitePins,
    worker_inputs: BoundSubsetTaskInputs,
    readback: ManagerArmedReadback,
    material: tuple[HeldReleaseMaterial, ...],
    deadline: ClaimedReleaseDeadline,
    *,
    plan: OnePreparationPlan | None = None,
):
    return _candidate_assess(
        pins,
        worker_inputs,
        readback,
        material,
        deadline,
        plan=_plan(worker_inputs) if plan is None else plan,
    )


def _case() -> tuple:
    worker_material = (
        MaterialReference("entrypoint", "sealed_fd", "a" * 64, 4096, fd=7),
        MaterialReference(
            "interpreter",
            "pinned_runtime",
            "c" * 64,
            8_000_000,
            path="/synthetic/interpreter",
        ),
    )
    worker_inputs = BoundSubsetTaskInputs(
        run_id="subset-run",
        epoch="epoch-1",
        task_id="arvo:47101",
        preparation_id="prep-101",
        attempt_id="attempt-101",
        preparation_started_event_sha256="7" * 64,
        source_commit="a" * 40,
        cohort_sha256="8" * 64,
        admission_sha256="9" * 64,
        freeze_sha256="a" * 64,
        certification_sha256="b" * 64,
        budget_sha256="c" * 64,
        model_policy_sha256="d" * 64,
        metering_policy_sha256="e" * 64,
        launch_config_sha256="f" * 64,
        material_manifest_sha256=_digest(
            {"schema_version": 1, "items": [item.manifest_record() for item in worker_material]}
        ),
        aggregate_deadline_ns=50_000,
        manager_deadline_ns=40_000,
        stop_grace_ns=1_000,
        material=worker_material,
    )
    material = (
        HeldReleaseMaterial(
            name="entrypoint",
            worker_delivery="sealed_fd",
            manager_hold_kind="sealed_memfd",
            sha256="a" * 64,
            size_bytes=4096,
            held_identity_sha256="b" * 64,
            through_use_pin_sha256=None,
        ),
        HeldReleaseMaterial(
            name="interpreter",
            worker_delivery="pinned_runtime",
            manager_hold_kind="held_runtime_handle",
            sha256="c" * 64,
            size_bytes=8_000_000,
            held_identity_sha256="d" * 64,
            through_use_pin_sha256="e" * 64,
        ),
    )
    readback = ManagerArmedReadback(
        intent_file_sha256="1" * 64,
        armed_file_sha256="2" * 64,
        manager_boot_sha256="3" * 64,
        manager_invocation_sha256="4" * 64,
        manager_cgroup_sha256="5" * 64,
        phase="armed_paused",
        observed_at_ns=2_000,
        hard_stop_deadline_ns=12_000,
        stop_grace_ns=1_000,
        manager_owned=True,
        worker_held=True,
        enumeration_complete=True,
        migration_prevented=True,
        hard_timeout_armed=True,
        member_count=2,
    )
    facts = {
        "schema_version": 1,
        "preparation_binding_sha256": worker_inputs.preparation_started_event_sha256,
        "worker_inputs_sha256": worker_inputs.identity_sha256,
        "preparation_started_event_sha256": worker_inputs.preparation_started_event_sha256,
        "worker_material_manifest_sha256": worker_inputs.material_manifest_sha256,
        "one_preparation_plan_sha256": _plan(worker_inputs).plan_sha256,
        "planned_request_id": "request-101",
        "full_cohort_ordinal": 751,
        "preparation_action": "observe_preparing",
        "staging_started": False,
        "intent_file_sha256": readback.intent_file_sha256,
        "armed_file_sha256": readback.armed_file_sha256,
        "manager_boot_sha256": readback.manager_boot_sha256,
        "manager_invocation_sha256": readback.manager_invocation_sha256,
        "manager_cgroup_sha256": readback.manager_cgroup_sha256,
        "armed_readback_sha256": _digest(asdict(readback)),
        "material_resolution_sha256": _digest([asdict(item) for item in material]),
        "release_nonce": "6" * 64,
        "release_ordinal": 1,
    }
    pins = ReleasePrerequisitePins(
        **{key: value for key, value in facts.items() if key != "schema_version"},
        persisted_release_claim_sha256=_digest(facts),
    )
    deadline = ClaimedReleaseDeadline(
        manager_boot_sha256="3" * 64,
        manager_now_ns=3_000,
        manager_readback_max_age_ns=2_000,
        startup_bound_ns=2_000,
        claimed_controller_remaining_ns=15_000,
        claimed_cleanup_reserve_ns=1_000,
    )
    return pins, worker_inputs, readback, material, deadline


def test_returns_only_candidate_facts_with_explicit_unresolved_authorities() -> None:
    pins, worker_inputs, readback, material, deadline = _case()

    result = assess_release_prerequisite(pins, worker_inputs, readback, material, deadline)

    assert result.release_claim_sha256 == pins.persisted_release_claim_sha256
    assert result.manager_runtime_residual_ns == 9_000
    assert result.claimed_controller_remaining_ns == 15_000
    assert "independent_pin_authority" in result.unresolved
    assert "durable_single_use_consumption" in result.unresolved
    assert "manager_platform_and_material_through_use" in result.unresolved
    assert not hasattr(result, "permission")
    assert not hasattr(result, "complete")


@pytest.mark.parametrize(
    "field",
    [
        "intent_file_sha256",
        "armed_file_sha256",
        "manager_boot_sha256",
        "manager_invocation_sha256",
        "manager_cgroup_sha256",
        "armed_readback_sha256",
        "material_resolution_sha256",
        "persisted_release_claim_sha256",
    ],
)
def test_rejects_foreign_independently_supplied_pin(field: str) -> None:
    pins, worker_inputs, readback, material, deadline = _case()
    with pytest.raises(ReleasePrerequisiteError):
        assess_release_prerequisite(
            replace(pins, **{field: "9" * 64}), worker_inputs, readback, material, deadline
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("phase", "running"),
        ("manager_owned", False),
        ("worker_held", False),
        ("enumeration_complete", False),
        ("migration_prevented", False),
        ("hard_timeout_armed", False),
        ("member_count", 1),
    ],
)
def test_rejects_readback_without_armed_whole_cgroup_hold(field: str, value: object) -> None:
    pins, worker_inputs, readback, material, deadline = _case()
    with pytest.raises(ReleasePrerequisiteError):
        assess_release_prerequisite(
            pins, worker_inputs, replace(readback, **{field: value}), material, deadline
        )


def test_rejects_current_all_sealed_manager_class_mismatch() -> None:
    pins, worker_inputs, readback, material, deadline = _case()
    unresolved_interpreter = replace(
        material[1], manager_hold_kind="sealed_memfd", through_use_pin_sha256=None
    )
    with pytest.raises(ReleasePrerequisiteError):
        assess_release_prerequisite(
            pins, worker_inputs, readback, (material[0], unresolved_interpreter), deadline
        )


@pytest.mark.parametrize("bad_material", ["missing_pin", "swapped", "duplicate", "path"])
def test_rejects_unresolved_or_mutable_material(bad_material: str) -> None:
    pins, worker_inputs, readback, material, deadline = _case()
    if bad_material == "missing_pin":
        changed = (material[0], replace(material[1], through_use_pin_sha256=None))
    elif bad_material == "swapped":
        changed = material[::-1]
    elif bad_material == "duplicate":
        changed = (material[0], replace(material[1], name="entrypoint"))
    else:
        with pytest.raises(TypeError):
            HeldReleaseMaterial(**asdict(material[1]), path="/mutable/interpreter")
        return
    with pytest.raises(ReleasePrerequisiteError):
        assess_release_prerequisite(pins, worker_inputs, readback, changed, deadline)


@pytest.mark.parametrize(
    "field,value",
    [
        ("manager_boot_sha256", "9" * 64),
        ("manager_now_ns", 4_001),
        ("startup_bound_ns", 9_000),
        ("claimed_controller_remaining_ns", 10_999),
        ("claimed_cleanup_reserve_ns", 0),
        ("claimed_cleanup_reserve_ns", -1),
    ],
)
def test_rejects_foreign_stale_or_short_claimed_deadline(field: str, value: object) -> None:
    pins, worker_inputs, readback, material, deadline = _case()
    with pytest.raises(ReleasePrerequisiteError):
        assess_release_prerequisite(
            pins, worker_inputs, readback, material, replace(deadline, **{field: value})
        )


def test_rejects_second_release_ordinal() -> None:
    pins, worker_inputs, readback, material, deadline = _case()
    with pytest.raises(ReleasePrerequisiteError):
        assess_release_prerequisite(
            replace(pins, release_ordinal=2), worker_inputs, readback, material, deadline
        )


def test_rejects_foreign_preparation_binding_even_with_self_consistent_release_claim():
    pins, worker_inputs, readback, material, deadline = _case()
    with pytest.raises(ReleasePrerequisiteError):
        assess_release_prerequisite(
            _repin(pins, preparation_binding_sha256="0" * 64),
            worker_inputs,
            readback,
            material,
            deadline,
        )


def test_rejects_shortened_manager_stop_grace_even_with_new_readback_pin():
    pins, worker_inputs, readback, material, deadline = _case()
    shortened = replace(readback, stop_grace_ns=500)
    repinned = _repin(pins, armed_readback_sha256=_digest(asdict(shortened)))
    with pytest.raises(ReleasePrerequisiteError):
        assess_release_prerequisite(repinned, worker_inputs, shortened, material, deadline)


class _Lookalike(StrEnum):
    OBSERVE_PREPARING = "observe_preparing"
    ARMED_PAUSED = "armed_paused"
    SEALED_FD = "sealed_fd"
    SEALED_MEMFD = "sealed_memfd"
    BOOT = "3" * 64


@pytest.mark.parametrize(
    "part",
    ["preparation_action", "readback_phase", "worker_delivery", "manager_hold_kind", "boot"],
)
def test_rejects_string_enum_lookalikes_even_when_claim_digests_match(part: str):
    pins, worker_inputs, readback, material, deadline = _case()
    if part == "preparation_action":
        pins = _repin(pins, preparation_action=_Lookalike.OBSERVE_PREPARING)
    elif part == "readback_phase":
        readback = replace(readback, phase=_Lookalike.ARMED_PAUSED)
        pins = _repin(pins, armed_readback_sha256=_digest(asdict(readback)))
    elif part == "worker_delivery":
        material = (replace(material[0], worker_delivery=_Lookalike.SEALED_FD), material[1])
        pins = _repin(pins, material_resolution_sha256=_digest([asdict(item) for item in material]))
    elif part == "manager_hold_kind":
        material = (replace(material[0], manager_hold_kind=_Lookalike.SEALED_MEMFD), material[1])
        pins = _repin(pins, material_resolution_sha256=_digest([asdict(item) for item in material]))
    else:
        deadline = replace(deadline, manager_boot_sha256=_Lookalike.BOOT)
    with pytest.raises(ReleasePrerequisiteError):
        assess_release_prerequisite(pins, worker_inputs, readback, material, deadline)


@pytest.mark.parametrize(
    "field,value",
    [
        ("preparation_action", "observe_prepared"),
        ("staging_started", True),
        ("preparation_started_event_sha256", "9" * 64),
        ("worker_material_manifest_sha256", "9" * 64),
    ],
)
def test_requires_exact_pre_staging_preparation_and_worker_manifest(field: str, value: object):
    pins, worker_inputs, readback, material, deadline = _case()
    with pytest.raises(ReleasePrerequisiteError):
        assess_release_prerequisite(
            replace(pins, **{field: value}), worker_inputs, readback, material, deadline
        )


def test_rejects_worker_material_substitution_even_when_manager_claim_is_unchanged():
    pins, worker_inputs, readback, material, deadline = _case()
    other_material = (
        replace(worker_inputs.material[0], sha256="0" * 64),
        worker_inputs.material[1],
    )
    other_inputs = replace(
        worker_inputs,
        material=other_material,
        material_manifest_sha256=_digest(
            {"schema_version": 1, "items": [item.manifest_record() for item in other_material]}
        ),
    )
    with pytest.raises(ReleasePrerequisiteError):
        assess_release_prerequisite(pins, other_inputs, readback, material, deadline)


def test_rejects_worker_delivery_string_enum_lookalike():
    pins, worker_inputs, readback, material, deadline = _case()
    other_material = (
        replace(worker_inputs.material[0], delivery=_Lookalike.SEALED_FD),
        worker_inputs.material[1],
    )
    other_inputs = replace(worker_inputs, material=other_material)
    with pytest.raises(ReleasePrerequisiteError):
        assess_release_prerequisite(pins, other_inputs, readback, material, deadline)


def test_malformed_material_name_uses_release_contract_error():
    pins, worker_inputs, readback, material, deadline = _case()
    malformed = (material[0], replace(material[1], name=1))
    with pytest.raises(ReleasePrerequisiteError):
        assess_release_prerequisite(pins, worker_inputs, readback, malformed, deadline)


@pytest.mark.parametrize(
    "pin_field,value",
    [
        ("one_preparation_plan_sha256", "0" * 64),
        ("planned_request_id", "foreign-request"),
        ("full_cohort_ordinal", 752),
    ],
)
def test_rejects_foreign_plan_pin_request_or_full_cohort_ordinal(pin_field: str, value: object):
    pins, worker_inputs, readback, material, deadline = _case()
    with pytest.raises(ReleasePrerequisiteError):
        assess_release_prerequisite(
            _repin(pins, **{pin_field: value}), worker_inputs, readback, material, deadline
        )


@pytest.mark.parametrize(
    "plan_field,value",
    [
        ("task_id", "arvo:99999"),
        ("attempt_id", "other-attempt"),
        ("preparation_started_event_sha256", "0" * 64),
        ("worker_inputs_sha256", "0" * 64),
        ("request_id", "other-request"),
        ("full_cohort_ordinal", 752),
    ],
)
def test_rejects_changed_plan_identity(plan_field: str, value: object):
    pins, worker_inputs, readback, material, deadline = _case()
    changed_plan = replace(_plan(worker_inputs), **{plan_field: value})
    with pytest.raises(ReleasePrerequisiteError):
        assess_release_prerequisite(
            pins, worker_inputs, readback, material, deadline, plan=changed_plan
        )
