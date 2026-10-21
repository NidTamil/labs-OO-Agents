# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Pure one-preparation plan checks with synthetic, unattested facts."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest
from nooa_cybergym.leaderboard.budgeted_subset_admission import (
    BudgetedSubsetPreview,
    BudgetedSubsetState,
)
from nooa_cybergym.leaderboard.budgeted_subset_capabilities import (
    BudgetedSubsetCapabilityAdmission,
)
from nooa_cybergym.leaderboard.budgeted_subset_material import (
    BudgetedSubsetMaterial,
    VerifiedSubsetCohort,
)
from nooa_cybergym.leaderboard.budgeted_subset_preparation_plan import (
    ClassifiedDependency,
    PreparationPlanError,
    verify_one_preparation_plan,
)
from nooa_cybergym.leaderboard.budgeted_subset_runtime import BudgetedSubsetRuntimeBinding
from nooa_cybergym.leaderboard.campaign import CampaignAction
from nooa_cybergym.leaderboard.capabilities import CapabilityRegistry
from nooa_cybergym.leaderboard.subset_dry_run_admission import OFFICIAL_SUBSET_TASK_IDS
from nooa_cybergym.leaderboard.subset_run_budget import VerifiedSubsetBudget
from nooa_cybergym.leaderboard.subset_worker_contract import (
    BoundSubsetTaskInputs,
    MaterialReference,
)

_HASHES = tuple(character * 64 for character in "0123456789abcdef")
_COHORT_IDS = (
    tuple(f"arvo:{100000 + number}" for number in range(750))
    + OFFICIAL_SUBSET_TASK_IDS
    + tuple(f"arvo:{200000 + number}" for number in range(747))
)


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _case() -> dict:
    budget = VerifiedSubsetBudget(
        run_id="subset-run",
        epoch="epoch-1",
        campaign_policy_sha256=_HASHES[1],
        model_policy_sha256=_HASHES[2],
        metering_policy_sha256=_HASHES[3],
        max_elapsed_seconds=432000,
        max_spend_units=500000000,
        signed_envelope=b"synthetic budget bytes",
        envelope_sha256=_HASHES[4],
        payload_json=b"synthetic payload bytes",
        payload_sha256=_HASHES[5],
    )
    preview = BudgetedSubsetPreview(
        run_id="subset-run",
        epoch="epoch-1",
        evidence_root=Path("/synthetic/evidence"),
        source_commit="a" * 40,
        cohort_sha256=_HASHES[6],
        freeze_sha256=_HASHES[7],
        certification_sha256=_HASHES[8],
        admission_sha256=_HASHES[9],
        payload_sha256=_HASHES[10],
        signed_admission=b"synthetic admission bytes",
        budget=budget,
    )
    state = BudgetedSubsetState(preview, object(), b"freeze", b"certification", object(), object())
    cohort = VerifiedSubsetCohort(
        signed_cohort=b"synthetic cohort bytes",
        tasks_json=b"synthetic tasks bytes",
        cohort_sha256=_HASHES[6],
        tasks_json_sha256=_HASHES[11],
        task_ids=_COHORT_IDS,
        asset_hashes_sha256=_HASHES[12],
        benchmark_commit="b" * 40,
        dataset_commit="c" * 40,
        mask_map_sha256=_HASHES[13],
        generator_sha256=_HASHES[14],
        harness_manifest_sha256=_HASHES[15],
    )
    material = BudgetedSubsetMaterial(
        state=state,
        cohort=cohort,
        asset_manifest_path=Path("/synthetic/assets.json"),
        image_manifest_path=Path("/synthetic/images.json"),
        scored_images_sha256=_HASHES[0],
        _controller_paths=None,
        _asset_entries=(),
        _image_rows=(),
    )
    registry = CapabilityRegistry(())
    admission = BudgetedSubsetCapabilityAdmission(
        run_id="subset-run",
        epoch="epoch-1",
        task_id="arvo:47101",
        preparation_id="prep-101",
        cohort_sha256=_HASHES[6],
        admission_sha256=_HASHES[9],
        budget_sha256=_HASHES[4],
        registry_sha256=registry.digest,
        image_id="sha256:" + _HASHES[0],
        _state=state,
    )
    runtime = BudgetedSubsetRuntimeBinding(
        state=state,
        material=material,
        admission=admission,
        task_id="arvo:47101",
        attempt_id="attempt-101",
        preparation_id="prep-101",
        source_commit="a" * 40,
        donor_configuration_sha256=_HASHES[1],
        bindings_sha256=_HASHES[2],
        registry=registry,
        bindings=(),
        _captured_schemas=(),
        _alternate_json=b"{}",
        _template_inventory=(),
        _donor=None,
        _bindings_path=Path("/synthetic/bindings.json"),
        _observed_image_id="sha256:" + _HASHES[0],
    )
    preparation_event = {
        "type": "preparation_started",
        "task_id": "arvo:47101",
        "preparation_id": "prep-101",
    }
    preparation_sha = hashlib.sha256(_canonical(preparation_event)).hexdigest()
    preparation = {
        "preparation_id": "prep-101",
        "preparation_started_event_sha256": preparation_sha,
        "preparation_started": preparation_event,
        "prepared": None,
        "prepared_event_sha256": None,
    }
    references = (
        MaterialReference("entrypoint", "sealed_fd", _HASHES[10], 128, fd=7),
        MaterialReference(
            "interpreter", "pinned_runtime", _HASHES[11], 100000, path="/opt/cybergym/python"
        ),
    )
    material_manifest = _canonical(
        {"schema_version": 1, "items": [reference.manifest_record() for reference in references]}
    )
    deadline_ns = 432001_000_000_000
    worker_inputs = BoundSubsetTaskInputs(
        run_id="subset-run",
        epoch="epoch-1",
        task_id="arvo:47101",
        preparation_id="prep-101",
        attempt_id="attempt-101",
        preparation_started_event_sha256=preparation_sha,
        source_commit="a" * 40,
        cohort_sha256=_HASHES[6],
        admission_sha256=_HASHES[9],
        freeze_sha256=_HASHES[7],
        certification_sha256=_HASHES[8],
        budget_sha256=_HASHES[4],
        model_policy_sha256=_HASHES[2],
        metering_policy_sha256=_HASHES[3],
        launch_config_sha256=_HASHES[5],
        material_manifest_sha256=hashlib.sha256(material_manifest).hexdigest(),
        aggregate_deadline_ns=deadline_ns,
        manager_deadline_ns=deadline_ns - 1_000_000_000,
        stop_grace_ns=500_000_000,
        material=references,
    )
    resources = {
        "schema_version": 2,
        "clock_basis": "suspend_aware_uptime_ns",
        "boot_domain_sha256": _HASHES[12],
        "accounting_sha256": _HASHES[13],
        "event_ordinal": 1,
        "run_id": "subset-run",
        "epoch": "epoch-1",
        "budget_sha256": _HASHES[4],
        "metering_policy_sha256": _HASHES[3],
        "started_at_ns": 1_000_000_000,
        "last_observed_ns": 2_000_000_000,
        "deadline_ns": deadline_ns,
        "stop": None,
        "tasks": {
            task: {"requests": 0, "primary_and_memory": 0, "deepseek_advisory": 0}
            for task in OFFICIAL_SUBSET_TASK_IDS
        },
        "attempts": {},
        "closures": {},
    }
    dependencies = (
        ClassifiedDependency(
            "docker_socket", "runtime_service", "external_runtime", _HASHES[12], None, ()
        ),
        ClassifiedDependency(
            "entrypoint",
            "python_module",
            "sealed_fd",
            _HASHES[10],
            128,
            ("docker_socket", "interpreter"),
        ),
        ClassifiedDependency(
            "interpreter", "executable", "pinned_runtime", _HASHES[11], 100000, ()
        ),
    )
    return {
        "state": state,
        "action": CampaignAction("observe_preparing", "arvo:47101"),
        "preparation": preparation,
        "runtime": runtime,
        "material": material,
        "worker_inputs": worker_inputs,
        "resource_snapshot": resources,
        "launch_config_sha256": _HASHES[5],
        "planned_request_id": "request-101",
        "expected_request_id": "request-101",
        "full_cohort_ordinal": 751,
        "dependencies": dependencies,
        "external_runtime_pins": {"docker_socket": _HASHES[12]},
        "expected_material_pins": {
            "cohort_sha256": cohort.cohort_sha256,
            "tasks_json_sha256": cohort.tasks_json_sha256,
            "full_cohort_order_sha256": hashlib.sha256(
                _canonical(list(cohort.task_ids))
            ).hexdigest(),
            "asset_hashes_sha256": cohort.asset_hashes_sha256,
            "benchmark_commit": cohort.benchmark_commit,
            "dataset_commit": cohort.dataset_commit,
            "mask_map_sha256": cohort.mask_map_sha256,
            "generator_sha256": cohort.generator_sha256,
            "harness_manifest_sha256": cohort.harness_manifest_sha256,
            "scored_images_sha256": material.scored_images_sha256,
        },
        "expected_runtime_pins": {
            "donor_configuration_sha256": runtime.donor_configuration_sha256,
            "bindings_sha256": runtime.bindings_sha256,
            "capability_registry_sha256": runtime.registry.digest,
            "observed_native_image_id": runtime._observed_image_id,
        },
        "expected_resource_pins": {
            "boot_domain_sha256": resources["boot_domain_sha256"],
            "accounting_sha256": resources["accounting_sha256"],
            "event_ordinal": resources["event_ordinal"],
            "last_observed_ns": resources["last_observed_ns"],
        },
    }


def test_one_preparation_plan_binds_verified_facts_without_effect_authority():
    inputs = _case()
    plan = verify_one_preparation_plan(**inputs)

    assert plan.schema_version == 1
    assert (plan.task_id, plan.preparation_id, plan.attempt_id, plan.request_id) == (
        "arvo:47101",
        "prep-101",
        "attempt-101",
        "request-101",
    )
    assert plan.full_cohort_ordinal == 751
    assert (
        plan.preparation_started_event_sha256
        == inputs["preparation"]["preparation_started_event_sha256"]
    )
    assert plan.worker_inputs_sha256 == inputs["worker_inputs"].identity_sha256
    assert plan.plan_sha256 == verify_one_preparation_plan(**inputs).plan_sha256
    assert not hasattr(plan, "permitted")


@pytest.mark.parametrize("pin_group", ["material", "runtime", "resource"])
def test_one_preparation_plan_rejects_independent_pin_swap(pin_group):
    inputs = _case()
    expected = dict(inputs[f"expected_{pin_group}_pins"])
    first_key = next(iter(expected))
    expected[first_key] = _HASHES[15]
    inputs[f"expected_{pin_group}_pins"] = expected
    with pytest.raises(PreparationPlanError):
        verify_one_preparation_plan(**inputs)


@pytest.mark.parametrize(
    "name, replacement",
    [
        ("full_cohort_ordinal", 752),
        ("planned_request_id", "request-102"),
        ("action", CampaignAction("observe_prepared", "arvo:47101")),
    ],
)
def test_one_preparation_plan_rejects_ordinal_request_or_action_replay(name, replacement):
    inputs = _case()
    inputs[name] = replacement
    with pytest.raises(PreparationPlanError):
        verify_one_preparation_plan(**inputs)


def test_one_preparation_plan_recomputes_ordinal_from_preserved_cohort_order():
    inputs = _case()
    original = inputs["material"].cohort.task_ids
    shifted = list(original)
    shifted[750], shifted[751] = shifted[751], shifted[750]
    cohort = replace(inputs["material"].cohort, task_ids=tuple(shifted))
    material = replace(inputs["material"], cohort=cohort)
    inputs["material"] = material
    inputs["runtime"] = replace(inputs["runtime"], material=material)
    inputs["expected_material_pins"]["full_cohort_order_sha256"] = hashlib.sha256(
        _canonical(shifted)
    ).hexdigest()
    with pytest.raises(PreparationPlanError, match="ordinal"):
        verify_one_preparation_plan(**inputs)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda case: case.update(
            worker_inputs=replace(case["worker_inputs"], attempt_id="attempt-102")
        ),
        lambda case: case["preparation"].update(prepared={"type": "prepared"}),
        lambda case: case["preparation"].update(prepared_event_sha256=_HASHES[0]),
        lambda case: case["preparation"]["preparation_started"].update(preparation_id="prep-102"),
    ],
)
def test_one_preparation_plan_rejects_attempt_or_preparation_replay(mutation):
    inputs = _case()
    mutation(inputs)
    with pytest.raises(PreparationPlanError):
        verify_one_preparation_plan(**inputs)


def test_one_preparation_plan_rejects_noncanonical_preparation_event():
    inputs = _case()
    event = inputs["preparation"]["preparation_started"]
    event["extra"] = "unverified"
    event_sha256 = hashlib.sha256(_canonical(event)).hexdigest()
    inputs["preparation"]["preparation_started_event_sha256"] = event_sha256
    inputs["worker_inputs"] = replace(
        inputs["worker_inputs"], preparation_started_event_sha256=event_sha256
    )
    with pytest.raises(PreparationPlanError):
        verify_one_preparation_plan(**inputs)


@pytest.mark.parametrize(
    "dependencies",
    [
        lambda items: items[:-1],
        lambda items: items[:1] + (replace(items[1], depends_on=("missing",)),) + items[2:],
        lambda items: items[:2] + (replace(items[2], depends_on=("entrypoint",)),),
    ],
)
def test_one_preparation_plan_rejects_open_or_unknown_dependency(dependencies):
    inputs = _case()
    inputs["dependencies"] = dependencies(inputs["dependencies"])
    with pytest.raises(PreparationPlanError):
        verify_one_preparation_plan(**inputs)


@pytest.mark.parametrize("bad_value", [[], None])
@pytest.mark.parametrize("resource_key", ["tasks", "attempts", "closures"])
def test_one_preparation_plan_rejects_malformed_resource_maps(bad_value, resource_key):
    inputs = _case()
    inputs["resource_snapshot"][resource_key] = bad_value
    with pytest.raises(PreparationPlanError):
        verify_one_preparation_plan(**inputs)


def test_one_preparation_plan_rejects_malformed_dependency_kind():
    inputs = _case()
    object.__setattr__(inputs["dependencies"][0], "kind", [])
    with pytest.raises(PreparationPlanError):
        verify_one_preparation_plan(**inputs)


def test_one_preparation_plan_requires_integer_resource_schema_version():
    inputs = _case()
    inputs["resource_snapshot"]["schema_version"] = 2.0
    with pytest.raises(PreparationPlanError):
        verify_one_preparation_plan(**inputs)


def test_one_preparation_plan_rejects_malformed_runtime_admission():
    inputs = _case()
    inputs["runtime"] = replace(inputs["runtime"], admission=object())
    with pytest.raises(PreparationPlanError):
        verify_one_preparation_plan(**inputs)


def test_dependency_constructor_rejects_unknown_classification():
    with pytest.raises(PreparationPlanError):
        ClassifiedDependency("dependency", "unknown", "sealed_fd", _HASHES[0], 10, ())


def test_one_preparation_plan_requires_entrypoint_and_interpreter_classification():
    inputs = _case()
    object.__setattr__(inputs["dependencies"][1], "kind", "resource_file")
    with pytest.raises(PreparationPlanError, match="classification"):
        verify_one_preparation_plan(**inputs)
