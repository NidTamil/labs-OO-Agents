# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Pure consistency plan for one already committed subset preparation.

The caller supplies independently verified state, resource and dependency facts.
This module reads no files or clocks and grants no staging, process, signing,
Docker, UI or model effect permission. A closed *declared* graph does not prove
that every actual import or runtime dependency was discovered or held immutable.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Literal

from .budgeted_subset_admission import BudgetedSubsetPreview, BudgetedSubsetState
from .budgeted_subset_capabilities import BudgetedSubsetCapabilityAdmission
from .budgeted_subset_material import BudgetedSubsetMaterial, VerifiedSubsetCohort
from .budgeted_subset_runtime import BudgetedSubsetRuntimeBinding
from .campaign import CampaignAction, _json_bytes
from .capabilities import CapabilityRegistry
from .subset_dry_run_admission import OFFICIAL_SUBSET_TASK_IDS
from .subset_worker_contract import BoundSubsetTaskInputs, WorkerContractError

_NAME = re.compile(r"[a-z][a-z0-9_.-]{0,127}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_MATERIAL_KINDS = frozenset({"python_module", "native_library", "resource_file", "executable"})
_EXTERNAL_KINDS = frozenset(
    {"runtime_service", "credential_channel", "container_image", "ui_route"}
)


class PreparationPlanError(ValueError):
    """Supplied one-preparation facts disagree or a declared dependency is open."""


def _digest(value: object) -> bool:
    return type(value) is str and _SHA.fullmatch(value) is not None


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()


@dataclass(frozen=True, slots=True)
class ClassifiedDependency:
    """One declared dependency identity; delivery and discovery proof are external."""

    name: str
    kind: Literal[
        "python_module",
        "native_library",
        "resource_file",
        "executable",
        "runtime_service",
        "credential_channel",
        "container_image",
        "ui_route",
    ]
    delivery: Literal["sealed_fd", "pinned_runtime", "external_runtime"]
    sha256: str
    size_bytes: int | None
    depends_on: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            type(self.name) is not str
            or _NAME.fullmatch(self.name) is None
            or type(self.kind) is not str
            or type(self.delivery) is not str
            or not _digest(self.sha256)
            or type(self.depends_on) is not tuple
            or any(
                type(name) is not str or _NAME.fullmatch(name) is None for name in self.depends_on
            )
            or tuple(sorted(set(self.depends_on))) != self.depends_on
            or self.name in self.depends_on
        ):
            raise PreparationPlanError("canonical named dependency and sorted edges required")
        if self.kind in _MATERIAL_KINDS:
            if (
                self.delivery not in {"sealed_fd", "pinned_runtime"}
                or type(self.size_bytes) is not int
                or self.size_bytes <= 0
            ):
                raise PreparationPlanError("material dependency needs exact classified bytes")
        elif self.kind in _EXTERNAL_KINDS:
            if self.delivery != "external_runtime" or self.size_bytes is not None:
                raise PreparationPlanError("external dependency needs a separate runtime pin")
        else:
            raise PreparationPlanError("unknown dependency classification")


@dataclass(frozen=True, slots=True)
class OnePreparationPlan:
    """Deterministic identity summary only; no permission or readiness result."""

    schema_version: int
    run_id: str
    epoch: str
    task_id: str
    preparation_id: str
    preparation_started_event_sha256: str
    attempt_id: str
    request_id: str
    full_cohort_ordinal: int
    worker_inputs_sha256: str
    dependency_declaration_sha256: str
    source_commit: str
    cohort_sha256: str
    admission_sha256: str
    freeze_sha256: str
    certification_sha256: str
    budget_sha256: str
    model_policy_sha256: str
    metering_policy_sha256: str
    launch_config_sha256: str
    donor_configuration_sha256: str
    bindings_sha256: str
    capability_registry_sha256: str
    scored_images_sha256: str
    observed_native_image_id: str
    resource_boot_domain_sha256: str
    resource_accounting_sha256: str
    resource_event_ordinal: int
    resource_observed_ns: int
    material_pins_sha256: str
    runtime_pins_sha256: str

    @property
    def plan_sha256(self) -> str:
        return hashlib.sha256(_canonical(asdict(self))).hexdigest()


def _dependency_digest(
    dependencies: tuple[ClassifiedDependency, ...],
    inputs: BoundSubsetTaskInputs,
    external_runtime_pins: Mapping[str, str],
) -> str:
    if (
        type(dependencies) is not tuple
        or not 2 <= len(dependencies) <= 512
        or any(type(item) is not ClassifiedDependency for item in dependencies)
        or tuple(item.name for item in dependencies)
        != tuple(sorted({item.name for item in dependencies}))
        or not isinstance(external_runtime_pins, Mapping)
    ):
        raise PreparationPlanError("unique sorted bounded dependency declaration required")
    for item in dependencies:
        item.__post_init__()
    by_name = {item.name: item for item in dependencies}
    materials = {item.name: item for item in inputs.material}
    declared_material = {
        item.name: item for item in dependencies if item.delivery != "external_runtime"
    }
    external = {item.name: item for item in dependencies if item.delivery == "external_runtime"}
    if set(materials) != set(declared_material) or set(external) != set(external_runtime_pins):
        raise PreparationPlanError("declared material or external runtime dependencies differ")
    for name, item in declared_material.items():
        reference = materials[name]
        if (item.delivery, item.sha256, item.size_bytes) != (
            reference.delivery,
            reference.sha256,
            reference.size_bytes,
        ):
            raise PreparationPlanError("dependency differs from worker material reference")
    for name, item in external.items():
        if not _digest(external_runtime_pins[name]) or external_runtime_pins[name] != item.sha256:
            raise PreparationPlanError("external dependency differs from supplied runtime pin")
    if "entrypoint" not in by_name or "interpreter" not in by_name:
        raise PreparationPlanError("entrypoint and interpreter dependencies required")
    if (by_name["entrypoint"].kind, by_name["entrypoint"].delivery) != (
        "python_module",
        "sealed_fd",
    ) or (by_name["interpreter"].kind, by_name["interpreter"].delivery) != (
        "executable",
        "pinned_runtime",
    ):
        raise PreparationPlanError("entrypoint or interpreter classification differs")
    reached: set[str] = set()
    active: set[str] = set()

    def visit(name: str) -> None:
        if name in active:
            raise PreparationPlanError("cyclic dependency declaration")
        if name in reached:
            return
        item = by_name.get(name)
        if item is None:
            raise PreparationPlanError("dependency edge names an unknown dependency")
        active.add(name)
        for child in item.depends_on:
            visit(child)
        active.remove(name)
        reached.add(name)

    visit("entrypoint")
    if reached != set(by_name):
        raise PreparationPlanError("unreachable extra dependency declaration")
    return hashlib.sha256(
        _canonical(
            {
                "schema_version": 1,
                "dependencies": [asdict(item) for item in dependencies],
                "external_runtime_pins": dict(external_runtime_pins),
            }
        )
    ).hexdigest()


def _expect_pins(actual: dict[str, object], expected: Mapping, label: str) -> str:
    if (
        not isinstance(expected, Mapping)
        or set(expected) != set(actual)
        or any(expected[key] != value for key, value in actual.items())
    ):
        raise PreparationPlanError(f"independent {label} consistency pins differ")
    return hashlib.sha256(_canonical(actual)).hexdigest()


def verify_one_preparation_plan(
    *,
    state: BudgetedSubsetState,
    action: CampaignAction,
    preparation: Mapping,
    runtime: BudgetedSubsetRuntimeBinding,
    material: BudgetedSubsetMaterial,
    worker_inputs: BoundSubsetTaskInputs,
    resource_snapshot: Mapping,
    launch_config_sha256: str,
    planned_request_id: str,
    expected_request_id: str,
    full_cohort_ordinal: int,
    dependencies: tuple[ClassifiedDependency, ...],
    external_runtime_pins: Mapping[str, str],
    expected_material_pins: Mapping[str, object],
    expected_runtime_pins: Mapping[str, object],
    expected_resource_pins: Mapping[str, object],
) -> OnePreparationPlan:
    """Compare already observed identities; never refresh or grant effects.

    The caller must independently re-attest state, bytes, resource clock and
    durable request intent before using this consistency plan. The caller's
    expected request ID and pin maps are consistency checks, not that evidence.
    The supplied graph closes only over its declared nodes; it does not prove
    exhaustive discovery of Python imports, native libraries or runtime reads.
    """
    if (
        type(state) is not BudgetedSubsetState
        or type(state.preview) is not BudgetedSubsetPreview
        or type(runtime) is not BudgetedSubsetRuntimeBinding
        or type(material) is not BudgetedSubsetMaterial
        or type(material.cohort) is not VerifiedSubsetCohort
        or type(worker_inputs) is not BoundSubsetTaskInputs
        or type(runtime.admission) is not BudgetedSubsetCapabilityAdmission
        or type(runtime.registry) is not CapabilityRegistry
        or runtime.state is not state
        or runtime.material is not material
        or material.state is not state
        or type(action) is not CampaignAction
        or action != CampaignAction("observe_preparing", worker_inputs.task_id)
        or not isinstance(preparation, Mapping)
        or not isinstance(resource_snapshot, Mapping)
        or not _digest(launch_config_sha256)
        or type(planned_request_id) is not str
        or _ID.fullmatch(planned_request_id) is None
        or planned_request_id != expected_request_id
        or planned_request_id in {worker_inputs.preparation_id, worker_inputs.attempt_id}
    ):
        raise PreparationPlanError(
            "exact committed subset preparation and planned request required"
        )
    preview = state.preview
    cohort = material.cohort
    ordered = cohort.task_ids
    if (
        preview.task_ids != OFFICIAL_SUBSET_TASK_IDS
        or type(ordered) is not tuple
        or len(ordered) != 1507
        or any(type(task_id) is not str for task_id in ordered)
        or len(set(ordered)) != 1507
        or not set(OFFICIAL_SUBSET_TASK_IDS).issubset(ordered)
        or cohort.cohort_sha256 != preview.cohort_sha256
        or worker_inputs.task_id not in ordered
        or type(full_cohort_ordinal) is not int
        or full_cohort_ordinal != ordered.index(worker_inputs.task_id) + 1
    ):
        raise PreparationPlanError("preserved full-cohort task order or ordinal differs")
    material_pins = {
        "cohort_sha256": cohort.cohort_sha256,
        "tasks_json_sha256": cohort.tasks_json_sha256,
        "full_cohort_order_sha256": hashlib.sha256(_canonical(list(ordered))).hexdigest(),
        "asset_hashes_sha256": cohort.asset_hashes_sha256,
        "benchmark_commit": cohort.benchmark_commit,
        "dataset_commit": cohort.dataset_commit,
        "mask_map_sha256": cohort.mask_map_sha256,
        "generator_sha256": cohort.generator_sha256,
        "harness_manifest_sha256": cohort.harness_manifest_sha256,
        "scored_images_sha256": material.scored_images_sha256,
    }
    material_pins_sha256 = _expect_pins(material_pins, expected_material_pins, "material")
    event = preparation.get("preparation_started")
    if (
        set(preparation)
        != {
            "preparation_id",
            "preparation_started",
            "preparation_started_event_sha256",
            "prepared",
            "prepared_event_sha256",
        }
        or preparation["prepared_event_sha256"] is not None
        or not isinstance(event, Mapping)
        or event
        != {
            "type": "preparation_started",
            "task_id": worker_inputs.task_id,
            "preparation_id": worker_inputs.preparation_id,
        }
        or hashlib.sha256(_json_bytes(event)).hexdigest()
        != preparation.get("preparation_started_event_sha256")
        or preparation.get("prepared") is not None
    ):
        raise PreparationPlanError("existing preparation event is changed or already prepared")
    if (
        runtime.task_id != worker_inputs.task_id
        or runtime.attempt_id != worker_inputs.attempt_id
        or runtime.preparation_id != worker_inputs.preparation_id
        or runtime.source_commit != worker_inputs.source_commit
        or runtime.admission._state is not state
        or (
            runtime.admission.run_id,
            runtime.admission.epoch,
            runtime.admission.task_id,
            runtime.admission.preparation_id,
            runtime.admission.cohort_sha256,
            runtime.admission.admission_sha256,
            runtime.admission.budget_sha256,
            runtime.admission.registry_sha256,
            runtime.admission.image_id,
        )
        != (
            preview.run_id,
            preview.epoch,
            worker_inputs.task_id,
            worker_inputs.preparation_id,
            preview.cohort_sha256,
            preview.admission_sha256,
            preview.budget.envelope_sha256,
            runtime.registry.digest,
            runtime._observed_image_id,
        )
        or not all(
            _digest(value)
            for value in (
                runtime.donor_configuration_sha256,
                runtime.bindings_sha256,
                material.scored_images_sha256,
            )
        )
    ):
        raise PreparationPlanError("runtime, material or capability preparation binding differs")
    runtime_pins = {
        "donor_configuration_sha256": runtime.donor_configuration_sha256,
        "bindings_sha256": runtime.bindings_sha256,
        "capability_registry_sha256": runtime.registry.digest,
        "observed_native_image_id": runtime._observed_image_id,
    }
    runtime_pins_sha256 = _expect_pins(runtime_pins, expected_runtime_pins, "runtime")
    try:
        worker_inputs.require_existing_identity(
            preview=preview,
            preparation=preparation,
            resource_snapshot=resource_snapshot,
            signed_launch_config_sha256=launch_config_sha256,
            expected_attempt_id=runtime.attempt_id,
        )
    except WorkerContractError as error:
        raise PreparationPlanError("worker inputs differ from existing identities") from error
    tasks = resource_snapshot.get("tasks")
    attempts = resource_snapshot.get("attempts")
    closures = resource_snapshot.get("closures")
    if not all(isinstance(value, Mapping) for value in (tasks, attempts, closures)):
        raise PreparationPlanError("resource task, attempt and closure maps required")
    counts = tasks.get(worker_inputs.task_id)
    if (
        type(resource_snapshot.get("schema_version")) is not int
        or resource_snapshot["schema_version"] != 2
        or resource_snapshot.get("clock_basis") != "suspend_aware_uptime_ns"
        or not _digest(resource_snapshot.get("boot_domain_sha256"))
        or not _digest(resource_snapshot.get("accounting_sha256"))
        or resource_snapshot.get("metering_policy_sha256") != worker_inputs.metering_policy_sha256
        or type(resource_snapshot.get("event_ordinal")) is not int
        or resource_snapshot["event_ordinal"] < 0
        or not isinstance(counts, Mapping)
        or any(
            type(counts.get(key)) is not int or counts[key] != 0
            for key in ("requests", "primary_and_memory", "deepseek_advisory")
        )
        or worker_inputs.task_id in attempts
        or worker_inputs.task_id in closures
    ):
        raise PreparationPlanError("schema-two resource snapshot or unused task accounting differs")
    _expect_pins(
        {
            "boot_domain_sha256": resource_snapshot["boot_domain_sha256"],
            "accounting_sha256": resource_snapshot["accounting_sha256"],
            "event_ordinal": resource_snapshot["event_ordinal"],
            "last_observed_ns": resource_snapshot["last_observed_ns"],
        },
        expected_resource_pins,
        "resource",
    )
    dependency_sha256 = _dependency_digest(dependencies, worker_inputs, external_runtime_pins)
    return OnePreparationPlan(
        schema_version=1,
        run_id=preview.run_id,
        epoch=preview.epoch,
        task_id=worker_inputs.task_id,
        preparation_id=worker_inputs.preparation_id,
        preparation_started_event_sha256=worker_inputs.preparation_started_event_sha256,
        attempt_id=worker_inputs.attempt_id,
        request_id=planned_request_id,
        full_cohort_ordinal=full_cohort_ordinal,
        worker_inputs_sha256=worker_inputs.identity_sha256,
        dependency_declaration_sha256=dependency_sha256,
        source_commit=preview.source_commit,
        cohort_sha256=preview.cohort_sha256,
        admission_sha256=preview.admission_sha256,
        freeze_sha256=preview.freeze_sha256,
        certification_sha256=preview.certification_sha256,
        budget_sha256=preview.budget.envelope_sha256,
        model_policy_sha256=preview.budget.model_policy_sha256,
        metering_policy_sha256=preview.budget.metering_policy_sha256,
        launch_config_sha256=launch_config_sha256,
        donor_configuration_sha256=runtime.donor_configuration_sha256,
        bindings_sha256=runtime.bindings_sha256,
        capability_registry_sha256=runtime.registry.digest,
        scored_images_sha256=material.scored_images_sha256,
        observed_native_image_id=runtime._observed_image_id,
        resource_boot_domain_sha256=resource_snapshot["boot_domain_sha256"],
        resource_accounting_sha256=resource_snapshot["accounting_sha256"],
        resource_event_ordinal=resource_snapshot["event_ordinal"],
        resource_observed_ns=resource_snapshot["last_observed_ns"],
        material_pins_sha256=material_pins_sha256,
        runtime_pins_sha256=runtime_pins_sha256,
    )
