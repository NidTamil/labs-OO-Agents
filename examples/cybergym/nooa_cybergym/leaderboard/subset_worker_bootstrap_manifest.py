# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Bounded, inert bootstrap *claim consistency*, never bootstrap execution.

This compares separately supplied observations with the complete DECLARED graph.
It neither discovers dependencies nor proves exhaustive observation, immutable
bytes/FDs, signatures, trusted clocks, manager arm, release or cleanup. No
successful result permits staging, a provider request, UI Send or other effect.
The resolver vocabulary below is a proposed contract, not an installed loader.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass, fields

from .budgeted_subset_material import VerifiedSubsetCohort
from .budgeted_subset_preparation_plan import (
    ClassifiedDependency,
    OnePreparationPlan,
    PreparationPlanError,
    _dependency_digest,
)
from .subset_worker_contract import BoundSubsetTaskInputs, MaterialReference, WorkerContractError

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,127}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_MODULE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\Z")


class BootstrapManifestError(ValueError):
    """Malformed, open or disagreeing bootstrap claims."""


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _digest(value: object) -> bool:
    return type(value) is str and _SHA.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class FixedBootstrapResolution:
    """Exact symbolic lookups only, with no directory search or inheritance.

    Each pair is (lookup name, dependency name). All Python modules, native
    libraries, resource files and executables must occur in their respective
    maps. Native extensions belong in native_libraries, never pure Python maps.
    PATH is disabled: commands use the explicit command map. Environment is a
    complete replacement limited to LANG/LC_ALL=C and TZ=UTC0. Missing locale
    or timezone keys also mean those fixed defaults, never host defaults.
    Loader/search variables and credentials are outside this small vocabulary.
    """

    imports: tuple[tuple[str, str], ...]
    commands: tuple[tuple[str, str], ...]
    environment: tuple[tuple[str, str], ...]
    native_libraries: tuple[tuple[str, str], ...] = ()
    resources: tuple[tuple[str, str], ...] = ()
    import_policy: str = "exact_map_only"
    path_policy: str = "disabled_exact_commands_only"
    environment_policy: str = "replace_only"
    native_policy: str = "exact_map_only"
    resource_policy: str = "exact_map_only"


@dataclass(frozen=True, slots=True)
class WorkerBootstrapManifest:
    """Plan digest binds request, attempt and preserved full-cohort ordinal."""

    plan_sha256: str
    worker_inputs_sha256: str
    material_manifest_sha256: str
    dependencies: tuple[ClassifiedDependency, ...]
    resolution: FixedBootstrapResolution

    @property
    def manifest_sha256(self) -> str:
        return hashlib.sha256(_canonical(asdict(self))).hexdigest()


@dataclass(frozen=True, slots=True)
class BootstrapObservation:
    """Independent caller's claims, not a discovery or attestation mechanism.

    Material includes the observed FD/path as well as byte identity; the worker
    contract's stable material digest intentionally excludes ephemeral FD IDs.
    """

    manifest_sha256: str
    dependencies: tuple[ClassifiedDependency, ...]
    material: tuple[MaterialReference, ...]
    resolution: FixedBootstrapResolution


@dataclass(frozen=True, slots=True)
class BootstrapConsistency:
    """Names classified consistently with supplied claims; no authority flag."""

    manifest_sha256: str
    sealed_fd: tuple[str, ...]
    pinned_runtime: tuple[str, ...]
    external_runtime: tuple[str, ...]


def _resolution(
    value: FixedBootstrapResolution, dependencies: tuple[ClassifiedDependency, ...]
) -> None:
    if type(value) is not FixedBootstrapResolution or (
        value.import_policy,
        value.path_policy,
        value.environment_policy,
        value.native_policy,
        value.resource_policy,
    ) != (
        "exact_map_only",
        "disabled_exact_commands_only",
        "replace_only",
        "exact_map_only",
        "exact_map_only",
    ):
        raise BootstrapManifestError(
            "fixed import, PATH, environment, native and resource resolution required"
        )
    for entries, kind in (
        (value.imports, "python_module"),
        (value.commands, "executable"),
        (value.native_libraries, "native_library"),
        (value.resources, "resource_file"),
    ):
        if type(entries) is not tuple or len(entries) > 512:
            raise BootstrapManifestError("bounded immutable resolution map required")
        for pair in entries:
            if (
                type(pair) is not tuple
                or len(pair) != 2
                or any(type(item) is not str or _NAME.fullmatch(item) is None for item in pair)
            ):
                raise BootstrapManifestError(
                    "symbolic resolution names required; no pathname fallback"
                )
            if kind == "python_module" and _MODULE.fullmatch(pair[0]) is None:
                raise BootstrapManifestError("absolute Python module name required")
        if (
            tuple(sorted(entries)) != entries
            or len({key for key, _ in entries}) != len(entries)
            or len({target for _, target in entries}) != len(entries)
            or {target for _, target in entries}
            != {item.name for item in dependencies if item.kind == kind}
        ):
            raise BootstrapManifestError("exact sorted resolution coverage required")
    if type(value.environment) is not tuple or len(value.environment) > 3:
        raise BootstrapManifestError("bounded replacement environment required")
    for pair in value.environment:
        if (
            type(pair) is not tuple
            or len(pair) != 2
            or type(pair[0]) is not str
            or pair[0] not in {"LANG", "LC_ALL", "TZ"}
            or type(pair[1]) is not str
            or pair[1] != {"LANG": "C", "LC_ALL": "C", "TZ": "UTC0"}[pair[0]]
        ):
            raise BootstrapManifestError(
                "filesystem-independent C locale and UTC0 timezone literals required"
            )
    if tuple(sorted(value.environment)) != value.environment or len(dict(value.environment)) != len(
        value.environment
    ):
        raise BootstrapManifestError("unique sorted environment required")


def validate_worker_bootstrap_manifest(
    *,
    manifest: WorkerBootstrapManifest,
    observed: BootstrapObservation,
    plan: OnePreparationPlan,
    expected_plan_sha256: str,
    worker_inputs: BoundSubsetTaskInputs,
    full_cohort: VerifiedSubsetCohort,
    external_runtime_pins: Mapping[str, str],
) -> BootstrapConsistency:
    """Compare bounded declarations and independently supplied claims, with no IO.

    The expected plan pin, cohort ordering, runtime pins and observation must
    come from independent callers. This function cannot authenticate provenance
    or freshness and does not re-read runtime files or sample a clock.
    """
    if (
        type(manifest) is not WorkerBootstrapManifest
        or type(observed) is not BootstrapObservation
        or type(plan) is not OnePreparationPlan
        or type(worker_inputs) is not BoundSubsetTaskInputs
        or type(full_cohort) is not VerifiedSubsetCohort
        or not _digest(expected_plan_sha256)
    ):
        raise BootstrapManifestError("exact bootstrap claim contracts required")
    # Frozen dataclasses are not attestations. Recheck nested references rather
    # than treating a caller-constructed plan or inputs instance as authority.
    try:
        worker_inputs.__post_init__()
        for reference in worker_inputs.material:
            reference.__post_init__()
    except WorkerContractError as error:
        raise BootstrapManifestError("invalid worker inputs or material") from error
    for field in fields(plan):
        value = getattr(plan, field.name)
        if field.name.endswith("sha256") and not _digest(value):
            raise BootstrapManifestError("bounded plan digests required")
        if hasattr(worker_inputs, field.name) and value != getattr(worker_inputs, field.name):
            raise BootstrapManifestError("plan differs from worker identity")
    full_cohort_task_ids = full_cohort.task_ids
    if (
        type(plan.schema_version) is not int
        or plan.schema_version != 1
        or type(plan.request_id) is not str
        or _ID.fullmatch(plan.request_id) is None
        or plan.request_id in {plan.preparation_id, plan.attempt_id}
        or type(plan.resource_event_ordinal) is not int
        or not 0 <= plan.resource_event_ordinal <= (1 << 63) - 1
        or type(plan.resource_observed_ns) is not int
        or not 0 < plan.resource_observed_ns <= (1 << 63) - 1
        or type(plan.observed_native_image_id) is not str
        or not plan.observed_native_image_id.startswith("sha256:")
        or not _digest(plan.observed_native_image_id[7:])
        or type(full_cohort_task_ids) is not tuple
        or len(full_cohort_task_ids) != 1507
        or any(type(task) is not str or not 1 <= len(task) <= 128 for task in full_cohort_task_ids)
        or len(set(full_cohort_task_ids)) != 1507
        or type(plan.full_cohort_ordinal) is not int
        or not 1 <= plan.full_cohort_ordinal <= 1507
        or full_cohort_task_ids[plan.full_cohort_ordinal - 1] != plan.task_id
    ):
        raise BootstrapManifestError(
            "bounded plan identity and preserved full-1507 ordinal required"
        )
    cohort_pins = {
        "cohort_sha256": full_cohort.cohort_sha256,
        "tasks_json_sha256": full_cohort.tasks_json_sha256,
        "full_cohort_order_sha256": hashlib.sha256(
            _canonical(list(full_cohort_task_ids))
        ).hexdigest(),
        "asset_hashes_sha256": full_cohort.asset_hashes_sha256,
        "benchmark_commit": full_cohort.benchmark_commit,
        "dataset_commit": full_cohort.dataset_commit,
        "mask_map_sha256": full_cohort.mask_map_sha256,
        "generator_sha256": full_cohort.generator_sha256,
        "harness_manifest_sha256": full_cohort.harness_manifest_sha256,
        "scored_images_sha256": plan.scored_images_sha256,
    }
    if any(type(value) is not str or len(value) > 64 for value in cohort_pins.values()):
        raise BootstrapManifestError("bounded cohort pin claims required")
    if (
        full_cohort.cohort_sha256 != plan.cohort_sha256
        or hashlib.sha256(_canonical(cohort_pins)).hexdigest() != plan.material_pins_sha256
    ):
        raise BootstrapManifestError("full-cohort ordering or material pins differ from plan")
    runtime_pins = {
        "donor_configuration_sha256": plan.donor_configuration_sha256,
        "bindings_sha256": plan.bindings_sha256,
        "capability_registry_sha256": plan.capability_registry_sha256,
        "observed_native_image_id": plan.observed_native_image_id,
    }
    if hashlib.sha256(_canonical(runtime_pins)).hexdigest() != plan.runtime_pins_sha256:
        raise BootstrapManifestError("runtime pins differ from plan aggregate")
    if (
        plan.plan_sha256 != expected_plan_sha256
        or manifest.plan_sha256 != expected_plan_sha256
        or manifest.worker_inputs_sha256 != worker_inputs.identity_sha256
        or plan.worker_inputs_sha256 != worker_inputs.identity_sha256
        or manifest.material_manifest_sha256 != worker_inputs.material_manifest_sha256
    ):
        raise BootstrapManifestError("plan or worker material binding differs")
    if (
        type(manifest.dependencies) is not tuple
        or not 2 <= len(manifest.dependencies) <= 512
        or any(
            type(item) is not ClassifiedDependency
            or type(item.depends_on) is not tuple
            or len(item.depends_on) > 512
            for item in manifest.dependencies
        )
        or not isinstance(external_runtime_pins, Mapping)
        or len(external_runtime_pins) > 512
    ):
        raise BootstrapManifestError("bounded declared dependency graph required")
    try:
        declaration = _dependency_digest(
            manifest.dependencies, worker_inputs, external_runtime_pins
        )
    except PreparationPlanError as error:
        raise BootstrapManifestError("invalid declared dependency graph") from error
    if declaration != plan.dependency_declaration_sha256:
        raise BootstrapManifestError("declared graph differs from plan")
    if any(
        item.kind == "native_library" and item.delivery != "pinned_runtime"
        for item in manifest.dependencies
    ):
        raise BootstrapManifestError(
            "native dependencies require separately pinned runtime delivery"
        )
    _resolution(manifest.resolution, manifest.dependencies)
    if (
        type(observed.dependencies) is not tuple
        or observed.dependencies != manifest.dependencies
        or type(observed.material) is not tuple
        or observed.material != worker_inputs.material
        or type(observed.resolution) is not FixedBootstrapResolution
        or observed.resolution != manifest.resolution
        or observed.manifest_sha256 != manifest.manifest_sha256
    ):
        raise BootstrapManifestError("observed dependency closure or exact resolution differs")
    return BootstrapConsistency(
        manifest_sha256=manifest.manifest_sha256,
        sealed_fd=tuple(
            item.name for item in manifest.dependencies if item.delivery == "sealed_fd"
        ),
        pinned_runtime=tuple(
            item.name for item in manifest.dependencies if item.delivery == "pinned_runtime"
        ),
        external_runtime=tuple(
            item.name for item in manifest.dependencies if item.delivery == "external_runtime"
        ),
    )
