# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Synthetic claim comparisons only; no worker or process supervisor execution."""

import hashlib
import json
from dataclasses import replace
from importlib import import_module, util

import pytest
from nooa_cybergym.leaderboard.budgeted_subset_preparation_plan import (
    ClassifiedDependency,
    verify_one_preparation_plan,
)
from nooa_cybergym.leaderboard.subset_worker_contract import MaterialReference

from .test_budgeted_subset_preparation_plan import _case


def _fixture(with_resources=False):
    name = "nooa_cybergym.leaderboard.subset_worker_bootstrap_manifest"
    assert util.find_spec(name) is not None, "worker bootstrap manifest validator is missing"
    api = import_module(name)
    case = _case()
    if with_resources:
        references = tuple(
            sorted(
                case["worker_inputs"].material
                + (
                    MaterialReference(
                        "native", "pinned_runtime", "d" * 64, 500, path="/fixed/native.so"
                    ),
                    MaterialReference("policy", "sealed_fd", "e" * 64, 10, fd=9),
                ),
                key=lambda item: item.name,
            )
        )
        raw = json.dumps(
            {"schema_version": 1, "items": [item.manifest_record() for item in references]},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        case["worker_inputs"] = replace(
            case["worker_inputs"],
            material=references,
            material_manifest_sha256=hashlib.sha256(raw).hexdigest(),
        )
        deps = case["dependencies"]
        case["dependencies"] = (
            deps[0],
            replace(deps[1], depends_on=("docker_socket", "interpreter", "native", "policy")),
            deps[2],
            ClassifiedDependency("native", "native_library", "pinned_runtime", "d" * 64, 500, ()),
            ClassifiedDependency("policy", "resource_file", "sealed_fd", "e" * 64, 10, ()),
        )
    plan = verify_one_preparation_plan(**case)
    inputs = case["worker_inputs"]
    resolution = api.FixedBootstrapResolution(
        imports=(("worker", "entrypoint"),),
        commands=(("python", "interpreter"),),
        environment=(("LANG", "C"),),
        native_libraries=(("native", "native"),) if with_resources else (),
        resources=(("policy", "policy"),) if with_resources else (),
    )
    manifest = api.WorkerBootstrapManifest(
        plan_sha256=plan.plan_sha256,
        worker_inputs_sha256=inputs.identity_sha256,
        material_manifest_sha256=inputs.material_manifest_sha256,
        dependencies=case["dependencies"],
        resolution=resolution,
    )
    observed = api.BootstrapObservation(
        manifest_sha256=manifest.manifest_sha256,
        dependencies=case["dependencies"],
        material=inputs.material,
        resolution=resolution,
    )
    return api, {
        "manifest": manifest,
        "observed": observed,
        "plan": plan,
        "expected_plan_sha256": plan.plan_sha256,
        "worker_inputs": inputs,
        "full_cohort": case["material"].cohort,
        "external_runtime_pins": case["external_runtime_pins"],
    }


def test_classifies_complete_declared_observation_without_effect_authority():
    api, args = _fixture()
    result = api.validate_worker_bootstrap_manifest(**args)
    assert result.sealed_fd == ("entrypoint",)
    assert result.pinned_runtime == ("interpreter",)
    assert result.external_runtime == ("docker_socket",)


@pytest.mark.parametrize(
    "field,value",
    [
        ("run_id", "other-run"),
        ("epoch", "other-epoch"),
        ("task_id", "arvo:99999"),
        ("preparation_id", "other-preparation"),
        ("request_id", "other-request"),
        ("attempt_id", "other-attempt"),
        ("full_cohort_ordinal", 1),
        ("worker_inputs_sha256", "f" * 64),
    ],
)
def test_rejects_plan_identity_swap(field, value):
    api, args = _fixture()
    args["plan"] = replace(args["plan"], **{field: value})
    with pytest.raises(api.BootstrapManifestError):
        api.validate_worker_bootstrap_manifest(**args)


@pytest.mark.parametrize(
    "field", ["plan_sha256", "worker_inputs_sha256", "material_manifest_sha256"]
)
def test_rejects_manifest_binding_swap(field):
    api, args = _fixture()
    args["manifest"] = replace(args["manifest"], **{field: "f" * 64})
    with pytest.raises(api.BootstrapManifestError):
        api.validate_worker_bootstrap_manifest(**args)


@pytest.mark.parametrize("change", ["missing", "duplicate", "undeclared", "edge", "digest"])
def test_rejects_inexact_observed_dependency_closure(change):
    api, args = _fixture()
    deps = args["observed"].dependencies
    changed = {
        "missing": deps[1:],
        "duplicate": deps + (deps[0],),
        "undeclared": deps + (replace(deps[0], name="extra"),),
        "edge": (deps[0], replace(deps[1], depends_on=("interpreter",)), deps[2]),
        "digest": (replace(deps[0], sha256="f" * 64),) + deps[1:],
    }[change]
    args["observed"] = replace(args["observed"], dependencies=changed)
    with pytest.raises(api.BootstrapManifestError):
        api.validate_worker_bootstrap_manifest(**args)


@pytest.mark.parametrize(
    "change",
    [
        "ambient_import",
        "ambient_path",
        "inherit_env",
        "unknown_import",
        "duplicate_import",
        "missing_import",
        "unknown_command",
        "duplicate_env",
        "path_env",
        "oversized_env",
    ],
)
def test_rejects_open_or_unbounded_resolution(change):
    api, args = _fixture()
    values = {
        "ambient_import": {"import_policy": "ambient"},
        "ambient_path": {"path_policy": "search"},
        "inherit_env": {"environment_policy": "inherit"},
        "unknown_import": {"imports": (("worker", "missing"),)},
        "duplicate_import": {"imports": (("worker", "entrypoint"), ("worker", "entrypoint"))},
        "missing_import": {"imports": ()},
        "unknown_command": {"commands": (("python", "entrypoint"),)},
        "duplicate_env": {"environment": (("LANG", "C"), ("LANG", "C"))},
        "path_env": {"environment": (("PATH", "/mutable"),)},
        "oversized_env": {"environment": (("LANG", "x" * 4097),)},
    }[change]
    manifest = replace(args["manifest"], resolution=replace(args["manifest"].resolution, **values))
    args["manifest"] = manifest
    args["observed"] = replace(
        args["observed"], resolution=manifest.resolution, manifest_sha256=manifest.manifest_sha256
    )
    with pytest.raises(api.BootstrapManifestError):
        api.validate_worker_bootstrap_manifest(**args)


@pytest.mark.parametrize("change", ["fd", "path", "resolution", "manifest", "external", "order"])
def test_rejects_independent_observation_or_pin_disagreement(change):
    api, args = _fixture()
    observation = args["observed"]
    if change == "fd":
        observation = replace(
            observation, material=(replace(observation.material[0], fd=8), observation.material[1])
        )
    elif change == "path":
        observation = replace(
            observation,
            material=(
                observation.material[0],
                replace(observation.material[1], path="/mutable/python"),
            ),
        )
    elif change == "resolution":
        observation = replace(
            observation, resolution=replace(observation.resolution, environment=())
        )
    elif change == "manifest":
        observation = replace(observation, manifest_sha256="f" * 64)
    elif change == "external":
        args["external_runtime_pins"] = {"docker_socket": "f" * 64}
    else:
        args["full_cohort"] = replace(
            args["full_cohort"], task_ids=tuple(reversed(args["full_cohort"].task_ids))
        )
    args["observed"] = observation
    with pytest.raises(api.BootstrapManifestError):
        api.validate_worker_bootstrap_manifest(**args)


def test_rejects_changed_cohort_order_even_when_task_ordinal_unchanged():
    api, args = _fixture()
    tasks = args["full_cohort"].task_ids
    args["full_cohort"] = replace(args["full_cohort"], task_ids=(tasks[1], tasks[0]) + tasks[2:])
    with pytest.raises(api.BootstrapManifestError):
        api.validate_worker_bootstrap_manifest(**args)


@pytest.mark.parametrize(
    "field,value",
    [
        ("imports", (("other", "entrypoint"), ("worker", "entrypoint"))),
        ("commands", (("/mutable/python", "interpreter"),)),
        ("native_libraries", ()),
        ("resources", ()),
        ("native_policy", "system_loader"),
        ("resource_policy", "cwd_fallback"),
    ],
)
def test_requires_exact_native_resource_and_symbolic_lookup_maps(field, value):
    api, args = _fixture(with_resources=True)
    manifest = replace(
        args["manifest"], resolution=replace(args["manifest"].resolution, **{field: value})
    )
    args["manifest"] = manifest
    args["observed"] = replace(
        args["observed"], resolution=manifest.resolution, manifest_sha256=manifest.manifest_sha256
    )
    with pytest.raises(api.BootstrapManifestError):
        api.validate_worker_bootstrap_manifest(**args)


def test_classifies_native_and_resource_claims_in_their_delivery_groups():
    api, args = _fixture(with_resources=True)
    result = api.validate_worker_bootstrap_manifest(**args)
    assert result.sealed_fd == ("entrypoint", "policy")
    assert result.pinned_runtime == ("interpreter", "native")


def test_accepts_existing_contract_numeric_request_identity():
    api, args = _fixture()
    plan = replace(args["plan"], request_id="123-request")
    manifest = replace(args["manifest"], plan_sha256=plan.plan_sha256)
    args.update(
        plan=plan,
        expected_plan_sha256=plan.plan_sha256,
        manifest=manifest,
        observed=replace(args["observed"], manifest_sha256=manifest.manifest_sha256),
    )
    assert api.validate_worker_bootstrap_manifest(**args).sealed_fd == ("entrypoint",)


@pytest.mark.parametrize("field", ["resource_event_ordinal", "resource_observed_ns"])
def test_rejects_unbounded_plan_counters_even_with_matching_plan_pin(field):
    api, args = _fixture()
    plan = replace(args["plan"], **{field: 1 << 1000})
    manifest = replace(args["manifest"], plan_sha256=plan.plan_sha256)
    args.update(
        plan=plan,
        expected_plan_sha256=plan.plan_sha256,
        manifest=manifest,
        observed=replace(args["observed"], manifest_sha256=manifest.manifest_sha256),
    )
    with pytest.raises(api.BootstrapManifestError):
        api.validate_worker_bootstrap_manifest(**args)


@pytest.mark.parametrize(
    "environment",
    [
        (("TZ", ":/mutable/timezone"),),
        (("TZ", "Europe/Paris"),),
        (("LANG", "en_US.UTF-8"),),
        (("LC_ALL", "C.UTF-8"),),
    ],
)
def test_rejects_environment_that_can_resolve_undeclared_files(environment):
    api, args = _fixture()
    manifest = replace(
        args["manifest"], resolution=replace(args["manifest"].resolution, environment=environment)
    )
    args.update(
        manifest=manifest,
        observed=replace(
            args["observed"],
            resolution=manifest.resolution,
            manifest_sha256=manifest.manifest_sha256,
        ),
    )
    with pytest.raises(api.BootstrapManifestError):
        api.validate_worker_bootstrap_manifest(**args)


def test_accepts_only_explicit_filesystem_independent_locale_and_timezone_literals():
    api, args = _fixture()
    manifest = replace(
        args["manifest"],
        resolution=replace(
            args["manifest"].resolution,
            environment=(("LANG", "C"), ("LC_ALL", "C"), ("TZ", "UTC0")),
        ),
    )
    args.update(
        manifest=manifest,
        observed=replace(
            args["observed"],
            resolution=manifest.resolution,
            manifest_sha256=manifest.manifest_sha256,
        ),
    )
    assert api.validate_worker_bootstrap_manifest(**args).sealed_fd == ("entrypoint",)


@pytest.mark.parametrize(
    "field,value",
    [
        ("donor_configuration_sha256", "f" * 64),
        ("bindings_sha256", "f" * 64),
        ("capability_registry_sha256", "f" * 64),
        ("observed_native_image_id", "sha256:" + "f" * 64),
    ],
)
def test_rejects_inconsistent_runtime_aggregate_with_matching_plan_pin(field, value):
    api, args = _fixture()
    plan = replace(args["plan"], **{field: value})
    manifest = replace(args["manifest"], plan_sha256=plan.plan_sha256)
    args.update(
        plan=plan,
        expected_plan_sha256=plan.plan_sha256,
        manifest=manifest,
        observed=replace(args["observed"], manifest_sha256=manifest.manifest_sha256),
    )
    with pytest.raises(api.BootstrapManifestError):
        api.validate_worker_bootstrap_manifest(**args)
