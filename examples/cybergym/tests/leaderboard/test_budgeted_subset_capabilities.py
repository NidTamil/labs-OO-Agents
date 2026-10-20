# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Offline subset capability gates with temporary keys and actual signed state."""

import copy
from dataclasses import replace
from types import SimpleNamespace

import pytest
from nooa_cybergym.leaderboard import pinned_metering, run_resource_budget
from nooa_cybergym.leaderboard.budgeted_subset_admission import (
    bind_budgeted_subset_state,
    preview_budgeted_subset_admission,
)
from nooa_cybergym.leaderboard.capabilities import CapabilityRegistry
from nooa_cybergym.leaderboard.capability_runtime import CapabilityRuntime, ObservedPath
from nooa_cybergym.leaderboard.host_boundary_runtime import AdmittedPeer
from nooa_cybergym.leaderboard.subset_role_authority import SubsetRoleAuthority

from .test_budgeted_subset_admission import Resources, setup, sha
from .test_campaign import SCORED_IMAGE, _scored_registry
from .test_run_resource_budget import inputs as resource_inputs
from .test_subset_role_authority import inputs as role_inputs
from .test_subset_role_authority import signed


@pytest.fixture(autouse=True)
def lifecycle_store(monkeypatch):
    # This slice tests real signature/role/resource gates with a deterministic
    # lifecycle-store double. POSIX event/artifact durability is a separate test.
    from nooa_cybergym.leaderboard.xeus_authority import XeusCampaignAuthority

    rows = {}

    def create(self, root, run_id, event):
        key = (root, run_id)
        if key in rows:
            return False
        rows[key] = [copy.deepcopy(event)]
        return True

    def read(self, root, run_id):
        return copy.deepcopy(rows[(root, run_id)])

    def append(self, root, run_id, event, expected_revision):
        values = rows[(root, run_id)]
        if len(values) != expected_revision:
            return False
        values.append(copy.deepcopy(event))
        return True

    monkeypatch.setattr(XeusCampaignAuthority, "create_campaign_once", create)
    monkeypatch.setattr(XeusCampaignAuthority, "read_verified_events", read)
    monkeypatch.setattr(XeusCampaignAuthority, "append_event", append)


@pytest.fixture
def module():
    from nooa_cybergym.leaderboard import budgeted_subset_capabilities

    return budgeted_subset_capabilities


def bound(tmp_path, *, mutate=None, registry=None):
    registry = registry or _scored_registry()
    ids = sorted(e.capability_id for e in registry.entries)
    role_args, signers, role_files = role_inputs(tmp_path)
    authority = SubsetRoleAuthority(**role_args)
    old_authority, args, bindings = setup(tmp_path)
    metering = resource_inputs((run_resource_budget, pinned_metering), spend=500000000)["metering"]
    payloads = {
        kind: old_authority.artifacts[(kind, raw)].copy()
        for kind, raw in (
            ("subset_run_budget", args["signed_budget"]),
            ("harness_lock", bindings["signed_freeze"]),
            ("certification", bindings["signed_certification"]),
            ("budgeted_subset_admission", args["signed_admission"]),
        )
    }
    payloads["subset_run_budget"]["metering_policy_sha256"] = metering.sha256
    budget_raw = signed(signers["approval"], payloads["subset_run_budget"])
    harness = payloads["harness_lock"]
    harness.update(capability_registry_sha256=registry.digest, image_sha256=SCORED_IMAGE[7:])
    cert = payloads["certification"]
    cert.update(
        capability_registry_sha256=registry.digest,
        capability_coverage="all_enabled_exercised",
        enabled_capability_ids=ids,
        required_approved_capability_ids=ids,
        frozen_hashes={"image_sha256": SCORED_IMAGE[7:]},
    )
    if mutate:
        mutate(payloads)
    freeze = signed(signers["approval"], harness)
    cert["harness_sha256"] = sha(freeze)
    cert_raw = signed(signers["approval"], cert)
    admission = payloads["budgeted_subset_admission"]
    admission.update(
        freeze_sha256=sha(freeze),
        certification_sha256=sha(cert_raw),
        budget_sha256=sha(budget_raw),
        metering_policy_sha256=metering.sha256,
    )
    admission_raw = signed(signers["approval"], admission)
    args.update(
        authority=authority,
        signed_admission=admission_raw,
        signed_budget=budget_raw,
        expected_admission_sha256=sha(admission_raw),
        expected_budget_sha256=sha(budget_raw),
        expected_freeze_sha256=sha(freeze),
        expected_certification_sha256=sha(cert_raw),
        metering_policy_sha256=metering.sha256,
    )
    preview = preview_budgeted_subset_admission(**args)
    resources = run_resource_budget.RunResourceBudget.create(
        tmp_path / "resources.sqlite",
        budget=preview.budget,
        authority=authority,
        metering=metering,
    )
    bindings.update(
        authority=authority,
        signed_freeze=freeze,
        signed_certification=cert_raw,
        resource_budget=resources,
    )
    state = bind_budgeted_subset_state(preview, **bindings)
    assert authority.create_campaign_once(tmp_path, state.run_id, state.creation_event())
    state.mark_preparation_started(state.task_ids[0], preparation_id="prep-0")
    return state, resources, registry, bindings["readiness_verifier"], role_files, signers


def permit(module, state, registry):
    return module.verify_budgeted_subset_capability_admission(
        state=state,
        task_id=state.task_ids[0],
        registry=registry,
        observed_image_id=SCORED_IMAGE,
    )


def runtime(state, registry, admission):
    peer = AdmittedPeer("container-1", "network-1", "172.20.0.2")
    return CapabilityRuntime(
        registry=registry,
        expected_registry_sha256=registry.digest,
        bindings=(),
        peer=peer,
        task_id=state.task_ids[0],
        attempt_id="attempt-0",
        audit=SimpleNamespace(record=lambda event: True),
        path_observer=lambda path: ObservedPath(path, path, True, "file"),
        boundary_check=lambda observed: observed == peer,
        working_directory="/workspace",
        execution_paths=("/workspace/src",),
        execution_routes=(),
        model_id="glm-5.3",
        structural_terms=("buffer",),
        scored_admission=admission,
        observed_image_id=SCORED_IMAGE,
    )


def test_actual_signed_subset_admits_current_preparation_and_started_task(tmp_path, module):
    state, resources, registry, _, _, _ = bound(tmp_path)
    admission = permit(module, state, registry)
    assert admission.task_id == state.task_ids[0]
    assert admission.preparation_id == "prep-0"
    assert admission.registry_sha256 == registry.digest
    active = runtime(state, registry, admission)
    assert active.authorize_peer(AdmittedPeer("container-1", "network-1", "172.20.0.2")) is True
    state.mark_prepared(state.task_ids[0])
    state.mark_started(
        state.task_ids[0], request_id="request-0", attempt_id="attempt-0", launch_sha256="1" * 64
    )
    admission.verify_current(
        task_id=state.task_ids[0], registry=registry, observed_image_id=SCORED_IMAGE
    )
    assert active.authorize_peer(active.peer) is True
    assert resources.snapshot()["requests"] == 0


@pytest.mark.parametrize(
    "field",
    [
        "capability_registry_sha256",
        "enabled_capability_ids",
        "required_approved_capability_ids",
        "capability_coverage",
        "frozen_hashes",
    ],
)
def test_signed_report_cannot_substitute_capability_or_image_identity(tmp_path, module, field):
    def mutate(payloads):
        payloads["certification"][field] = "wrong"

    state, _, registry, *_ = bound(tmp_path, mutate=mutate)
    with pytest.raises(RuntimeError):
        permit(module, state, registry)


@pytest.mark.parametrize("field", ["capability_registry_sha256", "image_sha256"])
def test_signed_harness_must_bind_the_exact_registry_and_image(tmp_path, module, field):
    def mutate(payloads):
        payloads["harness_lock"][field] = "f" * 64

    state, _, registry, *_ = bound(tmp_path, mutate=mutate)
    with pytest.raises(RuntimeError):
        permit(module, state, registry)


def test_synthetic_capabilities_cannot_be_promoted_by_signed_subset(tmp_path, module):
    state, _, registry, *_ = bound(tmp_path, registry=_scored_registry(synthetic=True))
    with pytest.raises(RuntimeError, match="synthetic"):
        permit(module, state, registry)


def test_partial_approved_inventory_cannot_enter_subset(tmp_path, module):
    registry = CapabilityRegistry(_scored_registry().entries[:-1])
    state, _, registry, *_ = bound(tmp_path, registry=registry)
    with pytest.raises(RuntimeError, match="coverage"):
        permit(module, state, registry)


@pytest.mark.parametrize("change", ["task", "image", "registry", "preparation"])
def test_permit_cannot_be_rebound_to_other_task_material(tmp_path, module, change):
    state, _, registry, *_ = bound(tmp_path)
    admission = permit(module, state, registry)
    kwargs = {"task_id": state.task_ids[0], "registry": registry, "observed_image_id": SCORED_IMAGE}
    if change == "task":
        kwargs["task_id"] = state.task_ids[1]
    elif change == "image":
        kwargs["observed_image_id"] = "sha256:" + "f" * 64
    elif change == "registry":
        kwargs["registry"] = CapabilityRegistry(registry.entries[:-1])
    else:
        admission = replace(admission, preparation_id="other-preparation")
    with pytest.raises(RuntimeError):
        admission.verify_current(**kwargs)


@pytest.mark.parametrize("changed_role", ["approval", "runtime", "evaluator"])
def test_every_trust_pin_is_rechecked(tmp_path, module, changed_role):
    state, _, registry, _, files, _ = bound(tmp_path)
    admission = permit(module, state, registry)
    files[changed_role].write_bytes(files[changed_role].read_bytes() + b" ")
    with pytest.raises(RuntimeError):
        admission.verify_current(
            task_id=state.task_ids[0], registry=registry, observed_image_id=SCORED_IMAGE
        )


def test_raw_readiness_revocation_is_not_hidden_by_signed_pass(tmp_path, module):
    state, _, registry, readiness, *_ = bound(tmp_path)
    admission = permit(module, state, registry)
    readiness.accepted = False
    with pytest.raises(RuntimeError, match="readiness"):
        admission.verify_current(
            task_id=state.task_ids[0], registry=registry, observed_image_id=SCORED_IMAGE
        )


def test_existing_runtime_denies_new_tool_authority_after_aggregate_stop(tmp_path, module):
    state, resources, registry, *_ = bound(tmp_path)
    capability_runtime = runtime(state, registry, permit(module, state, registry))
    resources.stop(reason="operator_stop")
    assert capability_runtime.authorize_peer(capability_runtime.peer) is False


def test_terminal_task_cannot_create_fresh_capability_runtime(tmp_path, module):
    state, _, registry, _, _, signers = bound(tmp_path)
    admission = permit(module, state, registry)
    task = state.task_ids[0]
    state.mark_prepared(task)
    state.mark_started(task, request_id="request-0", attempt_id="attempt-0", launch_sha256="1" * 64)
    terminal = signed(
        signers["runtime"],
        {
            "schema_version": 1,
            "artifact_kind": "terminal_receipt",
            "run_id": state.run_id,
            "epoch": state.epoch,
            "task_id": task,
            "status": "timeout",
            "evidence_sha256": "2" * 64,
        },
    )
    state.mark_terminal(task, terminal)
    with pytest.raises(ValueError, match="admission"):
        runtime(state, registry, admission)


def test_protocol_resource_view_cannot_supply_operational_permission(tmp_path, module):
    state, _, registry, *_ = bound(tmp_path)
    state = replace(state, resource_budget=Resources(state.preview.budget.envelope_sha256))
    with pytest.raises(TypeError, match="resource"):
        permit(module, state, registry)


@pytest.mark.parametrize("created_before_start", [True, False])
def test_runtime_attempt_must_match_the_committed_started_attempt(
    tmp_path, module, created_before_start
):
    state, _, registry, *_ = bound(tmp_path)
    admission = permit(module, state, registry)
    existing = runtime(state, registry, admission) if created_before_start else None
    task = state.task_ids[0]
    state.mark_prepared(task)
    state.mark_started(
        task, request_id="request-0", attempt_id="different-attempt", launch_sha256="1" * 64
    )
    if existing is None:
        with pytest.raises(ValueError, match="admission"):
            runtime(state, registry, admission)
    else:
        assert existing.authorize_peer(existing.peer) is False
