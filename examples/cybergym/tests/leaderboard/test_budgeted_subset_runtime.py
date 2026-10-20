# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Offline runtime binding with synthetic signed metadata and captured schemas."""

from __future__ import annotations

import json
import subprocess
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from nooa_cybergym.leaderboard import budgeted_subset_material as material_module
from nooa_cybergym.leaderboard import pinned_metering, run_resource_budget
from nooa_cybergym.leaderboard.budgeted_subset_admission import (
    bind_budgeted_subset_state,
    preview_budgeted_subset_admission,
)
from nooa_cybergym.leaderboard.budgeted_subset_capabilities import (
    verify_budgeted_subset_capability_admission,
)
from nooa_cybergym.leaderboard.campaign import _json_bytes
from nooa_cybergym.leaderboard.capabilities import CapabilityRegistry, Status
from nooa_cybergym.leaderboard.capability_inventory import freeze_inventory, write_inventory
from nooa_cybergym.leaderboard.model_gateway import (
    PRIMARY_CODING_PLAN_BASE_URL,
    PRIMARY_MODEL,
    ModelPolicy,
)
from nooa_cybergym.leaderboard.runtime_config import (
    SecretFileRef,
    SigningKeyRef,
    load_runtime_config,
)
from nooa_cybergym.leaderboard.subset_role_authority import SubsetRoleAuthority

from . import test_budgeted_subset_capabilities as capability_tests
from . import test_budgeted_subset_material as material_tests
from . import test_capability_inventory as inventory_tests
from . import test_runtime_config as config_tests
from .test_budgeted_subset_admission import sha
from .test_run_resource_budget import inputs as resource_inputs
from .test_subset_role_authority import inputs as role_inputs
from .test_subset_role_authority import signed


@pytest.fixture
def module():
    from nooa_cybergym.leaderboard import budgeted_subset_runtime

    return budgeted_subset_runtime


@pytest.fixture
def factory(tmp_path, monkeypatch):
    capability_tests.lifecycle_store.__wrapped__(monkeypatch)

    def make(*, freeze_change=None, donor_change=None):
        component_root = tmp_path / "component"
        component_root.mkdir()
        capture, services, evidence, network = inventory_tests.setup(component_root)
        captured = json.loads(capture.path.read_bytes())
        captured["tools"].extend(
            {"name": name, "input_schema": {"type": "object", "properties": {}}}
            for name in ("TodoWrite", "TaskStop")
        )
        capture = inventory_tests.pin(capture.path, _json_bytes(captured))
        inventory = freeze_inventory(
            calibration=capture,
            services=services,
            component_evidence=(evidence,),
            network_policy=network,
            gbrain_provider_ids=("openai", "voyage"),
            gbrain_model_ids=("openai:embed", "voyage:rerank"),
        )
        outputs = write_inventory(component_root / "frozen", inventory)
        component = inventory.bundle.registry
        registry = CapabilityRegistry(
            tuple(
                replace(entry, evidence_refs=("synthetic-unit-signed-live-evidence",))
                if entry.status is Status.APPROVED
                else entry
                for entry in component.entries
            )
        )
        assert len(registry.entries) == 35

        donor_root = tmp_path / "donor"
        donor_root.mkdir()
        prepared = config_tests.prepared.__wrapped__(donor_root)
        config_tests.enable_takeover(prepared)
        raw_config = prepared[0]
        registry_path = Path(raw_config["artifacts"]["capability_registry"]["path"])
        registry_path.write_text(component.manifest_json, encoding="utf-8")
        raw_config["artifacts"]["capability_registry"] = config_tests.hashed(registry_path)
        template = Path(raw_config["repo_root"]) / "examples/cybergym/leaderboard/agent-template"
        template.mkdir(parents=True)
        (template / "CLAUDE.md").write_bytes(b"Generic synthetic template.\n")
        manifest_path = Path(raw_config["artifacts"]["harness_manifest"]["path"])
        manifest = json.loads(manifest_path.read_bytes())
        manifest["file_hashes"]["examples/cybergym/leaderboard/agent-template/CLAUDE.md"] = sha(
            (template / "CLAUDE.md").read_bytes()
        )
        manifest_path.write_bytes(_json_bytes(manifest))
        raw_config["artifacts"]["harness_manifest"] = config_tests.hashed(manifest_path)
        if donor_change:
            donor_change(raw_config)
        donor = load_runtime_config(prepared[1]())
        for args in (
            ("init",),
            ("add", "."),
            (
                "-c",
                "user.name=Unit Test",
                "-c",
                "user.email=unit@example.invalid",
                "commit",
                "-m",
                "synthetic metadata",
            ),
        ):
            subprocess.run(
                ["git", "-C", str(donor.repo_root), *args], check=True, capture_output=True
            )
        commit = subprocess.run(
            ["git", "-C", str(donor.repo_root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        model = ModelPolicy(
            PRIMARY_MODEL,
            donor.alternate_policy,
            registry.digest,
            PRIMARY_CODING_PLAN_BASE_URL,
            primary_takeover=donor.primary_takeover_policy,
        )

        metadata = tmp_path / "metadata"
        metadata.mkdir()
        data = material_tests.factory.__wrapped__(metadata, monkeypatch)()
        roles = tmp_path / "roles"
        roles.mkdir()
        role_args, signers, role_files = role_inputs(roles)
        authority = SubsetRoleAuthority(**role_args)
        old = data.authority
        cohort = old.artifacts[("cohort", data.cohort_raw)]
        cohort_raw = signed(signers["approval"], cohort)
        metering = resource_inputs((run_resource_budget, pinned_metering), spend=500000000)[
            "metering"
        ]
        metering_json = json.loads(metering.policy_json)
        metering_json["model_policy_sha256"] = model.digest
        metering_raw = _json_bytes(metering_json)
        metering = pinned_metering.verify_metering_policy(
            policy_json=metering_raw,
            expected_sha256=sha(metering_raw),
            model_policy_sha256=model.digest,
            required_dispatch_bounds=metering.required_dispatch_bounds,
        )
        budget = dict(
            old.artifacts[("subset_run_budget", data.state.preview.budget.signed_envelope)]
        )
        budget.update(model_policy_sha256=model.digest, metering_policy_sha256=metering.sha256)
        budget_raw = signed(signers["approval"], budget)
        freeze = dict(old.artifacts[("harness_lock", data.state.signed_freeze)])
        freeze.update(
            source_commit=commit,
            cohort_sha256=sha(cohort_raw),
            model_policy_sha256=model.digest,
            donor_configuration_sha256=donor.freeze_sha256,
            capability_registry_sha256=registry.digest,
            image_sha256=donor.image_id[7:],
            capability_bindings_sha256=sha(outputs["bindings_path"].read_bytes()),
        )
        if freeze_change:
            freeze_change(freeze)
        freeze_raw = signed(signers["approval"], freeze)
        certificate = dict(old.artifacts[("certification", data.state.signed_certification)])
        ids = sorted(entry.capability_id for entry in registry.entries)
        certificate.update(
            cohort_sha256=sha(cohort_raw),
            harness_sha256=sha(freeze_raw),
            policy_sha256=model.digest,
            capability_registry_sha256=registry.digest,
            capability_coverage="all_enabled_exercised",
            enabled_capability_ids=ids,
            required_approved_capability_ids=ids,
            frozen_hashes={"image_sha256": donor.image_id[7:]},
        )
        certificate_raw = signed(signers["approval"], certificate)
        admission_payload = dict(
            old.artifacts[("budgeted_subset_admission", data.state.preview.signed_admission)]
        )
        admission_payload.update(
            source_commit=commit,
            cohort_sha256=sha(cohort_raw),
            freeze_sha256=sha(freeze_raw),
            certification_sha256=sha(certificate_raw),
            budget_sha256=sha(budget_raw),
            model_policy_sha256=model.digest,
            metering_policy_sha256=metering.sha256,
        )
        admission_raw = signed(signers["approval"], admission_payload)
        preview = preview_budgeted_subset_admission(
            signed_admission=admission_raw,
            signed_budget=budget_raw,
            authority=authority,
            run_id=data.state.run_id,
            epoch=data.state.epoch,
            evidence_root=data.paths.evidence_root,
            expected_admission_sha256=sha(admission_raw),
            expected_budget_sha256=sha(budget_raw),
            expected_cohort_sha256=sha(cohort_raw),
            expected_freeze_sha256=sha(freeze_raw),
            expected_certification_sha256=sha(certificate_raw),
            campaign_policy_sha256="a" * 64,
            model_policy_sha256=model.digest,
            metering_policy_sha256=metering.sha256,
            source_commit=commit,
        )
        resources = run_resource_budget.RunResourceBudget.create(
            tmp_path / "resources.sqlite",
            budget=preview.budget,
            authority=authority,
            metering=metering,
        )
        state = bind_budgeted_subset_state(
            preview,
            authority=authority,
            signed_freeze=freeze_raw,
            signed_certification=certificate_raw,
            readiness_verifier=data.readiness,
            resource_budget=resources,
        )
        assert authority.create_campaign_once(
            state.evidence_root, state.run_id, state.creation_event()
        )
        data.state, data.authority, data.cohort_raw = state, authority, cohort_raw
        material = material_tests.load(material_module, data)
        task = material_tests.prepare(data)
        admission = verify_budgeted_subset_capability_admission(
            state=state, task_id=task, registry=registry, observed_image_id=donor.image_id
        )
        return SimpleNamespace(
            donor=donor,
            state=state,
            material=material,
            task=task,
            admission=admission,
            registry=registry,
            bindings_path=outputs["bindings_path"],
            model=model,
            template=template,
            resources=resources,
            data=data,
            role_files=role_files,
            inventory=inventory,
        )

    return make


def bind(module, data, **changes):
    args = {
        "donor": data.donor,
        "state": data.state,
        "material": data.material,
        "task_id": data.task,
        "attempt_id": "attempt-0",
        "admission": data.admission,
        "registry": data.registry,
        "bindings_path": data.bindings_path,
        "observed_image_id": data.donor.image_id,
    }
    return module.bind_budgeted_subset_runtime(**(args | changes))


def test_binds_exact_source_takeover_full_registries_real_schema_provenance_and_templates(
    module, factory
):
    data = factory()
    result = bind(module, data)
    assert result.state is data.state
    assert result.material is data.material
    assert result.admission is data.admission
    assert result.task_id == data.task and result.attempt_id == "attempt-0"
    assert result.preparation_id == "synthetic-preparation"
    assert result.bindings == data.inventory.bundle.bindings
    assert result.images.task_ids == data.material.cohort.task_ids
    assert len(result.images.task_ids) == 1507
    assert result.model_policy.digest == data.model.digest
    assert result.model_policy.capability_policy_sha256 != data.donor.registry.digest
    assert result.model_policy.primary_takeover == data.donor.primary_takeover_policy
    assert "Read" in result.captured_schemas
    assert result.template_files == {
        "CLAUDE.md": (data.template / "CLAUDE.md", sha((data.template / "CLAUDE.md").read_bytes()))
    }
    with pytest.raises(TypeError):
        result.template_files["injected.md"] = (data.template / "CLAUDE.md", "a" * 64)
    result.captured_schemas.clear()
    result.images._images.clear()
    assert "Read" in result.captured_schemas and result.images.images_for(data.task)
    result.verify_current()
    assert data.resources.snapshot()["requests"] == 0
    assert not tuple(data.material.paths.staging_root.iterdir())


@pytest.mark.parametrize(
    "field", ["donor_configuration_sha256", "capability_bindings_sha256", "scored_images_sha256"]
)
def test_signed_freeze_pins_cannot_be_substituted(module, factory, field):
    with pytest.raises((RuntimeError, ValueError)):
        data = factory(freeze_change=lambda value: value.update({field: "f" * 64}))
        bind(module, data)


@pytest.mark.parametrize(
    "which",
    [
        "wrong_task",
        "different_material_state",
        "legacy_admission",
        "donor_namespace",
        "wrong_image",
        "missing_attempt",
    ],
)
def test_runtime_requires_exact_same_subset_context(module, factory, which):
    data = factory()
    changes = {
        "wrong_task": {"task_id": data.state.task_ids[1]},
        "different_material_state": {"material": replace(data.material, state=replace(data.state))},
        "legacy_admission": {"admission": SimpleNamespace(**{})},
        "donor_namespace": {"donor": SimpleNamespace(**{})},
        "wrong_image": {"observed_image_id": "sha256:" + "f" * 64},
        "missing_attempt": {"attempt_id": ""},
    }[which]
    with pytest.raises((RuntimeError, TypeError, ValueError)):
        bind(module, data, **changes)


@pytest.mark.parametrize(
    "which",
    [
        "template",
        "binding",
        "capture",
        "role",
        "stop",
        "prepared",
        "untracked_source",
        "tracked_source",
    ],
)
def test_runtime_reverification_refuses_drift_or_changed_preparation(module, factory, which):
    data = factory()
    result = bind(module, data)
    if which == "template":
        (data.template / "CLAUDE.md").write_bytes(b"changed template")
    elif which == "binding":
        data.bindings_path.write_bytes(data.bindings_path.read_bytes() + b" ")
    elif which == "capture":
        data.inventory.calibration.path.write_bytes(b"changed schema capture")
    elif which == "role":
        data.role_files["approval"].write_bytes(b"changed trust pin")
    elif which == "stop":
        data.resources.stop(reason="operator_stop")
    elif which == "prepared":
        data.state.mark_prepared(data.task)
    elif which == "untracked_source":
        (data.donor.repo_root / "untracked.txt").write_bytes(b"unexpected source")
    else:
        (data.donor.repo_root / "frozen-driver.py").write_bytes(b"modified tracked source")
    with pytest.raises((RuntimeError, ValueError)):
        result.verify_current()


def test_runtime_rejects_schema_one_without_takeover(module, factory):
    def legacy(value):
        value["schema_version"] = 1
        value.pop("policies")

    data = factory(donor_change=legacy)
    with pytest.raises(RuntimeError, match="schema|takeover"):
        bind(module, data)


def test_policy_changes_returned_to_caller_do_not_mutate_binding(module, factory):
    data = factory()
    result = bind(module, data)
    result.model_policy.alternate.__dict__["deepseek_max_requests"] = 1
    assert result.model_policy.digest == data.model.digest


def test_donor_template_inventory_cannot_be_forged_outside_its_manifest(module, factory):
    data = factory()
    forged = replace(
        data.donor,
        harness_files=tuple(
            pin for pin in data.donor.harness_files if pin.path.name != "CLAUDE.md"
        ),
    )
    assert forged.freeze_sha256 == data.donor.freeze_sha256
    with pytest.raises(RuntimeError, match="inventory differs"):
        bind(module, data, donor=forged)


def test_clean_but_different_source_commit_is_denied(module, factory):
    data = factory()
    subprocess.run(
        [
            "git",
            "-C",
            str(data.donor.repo_root),
            "-c",
            "user.name=Unit Test",
            "-c",
            "user.email=unit@example.invalid",
            "commit",
            "--allow-empty",
            "-m",
            "different source",
        ],
        check=True,
        capture_output=True,
    )
    with pytest.raises(RuntimeError, match="source commit"):
        bind(module, data)


def test_binding_bytes_rechecked_after_native_schema_provenance(module, factory, monkeypatch):
    data = factory()
    original = module.load_captured_native_schemas

    def change_after_read(*args):
        schemas = original(*args)
        data.bindings_path.write_bytes(data.bindings_path.read_bytes() + b" ")
        return schemas

    monkeypatch.setattr(module, "load_captured_native_schemas", change_after_read)
    with pytest.raises(ValueError, match="digest changed"):
        bind(module, data)


@pytest.mark.parametrize("operation", ["bind", "reverify"])
def test_public_subset_runtime_binding_never_reopens_donor_private_inputs(
    module, factory, monkeypatch, operation
):
    data = factory()
    binding = bind(module, data) if operation == "reverify" else None

    def forbidden(*args, **kwargs):
        raise AssertionError("public subset binding accessed a private donor input")

    monkeypatch.setattr(SecretFileRef, "read_bytes", forbidden)
    monkeypatch.setattr(SigningKeyRef, "load_private_key", forbidden)
    if binding is None:
        bind(module, data)
    else:
        binding.verify_current()


def test_key_free_subset_revalidation_still_rejects_public_drift(module, factory, monkeypatch):
    data = factory()
    binding = bind(module, data)

    def forbidden(*args, **kwargs):
        raise AssertionError("public subset binding accessed a private donor input")

    monkeypatch.setattr(SecretFileRef, "read_bytes", forbidden)
    monkeypatch.setattr(SigningKeyRef, "load_private_key", forbidden)
    data.donor.artifacts["native_runtime"].path.write_bytes(b"changed public runtime metadata")
    with pytest.raises(ValueError, match="digest changed"):
        binding.verify_current()
