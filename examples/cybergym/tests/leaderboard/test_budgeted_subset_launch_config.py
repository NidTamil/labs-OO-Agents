# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Offline config binding with real synthetic role signatures; no live readiness."""

from __future__ import annotations

import copy
import hashlib
import os
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nooa_cybergym.leaderboard.budgeted_subset_admission import (
    bind_budgeted_subset_state,
    preview_budgeted_subset_admission,
)
from nooa_cybergym.leaderboard.budgeted_subset_launch_config import (
    load_budgeted_subset_launch_config,
    preflight_budgeted_subset_signers,
)
from nooa_cybergym.leaderboard.campaign import _json_bytes
from nooa_cybergym.leaderboard.subset_role_authority import SubsetRoleAuthority
from xeus_cybergym.ledger.signing import Ed25519Signer

from examples.cybergym.tests.leaderboard.test_budgeted_subset_admission import (
    Authority,
    Resources,
    setup,
)
from examples.cybergym.tests.leaderboard.test_scored_launch_config import _bundle
from examples.cybergym.tests.leaderboard.test_subset_role_authority import inputs, signed


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class Fixture:
    """Acyclic synthetic budget -> config -> freeze -> certificate -> admission."""

    def __init__(self, root):
        self.keys = {
            role: Ed25519PrivateKey.generate() for role in ("approval", "runtime", "evaluator")
        }
        self.trust_args, self.signers, self.registries = inputs(root, keys=self.keys)
        self.authority = SubsetRoleAuthority(**self.trust_args)
        self.path, _, self.config = _bundle(root)
        fake, self.args, self.bindings = setup(root, Authority())
        self.budget = copy.deepcopy(
            fake.artifacts[("subset_run_budget", self.args["signed_budget"])]
        )
        self.freeze = copy.deepcopy(
            fake.artifacts[("harness_lock", self.bindings["signed_freeze"])]
        )
        self.cert = copy.deepcopy(
            fake.artifacts[("certification", self.bindings["signed_certification"])]
        )
        self.admission = copy.deepcopy(
            fake.artifacts[("budgeted_subset_admission", self.args["signed_admission"])]
        )
        # This is only a digest-binding fixture, not a semantically valid metering policy.
        metering = root / "synthetic-metering.json"
        metering.write_bytes(b'{"synthetic_digest_only":true}')
        self.budget["metering_policy_sha256"] = sha(metering.read_bytes())
        budget_path = root / "synthetic-signed-budget.json"
        self.signed_budget = signed(self.signers["approval"], self.budget)
        budget_path.write_bytes(self.signed_budget)
        self.config.update(
            schema_version=1,
            scope="budgeted_subset_native_level1",
            run_id="test-run",
            epoch="test-epoch",
            budget={"path": str(budget_path), "sha256": sha(self.signed_budget)},
            metering={"path": str(metering), "sha256": sha(metering.read_bytes())},
            trust={
                role: {
                    "path": str(path),
                    "sha256": self.trust_args[f"{role}_sha256"],
                }
                for role, path in self.registries.items()
            },
        )
        self.config["paths"]["evidence_root"] = str(root)
        self.config["evaluator"]["key_id"] = "synthetic-evaluator"
        self.config["evaluator"]["public_key_sha256"] = sha(
            self.keys["evaluator"]
            .public_key()
            .public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
        self.donor = {
            "schema_version": 2,
            "signing": {
                "key_id": "synthetic-runtime",
                "public_key_sha256": sha(
                    self.keys["runtime"]
                    .public_key()
                    .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                ),
                "private_key_path": str(root / "unopened-runtime-private.pem"),
            },
        }
        self.write_donor()

    def write_donor(self):
        ref = self.config["files"]["donor_config"]
        Path(ref["path"]).write_bytes(_json_bytes(self.donor))
        ref["sha256"] = sha(Path(ref["path"]).read_bytes())

    def state(self, *, raw_config=None):
        self.path.write_bytes(_json_bytes(self.config) if raw_config is None else raw_config)
        self.freeze["budgeted_subset_launch_config_sha256"] = sha(self.path.read_bytes())
        freeze = signed(self.signers["approval"], self.freeze)
        self.cert["harness_sha256"] = sha(freeze)
        cert = signed(self.signers["approval"], self.cert)
        self.admission.update(
            budget_sha256=sha(self.signed_budget),
            metering_policy_sha256=self.budget["metering_policy_sha256"],
            freeze_sha256=sha(freeze),
            certification_sha256=sha(cert),
        )
        admission = signed(self.signers["approval"], self.admission)
        args = dict(self.args)
        args.update(
            authority=self.authority,
            signed_admission=admission,
            signed_budget=self.signed_budget,
            expected_admission_sha256=sha(admission),
            expected_budget_sha256=sha(self.signed_budget),
            expected_freeze_sha256=sha(freeze),
            expected_certification_sha256=sha(cert),
            metering_policy_sha256=self.budget["metering_policy_sha256"],
        )
        resources = Resources(sha(self.signed_budget))
        return bind_budgeted_subset_state(
            preview_budgeted_subset_admission(**args),
            authority=self.authority,
            signed_freeze=freeze,
            signed_certification=cert,
            readiness_verifier=self.bindings["readiness_verifier"],
            resource_budget=resources,
        )


def test_read_only_config_binds_actual_subset_state_and_all_pins(tmp_path):
    fixture = Fixture(tmp_path)
    state = fixture.state()
    before = set(tmp_path.rglob("*"))
    loaded = load_budgeted_subset_launch_config(state, fixture.path)
    assert loaded == fixture.config
    assert set(tmp_path.rglob("*")) == before
    assert state.authority is fixture.authority
    assert not Path(fixture.donor["signing"]["private_key_path"]).exists()
    assert not Path(fixture.config["evaluator"]["private_key_path"]).exists()


@pytest.mark.parametrize(
    "field,value",
    [
        ("scope", "scored_native_level1"),
        ("schema_version", 2),
        ("schema_version", True),
        ("run_id", "other-run"),
        ("epoch", "other-epoch"),
        ("max_parallel_tasks", 2),
        ("max_parallel_tasks", True),
        ("remote_alias", "unscoped-host"),
        ("ssh_port", 22),
        ("ssh_port", True),
        ("timeout_seconds", 59),
        ("timeout_seconds", 43201),
        ("timeout_seconds", True),
        ("server", "http://other-gateway"),
        ("freeze_sha256", "a" * 64),
        ("certification_sha256", "b" * 64),
    ],
)
def test_signed_config_identity_route_schema_and_no_hash_cycle(tmp_path, field, value):
    fixture = Fixture(tmp_path)
    fixture.config[field] = value
    with pytest.raises(RuntimeError):
        load_budgeted_subset_launch_config(fixture.state(), fixture.path)


def test_real_state_and_exact_role_authority_required(tmp_path):
    fixture = Fixture(tmp_path)
    state = fixture.state()
    for invalid in (object(), replace(state, authority=Authority())):
        with pytest.raises(RuntimeError, match="state|authority"):
            load_budgeted_subset_launch_config(invalid, fixture.path)


def test_actual_state_readiness_is_reverified(tmp_path):
    fixture = Fixture(tmp_path)
    state = fixture.state()
    fixture.bindings["readiness_verifier"].accepted = False
    with pytest.raises(RuntimeError, match="readiness"):
        load_budgeted_subset_launch_config(state, fixture.path)


@pytest.mark.parametrize(
    "category,name",
    [
        ("files", "donor_config"),
        ("files", "asset_manifest"),
        ("files", "image_manifest"),
        ("trust", "approval"),
        ("trust", "runtime"),
        ("trust", "evaluator"),
        (None, "budget"),
        (None, "metering"),
    ],
)
def test_changed_referenced_bytes_rejected(tmp_path, category, name):
    fixture = Fixture(tmp_path)
    state = fixture.state()
    ref = fixture.config[category][name] if category else fixture.config[name]
    Path(ref["path"]).write_bytes(b"changed")
    with pytest.raises((RuntimeError, ValueError)):
        load_budgeted_subset_launch_config(state, fixture.path)


def test_correctly_hashed_different_budget_or_metering_rejected(tmp_path):
    fixture = Fixture(tmp_path)
    for name in ("budget", "metering"):
        original = copy.deepcopy(fixture.config[name])
        other = tmp_path / f"other-{name}.json"
        other.write_bytes(b"{}")
        fixture.config[name] = {"path": str(other), "sha256": sha(b"{}")}
        with pytest.raises(RuntimeError, match="budget|metering"):
            load_budgeted_subset_launch_config(fixture.state(), fixture.path)
        fixture.config[name] = original


def test_trust_cannot_be_replaced_even_with_same_public_keys(tmp_path):
    fixture = Fixture(tmp_path)
    other = tmp_path / "different-approval-public.json"
    other.write_bytes(fixture.registries["approval"].read_bytes())
    fixture.config["trust"]["approval"]["path"] = str(other)
    with pytest.raises(RuntimeError, match="trust"):
        load_budgeted_subset_launch_config(fixture.state(), fixture.path)


def test_config_digest_and_duplicate_keys_rejected(tmp_path):
    fixture = Fixture(tmp_path)
    state = fixture.state()
    fixture.path.write_bytes(fixture.path.read_bytes() + b" ")
    with pytest.raises(RuntimeError, match="digest"):
        load_budgeted_subset_launch_config(state, fixture.path)
    raw = _json_bytes(fixture.config)[:-1] + b',"schema_version":1}'
    with pytest.raises(RuntimeError, match="JSON"):
        load_budgeted_subset_launch_config(fixture.state(raw_config=raw), fixture.path)


def test_config_transport_limit_is_checked_before_json_parse(tmp_path, monkeypatch):
    import nooa_cybergym.leaderboard.budgeted_subset_launch_config as module

    fixture = Fixture(tmp_path)
    state = fixture.state(raw_config=b" " * 65537)

    def forbidden(*args, **kwargs):
        raise AssertionError("oversized config must not reach JSON parser")

    monkeypatch.setattr(module, "_json", forbidden)
    with pytest.raises(RuntimeError, match="bounded regular"):
        load_budgeted_subset_launch_config(state, fixture.path)


def test_parent_alias_and_hardlinked_file_rejected(tmp_path):
    fixture = Fixture(tmp_path)
    ref = fixture.config["files"]["bindings"]
    original_path = ref["path"]
    ref["path"] = str(tmp_path) + "/staging_root/../bindings.json"
    with pytest.raises(RuntimeError, match="unaliased"):
        load_budgeted_subset_launch_config(fixture.state(), fixture.path)
    ref["path"] = original_path
    os.link(original_path, tmp_path / "hardlinked-bindings.json")
    with pytest.raises(RuntimeError, match="bounded regular"):
        load_budgeted_subset_launch_config(fixture.state(), fixture.path)


@pytest.mark.parametrize("target", ["files", "paths", "trust"])
def test_missing_reference_sets_rejected(tmp_path, target):
    fixture = Fixture(tmp_path)
    fixture.config[target].pop(next(iter(fixture.config[target])))
    with pytest.raises(RuntimeError):
        load_budgeted_subset_launch_config(fixture.state(), fixture.path)


@pytest.mark.parametrize("target", ["config", "file", "directory"])
def test_relative_or_aliased_paths_rejected(tmp_path, target):
    fixture = Fixture(tmp_path)
    if target == "file":
        fixture.config["files"]["bindings"]["path"] = "bindings.json"
    if target == "directory":
        fixture.config["paths"]["staging_root"] = str(tmp_path / "missing")
    path = Path("relative-config.json") if target == "config" else fixture.path
    with pytest.raises(RuntimeError):
        load_budgeted_subset_launch_config(fixture.state(), path)


def test_evidence_root_matches_signed_state(tmp_path):
    fixture = Fixture(tmp_path)
    fixture.config["paths"]["evidence_root"] = fixture.config["paths"]["staging_root"]
    with pytest.raises(RuntimeError, match="evidence root"):
        load_budgeted_subset_launch_config(fixture.state(), fixture.path)


def test_already_acquired_signers_are_role_verified_without_private_reads(tmp_path, monkeypatch):
    fixture = Fixture(tmp_path)
    state = fixture.state()

    def forbidden(*args, **kwargs):
        raise AssertionError("private loader must not run")

    monkeypatch.setattr(serialization, "load_pem_private_key", forbidden)
    result = preflight_budgeted_subset_signers(
        state,
        fixture.path,
        runtime_signer=fixture.signers["runtime"],
        evaluator_signer=fixture.signers["evaluator"],
    )
    assert result.config == fixture.config
    assert result.runtime_verifier.verify(result.runtime_signer.sign(b"synthetic")) == b"synthetic"
    fixture.registries["approval"].write_bytes(b"changed")
    with pytest.raises(RuntimeError):
        result.runtime_verifier.verify(result.runtime_signer.sign(b"synthetic"))


@pytest.mark.parametrize(
    "role,replacement",
    [
        ("runtime", "approval"),
        ("runtime", "evaluator"),
        ("evaluator", "approval"),
        ("evaluator", "runtime"),
    ],
)
def test_wrong_role_signer_rejected_with_correct_signature(tmp_path, role, replacement):
    fixture = Fixture(tmp_path)
    kwargs = {f"{name}_signer": fixture.signers[name] for name in ("runtime", "evaluator")}
    kwargs[f"{role}_signer"] = fixture.signers[replacement]
    with pytest.raises(RuntimeError, match="signer"):
        preflight_budgeted_subset_signers(fixture.state(), fixture.path, **kwargs)


def test_spoofed_runtime_key_id_fails_real_challenge(tmp_path):
    fixture = Fixture(tmp_path)
    spoofed = Ed25519Signer(private_key=fixture.keys["approval"], key_id="synthetic-runtime")
    with pytest.raises(RuntimeError, match="signer"):
        preflight_budgeted_subset_signers(
            fixture.state(),
            fixture.path,
            runtime_signer=spoofed,
            evaluator_signer=fixture.signers["evaluator"],
        )


def test_runtime_metadata_cannot_choose_approval_key(tmp_path):
    fixture = Fixture(tmp_path)
    fixture.donor["signing"]["key_id"] = "synthetic-approval"
    fixture.write_donor()
    with pytest.raises(RuntimeError, match="outside its trusted role"):
        preflight_budgeted_subset_signers(
            fixture.state(),
            fixture.path,
            runtime_signer=fixture.signers["approval"],
            evaluator_signer=fixture.signers["evaluator"],
        )


def test_schema1_donor_is_not_accepted_for_new_takeover_state(tmp_path):
    fixture = Fixture(tmp_path)
    fixture.donor["schema_version"] = 1
    fixture.write_donor()
    with pytest.raises(RuntimeError, match="schema-two donor"):
        preflight_budgeted_subset_signers(
            fixture.state(),
            fixture.path,
            runtime_signer=fixture.signers["runtime"],
            evaluator_signer=fixture.signers["evaluator"],
        )


@pytest.mark.parametrize("role", ["runtime", "evaluator"])
def test_frozen_public_signer_fingerprint_must_match_role_registry(tmp_path, role):
    fixture = Fixture(tmp_path)
    if role == "runtime":
        fixture.donor["signing"]["public_key_sha256"] = "0" * 64
        fixture.write_donor()
    else:
        fixture.config["evaluator"]["public_key_sha256"] = "0" * 64
    with pytest.raises(RuntimeError, match="signer"):
        preflight_budgeted_subset_signers(
            fixture.state(),
            fixture.path,
            runtime_signer=fixture.signers["runtime"],
            evaluator_signer=fixture.signers["evaluator"],
        )
