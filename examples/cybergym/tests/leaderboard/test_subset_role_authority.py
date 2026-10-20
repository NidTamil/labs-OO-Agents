# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Role isolation with temporary public registries and real synthetic signatures."""

from __future__ import annotations

import hashlib
import json
from dataclasses import FrozenInstanceError

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nooa_cybergym.leaderboard.campaign import _json_bytes
from nooa_cybergym.leaderboard.subset_role_authority import SubsetRoleAuthority
from nooa_cybergym.leaderboard.xeus_authority import XeusCampaignAuthority
from xeus_cybergym.ledger.signing import Ed25519Signer, SignatureVerificationError

APPROVAL_KINDS = (
    "harness_lock",
    "cohort",
    "subset_run_budget",
    "budgeted_subset_admission",
    "certification",
)
RUNTIME_KINDS = (
    "terminal_receipt",
    "subset_driver_quiescence",
    "subset_preparation_quiescence",
)


def payload(kind, version=1):
    value = {
        "schema_version": version,
        "artifact_kind": kind,
        "scope": "native_subset_dry_run_level1",
        "run_id": "synthetic-run",
        "epoch": "synthetic-epoch",
        "task_ids": ["arvo:47101"],
        "previously_exposed_task_ids": ["arvo:47101", "arvo:3938"],
        "task_id": "arvo:47101",
        "attempt_id": "synthetic-attempt",
        "preparation_id": "synthetic-preparation",
        "preparation_started_event_sha256": "a" * 64,
        "prepared_event_sha256": "a" * 64,
        "native_send_occurred": False,
        "status": "accepted" if kind == "certification" else "timeout",
        "harness_sha256": "a" * 64,
        "cohort_sha256": "b" * 64,
        "campaign_policy_sha256": "c" * 64,
        "tasks_json_sha256": "d" * 64,
        "budget_sha256": "e" * 64,
        "metering_policy_sha256": "f" * 64,
        "max_elapsed_seconds": 432000,
        "max_spend_units": 500000000,
        "launch_sha256": "a" * 64,
        "final_accounting_sha256": "b" * 64,
        "terminal_receipt_sha256": "c" * 64,
        "owned_cleanup_complete": True,
    }
    if version == 2:
        value.update(
            takeover_policy_sha256="d" * 64,
            memory_model_bindings_sha256="e" * 64,
            primary_takeover={"schema_version": 1},
        )
    return value


def public_pem(key):
    return (
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode("ascii")
    )


def inputs(tmp_path, *, keys=None, ids=None):
    keys = keys or {
        role: Ed25519PrivateKey.generate() for role in ("approval", "runtime", "evaluator")
    }
    ids = ids or {role: f"synthetic-{role}" for role in keys}
    args, signers, files = {}, {}, {}
    for role, key in keys.items():
        path = tmp_path / f"{role}-public.json"
        path.write_text(json.dumps({ids[role]: public_pem(key)}), encoding="utf-8")
        args[f"{role}_registry"] = path
        args[f"{role}_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        signers[role] = Ed25519Signer(private_key=key, key_id=ids[role])
        files[role] = path
    return args, signers, files


def signed(signer, value):
    return _json_bytes(signer.sign(_json_bytes(value)).model_dump())


@pytest.mark.parametrize("kind", APPROVAL_KINDS + RUNTIME_KINDS)
@pytest.mark.parametrize("role", ["approval", "runtime", "evaluator"])
def test_correct_signature_is_accepted_only_by_assigned_artifact_role(tmp_path, kind, role):
    args, signers, _ = inputs(tmp_path)
    authority = SubsetRoleAuthority(**args)
    data = payload(kind)
    observed = authority.attest_signed(kind, signed(signers[role], data))
    permitted = "approval" if kind in APPROVAL_KINDS else "runtime"
    assert observed == (data if role == permitted else None)


@pytest.mark.parametrize("role", ["approval", "runtime", "evaluator"])
def test_schema2_certification_has_explicit_approval_only_method(tmp_path, role):
    args, signers, _ = inputs(tmp_path)
    authority = SubsetRoleAuthority(**args)
    data = payload("certification", version=2)
    raw = signed(signers[role], data)
    assert authority.attest_signed("certification", raw) is None
    assert authority.attest_takeover_certification(raw) == (data if role == "approval" else None)
    old = payload("certification")
    assert authority.attest_takeover_certification(signed(signers[role], old)) is None


@pytest.mark.parametrize(
    "kind",
    ["decision", "practice_admission", "subset_dry_run_admission", "evaluator_result", "unknown"],
)
def test_unknown_or_out_of_scope_artifact_kinds_fail_closed(tmp_path, kind):
    args, signers, _ = inputs(tmp_path)
    authority = SubsetRoleAuthority(**args)
    assert authority.attest_signed(kind, signed(signers["approval"], payload(kind))) is None


@pytest.mark.parametrize(
    "view,accepted_role", [("runtime_verifier", "runtime"), ("evaluator_verifier", "evaluator")]
)
def test_separate_public_verifiers_never_accept_other_roles(tmp_path, view, accepted_role):
    args, signers, _ = inputs(tmp_path)
    authority = SubsetRoleAuthority(**args)
    verifier = getattr(authority, view)
    for role, signer in signers.items():
        envelope = signer.sign(b"synthetic typed receipt payload")
        if role == accepted_role:
            assert verifier.verify(envelope) == b"synthetic typed receipt payload"
        else:
            with pytest.raises(SignatureVerificationError):
                verifier.verify(envelope)


@pytest.mark.parametrize(
    "roles", [("approval", "runtime"), ("approval", "evaluator"), ("runtime", "evaluator")]
)
def test_key_ids_must_be_disjoint_even_with_different_public_keys(tmp_path, roles):
    ids = {role: f"synthetic-{role}" for role in ("approval", "runtime", "evaluator")}
    ids[roles[1]] = ids[roles[0]]
    args, _, _ = inputs(tmp_path, ids=ids)
    with pytest.raises(RuntimeError, match="overlap"):
        SubsetRoleAuthority(**args)


@pytest.mark.parametrize(
    "roles", [("approval", "runtime"), ("approval", "evaluator"), ("runtime", "evaluator")]
)
def test_same_raw_public_key_cannot_cross_roles_under_different_ids(tmp_path, roles):
    keys = {role: Ed25519PrivateKey.generate() for role in ("approval", "runtime", "evaluator")}
    keys[roles[1]] = keys[roles[0]]
    args, _, _ = inputs(tmp_path, keys=keys)
    with pytest.raises(RuntimeError, match="overlap"):
        SubsetRoleAuthority(**args)


@pytest.mark.parametrize("changed_role", ["approval", "runtime", "evaluator"])
def test_every_registry_pin_is_rechecked_before_attestation(tmp_path, changed_role):
    args, signers, files = inputs(tmp_path)
    authority = SubsetRoleAuthority(**args)
    files[changed_role].write_bytes(files[changed_role].read_bytes() + b" ")
    with pytest.raises(RuntimeError, match="digest"):
        authority.attest_signed(
            "harness_lock", signed(signers["approval"], payload("harness_lock"))
        )
    with pytest.raises(RuntimeError, match="digest"):
        authority.attest_takeover_certification(
            signed(signers["approval"], payload("certification", version=2))
        )
    with pytest.raises(RuntimeError, match="digest"):
        authority.runtime_verifier.verify(signers["runtime"].sign(b"runtime"))
    with pytest.raises(RuntimeError, match="digest"):
        authority.evaluator_verifier.verify(signers["evaluator"].sign(b"evaluator"))


def test_pinned_registry_paths_and_verifier_roles_are_immutable(tmp_path):
    args, _, _ = inputs(tmp_path)
    authority = SubsetRoleAuthority(**args)
    with pytest.raises((AttributeError, FrozenInstanceError, TypeError)):
        authority._pins = ()
    verifier = authority.evaluator_verifier
    with pytest.raises((AttributeError, FrozenInstanceError, TypeError)):
        verifier._role = "approval"


@pytest.mark.parametrize(
    "view,role", [("runtime_verifier", "runtime"), ("evaluator_verifier", "evaluator")]
)
def test_cached_verifier_view_cannot_keep_using_changed_trust(tmp_path, view, role):
    args, signers, files = inputs(tmp_path)
    authority = SubsetRoleAuthority(**args)
    verifier = getattr(authority, view)
    envelope = signers[role].sign(b"synthetic typed receipt")
    assert verifier.verify(envelope) == b"synthetic typed receipt"
    files["approval"].write_bytes(files["approval"].read_bytes() + b" ")
    with pytest.raises(RuntimeError, match="digest"):
        verifier.verify(envelope)


def test_wrong_digest_and_nonpublic_key_files_are_rejected(tmp_path):
    args, _, files = inputs(tmp_path)
    with pytest.raises(RuntimeError, match="digest"):
        SubsetRoleAuthority(**{**args, "approval_sha256": "0" * 64})
    private = Ed25519PrivateKey.generate()
    private_pem = private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode("ascii")
    files["runtime"].write_text(json.dumps({"synthetic-runtime": private_pem}), encoding="utf-8")
    args["runtime_sha256"] = hashlib.sha256(files["runtime"].read_bytes()).hexdigest()
    with pytest.raises(RuntimeError, match="public key"):
        SubsetRoleAuthority(**args)


def test_no_private_key_loader_is_used(tmp_path, monkeypatch):
    args, signers, _ = inputs(tmp_path)
    monkeypatch.setattr(
        serialization,
        "load_pem_private_key",
        lambda *_a, **_kw: pytest.fail("private key loading forbidden"),
    )
    authority = SubsetRoleAuthority(**args)
    data = payload("harness_lock")
    assert authority.attest_signed("harness_lock", signed(signers["approval"], data)) == data


def test_noncanonical_signed_payload_and_envelope_selected_key_are_rejected(tmp_path):
    args, signers, _ = inputs(tmp_path)
    authority = SubsetRoleAuthority(**args)
    data = payload("harness_lock")
    raw = _json_bytes(signers["approval"].sign(json.dumps(data, indent=2).encode()).model_dump())
    assert authority.attest_signed("harness_lock", raw) is None
    runtime = signers["runtime"].sign(_json_bytes(data)).model_dump()
    runtime["key_id"] = "synthetic-approval"
    assert authority.attest_signed("harness_lock", _json_bytes(runtime)) is None


def test_ledger_operations_delegate_only_after_all_public_pins_verify(tmp_path, monkeypatch):
    args, _, files = inputs(tmp_path)
    calls = []

    def delegate(self, *args, **kwargs):
        assert set(self._verifier._public_keys) == {"synthetic-runtime"}
        calls.append((args, kwargs))
        return True

    for method in ("create_campaign_once", "read_verified_events", "append_event"):
        monkeypatch.setattr(XeusCampaignAuthority, method, delegate)
    authority = SubsetRoleAuthority(**args)
    created = {"type": "campaign_created", "run_id": "test-run"}
    assert authority.create_campaign_once(tmp_path, "test-run", created) is True
    assert authority.read_verified_events(tmp_path, "test-run") is True
    assert (
        authority.append_event(tmp_path, "test-run", {"type": "prepared"}, expected_revision=1)
        is True
    )
    assert len(calls) == 3
    files["evaluator"].write_bytes(files["evaluator"].read_bytes() + b" ")
    with pytest.raises(RuntimeError, match="digest"):
        authority.create_campaign_once(tmp_path, "test-run", created)
    with pytest.raises(RuntimeError, match="digest"):
        authority.read_verified_events(tmp_path, "test-run")
    with pytest.raises(RuntimeError, match="digest"):
        authority.append_event(tmp_path, "test-run", {"type": "prepared"}, expected_revision=1)
    assert len(calls) == 3


def test_legacy_xeus_authority_schema_behavior_is_unchanged(tmp_path):
    key = Ed25519PrivateKey.generate()
    legacy = XeusCampaignAuthority({"legacy": key.public_key()})
    signer = Ed25519Signer(private_key=key, key_id="legacy")
    old = payload("certification")
    new = payload("certification", version=2)
    assert legacy.attest_signed("certification", signed(signer, old)) == old
    assert legacy.attest_signed("certification", signed(signer, new)) is None
    assert legacy.attest_takeover_certification(signed(signer, new)) == new
