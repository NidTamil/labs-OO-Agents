# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Scored CLI input custody rejects missing or changed signed files."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nooa_cybergym.leaderboard.scored_campaign_inputs import (
    admit_signed_campaign,
    load_scored_public_keys,
    preview_signed_campaign,
    read_signed_campaign_inputs,
)


def _bundle(root: Path) -> None:
    root.mkdir()
    for name in ("decision", "certification", "harness_lock", "cohort"):
        (root / f"{name}.signed.json").write_bytes(f"signed:{name}".encode())
    (root / "tasks.json").write_bytes(b'["arvo:47101"]')
    (root / "campaign-policy.json").write_text('{"max_parallel_tasks":1}', encoding="utf-8")


def test_read_scored_inputs_requires_all_regular_bounded_files(tmp_path: Path):
    root = tmp_path / "scored"
    _bundle(root)
    inputs = read_signed_campaign_inputs(root)
    assert inputs.decision == b"signed:decision"
    assert inputs.campaign_policy == {"max_parallel_tasks": 1}
    assert inputs.tasks_json == b'["arvo:47101"]'

    (root / "decision.signed.json").unlink()
    with pytest.raises(RuntimeError, match="decision"):
        read_signed_campaign_inputs(root)
    (root / "decision.signed.json").write_bytes(b"x" * (1024 * 1024 + 1))
    with pytest.raises(RuntimeError, match="decision"):
        read_signed_campaign_inputs(root)


def test_scored_inputs_reject_duplicate_policy_keys_and_linked_input(tmp_path: Path):
    root = tmp_path / "scored"
    _bundle(root)
    (root / "campaign-policy.json").write_text(
        '{"max_parallel_tasks":1,"max_parallel_tasks":2}', encoding="utf-8"
    )
    with pytest.raises(RuntimeError, match="campaign-policy"):
        read_signed_campaign_inputs(root)
    (root / "campaign-policy.json").write_text('{"max_parallel_tasks":1}', encoding="utf-8")
    target = root / "original.json"
    target.write_bytes(b"signed:decision")
    (root / "decision.signed.json").unlink()
    (root / "decision.signed.json").symlink_to(target)
    with pytest.raises(RuntimeError, match="decision"):
        read_signed_campaign_inputs(root)


def test_scored_admission_passes_exact_signed_bytes_without_signing(tmp_path: Path, monkeypatch):
    import nooa_cybergym.leaderboard.scored_campaign_inputs as module

    root = tmp_path / "scored"
    _bundle(root)
    inputs = read_signed_campaign_inputs(root)
    calls = []
    authority = object()
    evidence = tmp_path / "ledger"
    evidence.mkdir()
    monkeypatch.setattr(
        module,
        "check_go_live",
        lambda **kw: calls.append(kw) or "verified-state",
    )
    assert (
        admit_signed_campaign(
            inputs,
            authority=authority,
            run_id="scored-1",
            evidence_root=evidence,
        )
        == "verified-state"
    )
    assert len(calls) == 1
    assert calls[0]["decision"] == b"signed:decision"
    assert calls[0]["cohort"] == b"signed:cohort"
    assert calls[0]["authority"] is authority
    assert calls[0]["run_id"] == "scored-1"
    assert calls[0]["evidence_root"] == evidence
    assert calls[0]["campaign_policy"] == json.loads('{"max_parallel_tasks":1}')


def test_scored_trust_registry_requires_exact_pinned_public_keys(tmp_path: Path):
    private = Ed25519PrivateKey.generate()
    pem = (
        private.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode("ascii")
    )
    registry = tmp_path / "trusted-public-keys.json"
    registry.write_text(json.dumps({"operator": pem}), encoding="utf-8")
    digest = hashlib.sha256(registry.read_bytes()).hexdigest()
    keys = load_scored_public_keys(registry, expected_sha256=digest)
    assert set(keys) == {"operator"}
    assert keys["operator"].public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ) == private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )

    with pytest.raises(RuntimeError, match="digest"):
        load_scored_public_keys(registry, expected_sha256="0" * 64)
    registry.write_text('{"operator":"bad","operator":"bad"}', encoding="utf-8")
    with pytest.raises(RuntimeError, match="duplicate"):
        load_scored_public_keys(
            registry, expected_sha256=hashlib.sha256(registry.read_bytes()).hexdigest()
        )


def test_scored_preview_binds_trust_and_signed_bytes_without_creating_campaign(
    tmp_path: Path, monkeypatch
):
    import nooa_cybergym.leaderboard.scored_campaign_inputs as module

    inputs_root = tmp_path / "inputs"
    _bundle(inputs_root)
    trust = tmp_path / "trusted.json"
    private = Ed25519PrivateKey.generate()
    pem = (
        private.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode("ascii")
    )
    trust.write_text(json.dumps({"operator": pem}), encoding="utf-8")
    ledger = tmp_path / "ledger"
    ledger.mkdir()
    calls = []
    authority = object()
    monkeypatch.setattr(
        module,
        "XeusCampaignAuthority",
        lambda keys: calls.append(("authority", set(keys))) or authority,
    )
    monkeypatch.setattr(
        module,
        "preview_go_live",
        lambda **kwargs: calls.append(("preview", kwargs)) or "verified-state",
    )
    result = preview_signed_campaign(
        input_root=inputs_root,
        trust_registry=trust,
        trust_sha256=hashlib.sha256(trust.read_bytes()).hexdigest(),
        run_id="scored-1",
        evidence_root=ledger,
    )
    assert result.state == "verified-state"
    assert result.authority is authority
    assert set(result.public_keys) == {"operator"}
    assert result.inputs.decision == b"signed:decision"
    assert calls[0] == ("authority", {"operator"})
    assert calls[1][0] == "preview"
    assert calls[1][1]["authority"] is authority
    assert calls[1][1]["decision"] == b"signed:decision"

    (inputs_root / "decision.signed.json").unlink()
    calls.clear()
    with pytest.raises(RuntimeError, match="decision"):
        preview_signed_campaign(
            input_root=inputs_root,
            trust_registry=trust,
            trust_sha256=hashlib.sha256(trust.read_bytes()).hexdigest(),
            run_id="scored-1",
            evidence_root=ledger,
        )
    assert calls == []
