# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""A signed live-synthetic result may back only the ordered practice pair."""

from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nooa_cybergym.leaderboard.practice_campaign import PracticeState
from nooa_cybergym.leaderboard.practice_capability_permit import PracticeCapabilityPermit
from xeus_cybergym.canonical import canonical_json
from xeus_cybergym.ledger import Ed25519Signer, Ed25519Verifier

from .test_capability_runtime import bundle, runtime


class Authority:
    def __init__(self, admission):
        self.admission = admission
        self.state = None

    def attest_signed(self, kind, envelope):
        assert kind == "practice_admission" and envelope == b"signed-admission"
        return self.admission

    def read_verified_events(self, _root, _run_id):
        return (self.state._root_event(),)


def _state(tmp_path):
    authority = Authority(
        {
            "schema_version": 1,
            "artifact_kind": "practice_admission",
            "run_id": "practice-1",
            "epoch": "practice-v26q",
            "task_ids": ["arvo:47101", "arvo:3938"],
            "scope": "native_practice_level1",
            "max_parallel_tasks": 1,
            "freeze_sha256": "a" * 64,
            "asset_hashes_sha256": "b" * 64,
            "selected_assets_sha256": "c" * 64,
            "host_key_sha256": "e" * 64,
            "vscode_exe_sha256": "d" * 64,
            "vscode_version": "1.140.0",
            "claude_extension_version": "2.1.289",
            "remote_host": "sunchaser-20260905.cinnamon-gamut.ts.net",
        }
    )
    state = PracticeState(
        "practice-1",
        "practice-v26q",
        tmp_path,
        hashlib.sha256(b"signed-admission").hexdigest(),
        b"signed-admission",
        authority,
    )
    authority.state = state
    return state


def _signed_report(tmp_path, registry, *, status="accepted"):
    key = Ed25519PrivateKey.generate()
    signer = Ed25519Signer(private_key=key, key_id="test-cert")
    verifier = Ed25519Verifier({"test-cert": key.public_key()})
    report = {
        "schema_version": 1,
        "scope": "live_native",
        "status": status,
        "failures": [],
        "capability_coverage": "all_enabled_exercised",
        "capability_registry_sha256": registry.digest,
        "enabled_capability_ids": [entry.capability_id for entry in registry.entries],
        "required_approved_capability_ids": [entry.capability_id for entry in registry.entries],
        "frozen_hashes": {"image_sha256": "e" * 64},
        "official_launch_authorised": False,
    }
    payload = canonical_json(report)
    envelope = canonical_json(signer.sign(payload).model_dump())
    report_file = tmp_path / "comparison.json"
    envelope_file = tmp_path / "comparison.signed.json"
    report_file.write_bytes(payload)
    envelope_file.write_bytes(envelope)
    return report_file, envelope_file, hashlib.sha256(envelope).hexdigest(), verifier


def _permit(tmp_path, registry, *, status="accepted"):
    state = _state(tmp_path)
    report, signed, digest, verifier = _signed_report(tmp_path, registry, status=status)
    return PracticeCapabilityPermit.from_signed_report(
        state=state,
        task_id="arvo:47101",
        registry=registry,
        image_id="sha256:" + "e" * 64,
        report_path=report,
        signed_report_path=signed,
        expected_signed_report_sha256=digest,
        verifier=verifier,
    )


def test_permit_allows_only_current_practice_task_with_original_bound_registry(tmp_path):
    built = bundle(tmp_path)
    permit = _permit(tmp_path, built.registry)
    assert permit.task_id == "arvo:47101"
    assert permit.registry_sha256 == built.registry.digest
    assert (
        runtime(
            built,
            task="arvo:47101",
            practice_permit=permit,
            observed_image_id="sha256:" + "e" * 64,
        ).task_id
        == "arvo:47101"
    )
    with pytest.raises(ValueError, match="component-only"):
        runtime(built, task="arvo:3938", practice_permit=permit, observed_image_id=permit.image_id)
    with pytest.raises(ValueError, match="component-only"):
        runtime(built, task="oss-fuzz:1", practice_permit=permit, observed_image_id=permit.image_id)
    with pytest.raises(ValueError, match="component-only"):
        runtime(built, task="arvo:47101")
    with pytest.raises(ValueError, match="component-only"):
        runtime(built, task="arvo:47101", practice_permit=permit)
    with pytest.raises(ValueError, match="component-only"):
        runtime(
            built,
            task="arvo:47101",
            practice_permit=replace(permit, admission_sha256="0" * 64),
            observed_image_id=permit.image_id,
        )


def test_permit_rejects_unsigned_or_unaccepted_report(tmp_path):
    built = bundle(tmp_path)
    with pytest.raises(RuntimeError, match="accepted"):
        _permit(tmp_path, built.registry, status="rejected")
    report, signed, digest, verifier = _signed_report(tmp_path, built.registry)
    signed.write_bytes(signed.read_bytes() + b" ")
    with pytest.raises(RuntimeError, match="signed"):
        PracticeCapabilityPermit.from_signed_report(
            state=_state(tmp_path),
            task_id="arvo:47101",
            registry=built.registry,
            image_id="sha256:" + "e" * 64,
            report_path=report,
            signed_report_path=signed,
            expected_signed_report_sha256=digest,
            verifier=verifier,
        )


def test_permit_rejects_noncurrent_task_before_runtime(tmp_path):
    built = bundle(tmp_path)
    state = _state(tmp_path)
    report, signed, digest, verifier = _signed_report(tmp_path, built.registry)
    with pytest.raises(RuntimeError, match="current practice task"):
        PracticeCapabilityPermit.from_signed_report(
            state=state,
            task_id="arvo:3938",
            registry=built.registry,
            image_id="sha256:" + "e" * 64,
            report_path=report,
            signed_report_path=signed,
            expected_signed_report_sha256=digest,
            verifier=verifier,
        )
