# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nooa_cybergym.leaderboard.gbrain_writer import OracleMemoryWriter
from nooa_cybergym.leaderboard.memory_transport import TransportDenied
from nooa_cybergym.leaderboard.synthetic_oracle import SyntheticOracleResult


def receipt(status="oracle_false"):
    return {
        "schema_version": 1,
        "artifact_kind": "terminal_receipt",
        "run_id": "synthetic-run",
        "epoch": "synthetic-epoch",
        "task_id": "synthetic-toy",
        "status": status,
        "oracle_true": status == "oracle_true",
        **dict.fromkeys(
            (
                "final_sha256",
                "final_declaration_sha256",
                "parent_event_digest",
                "oracle_request_sha256",
                "oracle_verdict_sha256",
            ),
            "a" * 64,
        ),
    }


class Bridge:
    def __init__(self):
        self.writes = []

    def exchange(self, message, *, timeout_seconds):
        if message["method"] == "xeus/evidence":
            return {
                "result": {
                    "source_ids": ["xeus-cybergym-workspace"],
                    "server_context_source_id": "xeus-cybergym-workspace",
                    "scopes": ["read", "write"],
                    "native_guard_bound": True,
                    "native_guard_binding_sha256": "c" * 64,
                    "session_mode": "writer",
                }
            }
        self.writes.append(message)
        return {
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(
                            {
                                "slug": message["params"]["arguments"]["slug"],
                                "channel": "capture",
                                "content_hash": "b" * 64,
                            }
                        ),
                    }
                ]
            },
        }


class Audit:
    def __init__(self):
        self.events = []

    def record(self, event):
        self.events.append(event)
        return True


@pytest.mark.parametrize("status", ["oracle_true", "oracle_false"])
def test_verified_actual_oracle_outcome_is_the_only_source_of_episode_label(tmp_path, status):
    bridge, audit = Bridge(), Audit()
    writer = OracleMemoryWriter(
        bridge=bridge,
        attest_receipt=lambda _: receipt(status),
        audit=audit,
        expected_guard_binding_sha256="c" * 64,
        evidence_root=tmp_path,
        run_id="synthetic-run",
        epoch="synthetic-epoch",
    )
    result = writer.publish(b"signed-receipt", task_id="synthetic-toy")
    content = bridge.writes[0]["params"]["arguments"]["content"]
    assert f"oracle_outcome: {status}" in content
    assert "tier: episodic" in content
    assert result["receipt_sha256"] == hashlib.sha256(b"signed-receipt").hexdigest()
    assert audit.events[-1]["event"] == "memory_oracle_episode_written"
    with pytest.raises(TransportDenied, match="attempted"):
        writer.publish(b"signed-receipt", task_id="synthetic-toy")
    assert len(bridge.writes) == 1


@pytest.mark.parametrize(
    "change",
    [
        {"status": "timeout"},
        {"oracle_true": True},
        {"task_id": "another"},
        {"oracle_verdict_sha256": ""},
        {"run_id": "another"},
    ],
)
def test_missing_or_mismatched_oracle_proof_never_writes(tmp_path, change):
    bridge = Bridge()
    writer = OracleMemoryWriter(
        bridge=bridge,
        attest_receipt=lambda _: receipt() | change,
        audit=Audit(),
        expected_guard_binding_sha256="c" * 64,
        evidence_root=tmp_path,
        run_id="synthetic-run",
        epoch="synthetic-epoch",
    )
    with pytest.raises(TransportDenied):
        writer.publish(b"signed-receipt", task_id="synthetic-toy")
    assert bridge.writes == []


def test_ambiguous_write_blocks_retry_across_new_writer_instance(tmp_path):
    class BrokenBridge(Bridge):
        def exchange(self, message, **kwargs):
            if message["method"] == "xeus/evidence":
                return super().exchange(message, **kwargs)
            raise TimeoutError()

    for bridge in (BrokenBridge(), Bridge()):
        writer = OracleMemoryWriter(
            bridge=bridge,
            attest_receipt=lambda _: receipt(),
            audit=Audit(),
            expected_guard_binding_sha256="c" * 64,
            evidence_root=tmp_path,
            run_id="synthetic-run",
            epoch="synthetic-epoch",
        )
        with pytest.raises(TransportDenied):
            writer.publish(b"signed-receipt", task_id="synthetic-toy")
        assert bridge.writes == []


def test_malformed_native_capture_never_counts_as_written(tmp_path):
    class WrongBridge(Bridge):
        def exchange(self, message, **kwargs):
            result = super().exchange(message, **kwargs)
            if message["method"] != "xeus/evidence":
                result["result"]["content"][0]["text"] = '{"channel":"capture","slug":"wrong"}'
            return result

    writer = OracleMemoryWriter(
        bridge=WrongBridge(),
        attest_receipt=lambda _: receipt(),
        audit=Audit(),
        expected_guard_binding_sha256="c" * 64,
        evidence_root=tmp_path,
        run_id="synthetic-run",
        epoch="synthetic-epoch",
    )
    with pytest.raises(TransportDenied):
        writer.publish(b"signed-receipt", task_id="synthetic-toy")


def synthetic_result(tmp_path, *, run_id="synthetic-run", task_id="synthetic-toy", true=True):
    pytest.importorskip("xeus_cybergym")
    from xeus_cybergym.canonical import canonical_json
    from xeus_cybergym.ledger import Ed25519Signer, Ed25519Verifier

    key = Ed25519PrivateKey.generate()
    signer = Ed25519Signer(private_key=key, key_id="synthetic-test")
    verifier = Ed25519Verifier({"synthetic-test": key.public_key()})
    payload = {
        "schema_version": 1,
        "artifact_kind": "synthetic_oracle_evidence",
        "request": {
            "scope": "synthetic_private_oracle",
            "run_id": run_id,
            "task_id": task_id,
            "attempt_id": "attempt-a",
            "candidate_sha256": "a" * 64,
            "freeze_sha256": "b" * 64,
        },
        "oracle_true": true,
        "observations": {
            "vulnerable": {"build_exit": 0, "test_exit": -6, "sanitizer": True},
            "fixed": {"build_exit": 0, "test_exit": 0, "sanitizer": False},
        },
        "final_declaration_sha256": "c" * 64,
        "parent_event_digest": "d" * 64,
    }
    data = canonical_json(payload)
    signed = tmp_path / "synthetic-oracle.signed.json"
    signed.write_bytes(canonical_json(signer.sign(data).model_dump()))
    result = SyntheticOracleResult(task_id, "a" * 64, true, hashlib.sha256(data).hexdigest(), signed, payload["observations"])
    return result, verifier


@pytest.mark.parametrize("true", [True, False])
def test_synthetic_episode_requires_signed_stopped_toy_oracle_and_is_labelled(tmp_path, true):
    result, verifier = synthetic_result(tmp_path, true=true)
    bridge, audit = Bridge(), Audit()
    writer = OracleMemoryWriter(
        bridge=bridge,
        attest_receipt=lambda _: None,
        audit=audit,
        expected_guard_binding_sha256="c" * 64,
        evidence_root=tmp_path,
        run_id="synthetic-run",
        epoch="synthetic-epoch",
    )
    with pytest.raises(TransportDenied, match="stopped"):
        writer.publish_synthetic(result, verifier=verifier, attempt_id="attempt-a", freeze_sha256="b" * 64, solver_stopped=lambda: False)
    assert bridge.writes == []
    written = writer.publish_synthetic(result, verifier=verifier, attempt_id="attempt-a", freeze_sha256="b" * 64, solver_stopped=lambda: True)
    content = bridge.writes[0]["params"]["arguments"]["content"]
    assert "synthetic toy oracle" in content
    outcome = "synthetic_oracle_true" if true else "synthetic_oracle_false"
    assert f"oracle_outcome: {outcome}" in content
    assert "reviewed: false" in content
    assert written["oracle_outcome"] == outcome
    assert audit.events[-1]["event"] == "memory_oracle_episode_written"


def test_synthetic_episode_rejects_tampering_and_identity_mismatch(tmp_path):
    result, verifier = synthetic_result(tmp_path)
    bridge = Bridge()
    writer = OracleMemoryWriter(
        bridge=bridge,
        attest_receipt=lambda _: None,
        audit=Audit(),
        expected_guard_binding_sha256="c" * 64,
        evidence_root=tmp_path,
        run_id="synthetic-run",
        epoch="synthetic-epoch",
    )
    with pytest.raises(TransportDenied):
        writer.publish_synthetic(result, verifier=verifier, attempt_id="wrong", freeze_sha256="b" * 64, solver_stopped=lambda: True)
    raw = result.signed_evidence.read_bytes()
    result.signed_evidence.write_bytes(raw.replace(b"synthetic", b"falsified", 1))
    with pytest.raises(TransportDenied):
        writer.publish_synthetic(result, verifier=verifier, attempt_id="attempt-a", freeze_sha256="b" * 64, solver_stopped=lambda: True)
    assert bridge.writes == []
