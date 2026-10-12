# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""A restarted controller may replay only a witnessed, signed scored terminal."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nooa_cybergym.leaderboard.campaign import CampaignAction
from nooa_cybergym.leaderboard.native_first_request import NativeFirstRequestWitness
from nooa_cybergym.leaderboard.native_launcher import (
    NativeLaunchAuthority,
    build_launch_manifest,
)
from nooa_cybergym.leaderboard.native_start_intent import publish_start_intent
from nooa_cybergym.leaderboard.scored_terminal_recovery import (
    ScoredTerminalRecovery,
    recover_scored_terminal,
)
from xeus_cybergym.canonical import canonical_json
from xeus_cybergym.ledger import Ed25519Signer, Ed25519Verifier, SignedEnvelope

TASK = "oss-fuzz:42535201"
RUN = "scored-1"
EPOCH = "epoch-1"
LAUNCH = "launch-1"
ATTEMPT = "attempt-1"
DIGEST = "a" * 64


def _signed(root: Path, name: str, value: dict, signer: Ed25519Signer) -> bytes:
    raw = canonical_json(signer.sign(canonical_json(value)).model_dump())
    (root / name).write_bytes(raw)
    return raw


def _setup(tmp_path: Path):
    controller_key = Ed25519PrivateKey.generate()
    evaluator_key = Ed25519PrivateKey.generate()
    controller = Ed25519Signer(private_key=controller_key, key_id="controller")
    controller_verifier = Ed25519Verifier({"controller": controller_key.public_key()})
    evaluator = Ed25519Signer(private_key=evaluator_key, key_id="evaluator")
    evaluator_verifier = Ed25519Verifier({"evaluator": evaluator_key.public_key()})
    manifest = build_launch_manifest(
        scope="official",
        run_id=RUN,
        task_id=TASK,
        launch_id=LAUNCH,
        ordinal=1,
        harness_sha256="b" * 64,
        task_manifest_bytes=b'{"official":true}',
        file_hashes={"CLAUDE.md": "c" * 64},
        container_id="d" * 64,
        hostname="d" * 12,
        uid=1000,
        pid_namespace="pid:[100]",
        mount_namespace="mnt:[200]",
        vscode_version="1.140.0",
        claude_extension_version="2.1.289",
        claude_extension_sha256="e" * 64,
        native_launch_url="http://registered-tool-gateway/native-launch",
    )
    envelope = canonical_json(controller.sign(canonical_json(manifest)).model_dump())
    evidence = tmp_path / "task"
    evidence.mkdir()
    launch = NativeLaunchAuthority.from_signed_envelope(
        envelope, {"controller": controller_key.public_key()}, evidence
    )
    launch.launch_dir.mkdir()
    from .test_native_launcher import receipt

    observed_receipt = receipt(manifest)
    observed_receipt["observed"]["hostname"] = manifest["hostname"]
    observed_receipt["observed"]["claude_extension_sha256"] = manifest["claude_extension_sha256"]
    (launch.launch_dir / "launcher-receipt.json").write_bytes(canonical_json(observed_receipt))
    audit = evidence / "model-requests.jsonl"
    common = {
        "task_id": TASK,
        "attempt_id": ATTEMPT,
        "request_id": "model-1",
        "role": "primary",
        "requested_model": "glm-5.3",
        "policy_sha256": "f" * 64,
    }
    audit.write_bytes(
        canonical_json({**common, "event": "request_reserved"})
        + b"\n"
        + canonical_json({**common, "event": "attempt_started"})
        + b"\n"
    )
    witness = NativeFirstRequestWitness(
        launch_authority=launch,
        attempt_id=ATTEMPT,
        model_audit=audit,
        policy_sha256="f" * 64,
        expected_model="glm-5.3",
    )
    publish_start_intent(
        evidence,
        signer=controller,
        verifier=controller_verifier,
        run_id=RUN,
        task_id=TASK,
        attempt_id=ATTEMPT,
        launch_id=LAUNCH,
        started_event_sha256=DIGEST,
    )
    request = {
        "schema_version": 1,
        "artifact_kind": "scored_official_evaluation_request",
        "run_id": RUN,
        "epoch": EPOCH,
        "task_id": TASK,
        "final_sha256": "1" * 64,
        "final_declaration_sha256": "2" * 64,
        "parent_event_digest": "3" * 64,
        "vulnerable_image_id": "sha256:" + "4" * 64,
        "fixed_image_id": "sha256:" + "5" * 64,
        "official_verifier_sha256": "6" * 64,
    }
    request_raw = _signed(evidence, "scored-evaluation-request.signed.json", request, controller)
    observed = {
        "task_id": TASK,
        "candidate_sha256": "1" * 64,
        "snapshot_sha256": "1" * 64,
        "network_disabled": True,
        "raw_exit_code": 0,
    }
    result = {
        "schema_version": 1,
        "artifact_kind": "scored_official_evaluation_result",
        "run_id": RUN,
        "epoch": EPOCH,
        "task_id": TASK,
        "request_sha256": hashlib.sha256(request_raw).hexdigest(),
        "vulnerable": {**observed, "image_id": request["vulnerable_image_id"], "raw_exit_code": 42},
        "fixed": {**observed, "image_id": request["fixed_image_id"]},
        "official_scoring_form": "raw",
        "official_solved": True,
    }
    result_raw = _signed(evidence, "scored-evaluation-result.signed.json", result, evaluator)
    terminal = {
        "schema_version": 1,
        "artifact_kind": "terminal_receipt",
        "run_id": RUN,
        "epoch": EPOCH,
        "task_id": TASK,
        "status": "oracle_true",
        "final_sha256": "1" * 64,
        "final_declaration_sha256": "2" * 64,
        "parent_event_digest": "3" * 64,
        "oracle_request_sha256": hashlib.sha256(request_raw).hexdigest(),
        "oracle_verdict_sha256": hashlib.sha256(result_raw).hexdigest(),
        "oracle_true": True,
    }
    terminal_raw = _signed(evidence, "terminal-receipt.signed.json", terminal, controller)

    class Authority:
        def attest_signed(self, kind, raw):
            assert kind == "terminal_receipt"
            return json.loads(controller_verifier.verify(SignedEnvelope.model_validate_json(raw)))

    class State:
        run_id = RUN
        epoch = EPOCH
        authority = Authority()

        def next_action(self):
            return CampaignAction("observe_started", TASK)

        def started_event_sha256(self, task_id, request_id):
            if (task_id, request_id) != (TASK, LAUNCH):
                raise RuntimeError("verified campaign start differs")
            return DIGEST

    inputs = {
        "state": State(),
        "task_id": TASK,
        "launch_authority": launch,
        "attempt_id": ATTEMPT,
        "witness": witness,
        "evidence_dir": evidence,
        "controller_verifier": controller_verifier,
        "evaluator_verifier": evaluator_verifier,
    }
    return SimpleNamespace(
        inputs=inputs,
        terminal=terminal_raw,
        evidence=evidence,
        audit=audit,
        audit_bytes=audit.read_bytes(),
        result=result,
        evaluator=evaluator,
        launch_envelope=envelope,
        public_keys={"controller": controller_key.public_key()},
    )


def test_recovery_replays_exact_witnessed_signed_terminal_without_dispatch(tmp_path):
    fixture = _setup(tmp_path)
    assert recover_scored_terminal(**fixture.inputs) == fixture.terminal


def test_recovery_rejects_missing_primary_request_and_changed_result(tmp_path):
    fixture = _setup(tmp_path)
    fixture.audit.write_bytes(b"")
    with pytest.raises(RuntimeError, match="first request"):
        recover_scored_terminal(**fixture.inputs)
    fixture.audit.write_bytes(fixture.audit_bytes)
    result_path = fixture.evidence / "scored-evaluation-result.signed.json"
    result_path.write_bytes(result_path.read_bytes() + b" ")
    with pytest.raises(RuntimeError, match="signed|canonical"):
        recover_scored_terminal(**fixture.inputs)


def test_recovery_rejects_validly_signed_but_changed_oracle_result(tmp_path):
    fixture = _setup(tmp_path)
    changed = {
        **fixture.result,
        "vulnerable": {**fixture.result["vulnerable"], "raw_exit_code": 0},
        "official_solved": False,
    }
    _signed(
        fixture.evidence,
        "scored-evaluation-result.signed.json",
        changed,
        fixture.evaluator,
    )
    with pytest.raises(RuntimeError, match="terminal differs"):
        recover_scored_terminal(**fixture.inputs)


def test_recovery_rejects_changed_ledger_launch_and_unsigned_terminal(tmp_path):
    fixture = _setup(tmp_path)
    fixture.inputs["state"].started_event_sha256 = lambda _task, _launch: "b" * 64
    with pytest.raises(RuntimeError, match="start intent differs"):
        recover_scored_terminal(**fixture.inputs)
    fixture.inputs["state"].started_event_sha256 = lambda _task, _launch: DIGEST
    terminal_path = fixture.evidence / "terminal-receipt.signed.json"
    terminal_path.write_bytes(b"{}")
    with pytest.raises((RuntimeError, ValueError)):
        recover_scored_terminal(**fixture.inputs)


def _restart_callback(fixture):
    (fixture.evidence / "native-launch.signed.json").write_bytes(fixture.launch_envelope)
    return ScoredTerminalRecovery(
        state=fixture.inputs["state"],
        evidence_dir=fixture.evidence,
        public_keys=fixture.public_keys,
        controller_verifier=fixture.inputs["controller_verifier"],
        evaluator_verifier=fixture.inputs["evaluator_verifier"],
        expected_policy_sha256="f" * 64,
        expected_model="glm-5.3",
    )


def test_restart_callback_reconstructs_signed_launch_and_replays_once(tmp_path):
    fixture = _setup(tmp_path)
    callback = _restart_callback(fixture)
    assert callback(TASK, LAUNCH) == fixture.terminal
    assert callback(TASK, LAUNCH) == fixture.terminal


def test_restart_callback_refuses_missing_or_tampered_launch_evidence(tmp_path):
    fixture = _setup(tmp_path)
    callback = _restart_callback(fixture)
    with pytest.raises(RuntimeError, match="launch"):
        callback(TASK, "another-launch")
    launch_path = fixture.evidence / "native-launch.signed.json"
    launch_path.write_bytes(b"{}")
    with pytest.raises((RuntimeError, ValueError), match="launch|signature"):
        callback(TASK, LAUNCH)


def test_restart_callback_does_not_infer_terminal_from_prepared_directory(tmp_path):
    fixture = _setup(tmp_path)
    callback = _restart_callback(fixture)
    (fixture.evidence / "terminal-receipt.signed.json").unlink()
    assert callback(TASK, LAUNCH) is None
