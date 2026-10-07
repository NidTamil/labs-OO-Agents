# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""A terminal receipt must derive from the real signed evaluator contracts."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nooa_cybergym.leaderboard.finalize import FinalLock
from xeus_cybergym.canonical import canonical_json
from xeus_cybergym.contracts import EvaluationRequest, EvaluationResult, EvaluationVerdict
from xeus_cybergym.contracts.artifacts import ExecutionTuple, SubmissionBundle, SubmissionFile
from xeus_cybergym.contracts.evaluation import OfficialScoringForm
from xeus_cybergym.contracts.runtime import RuntimeImageAttestation, RuntimeImageAuthority
from xeus_cybergym.contracts.task import ExecutionLimits
from xeus_cybergym.ledger import Ed25519Signer, Ed25519Verifier, SignedEnvelope


def _signer(key_id):
    key = Ed25519PrivateKey.generate()
    return Ed25519Signer(private_key=key, key_id=key_id), key.public_key()


def _signed(signer, value):
    return canonical_json(signer.sign(canonical_json(value)).model_dump())


def _attestation():
    authority = RuntimeImageAuthority(
        logical_ref="sha256:" + "1" * 64,
        backend="docker",
        expected_runtime_image_id="sha256:" + "2" * 64,
    )
    return RuntimeImageAttestation(
        logical_ref=authority.logical_ref,
        backend=authority.backend,
        observed_runtime_image_id=authority.expected_runtime_image_id,
        runtime_authority_digest=authority.digest(),
    )


def _evidence(tmp_path: Path):
    kernel_signer, kernel_key = _signer("kernel")
    evaluator_signer, evaluator_key = _signer("evaluator")
    controller_signer, controller_key = _signer("controller")
    task_digest = "sha256:" + "3" * 64
    final_dir = tmp_path / "final"
    final_dir.mkdir()
    candidate = final_dir / "poc"
    candidate.write_bytes(b"one locked candidate")
    candidate_digest = "sha256:" + hashlib.sha256(candidate.read_bytes()).hexdigest()
    bundle = SubmissionBundle(
        files=(
            SubmissionFile(
                path="poc",
                digest=candidate_digest,
                size_bytes=candidate.stat().st_size,
                media_type="application/octet-stream",
            ),
        ),
        execution=ExecutionTuple(
            entrypoint="poc",
            working_directory=".",
            argv=("poc",),
            allowed_environment=(),
            harness_profile_digest="sha256:" + "9" * 64,
            dependency_artifact_digests=(),
            execution_limits=ExecutionLimits(
                timeout_seconds=30,
                cpu_seconds=30,
                memory_bytes=1048576,
                output_bytes=1048576,
                repeat_count=1,
            ),
        ),
        task_digest=task_digest,
        scoring_policy_digest="sha256:" + "a" * 64,
    )
    bundle_digest = bundle.digest()
    binding_digest = "sha256:" + "5" * 64
    request = EvaluationRequest(
        evaluation_request_id=uuid4(),
        task_digest=task_digest,
        evaluator_binding_digest=binding_digest,
        submission_bundle_digest=bundle_digest,
        signed_submission_ref="artifact:submission",
    )
    runtime = _attestation()
    result = EvaluationResult(
        evaluation_id=uuid4(),
        task_digest=task_digest,
        evaluator_binding_digest=binding_digest,
        submission_bundle_digest=bundle_digest,
        verdict=EvaluationVerdict.SOLVED,
        evaluator_digest="sha256:" + "6" * 64,
        vulnerable_runtime_image=runtime,
        fixed_runtime_image=runtime,
        vulnerable_execution_ref="artifact:vulnerable",
        fixed_execution_ref="artifact:fixed",
        oracle_classification="verified target crash",
        replay_id=uuid4(),
        replay_bundle_ref="sha256:" + "7" * 64,
        completed_at=datetime.now(UTC),
        official_vul_exit_code=42,
        official_fix_exit_code=0,
        official_scoring_form=OfficialScoringForm.EFFECTIVE,
        official_solved=True,
    )
    declaration = final_dir / "agent-final.json"
    declared = {
        "schema_version": 1,
        "task_id": "arvo:1",
        "candidate_path": "/workspace/output/poc",
        "sha256": hashlib.sha256(candidate.read_bytes()).hexdigest(),
        "byte_length": candidate.stat().st_size,
        "selected_at": datetime.now(UTC).isoformat(),
        "selection_reason": "selected final candidate",
        "final_declaration": True,
        "selected_by": "glm_parent",
    }
    declaration.write_bytes(canonical_json(declared))
    lock = FinalLock(
        task_id="arvo:1",
        sha256=hashlib.sha256(candidate.read_bytes()).hexdigest(),
        byte_length=candidate.stat().st_size,
        poc_path=candidate,
        declaration_path=declaration,
        declaration=declared,
        parent_event_digest="8" * 64,
    )
    return {
        "lock": lock,
        "request_value": request,
        "result_value": result,
        "kernel_signer": kernel_signer,
        "evaluator_signer": evaluator_signer,
        "request": _signed(kernel_signer, request),
        "result": _signed(evaluator_signer, result),
        "bundle": canonical_json(bundle),
        "task_digest": task_digest,
        "kernel_verifier": Ed25519Verifier({"kernel": kernel_key}),
        "evaluator_verifier": Ed25519Verifier({"evaluator": evaluator_key}),
        "controller_signer": controller_signer,
        "controller_verifier": Ed25519Verifier({"controller": controller_key}),
    }


def test_terminal_receipt_verifies_evaluator_and_is_idempotent(tmp_path: Path):
    from nooa_cybergym.leaderboard.native_task_executor import NativeTerminalReceiptPublisher

    evidence = _evidence(tmp_path)
    publisher = NativeTerminalReceiptPublisher(
        run_id="run-1",
        epoch="epoch-1",
        task_id="arvo:1",
        task_digest=evidence["task_digest"],
        submission_file_path="poc",
        evidence_dir=tmp_path,
        kernel_verifier=evidence["kernel_verifier"],
        evaluator_verifier=evidence["evaluator_verifier"],
        controller_signer=evidence["controller_signer"],
        controller_verifier=evidence["controller_verifier"],
    )
    first = publisher.publish_oracle(
        lock=evidence["lock"],
        signed_request=evidence["request"],
        signed_result=evidence["result"],
        frozen_bundle=evidence["bundle"],
        solver_stopped=lambda: True,
    )
    second = publisher.publish_oracle(
        lock=evidence["lock"],
        signed_request=evidence["request"],
        signed_result=evidence["result"],
        frozen_bundle=evidence["bundle"],
        solver_stopped=lambda: True,
    )
    assert first == second
    payload = json.loads(
        evidence["controller_verifier"].verify(SignedEnvelope.model_validate_json(first))
    )
    assert payload["status"] == "oracle_true"
    assert payload["final_sha256"] == evidence["lock"].sha256
    assert payload["oracle_request_sha256"] == hashlib.sha256(evidence["request"]).hexdigest()
    assert payload["oracle_verdict_sha256"] == hashlib.sha256(evidence["result"]).hexdigest()


def test_terminal_receipt_rejects_changed_final_and_untrusted_verdict(tmp_path: Path):
    from nooa_cybergym.leaderboard.native_task_executor import NativeTerminalReceiptPublisher

    evidence = _evidence(tmp_path)
    publisher = NativeTerminalReceiptPublisher(
        run_id="run-1",
        epoch="epoch-1",
        task_id="arvo:1",
        task_digest=evidence["task_digest"],
        submission_file_path="poc",
        evidence_dir=tmp_path,
        kernel_verifier=evidence["kernel_verifier"],
        evaluator_verifier=evidence["evaluator_verifier"],
        controller_signer=evidence["controller_signer"],
        controller_verifier=evidence["controller_verifier"],
    )
    with pytest.raises((ValueError, RuntimeError)):
        publisher.publish_oracle(
            lock=evidence["lock"],
            signed_request=evidence["request"],
            signed_result=evidence["request"],
            frozen_bundle=evidence["bundle"],
            solver_stopped=lambda: True,
        )
    evidence["lock"].poc_path.write_bytes(b"changed candidate")
    with pytest.raises((ValueError, RuntimeError)):
        publisher.publish_oracle(
            lock=evidence["lock"],
            signed_request=evidence["request"],
            signed_result=evidence["result"],
            frozen_bundle=evidence["bundle"],
            solver_stopped=lambda: True,
        )


def test_terminal_receipt_rejects_a_verdict_for_another_candidate(tmp_path: Path):
    from nooa_cybergym.leaderboard.native_task_executor import NativeTerminalReceiptPublisher

    evidence = _evidence(tmp_path)
    publisher = NativeTerminalReceiptPublisher(
        run_id="run-1",
        epoch="epoch-1",
        task_id="arvo:1",
        task_digest=evidence["task_digest"],
        evidence_dir=tmp_path,
        submission_file_path="poc",
        kernel_verifier=evidence["kernel_verifier"],
        evaluator_verifier=evidence["evaluator_verifier"],
        controller_signer=evidence["controller_signer"],
        controller_verifier=evidence["controller_verifier"],
    )
    bundle = SubmissionBundle.model_validate_json(evidence["bundle"])
    other = bundle.model_copy(
        update={"files": (bundle.files[0].model_copy(update={"digest": "sha256:" + "e" * 64}),)}
    )
    other_request = evidence["request_value"].model_copy(
        update={"submission_bundle_digest": other.digest()}
    )
    other_result = evidence["result_value"].model_copy(
        update={"submission_bundle_digest": other.digest()}
    )
    with pytest.raises(RuntimeError, match="frozen task"):
        publisher.publish_oracle(
            lock=evidence["lock"],
            signed_request=_signed(evidence["kernel_signer"], other_request),
            signed_result=_signed(evidence["evaluator_signer"], other_result),
            frozen_bundle=canonical_json(other),
            solver_stopped=lambda: True,
        )


def test_terminal_receipt_requires_stopped_parent_and_unchanged_declaration(tmp_path: Path):
    from nooa_cybergym.leaderboard.native_task_executor import NativeTerminalReceiptPublisher

    evidence = _evidence(tmp_path)
    publisher = NativeTerminalReceiptPublisher(
        run_id="run-1",
        epoch="epoch-1",
        task_id="arvo:1",
        task_digest=evidence["task_digest"],
        submission_file_path="poc",
        evidence_dir=tmp_path,
        kernel_verifier=evidence["kernel_verifier"],
        evaluator_verifier=evidence["evaluator_verifier"],
        controller_signer=evidence["controller_signer"],
        controller_verifier=evidence["controller_verifier"],
    )
    with pytest.raises(RuntimeError, match="stopped"):
        publisher.publish_oracle(
            lock=evidence["lock"],
            signed_request=evidence["request"],
            signed_result=evidence["result"],
            frozen_bundle=evidence["bundle"],
            solver_stopped=lambda: False,
        )
    evidence["lock"].declaration_path.write_bytes(b'{"final_declaration":true}')
    with pytest.raises(ValueError, match="declaration"):
        publisher.publish_oracle(
            lock=evidence["lock"],
            signed_request=evidence["request"],
            signed_result=evidence["result"],
            frozen_bundle=evidence["bundle"],
            solver_stopped=lambda: True,
        )


def test_terminal_receipt_requires_controller_final_custody_path(tmp_path: Path):
    from nooa_cybergym.leaderboard.native_task_executor import NativeTerminalReceiptPublisher

    evidence = _evidence(tmp_path)
    outside = tmp_path / "outside-poc"
    outside.write_bytes(evidence["lock"].poc_path.read_bytes())
    publisher = NativeTerminalReceiptPublisher(
        run_id="run-1",
        epoch="epoch-1",
        task_id="arvo:1",
        task_digest=evidence["task_digest"],
        submission_file_path="poc",
        evidence_dir=tmp_path,
        kernel_verifier=evidence["kernel_verifier"],
        evaluator_verifier=evidence["evaluator_verifier"],
        controller_signer=evidence["controller_signer"],
        controller_verifier=evidence["controller_verifier"],
    )
    with pytest.raises(ValueError, match="custody"):
        publisher.publish_oracle(
            lock=replace(evidence["lock"], poc_path=outside),
            signed_request=evidence["request"],
            signed_result=evidence["result"],
            frozen_bundle=evidence["bundle"],
            solver_stopped=lambda: True,
        )


def test_failure_receipt_hashes_actual_durable_failure_evidence(tmp_path: Path):
    from nooa_cybergym.leaderboard.native_task_executor import NativeTerminalReceiptPublisher

    evidence = _evidence(tmp_path)
    publisher = NativeTerminalReceiptPublisher(
        run_id="run-1",
        epoch="epoch-1",
        task_id="arvo:1",
        task_digest=evidence["task_digest"],
        submission_file_path="poc",
        evidence_dir=tmp_path,
        kernel_verifier=evidence["kernel_verifier"],
        evaluator_verifier=evidence["evaluator_verifier"],
        controller_signer=evidence["controller_signer"],
        controller_verifier=evidence["controller_verifier"],
    )
    failure = tmp_path / "failure.json"
    failure.write_bytes(canonical_json({"event": "no_first_model_request", "request_id": "req-1"}))
    first = publisher.publish_failure(status="timeout", evidence_path=failure)
    assert publisher.publish_failure(status="timeout", evidence_path=failure) == first
    payload = json.loads(
        evidence["controller_verifier"].verify(SignedEnvelope.model_validate_json(first))
    )
    assert payload["status"] == "timeout"
    assert payload["evidence_sha256"] == hashlib.sha256(failure.read_bytes()).hexdigest()
    failure.write_bytes(b"changed")
    with pytest.raises(RuntimeError, match="differs"):
        publisher.publish_failure(status="timeout", evidence_path=failure)


def test_native_send_reserves_before_attempt_and_never_retries_ambiguous_click(tmp_path: Path):
    from nooa_cybergym.leaderboard.native_task_executor import PowerShellNativeSubmitter

    launch_dir = tmp_path / "launch"
    launch_dir.mkdir()
    receipt = {"event": "launch_reserved", "launch_id": "launch-1", "prompt_sha256": "a" * 64}
    (launch_dir / "launcher-receipt.json").write_bytes(canonical_json(receipt))
    script = tmp_path / "submit.ps1"
    script.write_bytes(b"frozen script")

    class Authority:
        manifest = {"task_id": "arvo:1", "launch_id": "launch-1"}

        def _check_receipt(self, value):
            if value != receipt:
                raise ValueError("launch receipt changed")

    Authority.launch_dir = launch_dir

    calls = []

    def interrupted(command, *, check):
        calls.append(command)
        assert check is True
        assert (launch_dir / "ui-submit-intent.json").is_file()
        (tmp_path / "ui-audit").mkdir()
        (tmp_path / "ui-audit" / "ui-send-reservation.json").write_bytes(
            canonical_json({"event": "ui_send_reserved"})
        )
        raise RuntimeError("desktop unavailable after intent")

    submitter = PowerShellNativeSubmitter(
        launch_authority=Authority(),
        script=script,
        script_sha256=hashlib.sha256(script.read_bytes()).hexdigest(),
        remote_alias="cybergym-e",
        profile_directory=tmp_path / "profile",
        audit_directory=tmp_path / "ui-audit",
        run_command=interrupted,
    )
    with pytest.raises(RuntimeError, match="desktop unavailable"):
        submitter.submit_once("launch-1")
    assert submitter.submit_once("launch-1") is False
    assert len(calls) == 1
    with pytest.raises(ValueError):
        submitter.submit_once("another-launch")


def test_native_send_requires_matching_attempt_audit(tmp_path: Path):
    from nooa_cybergym.leaderboard.native_task_executor import PowerShellNativeSubmitter

    launch_dir = tmp_path / "launch"
    launch_dir.mkdir()
    receipt = {"event": "launch_reserved", "launch_id": "launch-2", "prompt_sha256": "b" * 64}
    (launch_dir / "launcher-receipt.json").write_bytes(canonical_json(receipt))
    script = tmp_path / "submit.ps1"
    script.write_bytes(b"frozen script")

    class Authority:
        manifest = {"task_id": "arvo:2", "launch_id": "launch-2"}

        def _check_receipt(self, value):
            if value != receipt:
                raise ValueError("launch receipt changed")

    Authority.launch_dir = launch_dir
    calls = []

    def bad_attempt(command, *, check):
        calls.append(command)
        audit = tmp_path / "ui-audit"
        audit.mkdir()
        (audit / "ui-send-attempted.json").write_bytes(
            canonical_json(
                {
                    "schema_version": 1,
                    "event": "ui_send_attempted",
                    "launch_id": "another-launch",
                    "prompt_sha256": "b" * 64,
                    "remote_alias": "cybergym-e",
                    "provider_request_observed": False,
                }
            )
        )

    submitter = PowerShellNativeSubmitter(
        launch_authority=Authority(),
        script=script,
        script_sha256=hashlib.sha256(script.read_bytes()).hexdigest(),
        remote_alias="cybergym-e",
        profile_directory=tmp_path / "profile",
        audit_directory=tmp_path / "ui-audit",
        run_command=bad_attempt,
    )
    with pytest.raises(RuntimeError, match="attempt disagrees"):
        submitter.submit_once("launch-2")
    assert submitter.submit_once("launch-2") is False
    assert len(calls) == 1


def test_native_send_reports_only_a_matching_ui_attempt(tmp_path: Path):
    from nooa_cybergym.leaderboard.native_task_executor import PowerShellNativeSubmitter

    launch_dir = tmp_path / "launch"
    launch_dir.mkdir()
    receipt = {"event": "launch_reserved", "launch_id": "launch-3", "prompt_sha256": "c" * 64}
    (launch_dir / "launcher-receipt.json").write_bytes(canonical_json(receipt))
    script = tmp_path / "submit.ps1"
    script.write_bytes(b"frozen script")

    class Authority:
        manifest = {"task_id": "arvo:3", "launch_id": "launch-3"}

        def _check_receipt(self, value):
            if value != receipt:
                raise ValueError("launch receipt changed")

    Authority.launch_dir = launch_dir
    calls = []

    def matching_attempt(command, *, check):
        calls.append(command)
        audit = tmp_path / "ui-audit"
        audit.mkdir()
        (audit / "ui-send-attempted.json").write_bytes(
            canonical_json(
                {
                    "schema_version": 1,
                    "event": "ui_send_attempted",
                    "launch_id": "launch-3",
                    "prompt_sha256": "c" * 64,
                    "remote_alias": "cybergym-e",
                    "provider_request_observed": False,
                }
            )
        )

    submitter = PowerShellNativeSubmitter(
        launch_authority=Authority(),
        script=script,
        script_sha256=hashlib.sha256(script.read_bytes()).hexdigest(),
        remote_alias="cybergym-e",
        profile_directory=tmp_path / "profile",
        audit_directory=tmp_path / "ui-audit",
        run_command=matching_attempt,
    )
    assert submitter.submit_once("launch-3") is True
    assert submitter.submit_once("launch-3") is False
    assert len(calls) == 1
