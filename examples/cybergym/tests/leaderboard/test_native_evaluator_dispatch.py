# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""The native final reaches the isolated Xeus evaluator exactly once."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nooa_cybergym.leaderboard.finalize import FinalLock
from xeus_cybergym.canonical import canonical_json
from xeus_cybergym.contracts import (
    EvaluationRequest,
    EvaluationResult,
    EvaluationVerdict,
    EvaluatorTaskBinding,
    TargetOracle,
)
from xeus_cybergym.contracts.artifacts import ExecutionTuple
from xeus_cybergym.contracts.evaluation import OfficialScoringForm
from xeus_cybergym.contracts.runtime import RuntimeImageAttestation, RuntimeImageAuthority
from xeus_cybergym.contracts.task import ExecutionLimits
from xeus_cybergym.ledger import ArtifactStore, Ed25519Signer, Ed25519Verifier, SignedEnvelope


def _signer(name):
    private = Ed25519PrivateKey.generate()
    return Ed25519Signer(private_key=private, key_id=name), private.public_key()


def test_dispatch_is_signed_bound_to_locked_final_and_never_repeated(tmp_path: Path):
    from nooa_cybergym.leaderboard.native_evaluator_dispatch import NativeEvaluatorDispatch
    from nooa_cybergym.leaderboard.native_task_executor import NativeTerminalReceiptPublisher

    final = tmp_path / "final"
    final.mkdir()
    poc = final / "poc"
    poc.write_bytes(b"one final input")
    declaration = final / "agent-final.json"
    declared = {
        "schema_version": 1,
        "task_id": "arvo:1",
        "candidate_path": "/workspace/output/poc",
        "sha256": hashlib.sha256(poc.read_bytes()).hexdigest(),
        "byte_length": poc.stat().st_size,
        "selected_at": datetime.now(UTC).isoformat(),
        "selection_reason": "selected final candidate",
        "final_declaration": True,
        "selected_by": "glm_parent",
    }
    declaration.write_bytes(canonical_json(declared))
    lock = FinalLock(
        task_id="arvo:1",
        sha256=hashlib.sha256(poc.read_bytes()).hexdigest(),
        byte_length=poc.stat().st_size,
        poc_path=poc,
        declaration_path=declaration,
        declaration=declared,
        parent_event_digest="8" * 64,
    )
    kernel_signer, kernel_key = _signer("kernel")
    evaluator_signer, evaluator_key = _signer("evaluator")
    kernel_verifier = Ed25519Verifier({"kernel": kernel_key})
    evaluator_verifier = Ed25519Verifier({"evaluator": evaluator_key})
    objects = {}

    class Store:
        def put_bytes(self, data, media_type):
            digest = "sha256:" + hashlib.sha256(data).hexdigest()
            objects[digest] = data
            return SimpleNamespace(digest=digest)

    image = RuntimeImageAuthority(
        logical_ref="sha256:" + "1" * 64,
        backend="docker",
        expected_runtime_image_id="sha256:" + "2" * 64,
    )
    runtime = RuntimeImageAttestation(
        logical_ref=image.logical_ref,
        backend=image.backend,
        observed_runtime_image_id=image.expected_runtime_image_id,
        runtime_authority_digest=image.digest(),
    )
    calls = []

    def worker(command, *, check, timeout, env, stdout, stderr):
        calls.append(command)
        assert check is True and timeout == 300
        assert stdout == subprocess.DEVNULL and stderr == subprocess.DEVNULL
        assert env["XEUS_CYBERGYM_EVALUATOR_CONFIG"] == str(config)
        assert "ANTHROPIC_API_KEY" not in env
        request_path = Path(command[command.index("--request") + 1])
        result_path = Path(command[command.index("--result") + 1])
        request = EvaluationRequest.model_validate_json(
            kernel_verifier.verify(SignedEnvelope.model_validate_json(request_path.read_bytes()))
        )
        bundle = kernel_verifier.verify(
            SignedEnvelope.model_validate_json(objects[request.signed_submission_ref])
        )
        assert request.submission_bundle_digest == "sha256:" + hashlib.sha256(bundle).hexdigest()
        assert objects["sha256:" + lock.sha256] == poc.read_bytes()
        result = EvaluationResult(
            evaluation_id=uuid4(),
            task_digest=request.task_digest,
            evaluator_binding_digest=request.evaluator_binding_digest,
            submission_bundle_digest=request.submission_bundle_digest,
            verdict=EvaluationVerdict.SOLVED,
            evaluator_digest="sha256:" + "6" * 64,
            vulnerable_runtime_image=runtime,
            fixed_runtime_image=runtime,
            vulnerable_execution_ref="artifact:vulnerable",
            fixed_execution_ref="artifact:fixed",
            oracle_classification="verified crash",
            replay_id=uuid4(),
            replay_bundle_ref="sha256:" + "7" * 64,
            completed_at=datetime.now(UTC),
            official_vul_exit_code=42,
            official_fix_exit_code=0,
            official_scoring_form=OfficialScoringForm.EFFECTIVE,
            official_solved=True,
        )
        result_path.write_bytes(canonical_json(evaluator_signer.sign(canonical_json(result))))
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    config = tmp_path / "evaluator-config.json"
    config.write_bytes(b'{"private":"test-only"}')
    execution = ExecutionTuple(
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
    )
    dispatch = NativeEvaluatorDispatch(
        task_id="arvo:1",
        task_digest="sha256:" + "3" * 64,
        binding_digest="sha256:" + "5" * 64,
        scoring_policy_digest="sha256:" + "a" * 64,
        execution=execution,
        submission_file_path="poc",
        evidence_dir=tmp_path,
        artifact_store=Store(),
        kernel_signer=kernel_signer,
        kernel_verifier=kernel_verifier,
        evaluator_verifier=evaluator_verifier,
        evaluator_config=config,
        evaluator_config_sha256=hashlib.sha256(config.read_bytes()).hexdigest(),
        python_executable=Path(sys.executable),
        worker_env={"PATH": "/usr/bin:/bin"},
        run_worker=worker,
    )
    with pytest.raises(RuntimeError, match="stopped"):
        dispatch.evaluate(lock, solver_stopped=lambda: False)
    assert not objects and not calls
    assert not (tmp_path / "evaluation-request.signed.json").exists()
    first = dispatch.evaluate(lock, solver_stopped=lambda: True)
    assert first.frozen_bundle
    assert first.signed_request and first.signed_result
    controller_signer, controller_key = _signer("controller")
    receipt = NativeTerminalReceiptPublisher(
        run_id="run-1",
        epoch="epoch-1",
        task_id="arvo:1",
        task_digest="sha256:" + "3" * 64,
        submission_file_path="poc",
        evidence_dir=tmp_path,
        kernel_verifier=kernel_verifier,
        evaluator_verifier=evaluator_verifier,
        controller_signer=controller_signer,
        controller_verifier=Ed25519Verifier({"controller": controller_key}),
    ).publish_oracle(
        lock=lock,
        signed_request=first.signed_request,
        signed_result=first.signed_result,
        frozen_bundle=first.frozen_bundle,
        solver_stopped=lambda: True,
    )
    assert receipt == (tmp_path / "terminal-receipt.signed.json").read_bytes()
    assert dispatch.evaluate(lock, solver_stopped=lambda: True) == first
    assert len(calls) == 1
    (tmp_path / "evaluation-result.signed.json").unlink()
    with pytest.raises(RuntimeError, match="ambiguous"):
        dispatch.evaluate(lock, solver_stopped=lambda: True)
    assert len(calls) == 1


@pytest.mark.skipif(os.name != "posix", reason="Xeus local evaluator needs POSIX sandbox")
def test_dispatch_calls_real_xeus_worker_and_publishes_signed_verdict(tmp_path: Path):
    """Exercise the exact subprocess protocol against a harmless synthetic target."""
    import base64

    from nooa_cybergym.leaderboard.native_evaluator_dispatch import NativeEvaluatorDispatch
    from nooa_cybergym.leaderboard.native_task_executor import NativeTerminalReceiptPublisher

    task_id = "synthetic:worker-dispatch"
    poc_bytes = b"TRIGGER"
    final = tmp_path / "final"
    final.mkdir()
    poc = final / "poc"
    poc.write_bytes(poc_bytes)
    declaration = final / "agent-final.json"
    declared = {
        "schema_version": 1,
        "task_id": task_id,
        "candidate_path": "/workspace/output/poc",
        "sha256": hashlib.sha256(poc_bytes).hexdigest(),
        "byte_length": len(poc_bytes),
        "selected_at": datetime.now(UTC).isoformat(),
        "selection_reason": "selected harmless test input",
        "final_declaration": True,
        "selected_by": "glm_parent",
    }
    declaration.write_bytes(canonical_json(declared))
    lock = FinalLock(
        task_id=task_id,
        sha256=declared["sha256"],
        byte_length=len(poc_bytes),
        poc_path=poc,
        declaration_path=declaration,
        declaration=declared,
        parent_event_digest="8" * 64,
    )
    kernel_signer, kernel_key = _signer("kernel")
    evaluator_private = Ed25519PrivateKey.generate()
    evaluator_key = evaluator_private.public_key()
    kernel_verifier = Ed25519Verifier({"kernel": kernel_key})
    evaluator_verifier = Ed25519Verifier({"evaluator": evaluator_key})
    store_root = tmp_path / "objects"
    store = ArtifactStore(store_root)
    task_digest = "sha256:" + hashlib.sha256(b"synthetic task manifest").hexdigest()
    vulnerable_ref = "sha256:" + hashlib.sha256(b"vulnerable image").hexdigest()
    fixed_ref = "sha256:" + hashlib.sha256(b"fixed image").hexdigest()
    vulnerable_authority = RuntimeImageAuthority(
        logical_ref=vulnerable_ref, backend="local", expected_runtime_image_id=None
    )
    fixed_authority = RuntimeImageAuthority(
        logical_ref=fixed_ref, backend="local", expected_runtime_image_id=None
    )
    binding = EvaluatorTaskBinding(
        task_digest=task_digest,
        vulnerable_image_ref=vulnerable_ref,
        fixed_image_ref=fixed_ref,
        vulnerable_runtime_authority_digest=vulnerable_authority.digest(),
        fixed_runtime_authority_digest=fixed_authority.digest(),
        target_oracle=TargetOracle(
            allowed_sanitizers=("fixture",),
            expected_signal=86,
            required_frame_matchers=("vulnerable_entry",),
            minimum_matching_frames=1,
        ),
        repeat_count=3,
        required_match_threshold=3,
    )
    binding_digest = binding.binding_digest()
    registry = tmp_path / "bindings.json"
    registry.write_text(json.dumps({binding_digest: binding.model_dump(mode="json")}))
    vulnerable = tmp_path / "vulnerable_target.py"
    vulnerable.write_text(
        "import json,sys\nfrom pathlib import Path\n"
        "data=Path(sys.argv[1]).read_bytes()\n"
        "if data==b'TRIGGER':\n"
        " print(json.dumps({'sanitizer':'fixture','signal':86,'frames':"
        "[{'module':'target.py','function':'vulnerable_entry','source_suffix':'target.py'}]}))\n"
        " sys.exit(86)\n"
    )
    fixed = tmp_path / "fixed_target.py"
    fixed.write_text("import sys\nfrom pathlib import Path\nPath(sys.argv[1]).read_bytes()\n")
    sandboxes = tmp_path / "sandboxes"
    sandboxes.mkdir()
    config = tmp_path / "evaluator-config.json"
    config.write_text(
        json.dumps(
            {
                "artifact_store_root": str(store_root),
                "binding_registry_path": str(registry),
                "evaluator_digest": "sha256:" + hashlib.sha256(b"evaluator").hexdigest(),
                "evaluator_signing_key": {
                    "key_id": "evaluator",
                    "seed_b64": base64.b64encode(evaluator_private.private_bytes_raw()).decode(),
                },
                "kernel_public_keys": {
                    "kernel": base64.b64encode(kernel_key.public_bytes_raw()).decode(),
                },
                "backend": "local",
                "runtime_images": {
                    vulnerable_ref: vulnerable_authority.model_dump(mode="json"),
                    fixed_ref: fixed_authority.model_dump(mode="json"),
                },
                "image_targets": {vulnerable_ref: str(vulnerable), fixed_ref: str(fixed)},
                "sandbox_base_dir": str(sandboxes),
            }
        )
    )
    execution = ExecutionTuple(
        entrypoint="poc",
        working_directory=".",
        argv=("poc",),
        allowed_environment=(),
        harness_profile_digest="sha256:" + "9" * 64,
        dependency_artifact_digests=(),
        execution_limits=ExecutionLimits(
            timeout_seconds=15,
            cpu_seconds=5,
            memory_bytes=1 << 29,
            output_bytes=1 << 20,
            repeat_count=3,
        ),
    )
    dispatch = NativeEvaluatorDispatch(
        task_id=task_id,
        task_digest=task_digest,
        binding_digest=binding_digest,
        scoring_policy_digest="sha256:" + "a" * 64,
        execution=execution,
        submission_file_path="poc",
        evidence_dir=tmp_path,
        artifact_store=store,
        kernel_signer=kernel_signer,
        kernel_verifier=kernel_verifier,
        evaluator_verifier=evaluator_verifier,
        evaluator_config=config,
        evaluator_config_sha256=hashlib.sha256(config.read_bytes()).hexdigest(),
        python_executable=Path(sys.executable),
        worker_env={
            key: value
            for key, value in os.environ.items()
            if key in {"PATH", "HOME", "PYTHONPATH", "TMPDIR", "LANG", "LC_ALL"}
        },
    )
    evidence = dispatch.evaluate(lock, solver_stopped=lambda: True)
    result = EvaluationResult.model_validate_json(
        evaluator_verifier.verify(SignedEnvelope.model_validate_json(evidence.signed_result))
    )
    assert result.verdict is EvaluationVerdict.SOLVED
    assert result.official_solved is True
    assert dispatch.evaluate(lock, solver_stopped=lambda: True) == evidence
    controller_signer, controller_key = _signer("controller")
    receipt = NativeTerminalReceiptPublisher(
        run_id="synthetic-run",
        epoch="synthetic-epoch",
        task_id=task_id,
        task_digest=task_digest,
        submission_file_path="poc",
        evidence_dir=tmp_path,
        kernel_verifier=kernel_verifier,
        evaluator_verifier=evaluator_verifier,
        controller_signer=controller_signer,
        controller_verifier=Ed25519Verifier({"controller": controller_key}),
    ).publish_oracle(
        lock=lock,
        signed_request=evidence.signed_request,
        signed_result=evidence.signed_result,
        frozen_bundle=evidence.frozen_bundle,
        solver_stopped=lambda: True,
    )
    assert receipt == (tmp_path / "terminal-receipt.signed.json").read_bytes()
