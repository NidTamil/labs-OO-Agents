# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""One-shot Xeus evaluator dispatch for a stopped native parent's locked PoC."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from uuid import uuid4

from xeus_cybergym.canonical import canonical_json
from xeus_cybergym.contracts import EvaluationRequest, EvaluationResult
from xeus_cybergym.contracts.artifacts import ExecutionTuple, SubmissionBundle, SubmissionFile

from .finalize import FinalLock
from .native_task_executor import _bytes, _locked_final, _verified

_DIGEST = re.compile(r"sha256:[a-f0-9]{64}\Z")
_HASH = re.compile(r"[a-f0-9]{64}\Z")
_SAFE_ENV = frozenset({"PATH", "HOME", "PYTHONPATH", "TMPDIR", "LANG", "LC_ALL"})


@dataclass(frozen=True, slots=True)
class NativeEvaluationEvidence:
    frozen_bundle: bytes = field(repr=False)
    signed_request: bytes = field(repr=False)
    signed_result: bytes = field(repr=False)


class NativeEvaluatorDispatch:
    """Store one PoC, sign its frozen bundle, and invoke the isolated worker once.

    A durable signed request precedes process dispatch. If the process outcome
    is ambiguous, recovery may read a matching signed result but never runs the
    worker again. The private evaluator config stays outside the solver.
    """

    def __init__(
        self,
        *,
        task_id: str,
        task_digest: str,
        binding_digest: str,
        scoring_policy_digest: str,
        execution: ExecutionTuple,
        submission_file_path: str,
        evidence_dir: Path,
        artifact_store,
        kernel_signer,
        kernel_verifier,
        evaluator_verifier,
        evaluator_config: Path,
        evaluator_config_sha256: str,
        python_executable: Path,
        worker_env: Mapping[str, str],
        run_worker=subprocess.run,
    ):
        evidence = Path(evidence_dir)
        config = Path(evaluator_config)
        python = Path(python_executable)
        if (
            type(task_id) is not str
            or not task_id
            or any(
                type(value) is not str or _DIGEST.fullmatch(value) is None
                for value in (task_digest, binding_digest, scoring_policy_digest)
            )
            or type(execution) is not ExecutionTuple
            or type(submission_file_path) is not str
            or submission_file_path != execution.entrypoint
            or not evidence.is_absolute()
            or evidence.is_symlink()
            or not evidence.is_dir()
            or evidence.resolve() != evidence
            or not config.is_absolute()
            or config.is_symlink()
            or not config.is_file()
            or type(evaluator_config_sha256) is not str
            or _HASH.fullmatch(evaluator_config_sha256) is None
            or not python.is_absolute()
            or python.is_symlink()
            or not python.is_file()
            or not callable(getattr(artifact_store, "put_bytes", None))
            or not callable(getattr(kernel_signer, "sign", None))
            or not callable(getattr(kernel_verifier, "verify", None))
            or not callable(getattr(evaluator_verifier, "verify", None))
            or not isinstance(worker_env, Mapping)
            or any(
                type(key) is not str
                or key not in _SAFE_ENV
                or type(value) is not str
                or "\x00" in value
                for key, value in worker_env.items()
            )
            or not callable(run_worker)
        ):
            raise ValueError("frozen private native evaluator dispatch inputs required")
        self.task_id = task_id
        self.task_digest = task_digest
        self.binding_digest = binding_digest
        self.scoring_policy_digest = scoring_policy_digest
        self.execution = execution
        self.submission_file_path = submission_file_path
        self.evidence = evidence
        self.store = artifact_store
        self.kernel_signer = kernel_signer
        self.kernel_verifier = kernel_verifier
        self.evaluator_verifier = evaluator_verifier
        self.config = config
        self.config_sha256 = evaluator_config_sha256
        self.python = python
        self.worker_env = dict(worker_env)
        self.run_worker = run_worker

    def _write_once(self, target: Path, raw: bytes) -> None:
        with target.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name == "posix":
            directory = os.open(self.evidence, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)

    def _durable_result(self, result_path: Path) -> bytes:
        raw = _bytes(result_path, "signed evaluation result")
        # Windows requires a writable descriptor for FlushFileBuffers/fsync.
        mode = "r+b" if os.name == "nt" else "rb"
        with result_path.open(mode) as stream:
            os.fsync(stream.fileno())
        if os.name == "posix":
            directory = os.open(self.evidence, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        return raw

    def evaluate(
        self, lock: FinalLock, *, solver_stopped: Callable[[], bool]
    ) -> NativeEvaluationEvidence:
        candidate, _declaration = _locked_final(self.evidence, self.task_id, lock, solver_stopped)
        if (
            hashlib.sha256(_bytes(self.config, "private evaluator config")).hexdigest()
            != self.config_sha256
        ):
            raise RuntimeError("private evaluator config differs from frozen digest")
        candidate_ref = self.store.put_bytes(candidate, "application/octet-stream")
        if candidate_ref.digest != f"sha256:{lock.sha256}":
            raise RuntimeError("Xeus candidate artifact store identity differs")
        bundle = SubmissionBundle(
            files=(
                SubmissionFile(
                    path=self.submission_file_path,
                    digest=candidate_ref.digest,
                    size_bytes=len(candidate),
                    media_type="application/octet-stream",
                ),
            ),
            execution=self.execution,
            task_digest=self.task_digest,
            scoring_policy_digest=self.scoring_policy_digest,
        )
        bundle_raw = canonical_json(bundle)
        signed_bundle = self.kernel_signer.sign(bundle_raw)
        if self.kernel_verifier.verify(signed_bundle) != bundle_raw:
            raise RuntimeError("frozen submission signature failed self-verification")
        signed_bundle_raw = canonical_json(signed_bundle)
        submission_ref = self.store.put_bytes(
            signed_bundle_raw,
            "application/vnd.xeus.cybergym.signed-submission-bundle+json",
        )
        if submission_ref.digest != "sha256:" + hashlib.sha256(signed_bundle_raw).hexdigest():
            raise RuntimeError("Xeus signed submission artifact identity differs")

        request_path = self.evidence / "evaluation-request.signed.json"
        result_path = self.evidence / "evaluation-result.signed.json"
        if request_path.exists() or request_path.is_symlink():
            signed_request = _bytes(request_path, "signed evaluation request")
            request = _verified(signed_request, self.kernel_verifier, EvaluationRequest)
            if (
                request.task_digest != self.task_digest
                or request.evaluator_binding_digest != self.binding_digest
                or request.submission_bundle_digest != bundle.digest()
                or request.signed_submission_ref != submission_ref.digest
            ):
                raise RuntimeError("durable evaluation request differs from frozen final")
            if result_path.is_symlink() or not result_path.is_file():
                raise RuntimeError("evaluation outcome ambiguous; never redispatch")
            signed_result = self._durable_result(result_path)
            self._check_result(signed_result, request)
            return NativeEvaluationEvidence(bundle_raw, signed_request, signed_result)
        if result_path.exists() or result_path.is_symlink():
            raise RuntimeError("evaluation result exists without a durable request")

        request = EvaluationRequest(
            evaluation_request_id=uuid4(),
            task_digest=self.task_digest,
            evaluator_binding_digest=self.binding_digest,
            submission_bundle_digest=bundle.digest(),
            signed_submission_ref=submission_ref.digest,
        )
        signed_request = canonical_json(self.kernel_signer.sign(canonical_json(request)))
        if _verified(signed_request, self.kernel_verifier, EvaluationRequest) != request:
            raise RuntimeError("evaluation request signature failed self-verification")
        try:
            self._write_once(request_path, signed_request)
        except FileExistsError:
            raise RuntimeError(
                "evaluation request concurrently reserved; never redispatch"
            ) from None
        environment = dict(self.worker_env)
        environment["XEUS_CYBERGYM_EVALUATOR_CONFIG"] = str(self.config)
        self.run_worker(
            [
                str(self.python),
                "-m",
                "xeus_cybergym.evaluator.worker",
                "--request",
                str(request_path),
                "--result",
                str(result_path),
            ],
            check=True,
            timeout=300,
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        signed_result = self._durable_result(result_path)
        self._check_result(signed_result, request)
        return NativeEvaluationEvidence(bundle_raw, signed_request, signed_result)

    def _check_result(self, signed_result: bytes, request: EvaluationRequest) -> None:
        result = _verified(signed_result, self.evaluator_verifier, EvaluationResult)
        if (
            result.task_digest != request.task_digest
            or result.evaluator_binding_digest != request.evaluator_binding_digest
            or result.submission_bundle_digest != request.submission_bundle_digest
        ):
            raise RuntimeError("signed evaluator result differs from durable request")
