# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Controller-only signed terminal receipts from a locked final and real evaluator."""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

from xeus_cybergym.canonical import canonical_json
from xeus_cybergym.contracts import EvaluationRequest, EvaluationResult
from xeus_cybergym.contracts.artifacts import SubmissionBundle
from xeus_cybergym.ledger import SignedEnvelope

from .finalize import FinalLock

_HEX = re.compile(r"[a-f0-9]{64}\Z")


def _bytes(path: Path, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"{label} is missing or linked")
    value = path.read_bytes()
    if len(value) > 16 * 1024 * 1024:
        raise RuntimeError(f"{label} exceeds controller evidence limit")
    return value


def _verified(envelope: bytes, verifier, contract):
    if type(envelope) is not bytes or not 0 < len(envelope) <= 1024 * 1024:
        raise ValueError("bounded signed evaluator artifact required")
    payload = verifier.verify(SignedEnvelope.model_validate_json(envelope))
    value = contract.model_validate_json(payload)
    if canonical_json(value) != payload:
        raise ValueError("signed evaluator artifact is not canonical")
    return value


class NativeTerminalReceiptPublisher:
    """Publish at most one Xeus campaign receipt from attested evaluator bytes."""

    def __init__(
        self,
        *,
        run_id: str,
        epoch: str,
        task_id: str,
        task_digest: str,
        submission_file_path: str,
        evidence_dir: Path,
        kernel_verifier,
        evaluator_verifier,
        controller_signer,
        controller_verifier,
    ):
        root = Path(evidence_dir)
        if (
            any(type(value) is not str or not value for value in (run_id, epoch, task_id))
            or type(task_digest) is not str
            or re.fullmatch(r"sha256:[a-f0-9]{64}", task_digest) is None
            or type(submission_file_path) is not str
            or not submission_file_path
            or not root.is_absolute()
            or root.is_symlink()
            or not root.is_dir()
            or root.resolve() != root
            or any(
                not callable(getattr(value, name, None))
                for value, name in (
                    (kernel_verifier, "verify"),
                    (evaluator_verifier, "verify"),
                    (controller_signer, "sign"),
                    (controller_verifier, "verify"),
                )
            )
        ):
            raise ValueError("trusted native terminal receipt inputs required")
        self.run_id, self.epoch, self.task_id, self.task_digest = (
            run_id,
            epoch,
            task_id,
            task_digest,
        )
        self.submission_file_path = submission_file_path
        self.evidence_dir = root
        self.kernel_verifier = kernel_verifier
        self.evaluator_verifier = evaluator_verifier
        self.controller_signer = controller_signer
        self.controller_verifier = controller_verifier

    def _store(self, payload: dict) -> bytes:
        expected = canonical_json(payload)
        target = self.evidence_dir / "terminal-receipt.signed.json"
        if target.exists() or target.is_symlink():
            existing = _bytes(target, "terminal receipt")
            observed = self.controller_verifier.verify(SignedEnvelope.model_validate_json(existing))
            if observed != expected:
                raise RuntimeError("terminal receipt differs from settled evaluator evidence")
            return existing
        envelope = self.controller_signer.sign(expected)
        if self.controller_verifier.verify(envelope) != expected:
            raise RuntimeError("terminal receipt signature failed self-verification")
        raw = canonical_json(envelope.model_dump())
        if len(raw) > 65536:
            raise RuntimeError("signed terminal receipt exceeds campaign limit")
        try:
            with target.open("xb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        except FileExistsError:
            return self._store(payload)
        if os.name == "posix":
            descriptor = os.open(self.evidence_dir, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        return raw

    def publish_oracle(
        self,
        *,
        lock: FinalLock,
        signed_request: bytes,
        signed_result: bytes,
        frozen_bundle: bytes,
    ) -> bytes:
        if type(lock) is not FinalLock or lock.task_id != self.task_id:
            raise ValueError("matching stopped parent final lock required")
        candidate = _bytes(lock.poc_path, "locked final candidate")
        declaration = _bytes(lock.declaration_path, "parent final declaration")
        if (
            len(candidate) != lock.byte_length
            or hashlib.sha256(candidate).hexdigest() != lock.sha256
            or type(lock.parent_event_digest) is not str
            or _HEX.fullmatch(lock.parent_event_digest) is None
        ):
            raise RuntimeError("locked parent final changed")
        request = _verified(signed_request, self.kernel_verifier, EvaluationRequest)
        result = _verified(signed_result, self.evaluator_verifier, EvaluationResult)
        if type(frozen_bundle) is not bytes or not 0 < len(frozen_bundle) <= 16 * 1024 * 1024:
            raise ValueError("bounded frozen submission bundle required")
        bundle = SubmissionBundle.model_validate_json(frozen_bundle)
        if canonical_json(bundle) != frozen_bundle:
            raise ValueError("frozen submission bundle is not canonical")
        matching = tuple(file for file in bundle.files if file.path == self.submission_file_path)
        if (
            request.task_digest != self.task_digest
            or result.task_digest != self.task_digest
            or bundle.task_digest != self.task_digest
            or bundle.digest() != request.submission_bundle_digest
            or len(matching) != 1
            or matching[0].digest != f"sha256:{lock.sha256}"
            or matching[0].size_bytes != len(candidate)
            or request.evaluator_binding_digest != result.evaluator_binding_digest
            or request.submission_bundle_digest != result.submission_bundle_digest
        ):
            raise RuntimeError("evaluator request and verdict differ from frozen task")
        oracle_true = result.official_solved
        payload = {
            "schema_version": 1,
            "artifact_kind": "terminal_receipt",
            "run_id": self.run_id,
            "epoch": self.epoch,
            "task_id": self.task_id,
            "status": "oracle_true" if oracle_true else "oracle_false",
            "final_sha256": lock.sha256,
            "final_declaration_sha256": hashlib.sha256(declaration).hexdigest(),
            "parent_event_digest": lock.parent_event_digest,
            "oracle_request_sha256": hashlib.sha256(signed_request).hexdigest(),
            "oracle_verdict_sha256": hashlib.sha256(signed_result).hexdigest(),
            "oracle_true": oracle_true,
        }
        return self._store(payload)

    def publish_failure(self, *, status: str, evidence_path: Path) -> bytes:
        """Sign a real controller failure record without claiming an oracle result."""
        path = Path(evidence_path)
        if (
            status not in {"timeout", "failure"}
            or not path.is_absolute()
            or path.is_symlink()
            or not path.resolve().is_relative_to(self.evidence_dir)
            or path.name == "terminal-receipt.signed.json"
        ):
            raise ValueError("trusted controller failure evidence required")
        evidence = _bytes(path, "controller failure evidence")
        payload = {
            "schema_version": 1,
            "artifact_kind": "terminal_receipt",
            "run_id": self.run_id,
            "epoch": self.epoch,
            "task_id": self.task_id,
            "status": status,
            "evidence_sha256": hashlib.sha256(evidence).hexdigest(),
        }
        return self._store(payload)
