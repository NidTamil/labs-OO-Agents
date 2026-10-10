# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""One-shot signed practice evaluator for the official ARVO raw exit rule.

These are controller-only practice records, not Xeus evaluator certification.
The private fixed image is opened only after the native solver has stopped.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

from xeus_cybergym.canonical import canonical_json
from xeus_cybergym.ledger import SignedEnvelope

from .finalize import FinalLock
from .native_task_executor import _locked_final
from .practice_arvo_runner import official_raw_solved, run_arvo_image

_IMAGE = re.compile(r"sha256:[a-f0-9]{64}\Z")
_HASH = re.compile(r"[a-f0-9]{64}\Z")
_MAX_SIGNED = 1024 * 1024


def _read_signed(path: Path, verifier) -> tuple[bytes, dict]:
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= _MAX_SIGNED:
        raise RuntimeError("bounded signed practice record required")
    raw = path.read_bytes()
    if not 0 < len(raw) <= _MAX_SIGNED:
        raise RuntimeError("bounded signed practice record required")
    envelope = SignedEnvelope.model_validate_json(raw)
    if canonical_json(envelope.model_dump()) != raw:
        raise RuntimeError("noncanonical signed practice envelope")
    payload = verifier.verify(envelope)
    value = json.loads(payload)
    if type(value) is not dict or canonical_json(value) != payload:
        raise RuntimeError("noncanonical signed practice payload")
    return raw, value


def _write_signed_once(path: Path, value: dict, signer, verifier) -> bytes:
    payload = canonical_json(value)
    envelope = signer.sign(payload)
    if verifier.verify(envelope) != payload:
        raise RuntimeError("practice signature failed self-verification")
    raw = canonical_json(envelope.model_dump())
    if len(raw) > _MAX_SIGNED:
        raise RuntimeError("signed practice record exceeds limit")
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    if os.name == "posix":
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    return raw


class PracticeArvoEvaluator:
    """Evaluate one stopped parent final; a durable request forbids redispatch."""

    def __init__(
        self,
        *,
        run_id: str,
        epoch: str,
        task_id: str,
        evidence_dir: Path,
        vulnerable_image_id: str,
        fixed_image_id: str,
        official_verifier_source: Path,
        official_verifier_sha256: str,
        docker_client,
        controller_signer,
        controller_verifier,
        evaluator_signer,
        evaluator_verifier,
    ):
        evidence = Path(evidence_dir)
        official_source = Path(official_verifier_source)
        if (
            any(type(value) is not str or not value for value in (run_id, epoch, task_id))
            or any(
                type(value) is not str or _IMAGE.fullmatch(value) is None
                for value in (vulnerable_image_id, fixed_image_id)
            )
            or vulnerable_image_id == fixed_image_id
            or type(official_verifier_sha256) is not str
            or _HASH.fullmatch(official_verifier_sha256) is None
            or not official_source.is_absolute()
            or official_source.is_symlink()
            or not official_source.is_file()
            or official_source.stat().st_size > 1024 * 1024
            or hashlib.sha256(official_source.read_bytes()).hexdigest() != official_verifier_sha256
            or not evidence.is_absolute()
            or evidence.is_symlink()
            or not evidence.is_dir()
            or evidence.resolve() != evidence
            or any(
                not callable(getattr(value, name, None))
                for value, name in (
                    (controller_signer, "sign"),
                    (controller_verifier, "verify"),
                    (evaluator_signer, "sign"),
                    (evaluator_verifier, "verify"),
                )
            )
        ):
            raise ValueError("frozen private practice evaluator inputs required")
        self.run_id, self.epoch, self.task_id = run_id, epoch, task_id
        self.evidence = evidence
        self.vulnerable_image_id, self.fixed_image_id = vulnerable_image_id, fixed_image_id
        self.official_verifier_source = official_source
        self.official_verifier_sha256 = official_verifier_sha256
        self.docker_client = docker_client
        self.controller_signer, self.controller_verifier = controller_signer, controller_verifier
        self.evaluator_signer, self.evaluator_verifier = evaluator_signer, evaluator_verifier

    def evaluate(self, lock: FinalLock, *, solver_stopped) -> bytes:
        candidate, declaration = _locked_final(self.evidence, self.task_id, lock, solver_stopped)
        if (
            self.official_verifier_source.is_symlink()
            or not self.official_verifier_source.is_file()
            or self.official_verifier_source.stat().st_size > 1024 * 1024
            or hashlib.sha256(self.official_verifier_source.read_bytes()).hexdigest()
            != self.official_verifier_sha256
        ):
            raise RuntimeError("official verifier source differs from frozen digest")
        request_value = {
            "schema_version": 1,
            "artifact_kind": "practice_arvo_evaluation_request",
            "run_id": self.run_id,
            "epoch": self.epoch,
            "task_id": self.task_id,
            "final_sha256": lock.sha256,
            "final_declaration_sha256": hashlib.sha256(declaration).hexdigest(),
            "parent_event_digest": lock.parent_event_digest,
            "vulnerable_image_id": self.vulnerable_image_id,
            "fixed_image_id": self.fixed_image_id,
            "official_verifier_sha256": self.official_verifier_sha256,
        }
        request_path = self.evidence / "practice-evaluation-request.signed.json"
        result_path = self.evidence / "practice-evaluation-result.signed.json"
        terminal_path = self.evidence / "terminal-receipt.signed.json"
        if request_path.exists() or request_path.is_symlink():
            request_raw, verified_request = _read_signed(request_path, self.controller_verifier)
            if verified_request != request_value:
                raise RuntimeError("durable practice request differs from locked final")
            if not result_path.is_file() or result_path.is_symlink():
                raise RuntimeError("practice evaluation outcome ambiguous; never redispatch")
            result_raw, result_value = _read_signed(result_path, self.evaluator_verifier)
        else:
            if result_path.exists() or result_path.is_symlink():
                raise RuntimeError("practice result exists without durable request")
            request_raw = _write_signed_once(
                request_path, request_value, self.controller_signer, self.controller_verifier
            )
            snapshot_dir = self.evidence / "practice-arvo-snapshots"
            snapshot_dir.mkdir(mode=0o700, exist_ok=False)
            vulnerable = run_arvo_image(
                self.docker_client,
                image_id=self.vulnerable_image_id,
                candidate=lock.poc_path,
                snapshot_dir=snapshot_dir,
                expected_sha256=lock.sha256,
            )
            fixed = run_arvo_image(
                self.docker_client,
                image_id=self.fixed_image_id,
                candidate=lock.poc_path,
                snapshot_dir=snapshot_dir,
                expected_sha256=lock.sha256,
            )
            _locked_final(self.evidence, self.task_id, lock, solver_stopped)
            result_value = {
                "schema_version": 1,
                "artifact_kind": "practice_arvo_evaluation_result",
                "run_id": self.run_id,
                "epoch": self.epoch,
                "task_id": self.task_id,
                "request_sha256": hashlib.sha256(request_raw).hexdigest(),
                "vulnerable": vulnerable,
                "fixed": fixed,
                "official_scoring_form": "raw",
                "official_solved": official_raw_solved(
                    vulnerable["raw_exit_code"], fixed["raw_exit_code"]
                ),
            }
            result_raw = _write_signed_once(
                result_path, result_value, self.evaluator_signer, self.evaluator_verifier
            )
        if (
            set(result_value)
            != {
                "schema_version",
                "artifact_kind",
                "run_id",
                "epoch",
                "task_id",
                "request_sha256",
                "vulnerable",
                "fixed",
                "official_scoring_form",
                "official_solved",
            }
            or result_value["schema_version"] != 1
            or result_value["artifact_kind"] != "practice_arvo_evaluation_result"
            or result_value["run_id"] != self.run_id
            or result_value["epoch"] != self.epoch
            or result_value["task_id"] != self.task_id
            or result_value["request_sha256"] != hashlib.sha256(request_raw).hexdigest()
            or result_value["official_scoring_form"] != "raw"
            or result_value["vulnerable"].get("image_id") != self.vulnerable_image_id
            or result_value["fixed"].get("image_id") != self.fixed_image_id
            or result_value["vulnerable"].get("candidate_sha256") != lock.sha256
            or result_value["fixed"].get("candidate_sha256") != lock.sha256
            or result_value["official_solved"]
            is not official_raw_solved(
                result_value["vulnerable"]["raw_exit_code"],
                result_value["fixed"]["raw_exit_code"],
            )
        ):
            raise RuntimeError("signed practice result differs from official raw observations")
        terminal = {
            "schema_version": 1,
            "artifact_kind": "terminal_receipt",
            "run_id": self.run_id,
            "epoch": self.epoch,
            "task_id": self.task_id,
            "status": "oracle_true" if result_value["official_solved"] else "oracle_false",
            "final_sha256": lock.sha256,
            "final_declaration_sha256": hashlib.sha256(declaration).hexdigest(),
            "parent_event_digest": lock.parent_event_digest,
            "oracle_request_sha256": hashlib.sha256(request_raw).hexdigest(),
            "oracle_verdict_sha256": hashlib.sha256(result_raw).hexdigest(),
            "oracle_true": result_value["official_solved"],
        }
        if terminal_path.exists() or terminal_path.is_symlink():
            terminal_raw, verified_terminal = _read_signed(terminal_path, self.controller_verifier)
            if verified_terminal != terminal:
                raise RuntimeError("signed terminal receipt differs from practice evaluation")
            return terminal_raw
        return _write_signed_once(
            terminal_path, terminal, self.controller_signer, self.controller_verifier
        )
