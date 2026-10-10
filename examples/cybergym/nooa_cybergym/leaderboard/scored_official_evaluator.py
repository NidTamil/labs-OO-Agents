# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""One-shot scored oracle for a stopped, locked ARVO or OSS-Fuzz final.

The controller writes a signed request before opening either private image.
After an ambiguous dispatch it refuses to run either image again. Practice
records and their frozen filenames remain separate from this scored route.
"""

from __future__ import annotations

import hashlib
import re

from .finalize import FinalLock
from .native_task_executor import _locked_final
from .official_image_runner import run_official_image
from .practice_arvo_evaluator import (
    PracticeArvoEvaluator,
    _read_signed,
    _write_signed_once,
)
from .practice_arvo_runner import official_raw_solved

_TASK = re.compile(r"(?:arvo|oss-fuzz):[0-9]+\Z")


class ScoredOfficialEvaluator(PracticeArvoEvaluator):
    """Controller and evaluator signatures bind one official raw verdict."""

    def __init__(self, *, task_id: str, **kwargs):
        if type(task_id) is not str or _TASK.fullmatch(task_id) is None:
            raise ValueError("official scored task family required")
        super().__init__(task_id=task_id, **kwargs)

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
            "artifact_kind": "scored_official_evaluation_request",
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
        request_path = self.evidence / "scored-evaluation-request.signed.json"
        result_path = self.evidence / "scored-evaluation-result.signed.json"
        terminal_path = self.evidence / "terminal-receipt.signed.json"
        if request_path.exists() or request_path.is_symlink():
            request_raw, verified_request = _read_signed(request_path, self.controller_verifier)
            if verified_request != request_value:
                raise RuntimeError("durable scored request differs from locked final")
            if not result_path.is_file() or result_path.is_symlink():
                raise RuntimeError("scored evaluation outcome ambiguous; never redispatch")
            result_raw, result_value = _read_signed(result_path, self.evaluator_verifier)
        else:
            if terminal_path.exists() or terminal_path.is_symlink():
                raise RuntimeError("scored terminal exists without durable request")
            if result_path.exists() or result_path.is_symlink():
                raise RuntimeError("scored result exists without durable request")
            request_raw = _write_signed_once(
                request_path, request_value, self.controller_signer, self.controller_verifier
            )
            snapshot_dir = self.evidence / "scored-official-snapshots"
            snapshot_dir.mkdir(mode=0o700, exist_ok=False)
            vulnerable = run_official_image(
                self.docker_client,
                task_id=self.task_id,
                image_id=self.vulnerable_image_id,
                candidate=lock.poc_path,
                snapshot_dir=snapshot_dir,
                expected_sha256=lock.sha256,
            )
            fixed = run_official_image(
                self.docker_client,
                task_id=self.task_id,
                image_id=self.fixed_image_id,
                candidate=lock.poc_path,
                snapshot_dir=snapshot_dir,
                expected_sha256=lock.sha256,
            )
            _locked_final(self.evidence, self.task_id, lock, solver_stopped)
            result_value = {
                "schema_version": 1,
                "artifact_kind": "scored_official_evaluation_result",
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
            or result_value["artifact_kind"] != "scored_official_evaluation_result"
            or result_value["run_id"] != self.run_id
            or result_value["epoch"] != self.epoch
            or result_value["task_id"] != self.task_id
            or result_value["request_sha256"] != hashlib.sha256(request_raw).hexdigest()
            or result_value["official_scoring_form"] != "raw"
            or not all(
                type(result_value[name]) is dict
                and result_value[name].get("task_id") == self.task_id
                and result_value[name].get("image_id") == image_id
                and result_value[name].get("candidate_sha256") == lock.sha256
                and result_value[name].get("snapshot_sha256") == lock.sha256
                and result_value[name].get("network_disabled") is True
                for name, image_id in (
                    ("vulnerable", self.vulnerable_image_id),
                    ("fixed", self.fixed_image_id),
                )
            )
            or result_value["official_solved"]
            is not official_raw_solved(
                result_value["vulnerable"]["raw_exit_code"],
                result_value["fixed"]["raw_exit_code"],
            )
        ):
            raise RuntimeError("signed scored result differs from official raw observations")
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
                raise RuntimeError("signed terminal receipt differs from scored evaluation")
            return terminal_raw
        return _write_signed_once(
            terminal_path, terminal, self.controller_signer, self.controller_verifier
        )
