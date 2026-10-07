# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Controller-only signed terminal receipts from a locked final and real evaluator."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
from collections.abc import Callable, Mapping
from pathlib import Path

from xeus_cybergym.canonical import canonical_json
from xeus_cybergym.contracts import EvaluationRequest, EvaluationResult
from xeus_cybergym.contracts.artifacts import SubmissionBundle
from xeus_cybergym.ledger import SignedEnvelope

from .finalize import FinalLock, _validate_declaration

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


def _locked_final(
    evidence_dir: Path, task_id: str, lock: FinalLock, solver_stopped: Callable[[], bool]
) -> tuple[bytes, bytes]:
    """Recheck the stopped parent's exact immutable final before private use."""
    if type(lock) is not FinalLock or lock.task_id != task_id:
        raise ValueError("matching stopped parent final lock required")
    final = evidence_dir / "final"
    if (
        final.is_symlink()
        or not final.is_dir()
        or final.resolve() != final
        or lock.poc_path != final / "poc"
        or lock.declaration_path != final / "agent-final.json"
    ):
        raise ValueError("controller final custody path required")
    if not callable(solver_stopped) or solver_stopped() is not True:
        raise RuntimeError("native solver must be stopped before private final use")
    candidate = _bytes(lock.poc_path, "locked final candidate")
    declaration = _bytes(lock.declaration_path, "parent final declaration")
    declared = _validate_declaration(declaration, task_id)
    if (
        len(candidate) != lock.byte_length
        or hashlib.sha256(candidate).hexdigest() != lock.sha256
        or declared["sha256"] != lock.sha256
        or declared["byte_length"] != lock.byte_length
        or not isinstance(lock.declaration, Mapping)
        or declared != dict(lock.declaration)
        or type(lock.parent_event_digest) is not str
        or _HEX.fullmatch(lock.parent_event_digest) is None
    ):
        raise RuntimeError("locked parent final changed")
    return candidate, declaration


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
        solver_stopped: Callable[[], bool],
    ) -> bytes:
        candidate, declaration = _locked_final(
            self.evidence_dir, self.task_id, lock, solver_stopped
        )
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


class PowerShellNativeSubmitter:
    """Reserve one host-side Send attempt before invoking the pinned UI script.

    A failed or interrupted subprocess leaves the reservation in place. A later
    caller may inspect the gateway's first-model-request audit, but this class
    will never click Send again for the same native launch.
    """

    def __init__(
        self,
        *,
        launch_authority,
        script: Path,
        script_sha256: str,
        remote_alias: str,
        profile_directory: Path,
        audit_directory: Path,
        pwsh: str = "pwsh",
        run_command=subprocess.run,
    ):
        manifest = getattr(launch_authority, "manifest", None)
        launch_dir = Path(getattr(launch_authority, "launch_dir", ""))
        script = Path(script)
        profile = Path(profile_directory)
        audit = Path(audit_directory)
        if (
            type(manifest) is not dict
            or type(manifest.get("task_id")) is not str
            or type(manifest.get("launch_id")) is not str
            or not callable(getattr(launch_authority, "_check_receipt", None))
            or not launch_dir.is_absolute()
            or launch_dir.is_symlink()
            or not launch_dir.is_dir()
            or not script.is_absolute()
            or script.is_symlink()
            or not script.is_file()
            or type(script_sha256) is not str
            or _HEX.fullmatch(script_sha256) is None
            or type(remote_alias) is not str
            or re.fullmatch(r"[a-z][a-z0-9-]{1,63}", remote_alias) is None
            or not profile.is_absolute()
            or not audit.is_absolute()
            or audit.parent.is_symlink()
            or not audit.parent.is_dir()
            or not callable(run_command)
            or type(pwsh) is not str
            or not pwsh
        ):
            raise ValueError("frozen native host submission identity required")
        self.launch = launch_authority
        self.script = script
        self.script_sha256 = script_sha256
        self.remote_alias = remote_alias
        self.profile = profile
        self.audit = audit
        self.pwsh = pwsh
        self.run_command = run_command

    def submit_once(self, request_id: str) -> bool:
        """Return True only for this invocation's observed UI attempt."""
        if request_id != self.launch.manifest["launch_id"]:
            raise ValueError("campaign first-request identity differs from native launch")
        if (
            hashlib.sha256(_bytes(self.script, "native submit script")).hexdigest()
            != self.script_sha256
        ):
            raise RuntimeError("native submit script differs from frozen digest")
        receipt_path = self.launch.launch_dir / "launcher-receipt.json"
        raw = _bytes(receipt_path, "native launch receipt")
        receipt = json.loads(raw)
        if canonical_json(receipt) != raw:
            raise RuntimeError("native launch receipt is not canonical")
        self.launch._check_receipt(receipt)
        intent = canonical_json(
            {
                "schema_version": 1,
                "event": "ui_submit_intent",
                "task_id": self.launch.manifest["task_id"],
                "launch_id": request_id,
                "prompt_sha256": receipt["prompt_sha256"],
                "remote_alias": self.remote_alias,
                "script_sha256": self.script_sha256,
            }
        )
        target = self.launch.launch_dir / "ui-submit-intent.json"
        if target.exists() or target.is_symlink():
            if _bytes(target, "native UI submission intent") != intent:
                raise RuntimeError("native UI submission intent changed")
            return False
        if self.audit.exists() or self.audit.is_symlink():
            raise RuntimeError("unowned native UI audit directory already exists")
        try:
            with target.open("xb") as stream:
                stream.write(intent)
                stream.flush()
                os.fsync(stream.fileno())
        except FileExistsError:
            if _bytes(target, "native UI submission intent") != intent:
                raise RuntimeError("native UI submission intent changed") from None
            return False
        if os.name == "posix":
            directory = os.open(self.launch.launch_dir, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        self.run_command(
            [
                self.pwsh,
                "-NoProfile",
                "-File",
                str(self.script),
                "-RemoteAlias",
                self.remote_alias,
                "-ProfileDirectory",
                str(self.profile),
                "-ControllerReceipt",
                str(receipt_path),
                "-LaunchId",
                request_id,
                "-AuditDirectory",
                str(self.audit),
            ],
            check=True,
        )
        attempted = json.loads(_bytes(self.audit / "ui-send-attempted.json", "native UI attempt"))
        if (
            attempted.get("schema_version") != 1
            or attempted.get("event") != "ui_send_attempted"
            or attempted.get("launch_id") != request_id
            or attempted.get("prompt_sha256") != receipt["prompt_sha256"]
            or attempted.get("remote_alias") != self.remote_alias
            or attempted.get("provider_request_observed") is not False
        ):
            raise RuntimeError("native UI attempt disagrees with reserved launch")
        return True


class MailboxNativeSubmitter:
    """Correlate one signed outbound Send with the first native gateway admission.

    The campaign ledger's started intent must exist before publishing Send.
    The mailbox operation key is stable across controller restarts, while the
    Windows client reserves the actual click on disk before executing it. A
    failed/ambiguous acknowledgement never authorizes another click.
    """

    def __init__(
        self,
        *,
        launch_authority,
        mailbox,
        witness,
        remote_alias: str,
        started_intent: Callable[[str], bool],
        timeout_seconds: float = 120,
    ):
        manifest = getattr(launch_authority, "manifest", None)
        launch_dir = Path(getattr(launch_authority, "launch_dir", ""))
        if (
            type(manifest) is not dict
            or type(manifest.get("task_id")) is not str
            or type(manifest.get("launch_id")) is not str
            or not launch_dir.is_absolute()
            or launch_dir.is_symlink()
            or not launch_dir.is_dir()
            or not callable(getattr(launch_authority, "_check_receipt", None))
            or not callable(getattr(mailbox, "publish", None))
            or not callable(getattr(mailbox, "wait_ack", None))
            or not callable(getattr(witness, "observed", None))
            or type(remote_alias) is not str
            or re.fullmatch(r"[a-z][a-z0-9-]{1,63}", remote_alias) is None
            or not callable(started_intent)
            or type(timeout_seconds) not in {int, float}
            or not 0 < timeout_seconds <= 600
        ):
            raise ValueError("frozen outbound native submission identity required")
        if manifest.get("run_id", mailbox.run_id) != mailbox.run_id:
            raise ValueError("mailbox run differs from native launch")
        self.launch = launch_authority
        self.mailbox = mailbox
        self.witness = witness
        self.remote_alias = remote_alias
        self.started_intent = started_intent
        self.timeout = timeout_seconds

    def submit_once(self, request_id: str) -> bool:
        if request_id != self.launch.manifest["launch_id"]:
            raise ValueError("campaign launch identity differs from native launch")
        if self.started_intent(request_id) is not True:
            raise RuntimeError("verified campaign started intent required before native Send")
        if self.witness.observed(request_id):
            return True
        deadline = time.monotonic() + self.timeout
        receipt_path = self.launch.launch_dir / "launcher-receipt.json"
        while not receipt_path.exists() and time.monotonic() < deadline:
            time.sleep(0.25)
        receipt_raw = _bytes(receipt_path, "native launch receipt")
        if len(receipt_raw) > 4096:
            raise RuntimeError("native launch receipt exceeds outbound command limit")
        receipt = json.loads(receipt_raw)
        if canonical_json(receipt) != receipt_raw:
            raise RuntimeError("native launch receipt is not canonical")
        self.launch._check_receipt(receipt)
        command = self.mailbox.publish(
            operation_key=f"submit-{hashlib.sha256(request_id.encode()).hexdigest()}",
            action="submit",
            task_id=self.launch.manifest["task_id"],
            remote_host=self.remote_alias,
            launch_id=request_id,
            launch_receipt=receipt_raw,
        )
        remaining = max(0, deadline - time.monotonic())
        acknowledgement = self.mailbox.wait_ack(
            command.command_id, timeout_seconds=min(remaining, 600)
        )
        while time.monotonic() < deadline:
            if self.witness.observed(request_id):
                return True
            time.sleep(0.25)
        if self.witness.observed(request_id):
            return True
        raise RuntimeError(
            "native first model request was not observed after Windows UI "
            f"{acknowledgement.get('status', 'unknown')} acknowledgement"
        )
