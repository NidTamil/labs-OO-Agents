# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Controller-only native Send waits for a signed host ack and gateway admission."""

from __future__ import annotations

import hashlib
import json
import os
from types import SimpleNamespace

import pytest
from nooa_cybergym.leaderboard.native_first_request import NativeFirstRequestWitness
from nooa_cybergym.leaderboard.native_launcher import NativeLaunchAuthority, build_launch_manifest
from nooa_cybergym.leaderboard.native_task_executor import (
    MailboxNativeSubmitter,
    NativeTerminalReceiptPublisher,
)
from xeus_cybergym.canonical import canonical_json
from xeus_cybergym.ledger import SignedEnvelope

from .test_native_launcher import receipt, signed
from .test_native_task_executor import _evidence


def test_mailbox_submitter_requires_started_intent_and_never_reissues_send(tmp_path):
    launch_dir = tmp_path / "launch"
    launch_dir.mkdir()
    receipt = {
        "event": "launch_reserved",
        "launch_id": "launch-1",
        "session_id": None,
        "prompt_sha256": "a" * 64,
    }
    raw = canonical_json(receipt)
    (launch_dir / "launcher-receipt.json").write_bytes(raw)

    class Authority:
        manifest = {"task_id": "arvo:1", "launch_id": "launch-1"}

        def _check_receipt(self, value):
            assert value == receipt

    Authority.launch_dir = launch_dir

    class Witness:
        admitted = False

        def observed(self, launch_id):
            assert launch_id == "launch-1"
            return self.admitted

    class Mailbox:
        run_id = "run-1"

        def __init__(self):
            self.calls = []

        def publish(self, **kwargs):
            self.calls.append(kwargs)
            assert kwargs["launch_receipt"] == raw
            return SimpleNamespace(command_id="a" * 32)

        def wait_ack(self, command_id, *, timeout_seconds):
            assert command_id == "a" * 32
            assert 0 < timeout_seconds <= 30
            witness.admitted = True
            return {"status": "completed"}

    witness = Witness()
    mailbox = Mailbox()
    started = False
    submitter = MailboxNativeSubmitter(
        launch_authority=Authority(),
        mailbox=mailbox,
        witness=witness,
        remote_alias="cybergym-task-1",
        started_intent=lambda request_id: started and request_id == "launch-1",
        timeout_seconds=30,
    )
    with pytest.raises(RuntimeError, match="started intent"):
        submitter.submit_once("launch-1")
    assert not mailbox.calls
    started = True
    assert submitter.submit_once("launch-1") is True
    assert len(mailbox.calls) == 1
    assert submitter.submit_once("launch-1") is True
    assert len(mailbox.calls) == 1
    with pytest.raises(ValueError, match="launch"):
        submitter.submit_once("another-launch")


def test_prepared_launch_reserves_then_sends_and_creates_signed_terminal(tmp_path):
    """An unreserved prepared launch can reach a verified synthetic terminal receipt."""
    manifest = build_launch_manifest(
        scope="synthetic",
        run_id="run-1",
        task_id="arvo:1",
        launch_id="launch-1",
        ordinal=1,
        harness_sha256="a" * 64,
        task_manifest_bytes=b'{"synthetic":true}',
        file_hashes={"CLAUDE.md": "e" * 64},
        container_id="c" * 64,
        hostname="c" * 12,
        uid=1000,
        pid_namespace="pid:[100]",
        mount_namespace="mnt:[200]",
        vscode_version="1.140.0",
        claude_extension_version="2.1.289",
        claude_extension_sha256="d" * 64,
        native_launch_url="http://registered-tool-gateway/native-launch",
    )
    envelope, keys = signed(manifest)
    authority = NativeLaunchAuthority.from_signed_envelope(envelope, keys, tmp_path)
    assert not authority.launch_dir.exists()
    audit = tmp_path / "model-requests.jsonl"
    witness = NativeFirstRequestWitness(
        launch_authority=authority,
        attempt_id="attempt-1",
        model_audit=audit,
        policy_sha256="a" * 64,
        expected_model="glm-5.3",
    )

    class Mailbox:
        run_id = "run-1"

        def __init__(self):
            self.calls = []

        def publish(self, **kwargs):
            self.calls.append(kwargs)
            assert kwargs["launch_receipt"] == canonical_json(receipt(manifest))
            return SimpleNamespace(command_id="a" * 32)

        def wait_ack(self, command_id, *, timeout_seconds):
            assert command_id == "a" * 32 and timeout_seconds > 0
            event = {
                "event": "request_reserved",
                "task_id": "arvo:1",
                "attempt_id": "attempt-1",
                "request_id": "model-1",
                "role": "primary",
                "requested_model": "glm-5.3",
                "policy_sha256": "a" * 64,
            }
            audit.write_bytes(
                canonical_json(event)
                + b"\n"
                + canonical_json({**event, "event": "attempt_started"})
                + b"\n"
            )
            return {"status": "completed"}

    mailbox = Mailbox()
    started = False
    submitter = MailboxNativeSubmitter(
        launch_authority=authority,
        mailbox=mailbox,
        witness=witness,
        remote_alias="cybergym-task-1",
        started_intent=lambda launch_id: started and launch_id == "launch-1",
        timeout_seconds=5,
    )
    assert not mailbox.calls and witness.observed("launch-1") is False
    with pytest.raises(RuntimeError, match="started intent"):
        submitter.submit_once("launch-1")
    assert not mailbox.calls

    observed = receipt(manifest)
    if os.name == "posix":
        assert authority.reserve(observed)["status"] == "reserved"
    else:
        # Native authority directory fsync is POSIX-only; Linux tests the real reserve.
        authority.launch_dir.mkdir()
        (authority.launch_dir / "launcher-receipt.json").write_bytes(canonical_json(observed))
    started = True
    assert submitter.submit_once("launch-1") is True
    assert witness.observed("launch-1") is True
    assert len(mailbox.calls) == 1

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
    terminal = publisher.publish_oracle(
        lock=evidence["lock"],
        signed_request=evidence["request"],
        signed_result=evidence["result"],
        frozen_bundle=evidence["bundle"],
        solver_stopped=lambda: True,
    )
    verified = json.loads(
        evidence["controller_verifier"].verify(SignedEnvelope.model_validate_json(terminal))
    )
    assert terminal == (tmp_path / "terminal-receipt.signed.json").read_bytes()
    assert verified["status"] == "oracle_true"
    assert verified["final_sha256"] == evidence["lock"].sha256
    assert verified["oracle_verdict_sha256"] == hashlib.sha256(evidence["result"]).hexdigest()
