# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""The outbound Windows UI client receives only signed, one-shot host commands."""

from __future__ import annotations

import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nooa_cybergym.leaderboard.native_ui_mailbox import NativeUiMailbox
from xeus_cybergym.canonical import canonical_json
from xeus_cybergym.ledger import Ed25519Signer, Ed25519Verifier, SignedEnvelope


def mailbox(tmp_path):
    private = Ed25519PrivateKey.generate()
    signer = Ed25519Signer(private_key=private, key_id="controller")
    verifier = Ed25519Verifier({"controller": private.public_key()})
    return NativeUiMailbox(tmp_path, run_id="run-1", signer=signer, verifier=verifier), verifier


def test_open_command_is_signed_durable_and_idempotent(tmp_path):
    box, verifier = mailbox(tmp_path)
    first = box.publish(
        operation_key="task-1-open",
        action="open",
        task_id="synthetic:length-header",
        remote_host="cybergym-task-1",
        port=32355,
    )
    assert (
        box.publish(
            operation_key="task-1-open",
            action="open",
            task_id="synthetic:length-header",
            remote_host="cybergym-task-1",
            port=32355,
        )
        == first
    )
    pending = box.pending()
    assert pending == first.envelope
    payload = verifier.verify(SignedEnvelope.model_validate_json(pending))
    assert canonical_json(first.payload) == payload
    assert first.payload["action"] == "open"
    assert "credential" not in str(first.payload).lower()
    assert box.acknowledge(first.command_id, status="completed") == box.wait_ack(
        first.command_id, timeout_seconds=0
    )
    assert box.pending() is None
    with pytest.raises(RuntimeError, match="operation key"):
        box.publish(
            operation_key="task-1-open",
            action="open",
            task_id="synthetic:length-header",
            remote_host="cybergym-task-1",
            port=32356,
        )


def test_submit_requires_launch_and_exact_ui_audit_once(tmp_path):
    box, _ = mailbox(tmp_path)
    command = box.publish(
        operation_key="launch-1-submit",
        action="submit",
        task_id="synthetic:length-header",
        remote_host="cybergym-task-1",
        launch_id="launch-1",
        launch_receipt=canonical_json(
            {
                "event": "launch_reserved",
                "launch_id": "launch-1",
                "session_id": None,
                "prompt_sha256": "a" * 64,
            }
        ),
    )
    assert (
        command.payload["receipt_sha256"]
        == hashlib.sha256(
            canonical_json(
                {
                    "event": "launch_reserved",
                    "launch_id": "launch-1",
                    "session_id": None,
                    "prompt_sha256": "a" * 64,
                }
            )
        ).hexdigest()
    )
    assert command.payload["launch_receipt_base64"]
    with pytest.raises(ValueError, match="audit"):
        box.acknowledge(command.command_id, status="completed")
    audit = canonical_json(
        {
            "event": "ui_send_attempted",
            "launch_id": "launch-1",
            "prompt_sha256": "a" * 64,
            "observed_prompt_sha256": "a" * 64,
            "remote_alias": "cybergym-task-1",
        }
    )
    digest = hashlib.sha256(audit).hexdigest()
    settled = box.acknowledge(
        command.command_id,
        status="completed",
        ui_audit_sha256=digest,
        ui_audit_bytes=audit,
    )
    assert (
        box.acknowledge(
            command.command_id,
            status="completed",
            ui_audit_sha256=digest,
            ui_audit_bytes=audit,
        )
        == settled
    )
    with pytest.raises(RuntimeError, match="acknowledgement differs"):
        box.acknowledge(command.command_id, status="failed")


def test_read_only_mailbox_replays_after_restart_and_rejects_tampering(tmp_path):
    box, verifier = mailbox(tmp_path)
    command = box.publish(operation_key="run-reap-1", action="reap")
    reader = NativeUiMailbox(tmp_path, run_id="run-1", signer=None, verifier=verifier)
    assert reader.pending() == command.envelope
    with pytest.raises(RuntimeError, match="read-only"):
        reader.publish(operation_key="run-reap-2", action="reap")
    reader.acknowledge(command.command_id, status="completed")
    assert reader.wait_ack(command.command_id, timeout_seconds=0)["status"] == "completed"
    with box._connect() as connection:
        connection.execute(
            "UPDATE commands SET payload=? WHERE command_id=?", (b"{}", command.command_id)
        )
    with pytest.raises(RuntimeError, match="signature differs"):
        box.publish(operation_key="run-reap-1", action="reap")


def test_command_order_and_failed_ack_are_replayed_without_second_action(tmp_path):
    box, _ = mailbox(tmp_path)
    first = box.publish(operation_key="run-reap-1", action="reap")
    second = box.publish(
        operation_key="task-open-1",
        action="open",
        task_id="arvo:1",
        remote_host="cybergym-task-1",
        port=32355,
    )
    assert box.pending() == first.envelope
    box.acknowledge(first.command_id, status="failed")
    assert box.pending() == second.envelope
    with pytest.raises(TimeoutError):
        box.wait_ack(second.command_id, timeout_seconds=0)
