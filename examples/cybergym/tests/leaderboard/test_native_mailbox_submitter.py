# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Controller-only native Send waits for a signed host ack and gateway admission."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from nooa_cybergym.leaderboard.native_task_executor import MailboxNativeSubmitter
from xeus_cybergym.canonical import canonical_json


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
