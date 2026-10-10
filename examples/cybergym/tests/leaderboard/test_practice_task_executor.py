# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Practice executor coordinates the signed start intent and one native Send."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from nooa_cybergym.leaderboard.campaign import CampaignAction
from nooa_cybergym.leaderboard.campaign_runner import UiTarget
from nooa_cybergym.leaderboard.practice_task_executor import NativePracticeTaskExecutor


def test_practice_executor_publishes_verified_start_before_one_send(tmp_path):
    events = []
    launch = SimpleNamespace(
        task_id="arvo:47101",
        launch_id="launch-47101",
        remote_alias="cybergym-practice",
        ssh_port=22511,
        attempt_id="attempt-47101",
        evidence=tmp_path,
        launch_authority=object(),
        witness=object(),
    )

    class State:
        run_id = "practice-1"

        def next_action(self):
            return CampaignAction("observe_started", "arvo:47101")

        def started_event_sha256(self, task_id, request_id):
            assert (task_id, request_id) == ("arvo:47101", "launch-47101")
            events.append("verified-start")
            return "a" * 64

    class Worker:
        def ensure_prepared(self, task_id):
            assert task_id == "arvo:47101"
            events.append("prepared")
            return launch

        def await_terminal(self, task_id):
            assert task_id == "arvo:47101"
            events.append("terminal")
            return b"signed-receipt"

    def publish(evidence, **kwargs):
        assert evidence == tmp_path
        assert kwargs["started_event_sha256"] == "a" * 64
        events.append("intent")
        return b"signed-intent"

    def submitter(**kwargs):
        assert kwargs["remote_alias"] == "cybergym-practice"
        assert kwargs["started_intent"]("launch-47101") is True

        def send_once(request_id):
            assert request_id == "launch-47101"
            events.append("send")
            return True

        return SimpleNamespace(submit_once=send_once)

    executor = NativePracticeTaskExecutor(
        state=State(),
        worker=Worker(),
        mailbox=SimpleNamespace(run_id="practice-1"),
        signer=object(),
        verifier=object(),
        remote_alias="cybergym-practice",
        publish_intent=publish,
        submitter_factory=submitter,
    )
    executor.prepare("arvo:47101")
    assert executor.ui_target("arvo:47101") == UiTarget("cybergym-practice", 22511)
    assert executor.first_request_id("arvo:47101") == "launch-47101"
    executor.start("arvo:47101", "launch-47101")
    assert executor.await_terminal("arvo:47101") == b"signed-receipt"
    assert events.count("prepared") == 5
    assert events.count("send") == 1
    assert events.index("intent") < events.index("send") < events.index("terminal")


def test_practice_executor_rejects_wrong_launch_before_send(tmp_path):
    launch = SimpleNamespace(
        task_id="arvo:47101",
        launch_id="launch-47101",
        remote_alias="cybergym-practice",
        ssh_port=22511,
        attempt_id="attempt-47101",
        evidence=tmp_path,
        launch_authority=object(),
        witness=object(),
    )
    worker = SimpleNamespace(ensure_prepared=lambda _: launch, await_terminal=lambda _: b"unused")
    state = SimpleNamespace(
        run_id="practice-1",
        next_action=lambda: CampaignAction("observe_started", "arvo:47101"),
        started_event_sha256=lambda *_args: "a" * 64,
    )
    executor = NativePracticeTaskExecutor(
        state=state,
        worker=worker,
        mailbox=SimpleNamespace(run_id="practice-1"),
        signer=object(),
        verifier=object(),
        remote_alias="cybergym-practice",
        publish_intent=lambda *_args, **_kwargs: pytest.fail("intent must not publish"),
        submitter_factory=lambda **_kwargs: pytest.fail("Send must not be constructed"),
    )
    with pytest.raises(RuntimeError, match="launch identity"):
        executor.start("arvo:47101", "different-launch")
