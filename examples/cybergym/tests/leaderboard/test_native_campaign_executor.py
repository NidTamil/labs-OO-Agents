# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Cohort-wide native launch adapter; no official model request is dispatched."""

from types import SimpleNamespace

import pytest
from nooa_cybergym.leaderboard.campaign import CampaignAction
from nooa_cybergym.leaderboard.campaign_runner import UiTarget
from nooa_cybergym.leaderboard.native_campaign_executor import NativeCampaignTaskExecutor

TASK_ID = "oss-fuzz:42538616"
IDS = (TASK_ID, *(f"arvo:{index}" for index in range(1, 1507)))


def make_executor(tmp_path, *, manifest_task=TASK_ID):
    events = []
    observed = set()
    launch = SimpleNamespace(
        task_id=TASK_ID,
        launch_id="launch-oss-fuzz",
        attempt_id="attempt-oss-fuzz",
        remote_alias="cybergym-scored",
        ssh_port=22511,
        evidence=tmp_path,
        launch_authority=SimpleNamespace(
            manifest={
                "run_id": "scored-1",
                "task_id": manifest_task,
                "launch_id": "launch-oss-fuzz",
            },
            _check_receipt=lambda _receipt: None,
        ),
        witness=SimpleNamespace(observed=lambda request: request in observed),
    )

    class State:
        run_id = "scored-1"
        task_ids = IDS

        def next_action(self):
            return CampaignAction("observe_started", TASK_ID)

        def started_event_sha256(self, task_id, request_id):
            assert (task_id, request_id) == (TASK_ID, "launch-oss-fuzz")
            events.append("verified-start")
            return "a" * 64

    class Worker:
        def ensure_prepared(self, task_id):
            assert task_id == TASK_ID
            events.append("prepared")
            return launch

        def await_terminal(self, task_id):
            assert task_id == TASK_ID
            events.append("terminal")
            return b"signed-terminal"

    def publish(evidence, **kwargs):
        assert evidence == tmp_path
        assert kwargs["started_event_sha256"] == "a" * 64
        events.append("intent")
        return b"signed-intent"

    def submitter(**kwargs):
        assert kwargs["started_intent"]("launch-oss-fuzz") is True

        def submit_once(request_id):
            if request_id not in observed:
                observed.add(request_id)
                events.append("send")
            return True

        return SimpleNamespace(submit_once=submit_once)

    executor = NativeCampaignTaskExecutor(
        state=State(),
        worker=Worker(),
        mailbox=SimpleNamespace(run_id="scored-1"),
        signer=object(),
        verifier=object(),
        remote_alias="cybergym-scored",
        publish_intent=publish,
        submitter_factory=submitter,
    )
    return executor, events


def test_cohort_executor_accepts_oss_fuzz_and_reconciles_one_request(tmp_path):
    executor, events = make_executor(tmp_path)
    executor.prepare(TASK_ID)
    assert executor.ui_target(TASK_ID) == UiTarget("cybergym-scored", 22511)
    assert executor.first_request_id(TASK_ID) == "launch-oss-fuzz"
    executor.start(TASK_ID, "launch-oss-fuzz")
    executor.start(TASK_ID, "launch-oss-fuzz")
    assert executor.await_terminal(TASK_ID) == b"signed-terminal"
    assert events.count("send") == 1
    assert events.index("intent") < events.index("send") < events.index("terminal")


def test_cohort_executor_rejects_outside_task_before_worker(tmp_path):
    executor, events = make_executor(tmp_path)
    with pytest.raises(ValueError, match="signed cohort"):
        executor.prepare("arvo:47101")
    assert events == []


def test_cohort_executor_rejects_task_swapped_launch(tmp_path):
    executor, events = make_executor(tmp_path, manifest_task="arvo:1")
    with pytest.raises(RuntimeError, match="launch identity"):
        executor.first_request_id(TASK_ID)
    assert "send" not in events
