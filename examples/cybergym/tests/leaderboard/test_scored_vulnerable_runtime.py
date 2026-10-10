# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Scored run_test reaches only the pinned vulnerable image for its task family."""

from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from nooa_cybergym.leaderboard.deepseek import (
    AlternateModelPolicy,
    DeepSeekController,
    SharedCampaignBudget,
)
from nooa_cybergym.leaderboard.host_boundary_runtime import AdmittedPeer
from nooa_cybergym.leaderboard.native_tool_runtime import NativeToolCall
from nooa_cybergym.leaderboard.scored_vulnerable_runtime import (
    OfficialCohortRecipe,
    OfficialCohortVulnerableRunner,
)

IMAGE = "sha256:" + "a" * 64
TASK = "oss-fuzz:42535201"


@pytest.fixture
def fixture(tmp_path):
    output = tmp_path / "output"
    output.mkdir()
    candidate = output / "poc"
    candidate.write_bytes(b"candidate")
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    containers = []

    class Container:
        def start(self):
            pass

        def wait(self, timeout):
            assert timeout == 60
            return {"StatusCode": 1}

        def logs(self, **_):
            return iter((b"observed crash",))

        def remove(self, force):
            assert force is True

    def create(**kwargs):
        containers.append(kwargs)
        return Container()

    docker = SimpleNamespace(
        images=SimpleNamespace(get=lambda _: SimpleNamespace(id=IMAGE)),
        containers=SimpleNamespace(create=create),
    )

    class Audit:
        reject = None

        def __init__(self):
            self.events = []

        def record(self, event):
            self.events.append(event)
            return event["event"] != self.reject

    audit = Audit()
    observed = []
    policy = AlternateModelPolicy.model_validate_json(
        (
            Path(__file__).resolve().parents[2] / "leaderboard/config/alternate-model.json"
        ).read_bytes()
    )
    controller = DeepSeekController(
        policy,
        "synthetic-secret",
        audit=audit,
        registry_digest="a" * 64,
        budget=SharedCampaignBudget(),
    )
    runner = OfficialCohortVulnerableRunner(
        docker_client=docker,
        peer=AdmittedPeer("solver-container", "network-1", "172.30.0.2"),
        task_id=TASK,
        attempt_id="attempt-1",
        recipe=OfficialCohortRecipe(task_id=TASK, image_id=IMAGE),
        output=output,
        evidence=evidence,
        controller=controller,
        observe_failure=observed.append,
        snapshot_candidate=lambda path: {
            "candidate_path": path,
            "sha256": hashlib.sha256(candidate.read_bytes()).hexdigest(),
            "byte_length": candidate.stat().st_size,
        },
        audit=audit,
    )
    call = NativeToolCall(
        TASK,
        "attempt-1",
        "request-1",
        "session-1",
        None,
        "parent",
        "tool-1",
        "mcp__vulnerable__run_test",
        {"candidate_path": "/workspace/output/poc"},
    )
    return runner, call, containers, audit, observed


def test_scored_run_test_uses_oss_fuzz_command_and_only_vulnerable_image(fixture):
    runner, call, containers, audit, observed = fixture
    result = runner.run(call)
    assert result["test"]["raw_exit_code"] == 1
    assert result["debug_available"] is True
    assert len(observed) == 1
    assert len(containers) == 1
    assert containers[0]["image"] == IMAGE
    assert containers[0]["network_mode"] == "none"
    assert containers[0]["command"] == [
        "/bin/bash",
        "-c",
        "timeout -s SIGKILL 10 /usr/local/bin/run_poc 2>&1",
    ]
    assert IMAGE not in str(result)
    assert [event["event"] for event in audit.events[:2]] == [
        "vulnerable_test_started",
        "vulnerable_test_observed",
    ]


def test_scored_run_test_requires_audit_and_parent_authority(fixture):
    runner, call, containers, audit, observed = fixture
    audit.reject = "vulnerable_test_started"
    with pytest.raises(RuntimeError, match="audit"):
        runner.run(call)
    assert not containers and not observed
    audit.reject = None
    child = NativeToolCall(
        call.task_id,
        call.attempt_id,
        call.request_id,
        call.session_id,
        "child-1",
        "child",
        call.tool_id,
        call.name,
        call.arguments,
    )
    with pytest.raises(PermissionError):
        runner.run(child)
    assert not containers


def test_scored_runner_rejects_task_swapped_recipe(fixture):
    runner, call, containers, _, _ = fixture
    runner.recipe = OfficialCohortRecipe(task_id="arvo:47101", image_id=IMAGE)
    with pytest.raises(RuntimeError, match="task"):
        runner.run(call)
    assert not containers
