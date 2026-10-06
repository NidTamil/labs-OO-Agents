# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import importlib.util
import json
from uuid import uuid4

import pytest


def test_native_hook_collector_exists():
    assert importlib.util.find_spec("nooa_cybergym.leaderboard.native_hook_runtime") is not None


@pytest.fixture
def subject():
    from nooa_cybergym.leaderboard import native_hook_runtime

    return native_hook_runtime


def raw(kind="SessionStart", **fields):
    return {
        "hook_event_name": kind,
        "session_id": "a46bc934-4f40-4449-9af0-31c3309df992",
        "cwd": "/workspace",
        "transcript_path": "/home/agent/.claude/projects/-workspace/a46bc934-4f40-4449-9af0-31c3309df992.jsonl",
        **fields,
    }


def observation(subject, kind="SessionStart", **fields):
    return {
        "schema_version": 1,
        "event_id": str(uuid4()),
        "run_id": "synthetic-1",
        "task_id": "synthetic:overflow",
        "launch_id": "launch-1",
        "hook": subject.project_hook_input(raw(kind, **fields)),
    }


def test_hook_projection_preserves_native_ids_but_omits_tool_and_error_secrets(subject):
    payload = raw(
        "PostToolUseFailure",
        agent_id="a1234",
        tool_name="Bash",
        tool_use_id="toolu_1234",
        tool_input={"command": "echo secret-token"},
        error="secret-provider-key",
        effort={"level": "max"},
    )
    result = subject.project_hook_input(payload)
    assert result["agent_id"] == "a1234"
    assert result["tool_use_id"] == "toolu_1234"
    assert result["effort"] == "max"
    assert len(result["raw_input_sha256"]) == 64
    assert "secret" not in json.dumps(result)


def test_collector_orders_real_hook_lifecycle_and_recovers_from_database(subject, tmp_path):
    def open_collector():
        return subject.NativeHookCollector(
            tmp_path / "hooks.sqlite3",
            run_id="synthetic-1",
            task_id="synthetic:overflow",
            launch_id="launch-1",
        )

    collector = open_collector()
    start = observation(subject, source="startup", model="glm-5.3[1m]")
    collector.ingest(start)
    assert collector.ingest(start)["status"] == "duplicate"
    collector.ingest(observation(subject, "SubagentStart", agent_id="a1234", agent_type="Explore"))
    collector.ingest(
        observation(
            subject,
            "PreToolUse",
            agent_id="a1234",
            tool_name="Bash",
            tool_use_id="toolu_1234",
            tool_input={"command": "true"},
        )
    )
    assert collector.summary()["pending_tools"] == 1
    collector = open_collector()
    collector.ingest(
        observation(
            subject,
            "PostToolUse",
            agent_id="a1234",
            tool_name="Bash",
            tool_use_id="toolu_1234",
            tool_input={},
            tool_response="ok",
        )
    )
    collector.ingest(
        observation(
            subject,
            "SubagentStop",
            agent_id="a1234",
            agent_type="Explore",
            stop_hook_active=False,
            agent_transcript_path="/home/agent/.claude/projects/-workspace/a/subagents/agent-a1234.jsonl",
        )
    )
    collector.ingest(observation(subject, "Stop", stop_hook_active=False))
    collector.ingest(observation(subject, "SessionEnd", reason="other"))
    assert collector.summary() == {
        "sessions": 1,
        "open_sessions": 0,
        "children": 1,
        "open_children": 0,
        "pending_tools": 0,
        "events": 7,
    }


def test_unknown_child_and_unpaired_tool_completion_fail_closed(subject, tmp_path):
    collector = subject.NativeHookCollector(
        tmp_path / "hooks.sqlite3",
        run_id="synthetic-1",
        task_id="synthetic:overflow",
        launch_id="launch-1",
    )
    collector.ingest(observation(subject, source="startup", model="glm-5.3[1m]"))
    with pytest.raises(ValueError, match="child"):
        collector.ingest(
            observation(
                subject,
                "PreToolUse",
                agent_id="unknown",
                tool_name="Bash",
                tool_use_id="toolu_1",
                tool_input={},
            )
        )
    with pytest.raises(ValueError, match="tool"):
        collector.ingest(
            observation(
                subject,
                "PostToolUse",
                tool_name="Bash",
                tool_use_id="toolu_1",
                tool_input={},
                tool_response="ok",
            )
        )
    assert collector.summary()["events"] == 1


def test_native_request_identity_is_observation_not_admission(subject):
    body = {
        "metadata": {
            "user_id": json.dumps(
                {
                    "session_id": "session-1",
                    "device_id": "private-device",
                    "account_uuid": "private-account",
                }
            )
        }
    }
    result = subject.native_request_identity(
        (("x-claude-code-agent-id", "a1234"), ("x-claude-code-parent-agent-id", "parent-1")), body
    )
    assert result == {
        "session_id": "session-1",
        "agent_id": "a1234",
        "parent_agent_id": "parent-1",
        "parent_session_id": None,
    }
    assert "private" not in json.dumps(result)
    with pytest.raises(ValueError):
        subject.native_request_identity(
            (("x-claude-code-agent-id", "a"), ("X-Claude-Code-Agent-ID", "b")), body
        )


def test_observed_role_requires_open_session_and_bounds_three_children(subject, tmp_path):
    collector = subject.NativeHookCollector(
        tmp_path / "hooks.sqlite3",
        run_id="synthetic-1",
        task_id="synthetic:overflow",
        launch_id="launch-1",
    )
    session = raw()["session_id"]
    assert collector.observed_role(session, None) is None
    collector.ingest(observation(subject, source="startup", model="glm-5.3[1m]"))
    assert collector.observed_role(session, None) == "parent"
    assert collector.observed_role(session, "unknown") is None
    for agent in ("a1", "a2", "a3"):
        collector.ingest(
            observation(subject, "SubagentStart", agent_id=agent, agent_type="cybergym-recon")
        )
        assert collector.observed_role(session, agent) == "child"
    with pytest.raises(ValueError, match="child bound"):
        collector.ingest(
            observation(subject, "SubagentStart", agent_id="a4", agent_type="cybergym-recon")
        )


def test_closed_preflight_sessions_yield_to_one_model_session(subject, tmp_path):
    database = tmp_path / "hooks.sqlite3"

    def collector():
        return subject.NativeHookCollector(
            database,
            run_id="synthetic-1",
            task_id="synthetic:overflow",
            launch_id="launch-1",
        )

    first = raw()["session_id"]
    second = str(uuid4())
    third = str(uuid4())
    hooks = collector()
    hooks.ingest(observation(subject, session_id=first))
    hooks.ingest(observation(subject, session_id=second))
    assert hooks.model_role(second, None) == "parent"
    assert hooks.model_role(first, None) is None
    hooks.ingest(observation(subject, "SessionEnd", session_id=first))
    assert collector().model_role(second, None) == "parent"
    hooks.ingest(observation(subject, "SessionEnd", session_id=second))
    with pytest.raises(ValueError, match="model session"):
        hooks.ingest(observation(subject, session_id=third))


def test_preflight_sessions_are_bounded_and_cannot_leave_pending_tools(subject, tmp_path):
    hooks = subject.NativeHookCollector(
        tmp_path / "hooks.sqlite3",
        run_id="synthetic-1",
        task_id="synthetic:overflow",
        launch_id="launch-1",
    )
    for _ in range(8):
        session = str(uuid4())
        hooks.ingest(observation(subject, session_id=session))
        hooks.ingest(observation(subject, "SessionEnd", session_id=session))
    with pytest.raises(ValueError, match="preflight session bound"):
        hooks.ingest(observation(subject, session_id=str(uuid4())))

    concurrent = subject.NativeHookCollector(
        tmp_path / "concurrent.sqlite3",
        run_id="synthetic-1",
        task_id="synthetic:overflow",
        launch_id="launch-1",
    )
    for _ in range(3):
        concurrent.ingest(observation(subject, session_id=str(uuid4())))
    with pytest.raises(ValueError, match="concurrent preflight session bound"):
        concurrent.ingest(observation(subject, session_id=str(uuid4())))

    pending = subject.NativeHookCollector(
        tmp_path / "pending.sqlite3",
        run_id="synthetic-1",
        task_id="synthetic:overflow",
        launch_id="launch-1",
    )
    first = raw()["session_id"]
    pending.ingest(observation(subject, session_id=first))
    pending.ingest(observation(subject, "PreToolUse", session_id=first, tool_name="Bash", tool_use_id="toolu_1"))
    pending.ingest(observation(subject, "SessionEnd", session_id=first))
    with pytest.raises(ValueError, match="pending native tool"):
        pending.ingest(observation(subject, session_id=str(uuid4())))


def test_hooks_bind_only_reserved_shared_capacity_and_close_it(subject, tmp_path):
    from nooa_cybergym.leaderboard.child_capacity import ChildCapacity

    capacity = ChildCapacity(
        tmp_path / "capacity.sqlite",
        run_id="synthetic-1",
        task_id="synthetic:overflow",
        attempt_id="attempt-1",
        launch_id="launch-1",
    )
    collector = subject.NativeHookCollector(
        tmp_path / "hooks.sqlite",
        run_id="synthetic-1",
        task_id="synthetic:overflow",
        launch_id="launch-1",
        capacity=capacity,
    )
    collector.ingest(observation(subject))
    with capacity.advisory_slot("independent_recon"):
        with pytest.raises(ValueError, match="pending"):
            collector.ingest(
                observation(
                    subject, "SubagentStart", agent_id="unknown", agent_type="cybergym-recon"
                )
            )
        for index in (1, 2):
            capacity.reserve_native(f"tool-{index}", "cybergym-recon")
            collector.ingest(
                observation(
                    subject, "SubagentStart", agent_id=f"agent-{index}", agent_type="cybergym-recon"
                )
            )
        assert capacity.snapshot()["occupied"] == 3
        collector.ingest(
            observation(subject, "SubagentStop", agent_id="agent-1", agent_type="cybergym-recon")
        )
        assert capacity.snapshot()["occupied"] == 2
        assert collector.observed_role(raw()["session_id"], "agent-1") is None
        assert collector.observed_role(raw()["session_id"], "agent-2") == "child"
