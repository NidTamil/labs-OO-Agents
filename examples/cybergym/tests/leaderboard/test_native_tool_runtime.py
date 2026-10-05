import hashlib
import json
import sqlite3
from dataclasses import replace

import pytest
from nooa_cybergym.leaderboard.host_boundary_runtime import AdmittedPeer, GatewayRequest
from nooa_cybergym.leaderboard.native_tool_runtime import NativeToolController

PEER = AdmittedPeer("a" * 64, "b" * 64, "172.20.0.2")


def controller(tmp_path, authorize=lambda _: True, *, parent_tools=None, observed_role=None, captured_schemas=None, task_id="task"):
    parent_tools = parent_tools or frozenset({"Read", "Bash", "Agent"})
    return NativeToolController(
        tmp_path / "tools.sqlite",
        task_id=task_id,
        attempt_id="attempt",
        run_id="run",
        launch_id="launch",
        peer=PEER,
        policy_sha256="c" * 64,
        parent_tools=parent_tools,
        child_tools=frozenset({"Read"}),
        captured_schemas=captured_schemas or {
            name: hashlib.sha256(json.dumps({"name": name}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            for name in (parent_tools | {"Read", "Bash", "Agent"})
        },
        observed_role=observed_role
        or (
            lambda session, agent: (
                ("child" if agent else "parent") if session == "session" else None
            )
        ),
        authorize=authorize,
        redact=lambda value: value,
    )


def test_native_advertised_denied_tool_is_removed_before_provider(tmp_path):
    schema = {name: hashlib.sha256(json.dumps({"name": name}, sort_keys=True, separators=(",", ":")).encode()).hexdigest() for name in ("Read", "Bash", "Agent", "DeniedTool")}
    c = controller(tmp_path, captured_schemas=schema)
    request = model_request(names=("Read", "DeniedTool"))
    grant = c.begin_request(request)
    forwarded = c.forward_request(grant, request)
    assert [tool["name"] for tool in json.loads(forwarded.body)["tools"]] == ["Read"]
    assert [tool["name"] for tool in json.loads(request.body)["tools"]] == ["Read", "DeniedTool"]


def test_pinned_builtin_can_vary_description_and_input_shape_but_mcp_cannot(tmp_path):
    name = "mcp__gbrain__recall"
    c = controller(tmp_path, parent_tools=frozenset({"Read", "Bash", "Agent", name}))
    request = model_request(names=("Read", "Bash"))
    payload = json.loads(request.body)
    payload["tools"][0].update({"description": "Native read", "input_schema": {"type": "object", "properties": {"file_path": {"type": "string"}}}})
    request = replace(request, body=json.dumps(payload).encode())
    grant = c.begin_request(request)
    assert [tool["name"] for tool in json.loads(c.forward_request(grant, request).body)["tools"]] == ["Read", "Bash"]
    with __import__("sqlite3").connect(c.database) as connection:
        drift = json.loads(connection.execute("SELECT schema_drift FROM requests").fetchone()[0])
    assert [item["name"] for item in drift] == ["Read"]
    altered = model_request(names=(name,))
    mcp_payload = json.loads(altered.body)
    mcp_payload["tools"][0]["description"] = "altered MCP"
    with pytest.raises(PermissionError, match="schema"):
        c.begin_request(replace(altered, body=json.dumps(mcp_payload).encode()))


def test_synthetic_child_unknown_read_tools_are_captured_without_prompt(tmp_path):
    c = controller(tmp_path, task_id="synthetic:1")
    request = model_request(agent="child-1", names=("Read", "Grep", "Glob"))
    payload = json.loads(request.body)
    payload["messages"] = [{"role": "user", "content": "synthetic-private-prompt"}]
    with pytest.raises(PermissionError, match="schema"):
        c.begin_request(replace(request, body=json.dumps(payload).encode()))
    with sqlite3.connect(c.database) as connection:
        captured = connection.execute("SELECT schemas FROM child_schema_discovery").fetchone()[0]
    assert [item["name"] for item in json.loads(captured)] == ["Grep", "Glob"]
    assert b"synthetic-private-prompt" not in captured


def model_request(*, agent=None, names=None, **settings):
    if names is None:
        names = ("Read",) if agent else ("Read", "Bash", "Agent")
    headers = (("x-claude-code-agent-id", agent),) if agent else ()
    return GatewayRequest(
        "model-gateway",
        "POST",
        "/v1/messages",
        headers,
        json.dumps(
            {
                "model": "glm-5.3",
                "metadata": {"user_id": json.dumps({"session_id": "session"})},
                "stream": True,
                "max_tokens": 128000,
                "thinking": {"type": "adaptive"},
                "output_config": {"effort": "max"},
                "tools": [{"name": name} for name in names],
                **settings,
            }
        ).encode(),
        PEER,
    )


def tool_frames(tool="Read", args=None):
    args = args or {"file_path": "/workspace/description.txt"}
    events = [
        {"type": "message_start", "message": {"id": "msg-1", "model": "glm-5.3"}},
        {
            "type": "content_block_start",
            "index": 0,
            "content_block": {"type": "tool_use", "id": "tool-1", "name": tool, "input": {}},
        },
        {
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "input_json_delta", "partial_json": json.dumps(args)},
        },
        {"type": "content_block_stop", "index": 0},
        {"type": "message_stop"},
    ]
    return b"".join(("data: " + json.dumps(e) + "\n\n").encode() for e in events)


def hook(*, args=None, event="PreToolUse", agent=None):
    return {
        "schema_version": 1,
        "run_id": "run",
        "task_id": "task",
        "launch_id": "launch",
        "hook_input": {
            "hook_event_name": event,
            "session_id": "session",
            "agent_id": agent,
            "tool_use_id": "tool-1",
            "tool_name": "Read",
            "tool_input": args or {"file_path": "/workspace/description.txt"},
        },
    }


def test_unobserved_or_altered_tool_call_cannot_be_authorized(tmp_path):
    seen = []
    c = controller(tmp_path, lambda call: seen.append(call) or True)
    assert c.authorize_hook(hook()) is False
    grant = c.begin_request(model_request())
    stream = tool_frames()
    for i in range(0, len(stream), 7):
        c.observe_stream(grant, stream[i : i + 7])
    assert c.authorize_hook(hook(args={"file_path": "/etc/shadow"})) is False
    assert c.authorize_hook(hook()) is True
    assert len(seen) == 1
    assert c.authorize_hook(hook()) is False
    c.record_result(hook(event="PostToolUse"))
    assert c.summary()["completed"] == 1


def test_child_advertised_writable_tool_is_removed_before_provider(tmp_path):
    c = controller(tmp_path)
    request = model_request(agent="child-1", names=("Read", "Bash"))
    grant = c.begin_request(request)
    assert [tool["name"] for tool in json.loads(c.forward_request(grant, request).body)["tools"]] == ["Read"]
    c.observe_stream(grant, tool_frames())
    assert c.authorize_hook(hook(agent="child-1")) is True
    assert c.authorize_hook(hook()) is False


def test_unknown_peer_session_and_unrequested_provider_tool_are_denied(tmp_path):
    c = controller(tmp_path)
    with pytest.raises(PermissionError):
        c.begin_request(replace(model_request(), peer=replace(PEER, container_id="other")))
    grant = c.begin_request(model_request())
    with pytest.raises(PermissionError):
        c.observe_stream(grant, tool_frames("Write", {"file_path": "/tmp/forbidden"}))
    assert c.authorize_hook(hook()) is False


def test_authority_denial_and_unmatched_results_fail_closed(tmp_path):
    c = controller(tmp_path, lambda _: False)
    grant = c.begin_request(model_request())
    c.observe_stream(grant, tool_frames())
    assert c.authorize_hook(hook()) is False
    with pytest.raises(PermissionError):
        c.record_result(hook(event="PostToolUse"))


@pytest.mark.parametrize(
    "settings",
    [
        {"model": "glm-5.3[1m]"},
        {"model": "other"},
        {"stream": False},
        {"max_tokens": 128001},
        {"max_tokens": True},
        {"max_tokens": 0},
        {"thinking": {"type": "disabled"}},
        {"thinking": None},
        {"output_config": {"effort": "high"}},
        {"output_config": {}},
        {"temperature": float("nan")},
        {"temperature": float("inf")},
    ],
)
def test_generation_requires_frozen_glm_max_settings(tmp_path, settings):
    with pytest.raises(PermissionError):
        controller(tmp_path).begin_request(model_request(**settings))


def test_deferred_request_roster_stays_within_frozen_registry(tmp_path):
    c = controller(tmp_path)
    grant = c.begin_request(model_request(names=("Read",)))
    with pytest.raises(PermissionError):
        c.observe_stream(grant, tool_frames("Bash", {"command": "false"}))


def test_count_tokens_accepts_non_generation_payload_and_cannot_authorize_tools(tmp_path):
    c = controller(tmp_path)
    request = model_request()
    payload = json.loads(request.body)
    for field in ("thinking", "output_config", "max_tokens", "stream", "tools"):
        payload.pop(field)
    grant = c.begin_request(
        replace(request, path="/v1/messages/count_tokens", body=json.dumps(payload).encode())
    )
    c.observe_stream(grant, b'{"input_tokens":12}')
    c.finish_stream(grant, completed=True)
    assert c.authorize_hook(hook()) is False


def sse(*events):
    return b"".join(("data: " + json.dumps(event) + "\n\n").encode() for event in events)


@pytest.mark.parametrize(
    "event",
    [
        {"type": "content_block_stop", "index": 7},
        {
            "type": "content_block_delta",
            "index": 7,
            "delta": {"type": "input_json_delta", "partial_json": "{}"},
        },
        {"type": "message_stop"},
        {
            "type": "content_block_start",
            "index": True,
            "content_block": {"type": "tool_use", "id": "bad", "name": "Read", "input": {}},
        },
    ],
)
def test_invalid_stream_order_and_block_indexes_halt_admission(tmp_path, event):
    c = controller(tmp_path)
    grant = c.begin_request(model_request())
    with pytest.raises(PermissionError):
        c.observe_stream(grant, sse(event))
    assert c.authorize_hook(hook()) is False


def test_tool_stream_cannot_resume_after_message_stop(tmp_path):
    c = controller(tmp_path)
    grant = c.begin_request(model_request())
    c.observe_stream(grant, tool_frames())
    with pytest.raises(PermissionError):
        c.observe_stream(grant, tool_frames().replace(b"tool-1", b"tool-2"))
    assert c.authorize_hook(hook()) is False


def test_truncated_stream_cannot_leave_usable_tool_authority(tmp_path):
    c = controller(tmp_path)
    grant = c.begin_request(model_request())
    c.observe_stream(grant, tool_frames().rsplit(b"data:", 1)[0])
    with pytest.raises(PermissionError):
        c.finish_stream(grant, completed=True)
    assert c.authorize_hook(hook()) is False


@pytest.mark.parametrize(
    "partial", ['{"file_path":"a","file_path":"b"}', '{"value":NaN}', '{"value":1e999}']
)
def test_ambiguous_or_nonfinite_tool_arguments_are_rejected(tmp_path, partial):
    c = controller(tmp_path)
    grant = c.begin_request(model_request())
    events = [
        {"type": "message_start", "message": {"id": "msg", "model": "glm-5.3"}},
        {
            "type": "content_block_start",
            "index": 0,
            "content_block": {"type": "tool_use", "id": "tool-1", "name": "Read", "input": {}},
        },
        {
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "input_json_delta", "partial_json": partial},
        },
        {"type": "content_block_stop", "index": 0},
    ]
    with pytest.raises(PermissionError):
        c.observe_stream(grant, sse(*events))


@pytest.mark.parametrize(
    "subtype",
    [None, "general-purpose", "Explore", "cybergym-recon", "cybergym-debug", "cybergym-review"],
)
def test_agent_tool_restricts_native_child_type_before_capability_admission(tmp_path, subtype):
    seen = []
    c = controller(tmp_path, lambda call: seen.append(call) or True)
    args = {"prompt": "synthetic", "subagent_type": subtype}
    grant = c.begin_request(model_request())
    c.observe_stream(grant, tool_frames("Agent", args))
    envelope = hook(args=args)
    envelope["hook_input"]["tool_name"] = "Agent"
    allowed = subtype in {"cybergym-recon", "cybergym-debug", "cybergym-review"}
    assert c.authorize_hook(envelope) is allowed
    assert len(seen) == (1 if allowed else 0)


def test_restarted_controller_cannot_record_pending_result(tmp_path):
    c = controller(tmp_path)
    grant = c.begin_request(model_request())
    c.observe_stream(grant, tool_frames())
    assert c.authorize_hook(hook()) is True
    restarted = controller(tmp_path)
    with pytest.raises(PermissionError):
        restarted.record_result(hook(event="PostToolUse"))


def test_provider_grant_cannot_be_relabelled(tmp_path):
    c = controller(tmp_path)
    grant = c.begin_request(model_request())
    with pytest.raises(PermissionError):
        c.observe_stream(replace(grant, capability_policy_sha256="d" * 64), tool_frames())


def test_mcp_dispatch_claim_is_bound_to_actual_arguments_and_consumed_once(tmp_path):
    name = "mcp__gbrain__recall"
    args = {"query": "safe general procedure"}
    c = controller(tmp_path, parent_tools=frozenset({"Read", name}))
    grant = c.begin_request(model_request(names=("Read", name)))
    c.observe_stream(grant, tool_frames(name, args))
    envelope = hook(args=args)
    envelope["hook_input"]["tool_name"] = name
    with pytest.raises(PermissionError):
        c.resolve_mcp_call("tool-1", name, args)
    assert c.authorize_hook(envelope) is True
    with pytest.raises(PermissionError):
        c.resolve_mcp_call("tool-1", name, {"query": "altered"})
    call = c.resolve_mcp_call("tool-1", name, args)
    assert call.role == "parent" and call.request_id == grant.request_id
    assert c.summary() == {"dispatched": 1}
    with pytest.raises(PermissionError):
        c.resolve_mcp_call("tool-1", name, args)
    envelope["hook_input"]["hook_event_name"] = "PostToolUse"
    c.record_result(envelope)
    assert c.summary() == {"completed": 1}


def test_result_custody_failure_halts_further_model_admission(tmp_path):
    import sqlite3

    c = controller(tmp_path)
    grant = c.begin_request(model_request())
    c.observe_stream(grant, tool_frames())
    assert c.authorize_hook(hook()) is True
    with sqlite3.connect(c.database) as connection:
        connection.execute(
            "CREATE TRIGGER fail_result BEFORE UPDATE OF result ON tools "
            "BEGIN SELECT RAISE(FAIL, 'synthetic custody failure'); END"
        )
    with pytest.raises(PermissionError):
        c.record_result(hook(event="PostToolUse"))
    with pytest.raises(PermissionError):
        c.begin_request(model_request())


def test_ambiguous_hook_json_does_not_authorize_any_tool(tmp_path):
    c = controller(tmp_path)
    grant = c.begin_request(model_request())
    c.observe_stream(grant, tool_frames())
    body = (
        json.dumps(hook())
        .replace('"tool_name": "Read"', '"tool_name": "Bash", "tool_name": "Read"')
        .encode()
    )
    reply = c.handle(
        GatewayRequest("registered-tool-gateway", "POST", "/native-tools/authorize", (), body, PEER)
    )
    assert reply.status == 403
    assert c.summary() == {"observed": 1}


def test_child_header_requires_actual_bounded_collector_lifecycle(tmp_path):
    from uuid import uuid4

    from nooa_cybergym.leaderboard.native_hook_runtime import (
        NativeHookCollector,
        project_hook_input,
    )

    collector = NativeHookCollector(
        tmp_path / "hooks.sqlite", run_id="run", task_id="task", launch_id="launch"
    )

    def record(kind, **fields):
        return collector.ingest(
            {
                "schema_version": 1,
                "event_id": str(uuid4()),
                "run_id": "run",
                "task_id": "task",
                "launch_id": "launch",
                "hook": project_hook_input(
                    {
                        "hook_event_name": kind,
                        "session_id": "session",
                        "cwd": "/workspace",
                        "transcript_path": "/home/agent/.claude/projects/task/session.jsonl",
                        **fields,
                    }
                ),
            }
        )

    record("SessionStart")
    c = controller(tmp_path, observed_role=collector.observed_role)
    with pytest.raises(PermissionError):
        c.begin_request(model_request(agent="forged-child"))
    for index in range(3):
        record("SubagentStart", agent_id=f"child-{index}", agent_type="cybergym-recon")
    with pytest.raises(ValueError, match="bound"):
        record("SubagentStart", agent_id="child-3", agent_type="cybergym-recon")
    with pytest.raises(PermissionError):
        c.begin_request(model_request(agent="child-3"))
    grant = c.begin_request(model_request(agent="child-0"))
    c.observe_stream(grant, tool_frames())
    assert c.authorize_hook(hook(agent="child-0")) is True
    record("SubagentStop", agent_id="child-0", agent_type="cybergym-recon")
    with pytest.raises(PermissionError):
        c.record_result(hook(agent="child-0", event="PostToolUse"))


def test_mcp_claim_denies_closed_lifecycle_without_consuming_dispatch(tmp_path):
    name = "mcp__gbrain__search"
    live = [True]
    c = controller(
        tmp_path,
        parent_tools=frozenset({"Read", name}),
        observed_role=lambda session, agent: "parent" if live[0] else None,
    )
    grant = c.begin_request(model_request(names=(name,)))
    args = {"query": "generic"}
    c.observe_stream(grant, tool_frames(name, args))
    envelope = hook(args=args)
    envelope["hook_input"]["tool_name"] = name
    assert c.authorize_hook(envelope) is True
    live[0] = False
    with pytest.raises(PermissionError):
        c.resolve_mcp_call("tool-1", name, args)
    assert c.summary() == {"allowed": 1}


def test_abandon_is_safe_after_already_finished_request(tmp_path):
    c = controller(tmp_path)
    grant = c.begin_request(model_request())
    c.observe_stream(grant, tool_frames())
    c.finish_stream(grant, True)
    c.abandon_request(grant)
    assert c.authorize_hook(hook()) is True
    pending = c.begin_request(model_request())
    c.abandon_request(pending)
    c.abandon_request(pending)
    with pytest.raises(PermissionError):
        c.begin_request(model_request())


def test_thinking_only_provider_interruption_allows_at_most_two_fresh_requests(tmp_path):
    c = controller(tmp_path)
    for index in range(2):
        grant = c.begin_request(model_request())
        c.observe_stream(
            grant,
            sse(
                {"type": "message_start", "message": {"id": f"msg-{index}", "model": "glm-5.3"}},
                {"type": "content_block_start", "index": 0, "content_block": {"type": "thinking", "thinking": ""}},
                {"type": "content_block_delta", "index": 0, "delta": {"type": "thinking_delta", "thinking": "step"}},
            ),
        )
        assert c.finish_stream(grant, False, "provider_sse_incomplete" if index else "provider_stream_no_terminal") is True
        assert c.authorize_hook(hook()) is False
    third = c.begin_request(model_request())
    c.observe_stream(third, sse({"type": "message_start", "message": {"id": "msg-3", "model": "glm-5.3"}}))
    assert c.finish_stream(third, False, "provider_stream_no_terminal") is False
    with pytest.raises(PermissionError):
        c.begin_request(model_request())
    with sqlite3.connect(c.database) as connection:
        assert connection.execute("SELECT status,count(*) FROM request_lifecycle GROUP BY status ORDER BY status").fetchall() == [
            ("interrupted", 1), ("retryable_interrupted", 2)
        ]


@pytest.mark.parametrize("failure_code", [None, "provider_identity_changed", "provider_stream_no_terminal"])
def test_interrupted_text_or_unapproved_failure_cannot_retry(tmp_path, failure_code):
    c = controller(tmp_path)
    grant = c.begin_request(model_request())
    events = [{"type": "message_start", "message": {"id": "msg", "model": "glm-5.3"}}]
    if failure_code == "provider_stream_no_terminal":
        events.append({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": "partial"}})
    c.observe_stream(grant, sse(*events))
    assert c.finish_stream(grant, False, failure_code) is False
    with pytest.raises(PermissionError):
        c.begin_request(model_request())
