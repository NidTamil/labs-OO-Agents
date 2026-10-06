# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Real HTTP/ASGI/native-tool integration with a synthetic provider transport."""

import hashlib
import json
import socket
import sqlite3
from dataclasses import replace

import pytest
from nooa_cybergym.leaderboard.deepseek import AlternateModelPolicy, SharedCampaignBudget
from nooa_cybergym.leaderboard.host_boundary_runtime import AdmittedPeer, GatewayService
from nooa_cybergym.leaderboard.model_gateway import GatewayAudit, ModelPolicy
from nooa_cybergym.leaderboard.native_runtime import NativeModelDispatcher
from nooa_cybergym.leaderboard.native_tool_runtime import NativeToolController

from .test_model_service import CONFIG, StreamResponse, Transport
from .test_native_tool_runtime import hook, model_request, sse, tool_frames


def _exchange(port, host, path, body, headers=()):
    with socket.create_connection(("127.0.0.1", port), timeout=3) as connection:
        extra = "".join(f"{name}: {value}\r\n" for name, value in headers).encode()
        connection.sendall(
            f"POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {len(body)}\r\n".encode()
            + extra
            + b"\r\n"
            + body
        )
        output = b""
        while part := connection.recv(65536):
            output += part
    head, content = output.split(b"\r\n\r\n", 1)
    return int(head.split(b" ")[1]), content


def _dispatcher(tmp_path, response):
    peer = AdmittedPeer("a" * 64, "b" * 64, "127.0.0.1")
    tools = NativeToolController(
        tmp_path / "tools.sqlite",
        task_id="task",
        attempt_id="attempt",
        run_id="run",
        launch_id="launch",
        peer=peer,
        policy_sha256="c" * 64,
        parent_tools=frozenset({"Read", "Bash", "Agent"}),
        child_tools=frozenset({"Read"}),
        captured_schemas={
            name: hashlib.sha256(json.dumps({"name": name}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            for name in ("Read", "Bash", "Agent", "DeniedTool")
        },
        observed_role=lambda session, agent: (
            ("child" if agent else "parent") if session == "session" else None
        ),
        authorize=lambda call: call.name == "Read",
        redact=lambda value: value,
    )
    policy = ModelPolicy(
        primary="glm-5.3[1m]",
        alternate=AlternateModelPolicy.model_validate_json(CONFIG.read_text()),
        capability_policy_sha256="c" * 64,
        approved_zai_coding_plan_url="https://api.z.ai/api/anthropic",
    )
    transport = Transport(response)
    dispatcher = NativeModelDispatcher(
        tools=tools,
        task_token="synthetic-task",
        policy=policy,
        zai_token="synthetic-zai",
        deepseek_key="synthetic-deepseek",
        budget=SharedCampaignBudget(),
        audit=GatewayAudit(tmp_path / "requests.jsonl", tmp_path / "usage.jsonl"),
        mark_started=lambda task, attempt: True,
        transport=transport,
    )
    return dispatcher, tools, transport, peer


@pytest.mark.parametrize("native_path", ["/v1/messages", "/v1/messages?beta=true"])
def test_native_tool_provider_evidence_round_trips_through_actual_http(tmp_path, native_path):
    stream = tool_frames()
    # Include the same complete usage fields required of real provider evidence.
    events = [json.loads(frame[6:]) for frame in stream.split(b"\n\n") if frame]
    events[0]["message"]["usage"] = {
        "input_tokens": 11,
        "cache_read_input_tokens": 0,
        "cache_creation_input_tokens": 0,
    }
    events.insert(-1, {"type": "message_delta", "usage": {"output_tokens": 3}})
    wire = sse(*events)
    response = StreamResponse([wire[i : i + 13] for i in range(0, len(wire), 13)])
    dispatcher, tools, transport, peer = _dispatcher(tmp_path, response)
    with dispatcher:
        with GatewayService(
            ("127.0.0.1", 0),
            {"model-gateway": dispatcher, "registered-tool-gateway": tools.handle},
            lambda _: peer,
            tmp_path / "http.jsonl",
        ) as server:
            request = replace(model_request(), peer=peer, path=native_path)
            status, body = _exchange(server.port, "model-gateway", request.path, request.body)
            assert status == 200 and body == wire, body
            assert tools.summary() == {"observed": 1}
            status, body = _exchange(
                server.port,
                "registered-tool-gateway",
                "/native-tools/authorize",
                json.dumps(hook()).encode(),
            )
            assert status == 200 and json.loads(body)["permissionDecision"] == "allow"
            status, _ = _exchange(
                server.port,
                "registered-tool-gateway",
                "/native-tools/result",
                json.dumps(hook(event="PostToolUse")).encode(),
            )
            assert status == 200
    assert tools.summary() == {"completed": 1}
    assert len(transport.calls) == 1 and response.closed
    with sqlite3.connect(tools.database) as connection:
        assert connection.execute("SELECT status FROM request_lifecycle").fetchall() == [
            ("completed",)
        ]


def test_native_unknown_tool_never_reaches_provider(tmp_path):
    dispatcher, _, transport, peer = _dispatcher(tmp_path, StreamResponse([]))
    with dispatcher:
        with GatewayService(
            ("127.0.0.1", 0), {"model-gateway": dispatcher}, lambda _: peer, tmp_path / "http.jsonl"
        ) as server:
            request = replace(model_request(agent="child-1", names=("Read", "UnfrozenTool")), peer=peer)
            status, _ = _exchange(
                server.port, "model-gateway", request.path, request.body, request.headers
            )
            assert status == 403
    assert not transport.calls


def test_native_advertised_denied_tool_is_absent_from_provider_request(tmp_path):
    dispatcher, tools, transport, peer = _dispatcher(tmp_path, StreamResponse([]))
    request = replace(model_request(names=("Read", "DeniedTool")), peer=peer)
    with dispatcher:
        dispatcher(request)
    assert len(transport.calls) == 1
    assert [item["name"] for item in json.loads(transport.calls[0][2])["tools"]] == ["Read"]
    with sqlite3.connect(tools.database) as connection:
        assert json.loads(connection.execute("SELECT native_roster FROM requests").fetchone()[0]) == ["Read", "DeniedTool"]


def test_native_admission_denial_records_safe_reason_without_request_content(tmp_path):
    dispatcher, _, transport, peer = _dispatcher(tmp_path, StreamResponse([]))
    request = replace(model_request(names=("Read", "UnfrozenTool")), peer=peer)
    with dispatcher:
        response = dispatcher(request)
    assert response.status == 403
    assert not transport.calls
    events = [json.loads(line) for line in (tmp_path / "requests.jsonl").read_text().splitlines()]
    assert len(events) == 1
    assert {key: events[0][key] for key in ("event", "reason", "body_sha256", "body_bytes", "path")} == {
        "event": "native_admission_denied",
        "reason": "native advertised tool schema differs from frozen capture",
        "body_sha256": hashlib.sha256(request.body).hexdigest(),
        "body_bytes": len(request.body),
        "path": "/v1/messages",
    }
    assert events[0]["diagnostic"]["tool_schema_mismatches"][0]["name"] == "unknown"
    assert b"UnfrozenTool" not in (tmp_path / "requests.jsonl").read_bytes()


def test_denial_diagnostic_does_not_log_prompt_or_tool_description(tmp_path):
    dispatcher, _, _, peer = _dispatcher(tmp_path, StreamResponse([]))
    secret = "synthetic-only-private-prompt-marker"
    payload = json.loads(model_request(names=("Read",)).body)
    payload["messages"] = [{"role": "user", "content": secret}]
    payload["tools"][0]["description"] = secret
    request = replace(model_request(), peer=peer, body=json.dumps(payload).encode())
    with dispatcher:
        assert dispatcher(request).status == 403
    audit = (tmp_path / "requests.jsonl").read_text()
    assert secret not in audit
    assert json.loads(audit)["diagnostic"]["tool_schema_mismatches"][0]["name"] == "Read"
    assert json.loads(audit)["diagnostic"]["tool_schema_mismatches"][0]["input_schema_sha256"] == hashlib.sha256(b"null").hexdigest()


def test_provider_failure_is_abandoned_once_and_keeps_original_http_error(tmp_path):
    dispatcher, tools, transport, peer = _dispatcher(tmp_path, StreamResponse([], status=503))
    with dispatcher:
        with GatewayService(
            ("127.0.0.1", 0), {"model-gateway": dispatcher}, lambda _: peer, tmp_path / "http.jsonl"
        ) as server:
            request = replace(model_request(), peer=peer)
            status, body = _exchange(server.port, "model-gateway", request.path, request.body)
            assert status == 502 and json.loads(body)["error"]["type"] == "upstream_unavailable"
    with sqlite3.connect(tools.database) as connection:
        assert connection.execute("SELECT status FROM request_lifecycle").fetchall() == [
            ("interrupted",)
        ]
    assert len(transport.calls) == 1
