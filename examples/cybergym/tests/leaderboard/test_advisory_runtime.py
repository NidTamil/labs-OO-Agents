"""Real DeepSeekController exercised with a synthetic provider transport."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from contextlib import nullcontext
from pathlib import Path

import pytest
from nooa_cybergym.leaderboard.deepseek import (
    AlternateModelPolicy,
    DeepSeekController,
    ProviderResponse,
    SharedCampaignBudget,
)


def test_advisory_runtime_exists():
    assert importlib.util.find_spec("nooa_cybergym.leaderboard.advisory_runtime") is not None


@pytest.fixture
def setup(tmp_path):
    from nooa_cybergym.leaderboard.advisory_runtime import AdvisoryRuntime

    class Audit:
        def __init__(self):
            self.events = []

        def record(self, event):
            self.events.append(event)
            return True

    class Transport:
        def __init__(self):
            self.calls = []
            self.actions = []

        def send(self, endpoint, headers, payload, timeout):
            self.calls.append(payload)
            action = self.actions.pop(0)
            content = action if isinstance(action, str) else json.dumps(action)
            return ProviderResponse(
                200,
                {
                    "id": f"request-{len(self.calls)}",
                    "model": "deepseek-flash",
                    "choices": [{"message": {"content": content}}],
                    "usage": {
                        "prompt_tokens": 10,
                        "completion_tokens": 10,
                        "total_tokens": 20,
                        "prompt_cache_hit_tokens": 0,
                        "prompt_cache_miss_tokens": 10,
                    },
                },
            )

    policy = AlternateModelPolicy.model_validate_json(
        (
            Path(__file__).resolve().parents[2] / "leaderboard/config/alternate-model.json"
        ).read_bytes()
    )
    audit = Audit()
    transport = Transport()
    budget = SharedCampaignBudget()
    controller = DeepSeekController(
        policy,
        "synthetic-provider-secret",
        audit=audit,
        registry_digest="a" * 64,
        budget=budget,
        transport=transport,
    )
    calls = []
    started = []
    tools = {
        name: lambda args, role, action, name=name: (
            calls.append((name, args, role, action)) or {"data": "untrusted synthetic-source"}
        )
        for name in ("local_read", "clangd_read", "gbrain_recall", "gbrain_search")
    }

    def create():
        return AdvisoryRuntime(
            controller,
            database=tmp_path / "advisory.sqlite3",
            run_id="run-1",
            task_id="synthetic:1",
            attempt_id="attempt-1",
            launch_id="launch-1",
            task_brief="Synthetic vulnerable task description",
            tools=tools,
            mark_started=lambda task, attempt: started.append((task, attempt)) or True,
            child_slot=lambda role: nullcontext(),
            redact=lambda value: value,
            resolve_candidate=lambda path, digest: {
                "candidate_path": path,
                "sha256": digest,
                "byte_length": 3,
                "content_base64": base64.b64encode(b"poc").decode(),
                "captured_bytes": 3,
                "truncated": False,
            },
        )

    return create(), create, controller, transport, budget, calls, started


def test_independent_recon_uses_budgeted_real_controller_and_readonly_actions(setup):
    runtime, create, _, transport, budget, calls, started = setup
    transport.actions = [
        {
            "action": "local_read",
            "arguments": {
                "operation": "read",
                "path": "src/main.c",
                "start_line": 1,
                "max_lines": 50,
            },
        },
        {
            "action": "advice",
            "summary": "Bounds check is missing.",
            "evidence": ["src/main.c:4"],
            "risks": [],
        },
    ]
    result = runtime.run_recon()
    assert result["summary"] == "Bounds check is missing."
    assert len(calls) == 1 and calls[0][0] == "local_read"
    assert calls[0][3].provider_request_id == "request-1"
    assert calls[0][3].task_id == "synthetic:1"
    assert calls[0][3].name == "local_read"
    assert len(started) == 1
    assert budget.snapshot()["deepseek_requests"] == 2
    protocol = transport.calls[0]["messages"][0]["content"]
    assert '"action":"CAPABILITY"' not in protocol
    assert '"action":"local_read"' in protocol
    assert '"path":"/workspace/src"' in protocol
    assert all(
        request["reasoning_effort"] == "max" and request["thinking"] == {"type": "enabled"}
        for request in transport.calls
    )
    assert "untrusted_tool_observation" in transport.calls[-1]["messages"][-1]["content"]
    assert create().recon_status()["status"] == "complete"
    with pytest.raises(RuntimeError, match="already reserved"):
        create().run_recon()


def test_debug_requires_controller_admitted_failure_and_no_model_can_supply_it(setup):
    runtime, _, controller, transport, _, _, _ = setup
    with pytest.raises(RuntimeError, match="observed vulnerable failure"):
        runtime.run_debug("Check observed failure")
    assert not transport.calls
    failure = controller.admit_failure(
        task_id="synthetic:1",
        attempt_id="attempt-1",
        source="vulnerable_test",
        exit_code=1,
        evidence_digest="b" * 64,
    )
    runtime.observe_vulnerable_failure(failure)
    transport.actions = [
        {"action": "advice", "summary": "Inspect the length.", "evidence": [], "risks": []}
    ]
    assert runtime.run_debug("Check observed failure")["role"] == "conditional_debug_recovery"


def test_critic_is_bound_to_candidate_and_requires_recon(setup):
    runtime, _, _, transport, _, _, _ = setup
    with pytest.raises(RuntimeError, match="recon"):
        runtime.run_critic(
            candidate_path="/workspace/output/poc.bin",
            candidate_sha256="c" * 64,
            candidate_context="Current candidate rationale",
        )
    transport.actions = [
        {"action": "advice", "summary": "Recon complete.", "evidence": [], "risks": []}
    ]
    runtime.run_recon()
    transport.actions = [
        {
            "action": "advice",
            "summary": "Candidate has an unchecked assumption.",
            "evidence": [],
            "risks": ["length constraint"],
        }
    ]
    digest = hashlib.sha256(b"poc").hexdigest()
    runtime.run_critic(
        candidate_path="/workspace/output/poc.bin",
        candidate_sha256=digest,
        candidate_context="Current candidate rationale",
    )
    runtime.require_critic(digest)
    assert "cG9j" in transport.calls[-1]["messages"][1]["content"]
    with pytest.raises(RuntimeError, match="candidate"):
        runtime.require_critic("d" * 64)


def test_critic_rejects_controller_snapshot_bytes_not_matching_claimed_hash(setup):
    runtime, _, _, transport, *_ = setup
    transport.actions = [
        {"action": "advice", "summary": "Recon complete.", "evidence": [], "risks": []}
    ]
    runtime.run_recon()
    with pytest.raises(ValueError, match="snapshot"):
        runtime.run_critic(
            candidate_path="/workspace/output/poc.bin",
            candidate_sha256="a" * 64,
            candidate_context="Claimed candidate",
        )
    assert len(transport.calls) == 1


def test_undeclared_action_is_a_terminal_role_failure_without_retry(setup):
    runtime, create, _, transport, budget, calls, _ = setup
    transport.actions = [{"action": "Bash", "arguments": {"command": "curl secret"}}]
    with pytest.raises(RuntimeError, match="advisory role failed"):
        runtime.run_recon()
    assert not calls and budget.snapshot()["deepseek_requests"] == 1
    assert create().recon_status()["status"] == "failed"
    with pytest.raises(RuntimeError, match="already reserved"):
        create().run_recon()


def test_malformed_advisory_json_repairs_without_executing_hallucinated_tools(setup):
    runtime, _, _, transport, budget, calls, _ = setup
    transport.actions = [
        '{"action":"local_read","arguments":{"operation":"list","path":"/workspace/src"}}\n<DSML fake tool response>',
        {"action": "local_read", "arguments": {"operation": "list", "path": "/workspace/src"}},
        {"action": "advice", "summary": "Inspect the parser bounds.", "evidence": [], "risks": []},
    ]
    assert runtime.run_recon()["summary"] == "Inspect the parser bounds."
    assert len(calls) == 1
    assert budget.snapshot()["deepseek_requests"] == 3
    assert "fake tool response" not in json.dumps(transport.calls[1]["messages"])


def test_mcp_only_accepts_correlated_parent_calls(setup):
    from nooa_cybergym.leaderboard.advisory_runtime import advisory_mcp_handler
    from nooa_cybergym.leaderboard.host_boundary_runtime import AdmittedPeer, GatewayRequest

    runtime, *_ = setup
    peer = AdmittedPeer("container-1", "network-1", "172.30.0.2")
    handler = advisory_mcp_handler(
        runtime, peer=peer, resolve_parent_call=lambda request, body: False
    )
    request = GatewayRequest(
        "registered-tool-gateway",
        "POST",
        "/advisor/mcp",
        (),
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "debug",
                    "arguments": {"question": "help"},
                    "_meta": {"claudecode/toolUseId": "tool-1"},
                },
            }
        ).encode(),
        peer,
    )
    assert handler(request).status == 403


def test_advisory_negotiates_actual_native_latest_mcp_protocol(setup):
    from nooa_cybergym.leaderboard.advisory_runtime import advisory_mcp_handler
    from nooa_cybergym.leaderboard.host_boundary_runtime import AdmittedPeer, GatewayRequest

    runtime, *_ = setup
    peer = AdmittedPeer("container-1", "network-1", "172.30.0.2")
    handler = advisory_mcp_handler(runtime, peer=peer, resolve_parent_call=lambda *_: False)
    request = GatewayRequest(
        "registered-tool-gateway",
        "POST",
        "/advisor/mcp",
        (),
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "clientInfo": {"name": "claude-code", "version": "2.1.289"},
                    "capabilities": {},
                },
            }
        ).encode(),
        peer,
    )
    response = handler(request)
    assert response.status == 200
    assert json.loads(response.body)["result"]["protocolVersion"] == "2025-11-25"
