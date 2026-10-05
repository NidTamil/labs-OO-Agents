import base64
import hashlib
import json
import os
import sqlite3
from dataclasses import replace

import pytest
from nooa_cybergym.leaderboard.finalization_runtime import NativeFinalizer
from nooa_cybergym.leaderboard.native_tool_runtime import NativeToolCall


@pytest.mark.parametrize(
    "path",
    [
        "/etc/passwd",
        "/workspace/output/../private",
        "/workspace/output/C:\\private",
        "/workspace/output/a/../candidate.bin",
        "/workspace/output/agent-final.json",
    ],
)
def test_candidate_scope_is_checked_before_selection_is_reserved(tmp_path, path):
    finalizer, call, output = fixture(tmp_path)
    with pytest.raises((ValueError, RuntimeError)):
        finalizer.select_final(replace(call, arguments={**call.arguments, "candidate_path": path}))
    assert not (output / "agent-final.json").exists()
    assert finalizer.select_final(call)["selected"] is True


def test_candidate_hash_is_checked_before_critic_and_reservation(tmp_path):
    critics = []
    finalizer, call, output = fixture(tmp_path, critics.append)
    with pytest.raises(RuntimeError, match="hash|changed"):
        finalizer.select_final(replace(call, arguments={**call.arguments, "sha256": "f" * 64}))
    assert critics == []
    assert not (output / "agent-final.json").exists()
    assert finalizer.select_final(call)["selected"] is True


def test_critic_snapshot_reads_actual_candidate_with_full_hash_and_bounded_bytes(tmp_path):
    finalizer, call, output = fixture(tmp_path)
    snapshot = finalizer.snapshot_candidate(
        call.arguments["candidate_path"], call.arguments["sha256"]
    )
    assert base64.b64decode(snapshot["content_base64"]) == b"synthetic fixture"
    assert snapshot["truncated"] is False
    assert not (output / "agent-final.json").exists()
    large = b"x" * (128 * 1024)
    (output / "candidate.bin").write_bytes(large)
    with pytest.raises(RuntimeError, match="hash|changed"):
        finalizer.snapshot_candidate(call.arguments["candidate_path"], call.arguments["sha256"])
    snapshot = finalizer.snapshot_candidate(
        call.arguments["candidate_path"], hashlib.sha256(large).hexdigest()
    )
    assert snapshot["truncated"] is True
    assert snapshot["byte_length"] == len(large)
    assert snapshot["captured_bytes"] == 64 * 1024
    assert base64.b64decode(snapshot["content_base64"]) == large[: 64 * 1024]


def test_simultaneous_final_selections_produce_only_one_durable_declaration(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    finalizer, call, output = fixture(tmp_path)
    second = NativeFinalizer(
        output,
        finalizer.evidence,
        task_id="task",
        attempt_id="attempt",
        require_critic=lambda _: None,
    )

    def select(instance):
        try:
            return instance.select_final(call)["selected"]
        except RuntimeError:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(select, [finalizer, second])) == [False, True]
    assert finalizer.lock_after_stop(lambda: True).sha256 == call.arguments["sha256"]


def test_database_cannot_be_rebound_to_another_task_before_selection(tmp_path):
    finalizer, _, output = fixture(tmp_path)
    with pytest.raises(ValueError, match="another|identity"):
        NativeFinalizer(
            output,
            finalizer.evidence,
            task_id="other",
            attempt_id="attempt",
            require_critic=lambda _: None,
        )


def test_changed_candidate_consumes_lock_attempt_across_restart(tmp_path):
    finalizer, call, output = fixture(tmp_path)
    finalizer.select_final(call)
    (output / "candidate.bin").write_bytes(b"changed")
    with pytest.raises(RuntimeError, match="changed|hash"):
        finalizer.lock_after_stop(lambda: True)
    assert not (finalizer.evidence / "final").exists()
    assert list(finalizer.evidence.glob(".final-stage-*")) == []
    (output / "candidate.bin").write_bytes(b"synthetic fixture")
    restarted = NativeFinalizer(
        output,
        finalizer.evidence,
        task_id="task",
        attempt_id="attempt",
        require_critic=lambda _: None,
    )
    with pytest.raises(RuntimeError, match="lock.*attempt|already"):
        restarted.lock_after_stop(lambda: True)


def test_ambiguous_declaration_write_cannot_be_retried_or_locked(tmp_path, monkeypatch):
    from nooa_cybergym.leaderboard import finalization_runtime as runtime

    finalizer, call, output = fixture(tmp_path)

    def broken_sync(descriptor):
        raise OSError("synthetic disk failure")

    with monkeypatch.context() as patch:
        patch.setattr(runtime.os, "fsync", broken_sync)
        with pytest.raises(OSError):
            finalizer.select_final(call)
    with pytest.raises(RuntimeError, match="already"):
        finalizer.select_final(call)
    # A later solver-authored declaration must never repair an incomplete controller write.
    with sqlite3.connect(finalizer.database) as connection:
        declaration = connection.execute("SELECT declaration FROM selection").fetchone()[0]
    (output / "agent-final.json").write_bytes(declaration)
    with pytest.raises(RuntimeError, match="incomplete|declared"):
        finalizer.lock_after_stop(lambda: True)


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlink isolation")
@pytest.mark.parametrize("linked", ["output", "evidence"])
def test_linked_ancestor_is_rejected(tmp_path, linked):
    real = tmp_path / "real"
    (real / "output").mkdir(parents=True)
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    output = alias / "output" if linked == "output" else real / "output"
    evidence = alias / "evidence" if linked == "evidence" else tmp_path / "evidence"
    with pytest.raises(ValueError, match="controller|linked|absolute"):
        NativeFinalizer(
            output, evidence, task_id="task", attempt_id="attempt", require_critic=lambda _: None
        )


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlink isolation")
def test_candidate_symlink_and_database_sidecar_link_are_rejected(tmp_path):
    finalizer, call, output = fixture(tmp_path)
    (output / "candidate.bin").rename(tmp_path / "private")
    (output / "candidate.bin").symlink_to(tmp_path / "private")
    with pytest.raises(RuntimeError, match="symlink|linked"):
        finalizer.select_final(call)
    (output / "candidate.bin").unlink()
    (output / "candidate.bin").write_bytes(b"synthetic fixture")
    (finalizer.evidence / "native-final.sqlite-journal").symlink_to(tmp_path / "private")
    with pytest.raises((ValueError, RuntimeError), match="link|database"):
        finalizer.select_final(call)


def native_controller(tmp_path, args, *, role="parent", provider_model="glm-5.3", authorized=True):
    from nooa_cybergym.leaderboard.host_boundary_runtime import AdmittedPeer, GatewayRequest
    from nooa_cybergym.leaderboard.native_tool_runtime import NativeToolController

    peer = AdmittedPeer("a" * 64, "b" * 64, "172.20.0.2")
    name = "mcp__finalizer__select_final"
    agent = "child-1" if role == "child" else None
    controller = NativeToolController(
        tmp_path / "tools.sqlite",
        task_id="task",
        attempt_id="attempt",
        run_id="run",
        launch_id="launch",
        peer=peer,
        policy_sha256="c" * 64,
        parent_tools=frozenset({name}),
        child_tools=frozenset({name}),
        captured_schemas={name: hashlib.sha256(json.dumps({"name": name}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()},
        observed_role=lambda session, observed: (
            role if (session, observed) == ("session", agent) else None
        ),
        authorize=lambda _: authorized,
        redact=lambda value: value,
    )
    request = GatewayRequest(
        "model-gateway",
        "POST",
        "/v1/messages",
        (("x-claude-code-agent-id", agent),) if agent else (),
        json.dumps(
            {
                "model": "glm-5.3",
                "metadata": {"user_id": json.dumps({"session_id": "session"})},
                "stream": True,
                "max_tokens": 128000,
                "thinking": {"type": "adaptive"},
                "output_config": {"effort": "max"},
                "tools": [{"name": name}],
            }
        ).encode(),
        peer,
    )
    grant = controller.begin_request(request)
    events = [
        {"type": "message_start", "message": {"id": "message", "model": provider_model}},
        {
            "type": "content_block_start",
            "index": 0,
            "content_block": {"type": "tool_use", "id": "tool-final", "name": name, "input": {}},
        },
        {
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "input_json_delta", "partial_json": json.dumps(args)},
        },
        {"type": "content_block_stop", "index": 0},
        {"type": "message_stop"},
    ]
    controller.observe_stream(
        grant, b"".join(("data: " + json.dumps(event) + "\n\n").encode() for event in events)
    )
    controller.finish_stream(grant, True)
    admitted = controller.authorize_hook(
        {
            "schema_version": 1,
            "run_id": "run",
            "task_id": "task",
            "launch_id": "launch",
            "hook_input": {
                "hook_event_name": "PreToolUse",
                "session_id": "session",
                "agent_id": agent,
                "tool_use_id": "tool-final",
                "tool_name": name,
                "tool_input": args,
            },
        }
    )
    assert admitted is authorized
    return controller, peer


def rpc(peer, args, *, method="tools/call", params=None):
    from nooa_cybergym.leaderboard.host_boundary_runtime import GatewayRequest

    return GatewayRequest(
        "registered-tool-gateway",
        "POST",
        "/mcp/finalizer",
        (),
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params
                if params is not None
                else {
                    "name": "select_final",
                    "arguments": args,
                    "_meta": {"claudecode/toolUseId": "tool-final"},
                },
            }
        ).encode(),
        peer,
    )


def test_mcp_consumes_actual_provider_call_once_and_binds_proof(tmp_path):
    from nooa_cybergym.leaderboard.finalization_runtime import finalization_mcp_handler

    critic_hashes = []
    finalizer, call, _ = fixture(tmp_path, critic_hashes.append)
    controller, peer = native_controller(tmp_path, dict(call.arguments))
    handler = finalization_mcp_handler(
        finalizer, peer=peer, resolve_parent_call=controller.resolve_mcp_call
    )
    assert (
        handler(
            rpc(
                peer,
                {},
                method="initialize",
                params={
                    "protocolVersion": "2025-03-26",
                    "clientInfo": {"name": "test", "version": "1"},
                    "capabilities": {},
                },
            )
        ).status
        == 200
    )
    assert (
        json.loads(handler(rpc(peer, {}, method="tools/list", params={})).body)["result"]["tools"][
            0
        ]["name"]
        == "select_final"
    )
    receipt = handler(rpc(peer, dict(call.arguments)))
    assert receipt.status == 200
    assert critic_hashes == [call.arguments["sha256"]]
    request = rpc(
        peer,
        {},
        params={
            "name": "select_final",
            "arguments": dict(call.arguments),
            "_meta": {"claudecode/toolUseId": "tool-final", "role": "parent"},
        },
    )
    assert handler(replace(request, headers=(("x-role", "parent"),))).status == 403
    assert controller.summary()["dispatched"] == 1
    locked = finalizer.lock_after_stop(lambda: True)
    assert locked.sha256 == call.arguments["sha256"]
    assert (
        locked.parent_event_digest
        == json.loads(json.loads(receipt.body)["result"]["content"][0]["text"])[
            "native_event_digest"
        ]
    )


@pytest.mark.parametrize("role,authorized", [("child", True), ("parent", False)])
def test_mcp_rejects_child_or_unapproved_parent_provider_call(tmp_path, role, authorized):
    from nooa_cybergym.leaderboard.finalization_runtime import finalization_mcp_handler

    finalizer, call, output = fixture(tmp_path)
    controller, peer = native_controller(
        tmp_path, dict(call.arguments), role=role, authorized=authorized
    )
    handler = finalization_mcp_handler(
        finalizer, peer=peer, resolve_parent_call=controller.resolve_mcp_call
    )
    request = rpc(
        peer,
        {},
        params={
            "name": "select_final",
            "arguments": dict(call.arguments),
            "_meta": {"claudecode/toolUseId": "tool-final", "role": "parent"},
        },
    )
    assert handler(replace(request, headers=(("x-role", "parent"),))).status == 403
    assert not (output / "agent-final.json").exists()


def test_provider_model_mismatch_never_creates_parent_authority(tmp_path):
    _, call, _ = fixture(tmp_path)
    with pytest.raises(PermissionError):
        native_controller(tmp_path, dict(call.arguments), provider_model="other-model")


def test_missing_critic_consumes_mcp_call_without_retry_after_later_completion(tmp_path):
    from nooa_cybergym.leaderboard.finalization_runtime import finalization_mcp_handler

    def incomplete(_):
        raise RuntimeError("critic is incomplete")

    finalizer, call, output = fixture(tmp_path, incomplete)
    controller, peer = native_controller(tmp_path, dict(call.arguments))
    handler = finalization_mcp_handler(
        finalizer, peer=peer, resolve_parent_call=controller.resolve_mcp_call
    )
    request = rpc(peer, dict(call.arguments))
    assert handler(request).status == 503
    finalizer.require_critic = lambda _: None
    assert handler(request).status == 403
    assert not (output / "agent-final.json").exists()


def test_actual_advisory_critic_and_provider_parent_join_on_candidate_bytes(tmp_path):
    """Actual controllers with explicitly synthetic GLM/DeepSeek provider fixtures."""
    from contextlib import nullcontext
    from pathlib import Path

    from nooa_cybergym.leaderboard.advisory_runtime import AdvisoryRuntime
    from nooa_cybergym.leaderboard.deepseek import (
        AlternateModelPolicy,
        DeepSeekController,
        ProviderResponse,
        SharedCampaignBudget,
    )
    from nooa_cybergym.leaderboard.finalization_runtime import finalization_mcp_handler

    class Audit:
        def record(self, event):
            return True

    class Transport:
        def __init__(self):
            self.calls = []

        def send(self, endpoint, headers, payload, timeout):
            self.calls.append(payload)
            advice = {
                "action": "advice",
                "summary": "Synthetic fixture critique",
                "evidence": [],
                "risks": [],
            }
            return ProviderResponse(
                200,
                {
                    "id": f"synthetic-{len(self.calls)}",
                    "model": "deepseek-flash",
                    "choices": [{"message": {"content": json.dumps(advice)}}],
                    "usage": {
                        "prompt_tokens": 10,
                        "completion_tokens": 10,
                        "total_tokens": 20,
                        "prompt_cache_hit_tokens": 0,
                        "prompt_cache_miss_tokens": 10,
                    },
                },
            )

    finalizer, call, output = fixture(tmp_path)
    policy = AlternateModelPolicy.model_validate_json(
        (
            Path(__file__).resolve().parents[2] / "leaderboard/config/alternate-model.json"
        ).read_bytes()
    )
    transport = Transport()
    deepseek = DeepSeekController(
        policy,
        "synthetic-provider-secret",
        audit=Audit(),
        registry_digest="d" * 64,
        budget=SharedCampaignBudget(),
        transport=transport,
    )
    advisory = AdvisoryRuntime(
        deepseek,
        database=tmp_path / "advisory.sqlite",
        run_id="run",
        task_id="task",
        attempt_id="attempt",
        launch_id="launch",
        task_brief="Synthetic fixture",
        tools={
            name: lambda args, role: {}
            for name in ("local_read", "clangd_read", "gbrain_recall", "gbrain_search")
        },
        mark_started=lambda task, attempt: True,
        child_slot=lambda role: nullcontext(),
        redact=lambda value: value,
        resolve_candidate=finalizer.snapshot_candidate,
    )
    finalizer.require_critic = advisory.require_critic
    with pytest.raises(RuntimeError, match="recon|critic"):
        finalizer.select_final(call)
    assert not (output / "agent-final.json").exists()
    advisory.run_recon()
    with pytest.raises(RuntimeError, match="critic"):
        finalizer.select_final(call)
    advisory.run_critic(
        candidate_path=call.arguments["candidate_path"],
        candidate_sha256=call.arguments["sha256"],
        candidate_context="Untrusted description must not substitute for bytes",
    )
    critic_payload = json.dumps(transport.calls[-1])
    assert base64.b64encode(b"synthetic fixture").decode() in critic_payload
    controller, peer = native_controller(tmp_path, dict(call.arguments))
    handler = finalization_mcp_handler(
        finalizer, peer=peer, resolve_parent_call=controller.resolve_mcp_call
    )
    assert handler(rpc(peer, dict(call.arguments))).status == 200
    assert finalizer.lock_after_stop(lambda: True).poc_path.read_bytes() == b"synthetic fixture"


def test_mcp_peer_arguments_and_metadata_are_verified_before_consumption(tmp_path):
    from nooa_cybergym.leaderboard.finalization_runtime import finalization_mcp_handler

    finalizer, call, _ = fixture(tmp_path)
    controller, peer = native_controller(tmp_path, dict(call.arguments))
    handler = finalization_mcp_handler(
        finalizer, peer=peer, resolve_parent_call=controller.resolve_mcp_call
    )
    request = rpc(peer, dict(call.arguments))
    assert handler(replace(request, peer=replace(peer, network_id="other"))).status == 403
    assert handler(rpc(peer, {**call.arguments, "selection_reason": "changed"})).status == 403
    for meta in ({}, {"claudecode/toolUseId": None}):
        assert (
            handler(
                rpc(
                    peer,
                    {},
                    params={
                        "name": "select_final",
                        "arguments": dict(call.arguments),
                        "_meta": meta,
                    },
                )
            ).status
            == 403
        )
    assert handler(replace(request, body=b'{"jsonrpc":"2.0","jsonrpc":"2.0"}')).status == 400
    assert (
        handler(
            rpc(
                peer,
                {},
                params={
                    "name": "select_final",
                    "arguments": dict(call.arguments),
                    "_meta": {
                        "claudecode/toolUseId": "tool-final",
                        "progressToken": 1,
                        "context": {"trace": "inert"},
                    },
                },
            )
        ).status
        == 200
    )


def fixture(tmp_path, critic=lambda _: None):
    output = tmp_path / "task" / "output"
    output.mkdir(parents=True)
    (output / "candidate.bin").write_bytes(b"synthetic fixture")
    digest = hashlib.sha256(b"synthetic fixture").hexdigest()
    args = {
        "candidate_path": "/workspace/output/candidate.bin",
        "sha256": digest,
        "byte_length": 17,
        "selection_reason": "synthetic test",
    }
    call = NativeToolCall(
        "task",
        "attempt",
        "request",
        "session",
        None,
        "parent",
        "tool-final",
        "mcp__finalizer__select_final",
        args,
    )
    finalizer = NativeFinalizer(
        output, tmp_path / "evidence", task_id="task", attempt_id="attempt", require_critic=critic
    )
    return finalizer, call, output


def test_parent_only_single_final_is_bound_to_actual_tool_arguments(tmp_path):
    finalizer, call, output = fixture(tmp_path)
    with pytest.raises(PermissionError):
        finalizer.select_final(replace(call, role="child", agent_id="child"))
    receipt = finalizer.select_final(call)
    assert receipt["selected"] is True
    with pytest.raises(RuntimeError):
        finalizer.select_final(call)
    with pytest.raises(RuntimeError, match="stopped"):
        finalizer.lock_after_stop(lambda: False)
    locked = finalizer.lock_after_stop(lambda: True)
    assert locked.sha256 == call.arguments["sha256"]
    assert locked.poc_path.read_bytes() == b"synthetic fixture"


def test_critic_is_required_and_changed_candidate_cannot_be_locked(tmp_path):
    def blocked(_):
        raise RuntimeError("critic not completed")

    finalizer, call, output = fixture(tmp_path, blocked)
    with pytest.raises(RuntimeError, match="critic"):
        finalizer.select_final(call)
    assert not (output / "agent-final.json").exists()
    finalizer.require_critic = lambda _: None
    finalizer.select_final(call)
    (output / "candidate.bin").write_bytes(b"changed")
    with pytest.raises(RuntimeError, match="changed|hash"):
        finalizer.lock_after_stop(lambda: True)
