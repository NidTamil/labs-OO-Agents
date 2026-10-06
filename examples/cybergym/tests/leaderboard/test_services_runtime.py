# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Real service composition with synthetic external provider/stdio transports.

No test here is a native image or remote provider certification claim.
"""

import asyncio
import hashlib
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from nooa_cybergym.leaderboard.capabilities import CapabilityRegistry, Role
from nooa_cybergym.leaderboard.capability_runtime import CapabilityRuntime, ObservedPath
from nooa_cybergym.leaderboard.deepseek import ENDPOINT, AlternateModelPolicy
from nooa_cybergym.leaderboard.host_boundary_runtime import AdmittedPeer, GatewayRequest
from nooa_cybergym.leaderboard.model_gateway import ModelPolicy
from nooa_cybergym.leaderboard.native_hook_runtime import project_hook_input
from nooa_cybergym.leaderboard.native_launcher import NativeLaunchAuthority, build_launch_manifest
from nooa_cybergym.leaderboard.native_tool_runtime import NativeToolCall
from nooa_cybergym.leaderboard.native_workflows import frozen_workflows
from nooa_cybergym.leaderboard.network import NetworkPolicy
from nooa_cybergym.leaderboard.runtime_custody import TaskRuntimeContext
from nooa_cybergym.leaderboard.services_runtime import NativeServices, SealedRoutes
from nooa_cybergym.leaderboard.tool_services_runtime import ClangdClient
from nooa_cybergym.leaderboard.vulnerable_runtime import VulnerableRecipe
from xeus_cybergym.canonical import canonical_json

from .test_capability_runtime import TASK, bundle
from .test_memory_runtime import NativePeer, authority
from .test_model_service import CONFIG, PRIMARY_CHUNKS, StreamResponse, Transport
from .test_native_tool_runtime import model_request


def captured_schemas(bindings):
    return {
        binding.native_name: hashlib.sha256(binding.schema_json.encode()).hexdigest()
        for binding in bindings
        if not binding.native_name.startswith("advisory__")
    }


class ExternalBridge(NativePeer):
    def __init__(self, command, *, budget, audit, allowed_models):
        super().__init__()
        self.budget, self.audit, self.closed = budget, audit, False
        self.fail_recall = False

    def exchange(self, message, *, timeout_seconds):
        if self.closed:
            raise RuntimeError("external bridge closed")
        if message["method"] == "tools/call":
            number = self.budget.reserve_request()
            self.audit.record({"event": "memory_model_admitted", "shared_request_number": number})
            if self.fail_recall:
                raise RuntimeError("synthetic external recall failure")
            self.audit.record({"event": "memory_model_settled", "shared_request_number": number})
        return super().exchange(message, timeout_seconds=timeout_seconds)

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def provider_answer():
    return httpx.Response(
        200,
        json={
            "id": "synthetic-deepseek-1",
            "model": "deepseek-flash",
            "choices": [
                {
                    "message": {
                        "content": json.dumps(
                            {
                                "action": "advice",
                                "summary": "Synthetic external fixture",
                                "evidence": [],
                                "risks": [],
                            }
                        )
                    }
                }
            ],
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 10,
                "total_tokens": 20,
                "prompt_cache_hit_tokens": 0,
                "prompt_cache_miss_tokens": 10,
            },
        },
    )


@pytest.fixture
def assembled(tmp_path):
    from nooa_cybergym.leaderboard.services_runtime import CancellableDeepSeekTransport

    evidence, output, assets = (
        tmp_path / "evidence",
        tmp_path / "workspace/output",
        tmp_path / "assets",
    )
    for path in (evidence, output, assets):
        path.mkdir(mode=0o700, parents=True)
    context = TaskRuntimeContext(
        evidence,
        task_id=TASK,
        attempt_id="attempt-1",
        secrets=("synthetic-zai", "synthetic-deepseek"),
    )
    built = bundle(assets)
    peer = AdmittedPeer("c" * 64, "b" * 64, "172.20.0.2")
    gate = CapabilityRuntime(
        registry=built.registry,
        expected_registry_sha256=built.registry.digest,
        bindings=built.bindings,
        peer=peer,
        task_id=TASK,
        attempt_id="attempt-1",
        audit=context.audit,
        path_observer=lambda path: ObservedPath(path, path, True, "file"),
        boundary_check=lambda p: p == peer,
        working_directory="/workspace",
        execution_paths=("/workspace/src", "/workspace/output"),
        execution_routes=(),
        model_id="glm-5.3",
        structural_terms=("buffer",),
        synthetic_task_ids=frozenset({TASK}),
        network_policy=NetworkPolicy.load(CONFIG.with_name("network-policy.json")),
    )
    signer, verifier, keys = authority()
    manifest = build_launch_manifest(
        scope="synthetic",
        run_id="run",
        task_id=TASK,
        launch_id="launch",
        ordinal=1,
        harness_sha256="a" * 64,
        task_manifest_bytes=b'{"synthetic":true}',
        file_hashes={"CLAUDE.md": "e" * 64},
        container_id=peer.container_id,
        hostname="c" * 12,
        uid=1000,
        pid_namespace="pid:[100]",
        mount_namespace="mnt:[200]",
        vscode_version="1.140.0",
        claude_extension_version="2.1.289",
        claude_extension_sha256="d" * 64,
        native_launch_url="http://registered-tool-gateway/native-launch",
    )
    launch = NativeLaunchAuthority.from_signed_envelope(
        signer.sign(canonical_json(manifest)).model_dump_json().encode(), keys, evidence
    )
    model = Transport(StreamResponse(PRIMARY_CHUNKS))
    external_channel = SimpleNamespace(close=lambda: None, compile_database_sha256="f" * 64)

    def clangd_factory(api, *, container_id, source_roots, compile_commands):
        return ClangdClient(
            external_channel,
            read_source=lambda _: "synthetic source",
            source_roots=source_roots,
            container_id=container_id,
        )

    args = {
        "run_id": "run",
        "task_id": TASK,
        "attempt_id": "attempt-1",
        "launch_id": "launch",
        "evidence": evidence,
        "output": output,
        "peer": peer,
        "docker_client": SimpleNamespace(api=object()),
        "container": SimpleNamespace(id=peer.container_id),
        "capabilities": gate,
        "context": context,
        "model_policy": ModelPolicy(
            primary="glm-5.3[1m]",
            alternate=AlternateModelPolicy.model_validate_json(CONFIG.read_text()),
            capability_policy_sha256=built.registry.digest,
            approved_zai_coding_plan_url="https://api.z.ai/api/anthropic",
        ),
        "network_policy": NetworkPolicy.load(CONFIG.with_name("network-policy.json")),
        "launch_authority": launch,
        "zai_token": "synthetic-zai",
        "deepseek_key": "synthetic-deepseek",
        "gbrain_command": ("synthetic-external",),
        "gbrain_models": {},
        "signer": signer,
        "verifier": verifier,
        "public_keys": keys,
        "task_brief": "Synthetic parser fixture",
        "structural_terms": ("buffer",),
        "vulnerable_recipe": VulnerableRecipe(
            ("/usr/bin/true",), ("/tmp/vulnerable", "{candidate}"), "/workspace/src", 30, 30
        ),
        "captured_schemas": captured_schemas(built.bindings),
        "model_transport": model,
        "deepseek_transport": CancellableDeepSeekTransport(
            transport=httpx.MockTransport(lambda _: provider_answer())
        ),
        "bridge_factory": ExternalBridge,
        "clangd_factory": clangd_factory,
    }
    created = []

    def create(**changes):
        service = NativeServices(**(args | changes))
        created.append(service)
        return service

    yield SimpleNamespace(create=create, args=args, context=context, peer=peer, model=model)
    for service in created:
        service.close()
    args["deepseek_transport"].close()
    context.close()


def request(peer, endpoint="registered-tool-gateway", path="/mcp/clangd"):
    return GatewayRequest(
        endpoint,
        "POST",
        path,
        (),
        b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}',
        peer,
    )


def test_all_controllers_share_context_and_real_native_model_lifecycle(assembled):
    service = assembled.create()
    assert service.audit is service.capabilities.audit is assembled.context.audit
    assert (
        service.budget
        is service.bridge.budget
        is service.deepseek.budget
        is service.models.gateway._budget
        is assembled.context.budget
    )
    model = replace(model_request(names=("Read",)), peer=assembled.peer)
    model_payload = json.loads(model.body)
    model_payload["tools"] = [
        json.loads(binding.schema_json)
        for binding in service.capabilities.bindings
        if binding.native_name == "Read"
    ]
    model = replace(model, body=json.dumps(model_payload).encode())
    assert service.handlers["model-gateway"](model).status == 503
    assert (
        service.start_automatic_lanes(level1_facts=("buffer parser",), structural_terms=("buffer",))
        == ()
    )
    service._recon_future.result(timeout=5)
    assert service.start.started
    service.hooks.ingest(
        {
            "schema_version": 1,
            "event_id": str(uuid4()),
            "run_id": "run",
            "task_id": TASK,
            "launch_id": "launch",
            "hook": project_hook_input(
                {
                    "hook_event_name": "SessionStart",
                    "session_id": "session",
                    "cwd": "/workspace",
                    "transcript_path": "/home/agent/.claude/projects/-workspace/session.jsonl",
                    "source": "startup",
                    "model": "glm-5.3[1m]",
                }
            ),
        }
    )
    reply = service.handlers["model-gateway"](model)
    assert reply.status == 200
    assert b"message_stop" in b"".join(reply.body)
    assert service.budget.snapshot()["requests"] == 3
    assert service.budget.snapshot()["deepseek_requests"] == 1
    service.close()
    assert service.audit.record({"event": "outer-terminal-after-cleanup"}) is True
    for endpoint, route in service.handlers.items():
        assert route(request(assembled.peer, endpoint)).status == 503


def test_recall_failure_is_terminal_and_cannot_repeat_model_admission(assembled):
    service = assembled.create()
    service.bridge.fail_recall = True
    with pytest.raises(RuntimeError):
        service.start_automatic_lanes(level1_facts=("buffer",), structural_terms=("buffer",))
    count = service.budget.snapshot()["requests"]
    with pytest.raises(RuntimeError, match="one-shot"):
        service.start_automatic_lanes(level1_facts=("buffer",), structural_terms=("buffer",))
    assert count == service.budget.snapshot()["requests"] == 1
    assert not assembled.context.active


def test_different_authorization_audit_is_rejected_before_external_start(assembled, tmp_path):
    other = tmp_path / "other"
    other.mkdir(mode=0o700)
    with TaskRuntimeContext(
        other, task_id=TASK, attempt_id="attempt-1", secrets=("synthetic-zai", "synthetic-deepseek")
    ) as context:
        with pytest.raises(ValueError, match="context|audit"):
            assembled.create(context=context)
        assert context.budget.snapshot()["requests"] == 0


def test_close_interrupts_recon_transport_before_join_and_preserves_terminal_audit(assembled):
    from nooa_cybergym.leaderboard.services_runtime import CancellableDeepSeekTransport

    entered = threading.Event()

    async def blocked(_):
        entered.set()
        await asyncio.Event().wait()

    provider = CancellableDeepSeekTransport(transport=httpx.MockTransport(blocked))
    service = assembled.create(deepseek_transport=provider)
    service.start_automatic_lanes(level1_facts=("buffer",), structural_terms=("buffer",))
    assert entered.wait(5)
    with ThreadPoolExecutor(max_workers=1) as executor:
        executor.submit(service.close).result(timeout=5)
    assert service._recon_future.done() and service._recon_future.exception() is not None
    assert not assembled.context.active
    records = [json.loads(row)["event"] for row in service.audit.path.read_text().splitlines()]
    assert any(row.get("event") == "failure" and row.get("http_status") is None for row in records)


def test_cancelable_provider_enforces_absolute_deadline():
    from nooa_cybergym.leaderboard.services_runtime import CancellableDeepSeekTransport

    async def blocked(_):
        await asyncio.Event().wait()

    transport = CancellableDeepSeekTransport(transport=httpx.MockTransport(blocked))
    try:
        with pytest.raises(RuntimeError, match="deadline"):
            transport.send(ENDPOINT, {}, {}, 0.02)
    finally:
        transport.close()


def test_constructor_failure_closes_created_external_resources_and_halts_context(assembled):
    bridges = []

    def bridge_factory(*args, **kwargs):
        bridge = ExternalBridge(*args, **kwargs)
        bridges.append(bridge)
        return bridge

    def broken_clangd(*args, **kwargs):
        raise RuntimeError("synthetic clangd spawn failure")

    with pytest.raises(RuntimeError, match="clangd spawn"):
        assembled.create(bridge_factory=bridge_factory, clangd_factory=broken_clangd)
    assert bridges[0].closed
    assert not assembled.context.active
    assert assembled.context.audit.record({"event": "outer-construction-failed"}) is True


def test_recon_failure_halts_every_route_even_without_a_following_model_request(assembled):
    from nooa_cybergym.leaderboard.services_runtime import CancellableDeepSeekTransport

    failed = CancellableDeepSeekTransport(
        transport=httpx.MockTransport(lambda _: httpx.Response(503))
    )
    service = assembled.create(deepseek_transport=failed)
    service.start_automatic_lanes(level1_facts=("buffer",), structural_terms=("buffer",))
    with pytest.raises(RuntimeError):
        service._recon_future.result(timeout=5)
    # Wait for the callback itself, rather than racing future.set_exception's notification.
    service._recon_settled(service._recon_future)
    for endpoint, handler in service.handlers.items():
        assert handler(request(assembled.peer, endpoint)).status == 503
    assert not assembled.context.active


def test_simultaneous_startup_attempts_do_not_duplicate_automatic_recall(assembled):
    service = assembled.create()
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(
                service.start_automatic_lanes,
                level1_facts=("buffer",),
                structural_terms=("buffer",),
            )
            for _ in range(2)
        ]
        outcomes = []
        for future in futures:
            try:
                outcomes.append(future.result(timeout=5))
            except RuntimeError:
                outcomes.append("denied")
    service._recon_future.result(timeout=5)
    assert outcomes.count(()) == 1 and outcomes.count("denied") == 1
    assert service.budget.snapshot()["requests"] == 2


def test_simultaneous_close_waits_for_terminal_cleanup_before_returning(assembled):
    service = assembled.create()
    entered, released, second_started, second_finished = (threading.Event() for _ in range(4))

    def cleanup():
        entered.set()
        assert released.wait(5)

    service._resources.callback(cleanup)

    def second_close():
        second_started.set()
        service.close()
        second_finished.set()

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(service.close)
        assert entered.wait(5)
        second = executor.submit(second_close)
        assert second_started.wait(5)
        try:
            assert not second_finished.wait(0.1)
        finally:
            released.set()
            first.result(timeout=5)
            second.result(timeout=5)


def test_close_drains_admitted_http_handler_before_outer_audit_can_close(assembled):
    service = assembled.create()
    entered, release, canceled = (threading.Event() for _ in range(3))

    def handler(_):
        entered.set()
        assert release.wait(5)
        service.audit.record({"event": "terminal-http-handler"})

    route = service._guard(handler)
    service._resources.callback(canceled.set)
    with ThreadPoolExecutor(max_workers=2) as executor:
        running = executor.submit(route, request(assembled.peer))
        assert entered.wait(5)
        closing = executor.submit(service.close)
        assert canceled.wait(5)
        try:
            with pytest.raises(TimeoutError):
                closing.result(timeout=0.1)
        finally:
            release.set()
            running.result(timeout=5)
            closing.result(timeout=5)
    assert "terminal-http-handler" in service.audit.path.read_text()


def test_parent_admission_waits_for_actual_recon_child_slot(assembled, monkeypatch):
    service = assembled.create()
    entering, release = threading.Event(), threading.Event()
    original = service.advisor.child_slot

    @contextmanager
    def delayed(role):
        entering.set()
        assert release.wait(5)
        with original(role):
            yield

    monkeypatch.setattr(service.advisor, "child_slot", delayed)
    with ThreadPoolExecutor(max_workers=1) as executor:
        startup = executor.submit(
            service.start_automatic_lanes, level1_facts=("buffer",), structural_terms=("buffer",)
        )
        assert entering.wait(5)
        try:
            with pytest.raises(TimeoutError):
                startup.result(timeout=0.1)
            model = replace(model_request(names=("Read",)), peer=assembled.peer)
            assert service.handlers["model-gateway"](model).status == 503
        finally:
            release.set()
            startup.result(timeout=5)
    service._recon_future.result(timeout=5)


def test_frozen_workflow_reserves_actual_batch_and_rejects_unobserved_debug(assembled, tmp_path):
    assets = tmp_path / "workflow-assets"
    assets.mkdir()
    workflows = frozen_workflows()
    built = bundle(
        assets, name="Workflow", roles=(Role.PARENT,), paths=("/workspace/.claude/workflows",)
    )
    existing = assembled.args["capabilities"]
    registry = CapabilityRegistry((*existing.registry.entries, *built.registry.entries))
    gate = CapabilityRuntime(
        registry=registry,
        expected_registry_sha256=registry.digest,
        bindings=(*existing.bindings, *built.bindings),
        peer=assembled.peer,
        task_id=TASK,
        attempt_id="attempt-1",
        audit=assembled.context.audit,
        path_observer=lambda path: ObservedPath(path, path, True, "file"),
        boundary_check=lambda p: p == assembled.peer,
        working_directory="/workspace",
        execution_paths=("/workspace/src", "/workspace/output"),
        execution_routes=(),
        model_id="glm-5.3",
        structural_terms=("buffer",),
        synthetic_task_ids=frozenset({TASK}),
        network_policy=assembled.args["network_policy"],
        frozen_workflows={item.script_path: item.sha256 for item in workflows},
        content_digest=lambda path: hashlib.sha256(
            next(item.source for item in workflows if item.script_path == path).read_bytes()
        ).hexdigest(),
    )
    service = assembled.create(
        capabilities=gate,
        captured_schemas=captured_schemas(gate.bindings),
        model_policy=replace(
            assembled.args["model_policy"], capability_policy_sha256=registry.digest
        ),
    )

    def call(name, tool_id):
        return NativeToolCall(
            TASK,
            "attempt-1",
            "request",
            "session",
            None,
            "parent",
            tool_id,
            "Workflow",
            {
                "scriptPath": next(
                    item.script_path
                    for item in workflows
                    if item.script_path.endswith("/" + name + ".js")
                ),
                "args": {"question": "Inspect synthetic parser"},
            },
        )

    with pytest.raises(ValueError, match="failure"):
        service._authorize(call("debug", "debug-1"))
    assert service.capacity.snapshot()["occupied"] == 0
    assert service._authorize(call("recon", "recon-1")) is True
    assert service.capacity.snapshot()["pending_native"] == 2
    assert service._authorize(call("review", "review-1")) is True
    assert service.capacity.snapshot()["occupied"] == 3
    with pytest.raises(RuntimeError, match="capacity"):
        service._authorize(call("review", "review-2"))


def test_sealed_routes_are_one_shot_and_closed_routes_fail_shut():
    policy = NetworkPolicy.load(CONFIG.with_name("network-policy.json"))
    routes = SealedRoutes(policy)
    with pytest.raises(RuntimeError):
        routes.seal({})
    assert routes(request(None)).status == 503
    routes.close()
    with pytest.raises(RuntimeError):
        routes.seal({name: lambda request: None for name in policy.allowed_logical_endpoints})
