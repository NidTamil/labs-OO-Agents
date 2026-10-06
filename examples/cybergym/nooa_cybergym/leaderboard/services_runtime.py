# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Join native, model, memory and advisory capabilities in one task controller.

This is service composition, not certification. The outer runner must observe
the actual Docker boundary, freeze identities, sign the launch, and later stop
the solver before locking its final. No personal workstation service is used.
"""

from __future__ import annotations

import asyncio
import json
import math
import os
import secrets
import threading
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
from pathlib import Path
from types import MappingProxyType

import httpx

from .advisory_runtime import AdvisoryRuntime, advisory_mcp_handler
from .advisory_tools_runtime import AdvisoryTools
from .capabilities import Role, Status
from .capability_runtime import CapabilityRuntime
from .child_capacity import ChildCapacity
from .deepseek import ENDPOINT, DeepSeekController, DeepSeekRole, ProviderResponse
from .documentation_service import VerifiedHTTPSNoRedirectTransport
from .finalization_runtime import NativeFinalizer, finalization_mcp_handler
from .gbrain_bridge import GBrainControllerBridge
from .host_boundary_runtime import AdmittedPeer, GatewayReply, GatewayRequest
from .memory import UnsafeMemory
from .memory_runtime import build_memory_gateway, build_signed_memory_bundle
from .model_gateway import GatewayAudit, ModelPolicy
from .native_hook_runtime import NativeHookCollector, native_hook_handler
from .native_launcher import NativeLaunchAuthority, native_launch_handler
from .native_runtime import NativeModelDispatcher
from .native_tool_runtime import NativeToolController
from .native_workflows import frozen_workflows, reserve_workflow
from .network import NetworkPolicy
from .runtime_custody import TaskRuntimeContext
from .tool_services_runtime import ClangdClient, DocumentationReader, RegisteredToolGateway
from .vulnerable_runtime import VulnerableRecipe, VulnerableRunner, vulnerable_mcp_handler


def _uncertified_token_counter(_text):
    # The live signed publication manifest starts with no approved pages. No
    # token counter is called for an empty result. Publishing pages later needs
    # an independently verified counter, not a guessed word/character count.
    raise UnsafeMemory("published memory requires a verified model token counter")


class CancellableDeepSeekTransport:
    """Synchronous controller interface with absolute deadlines and shutdown cancellation.

    One async client belongs to each admitted request. Closing cancels its task
    on the owning loop, so callers can settle terminal audit before joining the
    reconnaissance worker. The optional transport substitutes only provider I/O.
    """

    def __init__(self, *, transport=None):
        self._transport = transport
        self._lock = threading.Lock()
        self._active = set()
        self._closed = False

    def send(self, endpoint, headers, payload, timeout):
        if endpoint != ENDPOINT or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("official bounded DeepSeek endpoint required")
        try:
            return asyncio.run(self._send(headers, payload, timeout))
        except asyncio.CancelledError:
            raise RuntimeError("DeepSeek transport closed") from None
        except TimeoutError:
            raise RuntimeError("DeepSeek transport deadline exceeded") from None

    async def _send(self, headers, payload, timeout):
        binding = (asyncio.get_running_loop(), asyncio.current_task())
        with self._lock:
            if self._closed:
                raise RuntimeError("DeepSeek transport closed")
            self._active.add(binding)
        try:
            async with asyncio.timeout(timeout):
                async with httpx.AsyncClient(
                    transport=self._transport,
                    follow_redirects=False,
                    trust_env=False,
                    timeout=timeout,
                ) as client:
                    async with client.stream(
                        "POST", ENDPOINT, headers=headers, json=payload
                    ) as response:
                        if response.status_code != 200:
                            return ProviderResponse(response.status_code, {})
                        content = bytearray()
                        async for chunk in response.aiter_bytes():
                            content.extend(chunk)
                            if len(content) > 16 * 1024 * 1024:
                                raise RuntimeError("DeepSeek response exceeded bounded JSON size")
                        return ProviderResponse(response.status_code, json.loads(content))
        finally:
            with self._lock:
                self._active.discard(binding)

    def close(self):
        with self._lock:
            self._closed = True
            active = tuple(self._active)
        for loop, task in active:
            try:
                loop.call_soon_threadsafe(task.cancel)
            except RuntimeError:
                # The request may have finished and closed its loop after snapshot.
                pass


class SealedRoutes:
    """Create a listening boundary before a container, then attach its services once."""

    def __init__(self, policy: NetworkPolicy):
        self._allowed = policy.allowed_logical_endpoints
        self._handlers = None
        self._closed = False
        self._lock = threading.Lock()
        self.handlers = MappingProxyType(dict.fromkeys(self._allowed, self))

    def seal(self, handlers):
        candidate = dict(handlers)
        with self._lock:
            if (
                self._closed
                or self._handlers is not None
                or set(candidate) != self._allowed
                or not all(callable(h) for h in candidate.values())
            ):
                raise RuntimeError("gateway services must be sealed exactly once")
            self._handlers = MappingProxyType(candidate)

    def __call__(self, request: GatewayRequest):
        with self._lock:
            if self._closed or self._handlers is None or request.endpoint not in self._allowed:
                return GatewayReply(503, b'{"error":"task services not admitted"}')
            handler = self._handlers[request.endpoint]
        return handler(request)

    def close(self):
        with self._lock:
            self._closed = True


class NativeServices:
    def __init__(
        self,
        *,
        run_id: str,
        task_id: str,
        attempt_id: str,
        launch_id: str,
        evidence: Path,
        output: Path,
        peer: AdmittedPeer,
        docker_client,
        container,
        capabilities: CapabilityRuntime,
        context: TaskRuntimeContext,
        model_policy: ModelPolicy,
        network_policy: NetworkPolicy,
        launch_authority: NativeLaunchAuthority,
        zai_token: str,
        deepseek_key: str,
        gbrain_command,
        gbrain_models,
        signer,
        verifier,
        public_keys,
        task_brief: str,
        structural_terms: tuple[str, ...],
        vulnerable_recipe: VulnerableRecipe,
        captured_schemas: Mapping[str, str],
        compile_commands=(),
        memory_token_counter=_uncertified_token_counter,
        model_transport=None,
        deepseek_transport=None,
        bridge_factory=None,
        clangd_factory=None,
    ):
        if (
            type(capabilities) is not CapabilityRuntime
            or type(peer) is not AdmittedPeer
            or container.id != peer.container_id
            or type(launch_authority) is not NativeLaunchAuthority
            or capabilities.task_id != task_id
            or capabilities.attempt_id != attempt_id
            or capabilities.peer != peer
            or capabilities.registry.digest != model_policy.capability_policy_sha256
        ):
            raise ValueError("same-task observed identities and frozen capability policy required")
        if (
            type(context) is not TaskRuntimeContext
            or context.evidence != Path(evidence)
            or context.start.task_id != task_id
            or context.start.attempt_id != attempt_id
            or capabilities.audit is not context.audit
            or not context.active
            or any(context.audit.redact(value) == value for value in (zai_token, deepseek_key))
        ):
            raise ValueError(
                "same-task shared context and provider-redacting capability audit required"
            )
        if any(
            launch_authority.manifest.get(name) != value
            for name, value in (
                ("run_id", run_id),
                ("task_id", task_id),
                ("launch_id", launch_id),
                ("container_id", peer.container_id),
            )
        ):
            raise ValueError("signed launch must match composed task and container")
        self.evidence = Path(evidence)
        self.task_id, self.attempt_id = task_id, attempt_id
        self.capabilities = capabilities
        self.context = context
        self.start, self.audit, self.budget = context.start, context.audit, context.budget
        self._state_lock = threading.RLock()
        self._activity = threading.Condition(self._state_lock)
        self._inflight = 0
        self._resources = ExitStack()
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="cybergym-recon")
        self._recon_future = None
        self._recon_admitted = threading.Event()
        self._startup_complete = False
        self._startup_state = "new"
        self._closed = False
        self._close_done = threading.Event()
        self._close_failed = False
        self._vulnerable_failure_observed = threading.Event()
        try:
            self._workflows = frozen_workflows()
            self.capacity = ChildCapacity(
                self.evidence / "children.sqlite",
                run_id=run_id,
                task_id=task_id,
                attempt_id=attempt_id,
                launch_id=launch_id,
            )
            self.hooks = NativeHookCollector(
                self.evidence / "native-hooks.sqlite",
                run_id=run_id,
                task_id=task_id,
                launch_id=launch_id,
                capacity=self.capacity,
            )
            parent_tools, child_tools = set(), set()
            for binding in capabilities.bindings:
                if binding.native_name.startswith("advisory__"):
                    continue
                entry = next(
                    entry
                    for entry in capabilities.registry.entries
                    if entry.capability_id == binding.capability_id
                )
                if entry.status is Status.APPROVED:
                    if Role.PARENT in entry.roles:
                        parent_tools.add(binding.native_name)
                    if Role.CHILD in entry.roles:
                        child_tools.add(binding.native_name)
            self.tools = NativeToolController(
                self.evidence / "native-tools.sqlite",
                task_id=task_id,
                attempt_id=attempt_id,
                run_id=run_id,
                launch_id=launch_id,
                peer=peer,
                policy_sha256=model_policy.capability_policy_sha256,
                parent_tools=frozenset(parent_tools),
                child_tools=frozenset(child_tools),
                captured_schemas=captured_schemas,
                observed_role=self.hooks.model_role,
                authorize=self._authorize,
                redact=self.audit.redact,
            )
            self.models = self._resources.enter_context(
                NativeModelDispatcher(
                    tools=self.tools,
                    task_token=secrets.token_urlsafe(32),
                    policy=model_policy,
                    zai_token=zai_token,
                    deepseek_key=deepseek_key,
                    budget=self.budget,
                    audit=GatewayAudit(
                        self.evidence / "model-requests.jsonl", self.evidence / "model-usage.jsonl"
                    ),
                    mark_started=self.start.mark_started,
                    transport=model_transport,
                )
            )
            self.bridge = self._resources.enter_context(
                (bridge_factory or GBrainControllerBridge)(
                    gbrain_command,
                    budget=self.budget,
                    audit=self.audit,
                    allowed_models=gbrain_models,
                )
            )
            memory_bundle = build_signed_memory_bundle(
                bridge=self.bridge, signer=signer, verifier=verifier
            )
            for name, content in (
                ("memory-catalog.signed.json", memory_bundle.signed_catalog),
                ("memory-manifest.signed.json", memory_bundle.signed_manifest),
            ):
                with (self.evidence / name).open("xb") as stream:
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
            self.memory = build_memory_gateway(
                bridge=self.bridge,
                signed_catalog=memory_bundle.signed_catalog,
                signed_manifest=memory_bundle.signed_manifest,
                public_keys=public_keys,
                audit=self.audit,
                answer_filter=capabilities.safe_memory_filter,
                token_counter=memory_token_counter,
                authorize_peer=capabilities.authorize_peer,
                resolve_caller=self._memory_caller,
                task_id=task_id,
                attempt_id=attempt_id,
            )
            self.clangd = (clangd_factory or ClangdClient.for_docker)(
                docker_client.api,
                container_id=peer.container_id,
                source_roots=("/workspace/src",),
                compile_commands=compile_commands,
            )
            self._resources.callback(self.clangd.close)
            self.documentation = DocumentationReader(
                policy=network_policy,
                transport=VerifiedHTTPSNoRedirectTransport(),
                resolve_admission=capabilities.documentation_admission,
                audit=self.audit,
            )
            self.registered = RegisteredToolGateway(
                clangd=self.clangd,
                documentation=self.documentation,
                authorize_peer=capabilities.authorize_peer,
                resolve_caller=self._registered_caller,
                audit=self.audit,
                task_id=task_id,
                attempt_id=attempt_id,
            )
            self._deepseek_transport = deepseek_transport or CancellableDeepSeekTransport()
            if not callable(getattr(self._deepseek_transport, "close", None)):
                raise ValueError("cancelable DeepSeek transport required")
            self._resources.callback(self._deepseek_transport.close)
            self.deepseek = DeepSeekController(
                model_policy.alternate,
                deepseek_key,
                audit=self.audit,
                registry_digest=model_policy.capability_policy_sha256,
                budget=self.budget,
                transport=self._deepseek_transport,
            )
            self.finalizer = NativeFinalizer(
                output,
                self.evidence,
                task_id=task_id,
                attempt_id=attempt_id,
                require_critic=self._require_critic,
            )
            self.advisory_tools = AdvisoryTools(
                docker_client.api,
                container_id=peer.container_id,
                source_roots=("/workspace/src",),
                task_id=task_id,
                attempt_id=attempt_id,
                clangd=self.clangd,
                memory=self.memory._facade,
                structural_terms=structural_terms,
                authorize=self._authorize_advisory,
            )
            self.advisor = AdvisoryRuntime(
                self.deepseek,
                database=self.evidence / "advisory.sqlite",
                run_id=run_id,
                task_id=task_id,
                attempt_id=attempt_id,
                launch_id=launch_id,
                task_brief=task_brief,
                tools=self.advisory_tools.callbacks(),
                mark_started=self.start.mark_started,
                child_slot=self._advisory_slot,
                redact=self.audit.redact,
                resolve_candidate=self.finalizer.snapshot_candidate,
            )
            self.vulnerable = VulnerableRunner(
                container=container,
                peer=peer,
                task_id=task_id,
                attempt_id=attempt_id,
                recipe=vulnerable_recipe,
                controller=self.deepseek,
                observe_failure=self._observe_vulnerable_failure,
                snapshot_candidate=self.finalizer.hash_candidate,
                audit=self.audit,
            )
            self._launch = native_launch_handler(launch_authority, network_id=peer.network_id)
            self._hooks = native_hook_handler(
                self.hooks, container_id=peer.container_id, network_id=peer.network_id
            )
            self._advisor = advisory_mcp_handler(
                self.advisor, peer=peer, resolve_parent_call=self._advisor_caller
            )
            self._finalizer = finalization_mcp_handler(
                self.finalizer, peer=peer, resolve_parent_call=self.tools.resolve_mcp_call
            )
            self._vulnerable = vulnerable_mcp_handler(
                self.vulnerable, resolve_parent_call=self.tools.resolve_mcp_call
            )
            handlers = {
                "model-gateway": self._model_route,
                "gbrain-read-gateway": self.memory,
                "registered-tool-gateway": self._registered_route,
                "documentation-gateway": self._deny_direct_documentation,
                "cybergym-submit": self._vulnerable,
            }
            self.handlers = MappingProxyType(
                {name: self._guard(handler) for name, handler in handlers.items()}
            )
            if set(self.handlers) != network_policy.allowed_logical_endpoints:
                raise ValueError("unbound logical gateway endpoint")
            self.audit.record(
                {
                    "event": "services_composed",
                    "scope": "observed_task_services_not_certification",
                    "policy_sha256": model_policy.digest,
                    "parent_tools": sorted(parent_tools),
                    "child_tools": sorted(child_tools),
                    "compile_database_sha256": self.clangd.compile_database_sha256,
                    "workflow_sha256": {item.script_path: item.sha256 for item in self._workflows},
                }
            )
        except BaseException:
            self.close()
            raise

    def _active(self):
        with self._state_lock:
            return not self._closed and self.context.active

    def _guard(self, handler):
        def dispatch(request):
            with self._state_lock:
                if not self._active():
                    return GatewayReply(503, b'{"error":"task services closed or halted"}')
                self._inflight += 1
            try:
                if not self.capabilities.authorize_peer(request.peer):
                    return GatewayReply(403, b'{"error":"task peer denied"}')
                return handler(request)
            finally:
                self._leave_activity()

        return dispatch

    def _leave_activity(self):
        with self._activity:
            self._inflight -= 1
            self._activity.notify_all()

    def _authorize(self, call):
        if not self._active():
            return False
        if call.name == "Workflow":
            digest = self.capabilities.authorized_workflow_digest(call)
            if digest is None:
                return False
            reserve_workflow(
                self.capacity,
                call.tool_id,
                call.arguments,
                self._workflows,
                observed_sha256=digest,
                vulnerable_failure_observed=self._vulnerable_failure_observed.is_set(),
            )
            return True
        if self.capabilities.authorize(call) is not True:
            return False
        if call.name == "Agent":
            self.capacity.reserve_native(call.tool_id, call.arguments["subagent_type"])
        return True

    def _observe_vulnerable_failure(self, failure):
        self.advisor.observe_vulnerable_failure(failure)
        self._vulnerable_failure_observed.set()

    def _authorize_advisory(self, *args, **kwargs):
        return self._active() and self.capabilities.authorize_advisory(*args, **kwargs)

    @contextmanager
    def _advisory_slot(self, role):
        if not self._active():
            raise RuntimeError("task services halted before advisory admission")
        with self.capacity.advisory_slot(role):
            with self._state_lock:
                if not self._active():
                    raise RuntimeError("task services halted during advisory admission")
                if role == DeepSeekRole.INDEPENDENT_RECON.value:
                    self._recon_admitted.set()
            yield

    def _memory_caller(self, peer, tool_id, name, args):
        return self.capabilities.resolve_memory(self.tools, peer, tool_id, name, args)

    def _registered_caller(self, peer, tool_id, name, args):
        return self.capabilities.resolve_registered(self.tools, peer, tool_id, name, args)

    def _require_critic(self, sha256):
        self.advisor.require_critic(sha256)

    def _advisor_caller(self, request, body):
        if not self.capabilities.authorize_peer(request.peer):
            return False
        params = body.get("params", {})
        if type(params) is not dict or set(params) != {"name", "arguments", "_meta"}:
            return False
        meta, args, name = params["_meta"], params["arguments"], params["name"]
        if (
            type(meta) is not dict
            or type(args) is not dict
            or name not in {"recon_status", "debug", "critic"}
            or len(json.dumps(meta)) > 16384
        ):
            return False
        call = self.tools.resolve_mcp_call(
            meta.get("claudecode/toolUseId"), "mcp__advisor__" + name, args
        )
        return call.role == "parent"

    def start_automatic_lanes(self, *, level1_facts, structural_terms):
        with self._state_lock:
            if not self._active() or self._startup_state != "new":
                raise RuntimeError("automatic lanes are one-shot")
            self._startup_state = "starting"
            self._inflight += 1
        # Recall is model-accounted before admission. Advice starts independently
        # before the native parent; it consumes one of the same three child slots.
        try:
            self.audit.record({"event": "automatic_lanes_starting"})
            selections = self.memory.automatic_recall(
                level1_facts=level1_facts, structural_terms=structural_terms
            )
            with self._state_lock:
                if not self._active():
                    raise RuntimeError("services closed during automatic startup")
                self._recon_future = self._executor.submit(self.advisor.run_recon)
                self._recon_future.add_done_callback(self._recon_settled)
            if not self._recon_admitted.wait(min(30, self.budget.remaining_seconds())):
                raise RuntimeError("mandatory reconnaissance child slot was not admitted")
            with self._state_lock:
                if not self._active() or self._startup_state != "starting":
                    raise RuntimeError("mandatory reconnaissance startup failed")
                self._startup_state = "complete"
                self._startup_complete = True
            return selections
        except BaseException:
            with self._state_lock:
                self._startup_state = "failed"
                self._startup_complete = False
                self.context.halt()
                self._recon_admitted.set()
            raise
        finally:
            self._leave_activity()

    def _recon_settled(self, future):
        if future.cancelled() or future.exception() is not None:
            with self._state_lock:
                self._startup_state = "failed"
                self._startup_complete = False
                self.context.halt()
                self._recon_admitted.set()

    def _model_route(self, request):
        if not self._startup_complete or self._closed:
            return GatewayReply(503, b'{"error":"automatic task lanes not started"}')
        if self._recon_future.cancelled() or (
            self._recon_future.done() and self._recon_future.exception() is not None
        ):
            return GatewayReply(503, b'{"error":"mandatory reconnaissance failed"}')
        return self.models(request)

    @staticmethod
    def _deny_direct_documentation(_request):
        # Documentation is exposed through correlated native MCP only. Merely
        # reaching the logical HTTP host conveys no provider tool-call authority.
        return GatewayReply(403, b'{"error":"use the registered documentation MCP"}')

    def _registered_route(self, request):
        if self._closed:
            return GatewayReply(503, b'{"error":"task services closed"}')
        if request.path in {"/native-launch/reserve", "/native-launch/events"}:
            return self._launch(request)
        if request.path == "/native-launch/hooks":
            return self._hooks(request)
        if request.path in {"/native-tools/authorize", "/native-tools/result"}:
            return self.tools.handle(request)
        if request.path == "/advisor/mcp":
            return self._advisor(request)
        if request.path == "/mcp/finalizer":
            return self._finalizer(request)
        return self.registered(request)

    def close(self):
        with self._state_lock:
            wait_for_owner = self._closed
            self._closed = True
            self.context.halt()
            self._recon_admitted.set()
        if wait_for_owner:
            self._close_done.wait()
            if self._close_failed:
                raise RuntimeError("task service cleanup failed")
            return
        # Cancel provider/model I/O before joining the worker. Keep the shared
        # audit alive for terminal settlement; its outer owner closes it later.
        try:
            try:
                self._resources.close()
            finally:
                try:
                    self._executor.shutdown(wait=True, cancel_futures=True)
                finally:
                    with self._activity:
                        self._activity.wait_for(lambda: self._inflight == 0)
        except BaseException:
            self._close_failed = True
            raise
        finally:
            self._close_done.set()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
