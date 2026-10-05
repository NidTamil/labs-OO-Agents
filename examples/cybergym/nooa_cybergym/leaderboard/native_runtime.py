"""Wire native provider requests to audited controller admission and tool custody."""

from __future__ import annotations

import hashlib
import threading
from collections.abc import Callable
from dataclasses import replace

from .deepseek import SharedCampaignBudget
from .host_boundary_runtime import AdmittedPeer, GatewayReply, GatewayRequest
from .model_gateway import (
    GatewayAudit,
    ModelPolicy,
    NativeModelGateway,
    StreamingTransport,
    TrustedAdmission,
)
from .model_runtime import TaskModelRoute
from .native_tool_runtime import NativeToolController

_SAFE_DENIALS = frozenset(
    {
        "native model peer denied",
        "native model request malformed",
        "native generation settings differ from frozen policy",
        "native lifecycle identity not observed",
        "native tool roster malformed",
        "native tool roster exceeds frozen role scope",
        "native advertised tool schema differs from frozen capture",
        "native request custody failed",
    }
)


class NativeModelDispatcher:
    """Bind a request-scoped opaque grant before the async model service runs.

    The HTTP request cannot supply a TrustedAdmission. Its Docker peer must
    match the task, native lifecycle must be observed, and the tool roster must
    comply with the frozen role. Tool effects still require a later exact
    provider-call match plus the controller's capability authorizer.
    """

    def __init__(
        self,
        *,
        tools: NativeToolController,
        task_token: str,
        policy: ModelPolicy,
        zai_token: str,
        deepseek_key: str,
        budget: SharedCampaignBudget,
        audit: GatewayAudit,
        mark_started: Callable[[str, str], bool],
        transport: StreamingTransport | None = None,
    ):
        if tools.policy_sha256 != policy.capability_policy_sha256:
            raise ValueError("native capability policy does not match model policy")
        self.tools = tools
        self.audit = audit
        self._current = threading.local()
        self.gateway = NativeModelGateway(
            task_id=tools.task_id,
            attempt_id=tools.attempt_id,
            task_token=task_token,
            model_policy=policy,
            zai_coding_plan_url=policy.approved_zai_coding_plan_url,
            zai_coding_plan_token=zai_token,
            deepseek_api_key=deepseek_key,
            budget=budget,
            audit=audit,
            resolve_admission=self._resolve,
            mark_started=mark_started,
            transport=transport,
            native_stream_observer=tools.observe_stream,
            native_stream_finished=tools.finish_stream,
        )
        self.route = TaskModelRoute(self.gateway, task_token, self._connection)

    @staticmethod
    def _resolve(handle: object) -> TrustedAdmission:
        if type(handle) is not TrustedAdmission:
            raise PermissionError("native controller admission required")
        return handle

    def _connection(self, peer: AdmittedPeer):
        binding = getattr(self._current, "binding", None)
        return binding[1] if binding is not None and binding[0] == peer else None

    def __call__(self, request: GatewayRequest) -> GatewayReply:
        try:
            grant = self.tools.begin_request(request)
        except Exception as error:
            reason = str(error) if type(error) is PermissionError else "native admission failed"
            if reason not in _SAFE_DENIALS:
                reason = "native admission failed"
            body = request.body if type(request.body) is bytes else b""
            event = {
                    "event": "native_admission_denied",
                    "reason": reason,
                    "body_sha256": hashlib.sha256(body).hexdigest(),
                    "body_bytes": len(body),
                    "path": request.path if request.path in {"/v1/messages", "/v1/messages?beta=true", "/v1/messages/count_tokens"} else "other",
                }
            if body:
                event["diagnostic"] = self.tools.admission_diagnostic(request)
            self.audit.record_request(event)
            return GatewayReply(403, b'{"error":"native request denied"}')
        self._current.binding = (request.peer, grant)
        try:
            filtered = self.tools.forward_request(grant, request)
            # Claude Code 2.1.289 adds this fixed beta query. The upstream
            # Anthropic-compatible path has no query; preserve original ingress
            # in the boundary audit and admit only this observed exact variant.
            forwarded = (
                replace(filtered, path="/v1/messages")
                if request.path == "/v1/messages?beta=true"
                else filtered
            )
            response = self.route(forwarded)
            if response.status >= 400:
                self.tools.abandon_request(grant)
            return response
        finally:
            del self._current.binding

    def close(self):
        self.route.close()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()
