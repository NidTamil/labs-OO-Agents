# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Controller-owned streaming boundary for the native Claude model routes.

The HTTP listener supplies a task-authenticated, server-side connection context.
``resolve_admission`` must derive its grant from controller/workflow state, never
from the request JSON. This module has no listener, credential injection into a
solver process, or claim of a certified provider session. The existing DeepSeek
policy and shared campaign budget remain the authority for limits and routes.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import socket
import ssl
import threading
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

import httpcore
import httpx

from .deepseek import (
    CONTEXT_TOKENS,
    ENDPOINT,
    MAX_OUTPUT_TOKENS,
    MODEL,
    ROLE_LIMITS,
    AlternateModelPolicy,
    BudgetExceeded,
    DeepSeekRole,
    FailureEvidence,
    SharedCampaignBudget,
)

PRIMARY_MODEL = "glm-5.3[1m]"
# Claude's [1m] suffix selects the client context window and is removed on
# the wire. The Coding Plan rejects it as an API model identifier.
PRIMARY_WIRE_MODEL = "glm-5.3"
PRIMARY_CONTEXT_TOKENS = 1_000_000
PRIMARY_CODING_PLAN_BASE_URL = "https://api.z.ai/api/anthropic"
_PRIMARY_PATHS = frozenset(("/v1/messages", "/v1/messages/count_tokens"))
_DEEPSEEK_PATH = "/v1/chat/completions"
_MAX_OUTPUT_TOKENS = 128_000
_MAX_IDENTITY_BUFFER = 1_048_576
_MAX_SEMANTIC_SSE_FRAME_BYTES = 8 * 1_048_576
_MAX_SEMANTIC_HOLD_BYTES = 16 * 1_048_576
# Short overlaps with a random credential prefix are common in ordinary text.
# Keep them buffered across chunks for full-secret detection, but do not treat
# fewer than eight matching bytes as credential disclosure at stream end.
_MIN_IDENTIFYING_FRAGMENT = 8
_SSE_FRAME_END = re.compile(rb"(?:\r?\n){2}")
_STATIC_RESPONSE_STRING_KEYS = frozenset(
    {
        "type",
        "id",
        "model",
        "role",
        "object",
        "status",
        "finish_reason",
        "stop_reason",
        "system_fingerprint",
        "model_version",
        "created",
        "event",
        "name",
        "_json_key",
    }
)
_MAX_CLOSE_SECONDS = 2.0
_FORBIDDEN_BODY_FIELDS = frozenset(
    ("role", "trigger", "failure", "capability_policy_hash", "capabilityPolicy")
)
_HOP_HEADERS = frozenset(
    ("connection", "content-length", "set-cookie", "transfer-encoding", "www-authenticate")
)


class GatewayPolicyError(PermissionError):
    """A request has no matching trusted, declared route."""


class GatewayDeadlineExceeded(TimeoutError):
    """The hard task or role deadline interrupted the stream."""


class GatewayUpstreamError(RuntimeError):
    """The provider failed; its body and transport exception are withheld."""


def _failure_code(error: Exception | None) -> str | None:
    """Audit fixed internal failure categories without copying upstream text."""
    if error is None:
        return None
    return {
        "provider stream ended without terminal event": "provider_stream_no_terminal",
        "provider SSE frame ended incomplete": "provider_sse_incomplete",
        "provider stream failed": "provider_transport_failure",
        "provider response contains a controller credential": "credential_denied",
        "provider response contains a controller credential fragment": "credential_fragment_denied",
        "provider identity missing or changed": "provider_identity_invalid",
        "provider response has invalid SSE JSON": "provider_sse_invalid",
        "provider SSE frame exceeds semantic guard limit": "provider_sse_limit",
        "provider SSE hold exceeds semantic guard limit": "provider_sse_hold_limit",
        "provider response semantic frame is too complex": "provider_sse_complexity",
        "provider returned non-success status": "provider_http_error",
        "provider usage invalid": "provider_usage_invalid",
    }.get(str(error), "other_failure")


def _digest(value: object) -> bool:
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


@dataclass(frozen=True, slots=True)
class ModelPolicy:
    """Freeze model routes from the controller's signed harness configuration."""

    primary: str
    alternate: AlternateModelPolicy
    capability_policy_sha256: str
    approved_zai_coding_plan_url: str

    def __post_init__(self) -> None:
        if self.primary != PRIMARY_MODEL:
            raise ValueError("primary model differs from frozen GLM route")
        if type(self.alternate) is not AlternateModelPolicy:
            raise TypeError("validated DeepSeek policy required")
        self.alternate.assert_ready()
        if not _digest(self.capability_policy_sha256):
            raise ValueError("capability policy digest required")
        if self.approved_zai_coding_plan_url != PRIMARY_CODING_PLAN_BASE_URL:
            raise ValueError("approved Z.ai Coding Plan endpoint required")

    @property
    def digest(self) -> str:
        canonical = json.dumps(
            {
                "primary": self.primary,
                "alternate_sha256": self.alternate.digest,
                "capability_policy_sha256": self.capability_policy_sha256,
                "approved_zai_coding_plan_url": self.approved_zai_coding_plan_url,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class TrustedAdmission:
    """A grant returned by controller-owned admission resolution.

    The HTTP listener must not construct this from body fields or solver headers.
    A debug failure is admitted by the controller's vulnerable-side observer.
    """

    task_id: str
    attempt_id: str
    request_id: str
    role: DeepSeekRole | None
    trigger: str | None
    capability_policy_sha256: str
    workflow_id: str | None = None
    failure: FailureEvidence | None = None


@dataclass(frozen=True, slots=True)
class GatewayResult:
    request_id: str
    http_status: int
    usage_status: str
    counted_tokens: int


class StreamingResponse(Protocol):
    status_code: int
    headers: Mapping[str, str]

    def aiter_bytes(self): ...

    async def aclose(self) -> None: ...


class StreamingTransport(Protocol):
    async def open_stream(
        self, url: str, headers: Mapping[str, str], body: bytes, timeout: float
    ) -> StreamingResponse: ...


class _HttpxResponse:
    def __init__(self, client: httpx.AsyncClient, response: httpx.Response):
        self._client = client
        self._response = response
        self.status_code = response.status_code
        self.headers = response.headers

    def aiter_bytes(self):
        return self._response.aiter_raw()

    async def aclose(self) -> None:
        try:
            await self._response.aclose()
        finally:
            await self._client.aclose()


def _system_resolver(host: str, port: int) -> list[tuple]:
    return socket.getaddrinfo(
        host, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
    )


class _PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Resolve every connection, approve every answer, then dial only a numeric IP."""

    def __init__(self, host: str, resolver: Callable, backend: httpcore.AsyncNetworkBackend):
        self._host = host
        self._resolver = resolver
        self._backend = backend

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        if host != self._host or port != 443 or local_address is not None:
            raise GatewayUpstreamError("unapproved provider destination")
        loop = asyncio.get_running_loop()
        started = loop.time()
        try:
            answers = await asyncio.wait_for(
                asyncio.to_thread(self._resolver, host, port), timeout=timeout
            )
            if not isinstance(answers, (list, tuple)) or not 1 <= len(answers) <= 64:
                raise GatewayUpstreamError("unapproved provider destination")
            approved: list[str] = []
            for answer in answers:
                if not isinstance(answer, tuple) or len(answer) != 5:
                    raise GatewayUpstreamError("unapproved provider destination")
                family, kind, protocol, _, sockaddr = answer
                if (
                    family not in (socket.AF_INET, socket.AF_INET6)
                    or kind != socket.SOCK_STREAM
                    or protocol not in (0, socket.IPPROTO_TCP)
                    or not isinstance(sockaddr, tuple)
                    or len(sockaddr) != (2 if family == socket.AF_INET else 4)
                    or sockaddr[1] != port
                    or not isinstance(sockaddr[0], str)
                    or "%" in sockaddr[0]
                ):
                    raise GatewayUpstreamError("unapproved provider destination")
                address = ipaddress.ip_address(sockaddr[0])
                if (
                    (family == socket.AF_INET) != (address.version == 4)
                    or not address.is_global
                    or address.is_multicast
                ):
                    raise GatewayUpstreamError("unapproved provider destination")
                approved.append(str(address))
            remaining = None if timeout is None else timeout - (loop.time() - started)
            if remaining is not None and remaining <= 0:
                raise GatewayUpstreamError("provider connection timed out")
            return await self._backend.connect_tcp(
                approved[0],
                port,
                timeout=remaining,
                local_address=None,
                socket_options=socket_options,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise GatewayUpstreamError("provider connection failed") from None

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):
        raise GatewayUpstreamError("unapproved provider destination")

    async def sleep(self, seconds):
        await self._backend.sleep(seconds)


class _CoreResponseStream(httpx.AsyncByteStream):
    def __init__(self, stream: httpcore.AsyncByteStream):
        self._stream = stream

    async def __aiter__(self):
        async for chunk in self._stream:
            yield chunk

    async def aclose(self):
        await self._stream.aclose()


class _PinnedHTTPXTransport(httpx.AsyncBaseTransport):
    def __init__(self, host: str, resolver: Callable, backend: httpcore.AsyncNetworkBackend):
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl.create_default_context(),
            proxy=None,
            max_connections=1,
            max_keepalive_connections=0,
            http1=True,
            http2=False,
            retries=0,
            network_backend=_PinnedNetworkBackend(host, resolver, backend),
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        core_request = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )
        response = await self._pool.handle_async_request(core_request)
        return httpx.Response(
            status_code=response.status,
            headers=response.headers,
            stream=_CoreResponseStream(response.stream),
            extensions=response.extensions,
        )

    async def aclose(self) -> None:
        await self._pool.aclose()


class HttpxStreamingTransport:
    """One provider request with checked DNS, pinned IP, and original TLS identity."""

    def __init__(
        self,
        transport: httpx.AsyncBaseTransport | None = None,
        *,
        resolver: Callable | None = None,
        network_backend: httpcore.AsyncNetworkBackend | None = None,
    ):
        if transport is not None and (
            not isinstance(transport, httpx.MockTransport)
            or resolver is not None
            or network_backend is not None
        ):
            raise ValueError("only an isolated mock transport may bypass the pinned connection")
        self._transport = transport
        self._resolver = resolver or _system_resolver
        self._backend = network_backend or httpcore.AnyIOBackend()

    async def open_stream(self, url, headers, body, timeout):
        approved = {
            PRIMARY_CODING_PLAN_BASE_URL + "/v1/messages": "api.z.ai",
            PRIMARY_CODING_PLAN_BASE_URL + "/v1/messages/count_tokens": "api.z.ai",
            ENDPOINT: "api.deepseek.com",
        }
        if url not in approved:
            raise GatewayUpstreamError("unapproved provider route")
        if any(name.lower() == "host" for name in headers):
            raise GatewayUpstreamError("provider Host header must come from approved route")
        transport = self._transport or _PinnedHTTPXTransport(
            approved[url], self._resolver, self._backend
        )
        client = httpx.AsyncClient(
            transport=transport,
            follow_redirects=False,
            trust_env=False,
            timeout=httpx.Timeout(timeout),
        )
        try:
            request = client.build_request("POST", url, headers=headers, content=body)
            response = await client.send(request, stream=True)
            return _HttpxResponse(client, response)
        except BaseException:
            await client.aclose()
            raise


def _discard_close_result(task: asyncio.Task[None]) -> None:
    try:
        task.result()
    except BaseException:
        pass


async def _close_bounded(response: StreamingResponse, seconds: float) -> bool:
    """Abort a stuck close without holding the task past its hard deadline."""
    close_task = asyncio.create_task(response.aclose())
    try:
        done, _ = await asyncio.wait({close_task}, timeout=max(0.0, seconds))
    except asyncio.CancelledError:
        close_task.cancel()
        close_task.add_done_callback(_discard_close_result)
        return False
    if not done:
        close_task.cancel()
        close_task.add_done_callback(_discard_close_result)
        return False
    try:
        close_task.result()
    except BaseException:
        return False
    return True


class GatewayAudit:
    """Durable, append-only controller evidence with separate request/usage logs."""

    def __init__(self, request_path: Path, usage_path: Path):
        self._request_path = Path(request_path)
        self._usage_path = Path(usage_path)
        self._lock = threading.Lock()

    def _append(self, path: Path, event: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(event, sort_keys=True, separators=(",", ":"), allow_nan=False)
        with self._lock, path.open("a", encoding="utf-8") as file:
            file.write(line + "\n")
            file.flush()
            os.fsync(file.fileno())

    def record_request(self, event: dict[str, Any]) -> None:
        self._append(self._request_path, event)

    def record_usage(self, event: dict[str, Any]) -> None:
        self._append(self._usage_path, event)


class _StreamObservation:
    """Parse telemetry from SSE while forwarding the original bytes unchanged."""

    def __init__(self, request_id: str, model: str, role: str | None, *, count_tokens=False):
        self.request_id = request_id
        self.model = model
        self.role = role
        self._buffer = bytearray()
        self._data: list[bytes] = []
        self._is_deepseek = model == MODEL
        self._count_tokens = count_tokens
        self._json_body = bytearray()
        self.usage_payload_nonempty = False
        self.metadata_mismatch = False
        self.terminal = False
        self.input_tokens: int | None = None
        self.output_tokens: int | None = None
        self.cache_read_tokens: int | None = None
        self.cache_creation_tokens: int | None = None
        self.cache_miss_tokens: int | None = None
        self.reasoning_tokens: int | None = None
        self.total_tokens: int | None = None
        self.returned_model: str | None = None
        self.provider_request_id: str | None = None
        self.model_version: str | None = None
        self.system_fingerprint: str | None = None
        self._tool_calls: dict[str, dict[str, str | None]] = {}
        self._tool_indexes: dict[int, str] = {}

    @staticmethod
    def _number(value: Any) -> int | None:
        return value if type(value) is int and value >= 0 else None

    @staticmethod
    def _string(value: Any) -> str | None:
        return value if type(value) is str and value else None

    def feed(self, chunk: bytes) -> None:
        if self._count_tokens:
            self._json_body.extend(chunk)
            return
        self._buffer.extend(chunk)
        while b"\n" in self._buffer:
            line, _, remainder = self._buffer.partition(b"\n")
            self._buffer = bytearray(remainder)
            line = line.rstrip(b"\r")
            if not line:
                self._dispatch()
            elif line.startswith(b"data:"):
                self._data.append(line[5:].lstrip(b" "))

    def _dispatch(self) -> None:
        if not self._data:
            return
        raw = b"\n".join(self._data)
        self._data.clear()
        if raw == b"[DONE]":
            self.terminal = True
            return
        try:
            event = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            return
        if not isinstance(event, dict):
            return
        observed_model = self._string(event.get("model"))
        if observed_model and self.returned_model and observed_model != self.returned_model:
            self.metadata_mismatch = True
        self.returned_model = observed_model or self.returned_model
        self.provider_request_id = self._string(event.get("id")) or self.provider_request_id
        self.model_version = self._string(event.get("model_version")) or self.model_version
        self.system_fingerprint = (
            self._string(event.get("system_fingerprint")) or self.system_fingerprint
        )
        if self._is_deepseek:
            self._observe_deepseek(event)
        else:
            self._observe_primary(event)

    def _observe_primary(self, event: dict[str, Any]) -> None:
        kind = event.get("type")
        message = event.get("message")
        if kind == "message_start" and isinstance(message, dict):
            model = self._string(message.get("model"))
            if model and self.returned_model and model != self.returned_model:
                self.metadata_mismatch = True
            self.returned_model = model or self.returned_model
            self.provider_request_id = self._string(message.get("id")) or self.provider_request_id
            usage = message.get("usage")
        elif kind == "message_delta":
            usage = event.get("usage")
        else:
            usage = None
        if isinstance(usage, dict):
            # Z.ai's Anthropic stream omits cache creation when none was billed.
            # Keep the other mandatory counters unknown until actually observed.
            if "cache_creation_input_tokens" not in usage and kind == "message_delta":
                if self.cache_creation_tokens is None:
                    self.cache_creation_tokens = 0
            for source, destination in (
                ("input_tokens", "input_tokens"),
                ("output_tokens", "output_tokens"),
                ("cache_read_input_tokens", "cache_read_tokens"),
                ("cache_creation_input_tokens", "cache_creation_tokens"),
            ):
                value = self._number(usage.get(source))
                if value is not None:
                    setattr(self, destination, value)
        if kind == "content_block_start":
            block = event.get("content_block")
            if isinstance(block, dict) and block.get("type") == "tool_use":
                tool_id = self._string(block.get("id"))
                if tool_id:
                    self._tool_calls[tool_id] = {
                        "id": tool_id,
                        "name": self._string(block.get("name")),
                    }
        if kind == "message_stop":
            self.terminal = True

    def _observe_deepseek(self, event: dict[str, Any]) -> None:
        usage = event.get("usage")
        if isinstance(usage, dict):
            self.usage_payload_nonempty = self.usage_payload_nonempty or bool(usage)
            self.input_tokens = self._number(usage.get("prompt_tokens"))
            self.output_tokens = self._number(usage.get("completion_tokens"))
            self.total_tokens = self._number(usage.get("total_tokens"))
            self.cache_read_tokens = self._number(usage.get("prompt_cache_hit_tokens"))
            self.cache_miss_tokens = self._number(usage.get("prompt_cache_miss_tokens"))
            details = usage.get("completion_tokens_details")
            if isinstance(details, dict):
                self.reasoning_tokens = self._number(details.get("reasoning_tokens"))
        choices = event.get("choices")
        if not isinstance(choices, list):
            return
        for choice in choices:
            if not isinstance(choice, dict) or not isinstance(choice.get("delta"), dict):
                continue
            tool_calls = choice["delta"].get("tool_calls")
            if not isinstance(tool_calls, list):
                continue
            for call in tool_calls:
                if not isinstance(call, dict) or type(call.get("index")) is not int:
                    continue
                index = call["index"]
                tool_id = self._string(call.get("id")) or self._tool_indexes.get(index)
                if tool_id is None:
                    continue
                self._tool_indexes[index] = tool_id
                function = call.get("function")
                name = self._string(function.get("name")) if isinstance(function, dict) else None
                previous = self._tool_calls.get(tool_id)
                self._tool_calls[tool_id] = {
                    "id": tool_id,
                    "name": name or (previous["name"] if previous else None),
                }

    def finish(self) -> None:
        if not self._count_tokens:
            return
        try:
            body = json.loads(self._json_body)
        except (ValueError, UnicodeDecodeError):
            return
        if isinstance(body, dict) and self._number(body.get("input_tokens")) is not None:
            self.input_tokens = body["input_tokens"]
            self.returned_model = self._string(body.get("model"))
            self.terminal = True

    def invalid_deepseek_usage(self) -> bool:
        if not self._is_deepseek or not self.usage_payload_nonempty:
            return False
        return not (
            self.input_tokens is not None
            and self.output_tokens is not None
            and self.total_tokens == self.input_tokens + self.output_tokens
            and self.cache_read_tokens is not None
            and self.cache_miss_tokens is not None
            and self.cache_read_tokens + self.cache_miss_tokens == self.input_tokens
            and self.output_tokens <= MAX_OUTPUT_TOKENS
            and self.total_tokens <= CONTEXT_TOKENS
            and (self.reasoning_tokens is None or self.reasoning_tokens <= self.output_tokens)
        )

    def usage_row(
        self,
        *,
        outcome: str,
        reserved_tokens: int,
        secrets: tuple[str, ...],
        hex_forms: tuple[str, ...] = (),
    ):
        if self._count_tokens:
            complete = (
                self.terminal
                and self.input_tokens is not None
                and self.input_tokens <= PRIMARY_CONTEXT_TOKENS
            )
            observed_count = self.input_tokens if complete else None
        elif self._is_deepseek:
            complete = (
                self.terminal
                and self.input_tokens is not None
                and self.output_tokens is not None
                and self.total_tokens == self.input_tokens + self.output_tokens
                and self.cache_read_tokens is not None
                and self.cache_miss_tokens is not None
                and self.cache_read_tokens + self.cache_miss_tokens == self.input_tokens
                and self.output_tokens <= MAX_OUTPUT_TOKENS
                and self.total_tokens <= CONTEXT_TOKENS
                and (self.reasoning_tokens is None or self.reasoning_tokens <= self.output_tokens)
            )
            observed_count = self.total_tokens if complete else None
        else:
            complete = (
                self.terminal
                and self.input_tokens is not None
                and self.output_tokens is not None
                and self.output_tokens <= _MAX_OUTPUT_TOKENS
                and self.cache_read_tokens is not None
                and self.cache_creation_tokens is not None
            )
            observed_count = (
                self.input_tokens
                + self.cache_read_tokens
                + self.cache_creation_tokens
                + self.output_tokens
                if complete
                else None
            )
            if observed_count is not None and observed_count > PRIMARY_CONTEXT_TOKENS:
                complete = False
                observed_count = None
        status = (
            "observed"
            if outcome == "completed" and complete
            else ("interrupted" if outcome != "completed" or not self.terminal else "unavailable")
        )
        row = {
            "event": "usage",
            "request_id": self.request_id,
            "model": self.model,
            "role": self.role,
            "usage_status": status,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cache_read_tokens": self.cache_read_tokens,
            "cache_creation_tokens": self.cache_creation_tokens,
            "cache_miss_tokens": self.cache_miss_tokens,
            "reasoning_tokens": self.reasoning_tokens,
            "reserved_tokens": reserved_tokens,
            "counted_tokens": observed_count if status == "observed" else reserved_tokens,
            "tool_calls": list(self._tool_calls.values()),
            "returned_model": self.returned_model,
            "provider_request_id": self.provider_request_id,
            "model_version": self.model_version,
            "system_fingerprint": self.system_fingerprint,
            "observed_at_utc": datetime.now(UTC).isoformat(),
        }
        return _redact(row, secrets, hex_forms)


def _redact(value: Any, secrets: tuple[str, ...], hex_forms: tuple[str, ...] = ()) -> Any:
    if isinstance(value, str):
        for secret in secrets:
            if secret:
                value = value.replace(secret, "[REDACTED]")
        for hex_form in hex_forms:
            value = re.sub(re.escape(hex_form), "[REDACTED]", value, flags=re.IGNORECASE)
        return value
    if isinstance(value, dict):
        return {
            _redact(k, secrets, hex_forms): _redact(v, secrets, hex_forms) for k, v in value.items()
        }
    if isinstance(value, list):
        return [_redact(item, secrets, hex_forms) for item in value]
    return value


class _SecretStreamGuard:
    """Hold possible credential prefixes until the next provider bytes disambiguate them."""

    def __init__(self, secrets: tuple[str, ...]) -> None:
        self._secrets = tuple({secret.encode("utf-8") for secret in secrets if secret})
        self._tail = b""

    def feed(self, chunk: bytes) -> bytes:
        pending = self._tail + chunk
        if any(secret in pending for secret in self._secrets):
            raise GatewayUpstreamError("provider response contains a controller credential")
        held = max(
            (
                size
                for secret in self._secrets
                for size in range(1, min(len(secret), len(pending) + 1))
                if pending.endswith(secret[:size])
            ),
            default=0,
        )
        self._tail = pending[-held:] if held else b""
        return pending[:-held] if held else pending

    def finish(self) -> bytes:
        if len(self._tail) >= _MIN_IDENTIFYING_FRAGMENT:
            raise GatewayUpstreamError(
                "provider response contains a controller credential fragment"
            )
        tail, self._tail = self._tail, b""
        return tail


def _decoded_strings(value: Any) -> list[tuple[tuple[str | int, ...], str]]:
    """Inspect every JSON string, regardless of provider envelope shape."""
    found: list[tuple[tuple[str | int, ...], str]] = []
    stack: list[tuple[tuple[str | int, ...], Any]] = [((), value)]
    nodes = 0
    while stack:
        path, item = stack.pop()
        nodes += 1
        if nodes > 100_000:
            raise GatewayUpstreamError("provider response semantic frame is too complex")
        if type(item) is str:
            found.append((path, item))
        elif isinstance(item, dict):
            found.extend((path + ("_json_key",), key) for key in item)
            stack.extend((path + (key,), child) for key, child in reversed(tuple(item.items())))
        elif isinstance(item, list):
            stack.extend(
                (path + (index,), child) for index, child in reversed(tuple(enumerate(item)))
            )
    return found


def _secret_forms(secrets: tuple[str, ...]) -> tuple[str, ...]:
    """Cover common lossless encodings of controller credentials."""
    forms: set[str] = set()
    for secret in secrets:
        if not secret:
            continue
        raw = secret.encode("utf-8")
        standard = base64.b64encode(raw).decode("ascii")
        urlsafe = base64.urlsafe_b64encode(raw).decode("ascii")
        forms.update(
            (
                secret,
                standard,
                urlsafe,
                standard.rstrip("="),
                urlsafe.rstrip("="),
                raw.hex(),
                raw.hex().upper(),
            )
        )
    return tuple(sorted(forms, key=lambda value: (-len(value), value)))


def _hex_forms(secrets: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(secret.encode("utf-8").hex() for secret in secrets if secret)


def _contains_semantic_secret(
    value: str, forms: tuple[str, ...], hex_forms: tuple[str, ...]
) -> bool:
    return any(form in value for form in forms) or any(
        hex_form in value.lower() for hex_form in hex_forms
    )


def _secret_prefix_suffix(value: str, secrets: tuple[str, ...]) -> str:
    longest = ""
    for secret in secrets:
        for size in range(1, min(len(secret), len(value) + 1)):
            if size > len(longest) and value.endswith(secret[:size]):
                longest = secret[:size]
    return longest


class _SemanticSSEGuard:
    """Validate decoded SSE strings and hold possible credential fragments."""

    def __init__(self, secrets: tuple[str, ...], hex_forms: tuple[str, ...] = ()) -> None:
        self._secrets = tuple({secret for secret in secrets if secret})
        self._hex_forms = hex_forms
        self._pending = bytearray()
        self._held_frames: list[bytes] = []
        self._held_bytes = 0
        self._tails: dict[tuple[str | int, ...], str] = {}

    def _inspect_frame(self, frame: bytes) -> None:
        data = []
        for line in frame.splitlines():
            if line.startswith(b"data:"):
                data.append(line[5:].lstrip(b" "))
        if not data:
            return
        raw = b"\n".join(data)
        if raw == b"[DONE]":
            return
        try:
            payload = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            raise GatewayUpstreamError("provider response has invalid SSE JSON") from None
        for path, value in _decoded_strings(payload):
            if _contains_semantic_secret(value, self._secrets, self._hex_forms):
                raise GatewayUpstreamError("provider response contains a controller credential")
            if path and path[-1] in _STATIC_RESPONSE_STRING_KEYS:
                continue
            combined = self._tails.get(path, "") + value
            if _contains_semantic_secret(combined, self._secrets, self._hex_forms):
                raise GatewayUpstreamError("provider response contains a controller credential")
            tail = _secret_prefix_suffix(combined, self._secrets)
            hex_tail = _secret_prefix_suffix(combined.lower(), self._hex_forms)
            if len(hex_tail) > len(tail):
                tail = combined[-len(hex_tail) :]
            if tail:
                self._tails[path] = tail
            else:
                self._tails.pop(path, None)

    def feed(self, chunk: bytes) -> list[bytes]:
        self._pending.extend(chunk)
        released: list[bytes] = []
        while match := _SSE_FRAME_END.search(self._pending):
            if match.end() > _MAX_SEMANTIC_SSE_FRAME_BYTES:
                raise GatewayUpstreamError("provider SSE frame exceeds semantic guard limit")
            frame = bytes(self._pending[: match.end()])
            del self._pending[: match.end()]
            self._inspect_frame(frame)
            self._held_frames.append(frame)
            self._held_bytes += len(frame)
            if self._held_bytes > _MAX_SEMANTIC_HOLD_BYTES:
                raise GatewayUpstreamError("provider SSE hold exceeds semantic guard limit")
            if not self._tails:
                released.extend(self._held_frames)
                self._held_frames.clear()
                self._held_bytes = 0
        if len(self._pending) > _MAX_SEMANTIC_SSE_FRAME_BYTES:
            raise GatewayUpstreamError("provider SSE frame exceeds semantic guard limit")
        return released

    def finish(self) -> list[bytes]:
        if self._pending:
            raise GatewayUpstreamError("provider SSE frame ended incomplete")
        if any(len(tail) >= _MIN_IDENTIFYING_FRAGMENT for tail in self._tails.values()):
            raise GatewayUpstreamError(
                "provider response contains a controller credential fragment"
            )
        result = self._held_frames
        self._held_frames = []
        self._held_bytes = 0
        return result


def _check_decoded_json_secrets(
    data: bytes, secrets: tuple[str, ...], hex_forms: tuple[str, ...] = ()
) -> None:
    try:
        payload = json.loads(data)
    except (ValueError, UnicodeDecodeError):
        raise GatewayUpstreamError("provider response has invalid JSON") from None
    for _, value in _decoded_strings(payload):
        if _contains_semantic_secret(value, secrets, hex_forms):
            raise GatewayUpstreamError("provider response contains a controller credential")


def validate_request(
    payload: dict[str, Any], policy: ModelPolicy, path: str, grant: TrustedAdmission
) -> str:
    """Validate a provider-native body against a separately admitted route."""
    if type(payload) is not dict or type(grant) is not TrustedAdmission:
        raise GatewayPolicyError("trusted task admission required")
    if _FORBIDDEN_BODY_FIELDS.intersection(payload):
        raise GatewayPolicyError("body role/trigger fields cannot authorize a route")
    if grant.capability_policy_sha256 != policy.capability_policy_sha256:
        raise GatewayPolicyError("capability policy hash mismatch")
    model = payload.get("model")
    if path in _PRIMARY_PATHS and model == PRIMARY_WIRE_MODEL:
        if grant.role is not None or grant.trigger is not None or grant.failure is not None:
            raise GatewayPolicyError("primary request has an alternate role")
        if path == "/v1/messages" and (
            type(payload.get("max_tokens")) is not int
            or not 0 < payload["max_tokens"] <= _MAX_OUTPUT_TOKENS
            or (
                "max_output_tokens" in payload
                and (
                    type(payload["max_output_tokens"]) is not int
                    or not 0 < payload["max_output_tokens"] <= _MAX_OUTPUT_TOKENS
                )
            )
        ):
            raise GatewayPolicyError("primary output token ceiling exceeded or absent")
        return "primary"
    if model != MODEL or path != _DEEPSEEK_PATH:
        raise GatewayPolicyError("undeclared model or route")
    if type(grant.role) is not DeepSeekRole:
        raise GatewayPolicyError("trusted DeepSeek role required")
    expected_trigger = ROLE_LIMITS[grant.role][0]
    if grant.trigger != expected_trigger or not grant.workflow_id:
        raise GatewayPolicyError("trusted DeepSeek role/trigger/workflow required")
    if grant.role is DeepSeekRole.CONDITIONAL_DEBUG_RECOVERY:
        failure = grant.failure
        if (
            type(failure) is not FailureEvidence
            or failure.task_id != grant.task_id
            or failure.attempt_id != grant.attempt_id
            or failure.source not in ("vulnerable_build", "vulnerable_test")
            or failure.exit_code == 0
            or not _digest(failure.evidence_digest)
        ):
            raise GatewayPolicyError("debug requires controller-observed vulnerable failure")
    elif grant.failure is not None:
        raise GatewayPolicyError("failure admission belongs only to debug")
    if (
        payload.get("stream") is not True
        or payload.get("stream_options") != {"include_usage": True}
        or payload.get("thinking") != {"type": "enabled"}
        or payload.get("reasoning_effort") != "max"
        or type(payload.get("max_tokens")) is not int
        or payload["max_tokens"] != MAX_OUTPUT_TOKENS
        or not isinstance(payload.get("messages"), list)
        or not payload["messages"]
    ):
        raise GatewayPolicyError("DeepSeek request settings differ from active route")
    return "deepseek"


class NativeModelGateway:
    """Forward one native provider request under trusted task/role admission.

    ``forward`` is an HTTP-listener integration point: call it only after the
    listener has attached a controller-authenticated connection identity. The
    listener must close the client stream on an exception after headers start.
    """

    def __init__(
        self,
        *,
        task_id: str,
        attempt_id: str,
        task_token: str,
        model_policy: ModelPolicy,
        zai_coding_plan_url: str,
        zai_coding_plan_token: str,
        deepseek_api_key: str,
        budget: SharedCampaignBudget,
        audit: GatewayAudit,
        resolve_admission: Callable[[object], TrustedAdmission],
        mark_started: Callable[[str, str], bool],
        transport: StreamingTransport | None = None,
        native_stream_observer: Callable[[TrustedAdmission, bytes], None] | None = None,
        native_stream_finished: Callable[[TrustedAdmission, bool, str | None], bool] | None = None,
    ):
        if not all(
            type(value) is str and value
            for value in (task_id, attempt_id, task_token, zai_coding_plan_token, deepseek_api_key)
        ):
            raise ValueError("task identity and controller credentials required")
        if type(model_policy) is not ModelPolicy or not isinstance(budget, SharedCampaignBudget):
            raise TypeError("validated policy and shared campaign budget required")
        if zai_coding_plan_url != model_policy.approved_zai_coding_plan_url:
            raise ValueError("Z.ai route differs from approved Z.ai Coding Plan endpoint")
        self._task_id = task_id
        self._attempt_id = attempt_id
        self._task_token = task_token
        self._policy = model_policy
        self._zai_url = zai_coding_plan_url.rstrip("/")
        self._zai_token = zai_coding_plan_token
        self._deepseek_key = deepseek_api_key
        self._budget = budget
        self._audit = audit
        self._resolve_admission = resolve_admission
        self._mark_started = mark_started
        self._transport = transport or HttpxStreamingTransport()
        self._native_stream_observer = native_stream_observer
        self._native_stream_finished = native_stream_finished
        self._lock = asyncio.Lock()
        self._started = False
        self._halted_for_usage = False
        self._halted_for_audit = False
        self._seen_request_ids: set[str] = set()
        self._active_roles: set[DeepSeekRole] = set()
        self._role_usage = {
            role: {"requests": 0, "tokens": 0, "seconds": 0.0} for role in DeepSeekRole
        }

    def __repr__(self):
        return "<NativeModelGateway controller-owned state>"

    def _secrets(self) -> tuple[str, ...]:
        return (self._task_token, self._zai_token, self._deepseek_key)

    async def forward(
        self,
        *,
        path: str,
        authorization: str,
        body: bytes,
        trusted_connection: object,
        send_headers: Callable[[int, Mapping[str, str]], Awaitable[None]],
        send_chunk: Callable[[bytes], Awaitable[None]],
        upstream_headers: Mapping[str, str] | None = None,
    ) -> GatewayResult:
        if type(authorization) is not str or not hmac.compare_digest(
            authorization, "Bearer " + self._task_token
        ):
            raise GatewayPolicyError("task authorization failed")
        if type(body) is not bytes:
            raise GatewayPolicyError("JSON request body required")
        try:
            payload = json.loads(body)
        except (ValueError, UnicodeDecodeError):
            raise GatewayPolicyError("JSON request body required") from None
        grant = self._resolve_admission(trusted_connection)
        if (
            type(grant) is not TrustedAdmission
            or grant.task_id != self._task_id
            or grant.attempt_id != self._attempt_id
            or not grant.request_id
        ):
            raise GatewayPolicyError("trusted task/attempt admission required")
        route = validate_request(payload, self._policy, path, grant)

        async def emit_chunk(chunk: bytes) -> None:
            if self._native_stream_observer is not None and route == "primary":
                try:
                    self._native_stream_observer(grant, chunk)
                except Exception:
                    self._halted_for_audit = True
                    raise GatewayUpstreamError("native stream custody failed") from None
            await send_chunk(chunk)

        role = grant.role if route == "deepseek" else None
        reserved_tokens = CONTEXT_TOKENS if role else PRIMARY_CONTEXT_TOKENS
        async with self._lock:
            if self._halted_for_audit:
                raise GatewayPolicyError("controller audit unavailable; further admission denied")
            if self._halted_for_usage:
                raise GatewayPolicyError("usage unavailable; controller review required")
            if grant.request_id in self._seen_request_ids:
                raise GatewayPolicyError("duplicate request identity")
            try:
                remaining = self._budget.remaining_seconds()
                if role is not None:
                    _, max_calls, max_tokens, max_seconds = ROLE_LIMITS[role]
                    state = self._role_usage[role]
                    if role in self._active_roles:
                        raise GatewayPolicyError("role already has an active child request")
                    if state["requests"] >= max_calls:
                        raise GatewayPolicyError("role request limit exhausted")
                    if state["tokens"] + reserved_tokens > max_tokens:
                        raise GatewayPolicyError("role token limit exhausted")
                    remaining = min(remaining, max_seconds - state["seconds"])
                    if remaining <= 0:
                        raise GatewayPolicyError("role or task deadline exhausted")
                    shared_number = self._budget.reserve_deepseek_request()
                    state["requests"] += 1
                    state["tokens"] += reserved_tokens
                    self._active_roles.add(role)
                else:
                    if remaining <= 0:
                        raise GatewayPolicyError("task deadline exhausted")
                    shared_number = self._budget.reserve_request()
            except BudgetExceeded:
                raise GatewayPolicyError("shared request or task deadline exhausted") from None
            self._seen_request_ids.add(grant.request_id)
            first_request = not self._started
        started_at = time.monotonic()
        requested_at = datetime.now(UTC).isoformat()
        upstream_url = ENDPOINT if role else self._zai_url + path
        base_event = {
            "task_id": self._task_id,
            "attempt_id": self._attempt_id,
            "request_id": grant.request_id,
            "workflow_id": grant.workflow_id,
            "role": role.value if role else "primary",
            "trigger": grant.trigger,
            "requested_model": payload["model"],
            "configured_model": MODEL if role else self._policy.primary,
            "request_sha256": hashlib.sha256(body).hexdigest(),
            "policy_sha256": self._policy.digest,
            "capability_policy_sha256": self._policy.capability_policy_sha256,
            "upstream_endpoint": upstream_url,
            "shared_request_number": shared_number,
            "requested_at_utc": requested_at,
            "official_final_selector": "glm_parent",
        }
        observation = _StreamObservation(
            grant.request_id,
            payload["model"],
            role.value if role else None,
            count_tokens=path == "/v1/messages/count_tokens",
        )
        secret_forms = _secret_forms(self._secrets())
        hex_forms = _hex_forms(self._secrets())
        secret_guard = _SecretStreamGuard(secret_forms)
        semantic_guard = (
            None
            if path == "/v1/messages/count_tokens"
            else _SemanticSSEGuard(secret_forms, hex_forms)
        )
        response: StreamingResponse | None = None
        status: int | None = None
        hard_deadline: float | None = None
        outcome = "interrupted"
        error: Exception | None = None
        pre_forward_audit_failed = False
        start_failed = False
        try:
            self._audit.record_request(
                _redact(base_event | {"event": "request_reserved"}, self._secrets())
            )
            if first_request:
                try:
                    acknowledged = self._mark_started(self._task_id, self._attempt_id)
                except Exception:
                    acknowledged = False
                if acknowledged is not True:
                    start_failed = True
                else:
                    self._started = True
                    self._audit.record_request(
                        _redact(base_event | {"event": "attempt_started"}, self._secrets())
                    )
        except Exception:
            pre_forward_audit_failed = True
        url = upstream_url
        credential = self._deepseek_key if role else self._zai_token
        headers = {"Authorization": "Bearer " + credential, "Content-Type": "application/json"}
        if upstream_headers and role is None:
            for name, value in upstream_headers.items():
                if name.lower() in ("anthropic-version", "anthropic-beta", "accept"):
                    headers[name] = value
        try:
            if pre_forward_audit_failed:
                outcome = "audit_failed"
                # The finally block retains the reservation in usage evidence.
                raise GatewayUpstreamError("controller audit failed before provider dispatch")
            if start_failed:
                outcome = "start_failed"
                raise GatewayUpstreamError(
                    "controller attempt start failed before provider dispatch"
                )
            # A single asyncio timeout covers connection, every trickling chunk,
            # and downstream backpressure. Recheck after durable pre-forward audit.
            remaining = min(remaining, self._budget.remaining_seconds())
            if remaining <= 0:
                raise GatewayDeadlineExceeded("task deadline exhausted before provider dispatch")
            hard_deadline = time.monotonic() + remaining
            async with asyncio.timeout(remaining):
                response = await self._transport.open_stream(url, headers, body, remaining)
                status = response.status_code
                if status < 200 or status >= 300:
                    raise GatewayUpstreamError("provider returned non-success status")
                if any(
                    _contains_semantic_secret(name, secret_forms, hex_forms)
                    for name in response.headers
                ):
                    raise GatewayUpstreamError("provider response contains a controller credential")
                safe_headers = {
                    name: _redact(value, secret_forms, hex_forms)
                    for name, value in response.headers.items()
                    if name.lower() not in _HOP_HEADERS
                }
                pending: list[bytes] = []
                pending_bytes = 0
                identity_verified = False
                count_tokens = path == "/v1/messages/count_tokens"
                async for chunk in response.aiter_bytes():
                    observation.feed(chunk)
                    safe_chunk = secret_guard.feed(chunk)
                    safe_parts = [safe_chunk] if count_tokens else semantic_guard.feed(safe_chunk)
                    if observation.metadata_mismatch or (
                        observation.returned_model is not None
                        and observation.returned_model != payload["model"]
                    ):
                        raise GatewayUpstreamError("provider identity missing or changed")
                    if not identity_verified:
                        pending.extend(safe_parts)
                        pending_bytes += sum(map(len, safe_parts))
                        if pending_bytes > _MAX_IDENTITY_BUFFER:
                            raise GatewayUpstreamError("provider identity missing or changed")
                        if observation.returned_model == payload["model"] and not count_tokens:
                            identity_verified = True
                            await send_headers(status, safe_headers)
                            for held_chunk in pending:
                                await emit_chunk(held_chunk)
                            pending.clear()
                    else:
                        for safe_part in safe_parts:
                            if safe_part:
                                await emit_chunk(safe_part)
                final_raw = secret_guard.finish()
                if count_tokens:
                    if final_raw:
                        pending.append(final_raw)
                elif final_raw:
                    for safe_part in semantic_guard.feed(final_raw):
                        if identity_verified:
                            await emit_chunk(safe_part)
                        else:
                            pending.append(safe_part)
                if semantic_guard is not None:
                    for safe_part in semantic_guard.finish():
                        if identity_verified:
                            await emit_chunk(safe_part)
                        else:
                            pending.append(safe_part)
                observation.finish()
                if not observation.terminal:
                    raise GatewayUpstreamError("provider stream ended without terminal event")
                if count_tokens:
                    _check_decoded_json_secrets(b"".join(pending), secret_forms, hex_forms)
                    if (
                        observation.input_tokens is None
                        or observation.input_tokens > PRIMARY_CONTEXT_TOKENS
                    ):
                        raise GatewayUpstreamError("provider usage invalid")
                    if observation.returned_model not in (None, payload["model"]):
                        raise GatewayUpstreamError("provider identity missing or changed")
                    await send_headers(status, safe_headers)
                    for held_chunk in pending:
                        await emit_chunk(held_chunk)
                elif not identity_verified or not observation.provider_request_id:
                    raise GatewayUpstreamError("provider identity missing or changed")
                if role and observation.invalid_deepseek_usage():
                    raise GatewayUpstreamError("provider usage invalid")
                if (
                    not role
                    and not count_tokens
                    and (
                        observation.output_tokens is not None
                        and observation.output_tokens
                        > min(payload["max_tokens"], _MAX_OUTPUT_TOKENS)
                    )
                ):
                    raise GatewayUpstreamError("provider usage invalid")
            outcome = "completed"
        except TimeoutError:
            outcome = "deadline_exceeded"
            error = GatewayDeadlineExceeded("hard task or role deadline exceeded")
        except asyncio.CancelledError:
            outcome = "cancelled"
            raise
        except GatewayUpstreamError as exc:
            if outcome not in ("audit_failed", "start_failed"):
                outcome = "provider_error"
            error = exc
        except Exception:
            outcome = "transport_error"
            error = GatewayUpstreamError("provider stream failed")
        finally:
            if response is not None:
                close_seconds = (
                    0.0
                    if hard_deadline is None
                    else min(_MAX_CLOSE_SECONDS, hard_deadline - time.monotonic())
                )
                if not await _close_bounded(response, close_seconds):
                    if outcome != "deadline_exceeded" and (
                        hard_deadline is not None and time.monotonic() >= hard_deadline
                    ):
                        outcome = "deadline_exceeded"
                        error = GatewayDeadlineExceeded("hard task or role deadline exceeded")
                    elif outcome == "completed":
                        outcome = "transport_error"
                        error = GatewayUpstreamError("provider stream close failed")
            duration = time.monotonic() - started_at
            failure_code = _failure_code(error)
            retryable = False
            if self._native_stream_finished is not None and route == "primary":
                try:
                    custody_retry = self._native_stream_finished(
                        grant, outcome == "completed", failure_code
                    )
                    retryable = bool(
                        custody_retry
                        and outcome in {"provider_error", "transport_error"}
                        and failure_code in {
                            "provider_stream_no_terminal",
                            "provider_sse_incomplete",
                            "provider_transport_failure",
                        }
                    )
                except Exception:
                    self._halted_for_audit = True
                    outcome = "audit_failed"
                    error = GatewayUpstreamError("native stream custody failed")
                    failure_code = "native_custody_failed"
            usage = observation.usage_row(
                outcome=outcome,
                reserved_tokens=reserved_tokens,
                secrets=secret_forms,
                hex_forms=hex_forms,
            )
            audit_failed = False
            try:
                self._audit.record_usage(usage)
            except Exception:
                audit_failed = True
            try:
                self._audit.record_request(
                    _redact(
                        base_event
                        | {
                            "event": "request_terminal",
                            "outcome": "audit_failed" if audit_failed else outcome,
                            "failure_code": failure_code,
                            "retryable": retryable,
                            "http_status": status,
                            "duration_seconds": duration,
                            "usage_status": usage["usage_status"],
                            "counted_tokens": usage["counted_tokens"],
                            "returned_model": observation.returned_model,
                            "provider_request_id": observation.provider_request_id,
                            "model_version": observation.model_version,
                            "system_fingerprint": observation.system_fingerprint,
                            "completed_at_utc": datetime.now(UTC).isoformat(),
                        },
                        secret_forms,
                        hex_forms,
                    )
                )
            except Exception:
                audit_failed = True
            async with self._lock:
                if role:
                    state = self._role_usage[role]
                    state["seconds"] += duration
                    self._active_roles.discard(role)
                    if usage["usage_status"] == "observed" and not audit_failed:
                        state["tokens"] += usage["counted_tokens"] - reserved_tokens
                if usage["usage_status"] != "observed" and not retryable:
                    self._halted_for_usage = True
                if pre_forward_audit_failed or audit_failed:
                    self._halted_for_audit = True
                if audit_failed:
                    error = GatewayUpstreamError("controller audit failed after provider dispatch")
        if error is not None:
            raise error
        return GatewayResult(
            grant.request_id, status, usage["usage_status"], usage["counted_tokens"]
        )
