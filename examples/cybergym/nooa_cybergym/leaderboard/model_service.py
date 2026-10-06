# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Controller-mounted ASGI listener for the native model gateway.

The HTTP server must insert an opaque connection handle into the ASGI scope
extension named by ``CONNECTION_SCOPE_KEY``. That value is never taken from a
solver header or request body. The injected resolver maps it to the handle
accepted by ``NativeModelGateway.resolve_admission``; the gateway validates the
task token, controller grant, model route, budget, provider identity, and audit.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Callable, Mapping
from typing import Any

from .model_gateway import (
    GatewayDeadlineExceeded,
    GatewayPolicyError,
    GatewayUpstreamError,
    NativeModelGateway,
)

CONNECTION_SCOPE_KEY = "xeus.model_connection"
_PATHS = frozenset(("/v1/messages", "/v1/messages/count_tokens", "/v1/chat/completions"))
_MAX_BODY_BYTES = 16 * 1024 * 1024
_HEADER_NAME = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_SSE_SEPARATOR = re.compile(rb"(?:\r?\n){2}")
_MAX_SSE_FRAME_BYTES = 4 * 1024 * 1024
_CLAIM_PARTS = frozenset(
    ("role", "trigger", "failure", "workflow", "admission", "task", "attempt", "capability")
)
_CLAIM_FRAGMENTS = (
    "role",
    "trigger",
    "failure",
    "admission",
    "taskid",
    "attemptid",
    "requestid",
    "workflowid",
    "capabilitypolicy",
)
_BODY_CLAIMS = frozenset(
    (
        "role",
        "trigger",
        "failure",
        "taskid",
        "attemptid",
        "requestid",
        "workflowid",
        "capabilitypolicyhash",
        "capabilitypolicysha256",
        "admission",
    )
)
_SAFE_RESPONSE_HEADERS = frozenset(("content-type", "x-request-id"))


class ModelStreamAborted(RuntimeError):
    """The upstream stream failed after response headers reached the client."""


class _Rejected(Exception):
    def __init__(self, status: int):
        self.status = status


class ModelHTTPService:
    """ASGI HTTP handler mounted inside the controller-authenticated listener.

    ``resolve_connection`` receives only a server-injected opaque handle, not
    the HTTP scope. Returning ``None`` fails closed. It must resolve to the
    connection context used by the gateway's controller-owned admission logic.
    """

    def __init__(
        self,
        gateway: NativeModelGateway,
        resolve_connection: Callable[[object], object | None],
    ) -> None:
        if not isinstance(gateway, NativeModelGateway) or not callable(resolve_connection):
            raise TypeError("native gateway and controller connection resolver required")
        self._gateway = gateway
        self._resolve_connection = resolve_connection
        self._secret_bytes = tuple(
            value.encode("utf-8")
            for value in gateway._secrets()
            if value  # noqa: SLF001
        )
        self._secret_tail_size = max((len(value) for value in self._secret_bytes), default=1) - 1

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            raise RuntimeError("model service handles HTTP requests only")
        path = scope.get("path")
        if type(path) is not str or path not in _PATHS:
            await self._respond(send, 404)
            return
        if scope.get("method") != "POST":
            await self._respond(send, 405)
            return
        if scope.get("query_string", b"") != b"":
            await self._respond(send, 400)
            return

        try:
            authorization, upstream_headers, content_length = self._headers(scope)
            connection = self._connection(scope)
            body = await self._body(receive, content_length)
            if body is None:  # The client disconnected before completing its request.
                return
            self._validate_body(body)
        except _Rejected as rejected:
            await self._respond(send, rejected.status)
            return

        started = False
        pending_sse = bytearray()
        released_tail = b""

        def guard_payload(payload: bytes) -> None:
            nonlocal released_tail
            combined = released_tail + payload
            if any(secret in combined for secret in self._secret_bytes):
                raise RuntimeError("sensitive model stream payload")
            released_tail = combined[-self._secret_tail_size :] if self._secret_tail_size else b""

        async def send_headers(status: int, headers: Mapping[str, str]) -> None:
            nonlocal started
            if started or type(status) is not int or not 200 <= status < 300:
                raise RuntimeError("invalid model stream status")
            safe = [
                (b"cache-control", b"no-store"),
                (b"x-content-type-options", b"nosniff"),
            ]
            for name, value in headers.items():
                if type(name) is not str or type(value) is not str:
                    continue
                lowered = name.lower()
                if lowered in _SAFE_RESPONSE_HEADERS and _valid_header_value(value):
                    encoded = value.encode("latin-1")
                    if any(secret in encoded for secret in self._secret_bytes):
                        raise RuntimeError("sensitive model response header")
                    safe.append((lowered.encode("ascii"), encoded))
            started = True
            await send({"type": "http.response.start", "status": status, "headers": safe})

        async def send_chunk(chunk: bytes) -> None:
            if not started or type(chunk) is not bytes:
                raise RuntimeError("invalid model stream chunk")
            if path == "/v1/messages/count_tokens":
                guard_payload(chunk)
                await send({"type": "http.response.body", "body": chunk, "more_body": True})
                return
            pending_sse.extend(chunk)
            while match := _SSE_SEPARATOR.search(pending_sse):
                frame = bytes(pending_sse[: match.end()])
                del pending_sse[: match.end()]
                if _provider_error_frame(frame):
                    raise RuntimeError("provider stream error")
                guard_payload(frame)
                await send({"type": "http.response.body", "body": frame, "more_body": True})
            if len(pending_sse) > _MAX_SSE_FRAME_BYTES:
                raise RuntimeError("provider stream frame too large")

        forward = asyncio.create_task(
            self._gateway.forward(
                path=path,
                authorization=authorization,
                body=body,
                trusted_connection=connection,
                send_headers=send_headers,
                send_chunk=send_chunk,
                upstream_headers=upstream_headers,
            )
        )
        disconnected = asyncio.create_task(self._watch_disconnect(receive))
        try:
            done, _ = await asyncio.wait(
                (forward, disconnected), return_when=asyncio.FIRST_COMPLETED
            )
            if disconnected in done and forward not in done:
                return
            await forward
            if not started:
                await self._respond(send, 502)
                return
            if pending_sse:
                if _provider_error_frame(bytes(pending_sse)):
                    raise RuntimeError("provider stream error")
                guard_payload(bytes(pending_sse))
                await send(
                    {"type": "http.response.body", "body": bytes(pending_sse), "more_body": True}
                )
            await send({"type": "http.response.body", "body": b"", "more_body": False})
        except asyncio.CancelledError:
            raise
        except GatewayPolicyError:
            await self._error_or_abort(send, started, 403)
        except GatewayDeadlineExceeded:
            await self._error_or_abort(send, started, 504)
        except GatewayUpstreamError:
            await self._error_or_abort(send, started, 502)
        except Exception:
            await self._error_or_abort(send, started, 503)
        finally:
            if not forward.done():
                forward.cancel()
            if not disconnected.done():
                disconnected.cancel()
            await asyncio.gather(forward, disconnected, return_exceptions=True)

    def _connection(self, scope: dict[str, Any]) -> object:
        extensions = scope.get("extensions")
        if type(extensions) is not dict:
            raise _Rejected(403)
        handle = extensions.get(CONNECTION_SCOPE_KEY)
        if handle is None:
            raise _Rejected(403)
        try:
            connection = self._resolve_connection(handle)
        except Exception:
            raise _Rejected(403) from None
        if connection is None:
            raise _Rejected(403)
        return connection

    @staticmethod
    def _headers(scope: dict[str, Any]) -> tuple[str, dict[str, str], int | None]:
        raw = scope.get("headers", ())
        if type(raw) not in (list, tuple):
            raise _Rejected(400)
        parsed: dict[str, bytes] = {}
        for pair in raw:
            if (
                type(pair) not in (tuple, list)
                or len(pair) != 2
                or type(pair[0]) is not bytes
                or type(pair[1]) is not bytes
                or not _HEADER_NAME.fullmatch(pair[0])
                or any(char in pair[1] for char in (0, 10, 13))
            ):
                raise _Rejected(400)
            name = pair[0].decode("ascii").lower()
            if _header_claim(name):
                raise _Rejected(403)
            if name in parsed and name in (
                "authorization",
                "x-api-key",
                "content-type",
                "content-length",
                "anthropic-version",
                "anthropic-beta",
                "accept",
            ):
                raise _Rejected(400)
            parsed[name] = pair[1]
        if ("authorization" in parsed) == ("x-api-key" in parsed):
            raise _Rejected(400)
        try:
            if "authorization" in parsed:
                authorization = parsed["authorization"].decode("ascii")
            else:
                authorization = "Bearer " + parsed["x-api-key"].decode("ascii")
            content_type = parsed.get("content-type", b"application/json").decode("ascii")
            if content_type.lower().split(";", 1)[0].strip() != "application/json":
                raise _Rejected(415)
            length = None
            if "content-length" in parsed:
                raw_length = parsed["content-length"]
                if not raw_length.isdigit():
                    raise _Rejected(400)
                length = int(raw_length)
                if length > _MAX_BODY_BYTES:
                    raise _Rejected(413)
            upstream = {
                name: parsed[name].decode("latin-1")
                for name in ("anthropic-version", "anthropic-beta", "accept")
                if name in parsed
            }
        except (UnicodeError, ValueError):
            raise _Rejected(400) from None
        return authorization, upstream, length

    @staticmethod
    async def _body(receive: Any, content_length: int | None) -> bytes | None:
        chunks = bytearray()
        while True:
            message = await receive()
            if type(message) is not dict:
                raise _Rejected(400)
            if message.get("type") == "http.disconnect":
                return None
            if message.get("type") != "http.request":
                raise _Rejected(400)
            piece = message.get("body", b"")
            more = message.get("more_body", False)
            if type(piece) is not bytes or type(more) is not bool:
                raise _Rejected(400)
            if len(chunks) + len(piece) > _MAX_BODY_BYTES:
                raise _Rejected(413)
            chunks.extend(piece)
            if not more:
                if content_length is not None and len(chunks) != content_length:
                    raise _Rejected(400)
                return bytes(chunks)

    @staticmethod
    def _validate_body(body: bytes) -> None:
        try:
            payload = json.loads(body)
        except (ValueError, UnicodeError):
            raise _Rejected(400) from None
        if type(payload) is not dict:
            raise _Rejected(400)
        for key in payload:
            if type(key) is not str:
                raise _Rejected(400)
            normalized = "".join(char for char in key.lower() if char.isalnum())
            if normalized in _BODY_CLAIMS or any(
                fragment in normalized for fragment in _CLAIM_FRAGMENTS
            ):
                raise _Rejected(403)

    @staticmethod
    async def _watch_disconnect(receive: Any) -> bool:
        # No more request-body events are valid after more_body=False. Any
        # subsequent receive event means the stream is no longer usable.
        await receive()
        return True

    @staticmethod
    async def _error_or_abort(send: Any, started: bool, status: int) -> None:
        if started:
            # Raising after response.start asks the ASGI server to close the
            # incomplete stream; a clean EOF would falsely imply success.
            raise ModelStreamAborted("model stream interrupted") from None
        await ModelHTTPService._respond(send, status)

    @staticmethod
    async def _respond(send: Any, status: int) -> None:
        response = {
            400: ("invalid_request", "bad request"),
            403: ("forbidden", "request denied"),
            404: ("not_found", "not found"),
            405: ("method_not_allowed", "method not allowed"),
            413: ("request_too_large", "request too large"),
            415: ("unsupported_media_type", "unsupported media type"),
            502: ("upstream_unavailable", "upstream unavailable"),
            503: ("service_unavailable", "service unavailable"),
            504: ("deadline_exceeded", "deadline exceeded"),
        }[status]
        body = json.dumps(
            {"type": "error", "error": {"type": response[0], "message": response[1]}},
            separators=(",", ":"),
        ).encode()
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"cache-control", b"no-store"),
                    (b"x-content-type-options", b"nosniff"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body, "more_body": False})


def _header_claim(name: str) -> bool:
    parts = set(name.split("-"))
    compact = "".join(char for char in name if char.isalnum())
    return bool(parts & _CLAIM_PARTS) or any(part in compact for part in _CLAIM_FRAGMENTS)


def _valid_header_value(value: str) -> bool:
    try:
        encoded = value.encode("latin-1")
    except UnicodeError:
        return False
    return len(encoded) <= 8192 and not any(char in encoded for char in (0, 10, 13))


def _provider_error_frame(frame: bytes) -> bool:
    data_lines = []
    for line in frame.splitlines():
        if line.startswith(b"event:") and line[6:].strip().lower() == b"error":
            return True
        if line.startswith(b"data:"):
            data_lines.append(line[5:].lstrip(b" "))
    if not data_lines:
        return False
    try:
        payload = json.loads(b"\n".join(data_lines))
    except (ValueError, UnicodeError):
        return False
    return type(payload) is dict and (payload.get("type") == "error" or "error" in payload)
