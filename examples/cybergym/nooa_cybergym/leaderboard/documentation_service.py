# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Controller-owned terminating HTTPS fetch and ASGI documentation handler.

Mount this ASGI callable only behind a listener that authenticates the task
connection and supplies ``resolve_admission`` from trusted controller state.
The solver's query chooses a URL inside its already-authorized documentation
route; query/body/header claims never grant a role or capability. No listener
is started here, and this module does not make the current Docker topology
ready for live certification.
"""

from __future__ import annotations

import asyncio
import hashlib
import http.client
import ipaddress
import math
import socket
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol
from urllib.parse import parse_qs, urlsplit

import httpx

from .capabilities import AuditFailure, CapabilityAuthorizer, CapabilityRequest
from .network import (
    DocumentationGateway,
    GatewayResponse,
    NetworkDenied,
    NetworkPolicy,
)


class DocumentationUpstreamError(RuntimeError):
    """The trusted HTTPS fetch failed; the upstream details stay private."""


class DocumentationAuditFailure(RuntimeError):
    """A response cannot be released without acknowledged controller evidence."""


@dataclass(frozen=True, slots=True)
class PinnedDestination:
    """One checked numeric peer, retaining the approved TLS/HTTP hostname."""

    host: str
    port: int
    family: int
    sockaddr: tuple[Any, ...]


def _system_resolver(host: str, port: int) -> list[tuple[Any, ...]]:
    return socket.getaddrinfo(
        host,
        port,
        family=socket.AF_UNSPEC,
        type=socket.SOCK_STREAM,
        proto=socket.IPPROTO_TCP,
    )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connect by checked sockaddr; verify the certificate against its DNS name."""

    def __init__(self, destination: PinnedDestination, timeout: float) -> None:
        self._destination = destination
        self._tls_context = ssl.create_default_context()
        super().__init__(
            destination.host,
            port=destination.port,
            timeout=timeout,
            context=self._tls_context,
        )

    def connect(self) -> None:
        raw = socket.socket(self._destination.family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        raw.settimeout(self.timeout)
        try:
            # sockaddr is the already-vetted getaddrinfo result. No second
            # hostname resolution occurs between the check and connect.
            raw.connect(self._destination.sockaddr)
            self.sock = self._tls_context.wrap_socket(raw, server_hostname=self._destination.host)
        except BaseException:
            raw.close()
            raise


class VerifiedHTTPSNoRedirectTransport:
    """Read one TLS-verified hop, without env proxies, cookies, or redirects.

    ``transport`` and ``fetch_pinned`` are synthetic test seams. Production
    construction resolves once per hop, rejects any non-public DNS answer,
    connects to the vetted numeric address, and verifies TLS for the original
    approved hostname. An audited proxy needs its own certified adapter.
    """

    def __init__(
        self,
        *,
        transport: httpx.BaseTransport | None = None,
        timeout_seconds: float = 10.0,
        resolver: Callable[[str, int], list[tuple[Any, ...]]] | None = None,
        fetch_pinned: Callable[[str, PinnedDestination, int, float], GatewayResponse] | None = None,
    ) -> None:
        if (
            type(timeout_seconds) not in (int, float)
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise ValueError("documentation timeout must be finite and positive")
        if transport is not None and not isinstance(transport, httpx.MockTransport):
            raise TypeError("only a synthetic HTTP transport may bypass the pinned connector")
        if transport is not None and fetch_pinned is not None:
            raise TypeError("choose one synthetic fetch seam")
        if resolver is not None and not callable(resolver):
            raise TypeError("DNS resolver must be callable")
        if fetch_pinned is not None and not callable(fetch_pinned):
            raise TypeError("pinned fetcher must be callable")
        self._transport = transport
        self._timeout = float(timeout_seconds)
        self._resolver = resolver or _system_resolver
        self._fetch_pinned = fetch_pinned or self._real_fetch_pinned

    def get_no_redirect(self, url: str, *, max_bytes: int) -> GatewayResponse:
        parsed = urlsplit(url)
        try:
            port = 443 if parsed.port is None else parsed.port
        except ValueError:
            raise NetworkDenied("documentation transport requires a valid HTTPS port") from None
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or port != 443
        ):
            raise NetworkDenied("documentation transport requires an HTTPS origin")
        host = parsed.hostname
        if host == "localhost" or host.endswith((".local", ".internal")):
            raise NetworkDenied("documentation transport requires a public hostname")
        if type(max_bytes) is not int or not 0 < max_bytes <= 2_097_152:
            raise ValueError("documentation response limit is invalid")
        destination = self._resolve_public(host, port)
        try:
            if self._transport is not None:
                result = self._mock_fetch(url, max_bytes)
            else:
                result = self._fetch_pinned(url, destination, max_bytes, self._timeout)
            if type(result) is not GatewayResponse or type(result.body) is not bytes:
                raise DocumentationUpstreamError("documentation upstream unavailable")
            if len(result.body) > max_bytes:
                raise NetworkDenied("documentation response exceeds audited size limit")
            return result
        except NetworkDenied:
            raise
        except Exception:
            raise DocumentationUpstreamError("documentation upstream unavailable") from None

    def _resolve_public(self, host: str, port: int) -> PinnedDestination:
        try:
            # Literal IP hosts have no approved DNS identity to pin.
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise NetworkDenied("documentation destination must be a DNS hostname")
        try:
            answers = tuple(self._resolver(host, port))
        except Exception:
            raise DocumentationUpstreamError("documentation DNS unavailable") from None
        if not 0 < len(answers) <= 32:
            raise DocumentationUpstreamError("documentation DNS unavailable")
        destinations = []
        for answer in answers:
            if (
                type(answer) not in (tuple, list)
                or len(answer) != 5
                or answer[0] not in (socket.AF_INET, socket.AF_INET6)
                or answer[1] != socket.SOCK_STREAM
                or answer[2] not in (0, socket.IPPROTO_TCP)
                or type(answer[4]) not in (tuple, list)
                or len(answer[4]) not in (2, 4)
                or type(answer[4][0]) is not str
                or type(answer[4][1]) is not int
                or answer[4][1] != port
                or "%" in answer[4][0]
            ):
                raise NetworkDenied("documentation DNS answer is unaudited")
            try:
                address = ipaddress.ip_address(answer[4][0])
            except ValueError:
                raise NetworkDenied("documentation DNS answer is unaudited") from None
            if address.version != (4 if answer[0] == socket.AF_INET else 6):
                raise NetworkDenied("documentation DNS family mismatch")
            if not address.is_global:
                raise NetworkDenied("documentation DNS resolved outside public Internet")
            destinations.append(PinnedDestination(host, port, answer[0], tuple(answer[4])))
        return destinations[0]

    def _mock_fetch(self, url: str, max_bytes: int) -> GatewayResponse:
        with httpx.Client(
            transport=self._transport,
            verify=True,
            follow_redirects=False,
            trust_env=False,
            timeout=httpx.Timeout(self._timeout),
        ) as client:
            with client.stream(
                "GET",
                url,
                headers={
                    "Accept": "text/html,text/plain,text/markdown,application/xhtml+xml",
                    "Accept-Encoding": "identity",
                },
                follow_redirects=False,
            ) as response:
                content_type = response.headers.get("content-type", "")
                if 300 <= response.status_code < 400:
                    return GatewayResponse(
                        response.status_code,
                        content_type,
                        b"",
                        response.headers.get("location"),
                    )
                if response.status_code != 200:
                    return GatewayResponse(response.status_code, content_type, b"")
                chunks = []
                total = 0
                for chunk in response.iter_bytes():
                    total += len(chunk)
                    if total > max_bytes:
                        raise NetworkDenied("documentation response exceeds audited size limit")
                    chunks.append(chunk)
                return GatewayResponse(200, content_type, b"".join(chunks))

    @staticmethod
    def _real_fetch_pinned(
        url: str, destination: PinnedDestination, max_bytes: int, timeout_seconds: float
    ) -> GatewayResponse:
        parsed = urlsplit(url)
        target = parsed.path or "/"
        if parsed.query:
            target += "?" + parsed.query
        connection = _PinnedHTTPSConnection(destination, timeout_seconds)
        try:
            connection.request(
                "GET",
                target,
                headers={
                    "Accept": "text/html,text/plain,text/markdown,application/xhtml+xml",
                    "Accept-Encoding": "identity",
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            content_type = response.getheader("content-type", "")
            if 300 <= response.status < 400:
                return GatewayResponse(
                    response.status, content_type, b"", response.getheader("location")
                )
            if response.status != 200:
                return GatewayResponse(response.status, content_type, b"")
            if response.getheader("content-encoding", "identity").lower() != "identity":
                raise NetworkDenied("compressed documentation response is unaudited")
            chunks = []
            total = 0
            while chunk := response.read(min(65536, max_bytes - total + 1)):
                total += len(chunk)
                if total > max_bytes:
                    raise NetworkDenied("documentation response exceeds audited size limit")
                chunks.append(chunk)
            return GatewayResponse(200, content_type, b"".join(chunks))
        finally:
            connection.close()


@dataclass(frozen=True, slots=True)
class DocumentationAdmission:
    """Controller-authenticated request identity, never built from HTTP fields."""

    authorizer: CapabilityAuthorizer
    request: CapabilityRequest

    def __post_init__(self) -> None:
        if type(self.authorizer) is not CapabilityAuthorizer:
            raise TypeError("controller capability authorizer is required")
        if type(self.request) is not CapabilityRequest:
            raise TypeError("controller capability request is required")


@dataclass(frozen=True, slots=True)
class DocumentationAuditEvent:
    timestamp_utc: str
    policy_sha256: str
    task_id: str
    attempt_id: str
    request_id: str
    role: str
    route_id: str
    url_sha256: str
    outcome: str
    status_code: int
    bytes_released: int
    body_sha256: str
    redirect_count: int


class DocumentationAuditSink(Protocol):
    def record(self, event: DocumentationAuditEvent) -> bool:
        """Durably acknowledge controller-only request evidence."""


class DocumentationHTTPService:
    """ASGI handler that releases only checked content after an audit ACK."""

    def __init__(
        self,
        policy: NetworkPolicy,
        transport: VerifiedHTTPSNoRedirectTransport,
        resolve_admission: Callable[[dict[str, Any]], DocumentationAdmission | None],
        audit_sink: DocumentationAuditSink,
    ) -> None:
        if type(policy) is not NetworkPolicy:
            raise TypeError("frozen network policy required")
        if type(transport) is not VerifiedHTTPSNoRedirectTransport:
            raise TypeError("controller terminating HTTPS transport required")
        if not callable(resolve_admission) or not callable(getattr(audit_sink, "record", None)):
            raise TypeError("trusted admission resolver and audit sink are required")
        self._policy = policy
        self._transport = transport
        self._resolve_admission = resolve_admission
        self._audit_sink = audit_sink

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            raise RuntimeError("documentation service handles HTTP requests only")
        admission = self._admission(scope)
        if admission is None:
            await self._finish(send, None, "", "", "unauthenticated", 403, b"forbidden\n")
            return

        path = scope.get("path")
        prefix = "/v1/documentation/"
        if type(path) is not str or not path.startswith(prefix):
            await self._finish(send, admission, "", "", "malformed", 404, b"not found\n")
            return
        route_id = "documentation/" + path[len(prefix) :]
        if route_id not in self._policy.documentation_routes:
            await self._finish(send, admission, route_id, "", "malformed", 404, b"not found\n")
            return
        if admission.request.routes != (route_id,):
            await self._finish(send, admission, route_id, "", "denied", 403, b"forbidden\n")
            return
        if scope.get("method") != "GET" or self._has_body(scope):
            await self._finish(
                send, admission, route_id, "", "malformed", 405, b"method not allowed\n"
            )
            return
        url = self._sole_url(scope)
        if url is None:
            await self._finish(send, admission, route_id, "", "malformed", 400, b"bad request\n")
            return

        try:
            gateway = DocumentationGateway(self._policy, admission.authorizer, self._transport)
            result = await asyncio.to_thread(gateway.fetch, admission.request, url)
        except (NetworkDenied, ValueError):
            await self._finish(send, admission, route_id, url, "denied", 403, b"forbidden\n")
            return
        except AuditFailure:
            await self._finish(
                send, admission, route_id, url, "authorization_error", 503, b"service unavailable\n"
            )
            return
        except DocumentationUpstreamError:
            await self._finish(
                send, admission, route_id, url, "upstream_error", 502, b"upstream unavailable\n"
            )
            return
        await self._finish(
            send,
            admission,
            route_id,
            url,
            "released",
            200,
            result.body,
            body_sha256=hashlib.sha256(result.body).hexdigest(),
            redirect_count=len(result.redirect_chain) - 1,
        )

    def _admission(self, scope: dict[str, Any]) -> DocumentationAdmission | None:
        try:
            admission = self._resolve_admission(scope)
        except Exception:
            return None
        return admission if type(admission) is DocumentationAdmission else None

    @staticmethod
    def _has_body(scope: dict[str, Any]) -> bool:
        headers = scope.get("headers", ())
        for key, value in headers:
            if key.lower() == b"transfer-encoding":
                return True
            if key.lower() == b"content-length":
                try:
                    if int(value) != 0:
                        return True
                except ValueError:
                    return True
        return False

    @staticmethod
    def _sole_url(scope: dict[str, Any]) -> str | None:
        raw = scope.get("query_string", b"")
        if type(raw) is not bytes or not 0 < len(raw) <= 8192:
            return None
        try:
            fields = parse_qs(
                raw.decode("utf-8"), keep_blank_values=True, strict_parsing=True, max_num_fields=2
            )
        except (UnicodeDecodeError, ValueError):
            return None
        if set(fields) != {"url"} or len(fields["url"]) != 1:
            return None
        url = fields["url"][0]
        return url if 0 < len(url) <= 4096 and not any(ord(c) < 32 for c in url) else None

    async def _finish(
        self,
        send: Any,
        admission: DocumentationAdmission | None,
        route_id: str,
        url: str,
        outcome: str,
        status: int,
        body: bytes,
        *,
        body_sha256: str = "",
        redirect_count: int = 0,
    ) -> None:
        request = admission.request if admission else None
        event = DocumentationAuditEvent(
            timestamp_utc=datetime.now(UTC).isoformat(),
            policy_sha256=self._policy.digest,
            task_id=request.task_id if request else "unbound",
            attempt_id=request.attempt_id if request else "unbound",
            request_id=request.request_id if request else "unbound",
            role=admission.authorizer.trusted_role.value if admission else "unbound",
            route_id=route_id,
            url_sha256=hashlib.sha256(url.encode("utf-8")).hexdigest(),
            outcome=outcome,
            status_code=status,
            bytes_released=len(body) if status == 200 else 0,
            body_sha256=body_sha256,
            redirect_count=redirect_count,
        )
        try:
            if self._audit_sink.record(event) is not True:
                raise DocumentationAuditFailure("documentation evidence unavailable")
        except Exception:
            status = 503
            body = b"service unavailable\n"
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"text/plain; charset=utf-8"),
                    (b"cache-control", b"no-store"),
                    (b"x-content-type-options", b"nosniff"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
