# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Exercise the terminating documentation handler against a synthetic upstream."""

from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlencode

import httpx
import pytest
from nooa_cybergym.leaderboard import documentation_service as documentation_module
from nooa_cybergym.leaderboard.capabilities import (
    Capability,
    CapabilityAuthorizer,
    CapabilityRegistry,
    CapabilityRequest,
    ControlLabel,
    Effect,
    Role,
    Status,
    ToolIdentity,
)
from nooa_cybergym.leaderboard.documentation_service import (
    DocumentationAdmission,
    DocumentationHTTPService,
    VerifiedHTTPSNoRedirectTransport,
)
from nooa_cybergym.leaderboard.network import GatewayResponse, NetworkDenied, NetworkPolicy

POLICY_PATH = Path(__file__).parents[2] / "leaderboard/config/network-policy.json"
URL = "https://clang.llvm.org/docs/UsersManual.html"
PATH = "/v1/documentation/compiler/reference-v1"


@dataclass
class _Audit:
    events: list = field(default_factory=list)
    acknowledge: bool = True

    def record(self, event):
        self.events.append(event)
        return self.acknowledge


def _admission(capability_audit):
    identity = ToolIdentity(
        "documentation-gateway",
        "1",
        "1" * 64,
        "documentation.fetch",
        "1",
        "2" * 64,
        "terminating-docs-adapter",
        "1",
        "3" * 64,
    )
    entry = Capability(
        capability_id="docs.compiler",
        identity=identity,
        operation="fetch",
        status=Status.APPROVED,
        control_label=ControlLabel.LEAKAGE_BOUNDARY,
        purpose="Read audited generic compiler documentation",
        roles=(Role.CHILD,),
        effects=(Effect.READ, Effect.NETWORK),
        data_scopes=("generic-compiler-documentation",),
        path_scopes=(),
        routes=("documentation/compiler/reference-v1",),
        provider_ids=(),
        model_ids=(),
        credential_refs=(),
        accounting="one tool call",
        log_schema="network-v1",
        evidence_refs=("synthetic-route-cert",),
        certification_digest="4" * 64,
    )
    request = CapabilityRequest(
        capability_id=entry.capability_id,
        tool_id=identity.tool_id,
        identity=identity,
        operation="fetch",
        adapter_digest=identity.adapter_digest,
        effects=(Effect.READ, Effect.NETWORK),
        data_scopes=("generic-compiler-documentation",),
        paths=(),
        routes=("documentation/compiler/reference-v1",),
        provider_ids=(),
        model_ids=(),
        task_id="synthetic-task",
        attempt_id="attempt-1",
        request_id="request-1",
    )
    authorizer = CapabilityAuthorizer(CapabilityRegistry((entry,)), Role.CHILD, capability_audit)
    return DocumentationAdmission(authorizer, request)


def _public_dns(host, port):
    assert host == "clang.llvm.org"
    assert port == 443
    return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443))]


def _service(upstream, service_audit=None, capability_audit=None, resolver=_public_dns):
    service_audit = service_audit or _Audit()
    capability_audit = capability_audit or _Audit()
    admission = _admission(capability_audit)

    def resolve(scope):
        # The listener's authenticated connection context supplies the grant.
        # Request JSON, query parameters and claimed roles never construct it.
        return (
            admission if dict(scope["headers"]).get(b"x-task-token") == b"synthetic-token" else None
        )

    transport = VerifiedHTTPSNoRedirectTransport(
        transport=httpx.MockTransport(upstream), resolver=resolver
    )
    service = DocumentationHTTPService(
        NetworkPolicy.load(POLICY_PATH), transport, resolve, service_audit
    )
    return service, service_audit, capability_audit


def _invoke(service, *, path=PATH, query=None, token=True):
    sent = []
    headers = [(b"authorization", b"Bearer must-not-forward")]
    if token:
        headers.append((b"x-task-token", b"synthetic-token"))

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "method": "GET",
        "path": path,
        "query_string": urlencode(query or {"url": URL}).encode(),
        "headers": headers,
    }
    asyncio.run(service(scope, receive, send))
    return sent[0]["status"], sent[1]["body"]


def test_approved_document_is_released_only_after_audited_terminating_fetch():
    upstream_calls = []

    def upstream(request):
        upstream_calls.append(str(request.url))
        assert request.method == "GET"
        assert "authorization" not in request.headers
        assert "cookie" not in request.headers
        assert "x-task-token" not in request.headers
        return httpx.Response(
            200, headers={"content-type": "text/html"}, content=b"<h1>Generic compiler options</h1>"
        )

    service, service_audit, capability_audit = _service(upstream)
    status, body = _invoke(service)
    assert (status, body) == (200, b"<h1>Generic compiler options</h1>")
    assert upstream_calls == [URL]
    assert service_audit.events[0].outcome == "released"
    assert service_audit.events[0].bytes_released == len(body)
    assert capability_audit.events[0].disposition == "allowed"


def test_redirect_to_target_patch_is_blocked_without_second_upstream_request():
    upstream_calls = []

    def upstream(request):
        upstream_calls.append(str(request.url))
        return httpx.Response(
            302,
            headers={
                "location": "https://github.com/target/repo/commit/fixed",
            },
        )

    service, service_audit, _ = _service(upstream)
    status, body = _invoke(service)
    assert status == 403
    assert b"github" not in body
    assert upstream_calls == [URL]
    assert service_audit.events[0].outcome == "denied"


def test_mirrored_fixed_answer_body_never_reaches_agent():
    secret_answer = b"secret fixed content in repo-fix.tar.gz"

    def upstream(_):
        return httpx.Response(200, headers={"content-type": "text/html"}, content=secret_answer)

    service, audit, _ = _service(upstream)
    status, body = _invoke(service)
    assert status == 403
    assert secret_answer not in body
    assert audit.events[0].bytes_released == 0


def test_oversized_response_is_cut_off_and_not_released():
    def upstream(_):
        return httpx.Response(200, headers={"content-type": "text/plain"}, content=b"a" * 2_097_153)

    service, audit, _ = _service(upstream)
    status, body = _invoke(service)
    assert status == 403
    assert body != b"a" * 2_097_153
    assert audit.events[0].bytes_released == 0


def test_untrusted_or_claimed_role_request_never_fetches_upstream():
    upstream_calls = []

    def upstream(request):
        upstream_calls.append(str(request.url))
        return httpx.Response(200, content=b"unreachable")

    service, audit, _ = _service(upstream)
    assert _invoke(service, token=False)[0] == 403
    assert _invoke(service, query={"url": URL, "role": "controller"})[0] == 400
    assert _invoke(service, query={"url": "https://github.com/target/repo"})[0] == 403
    assert upstream_calls == []
    assert [event.outcome for event in audit.events] == ["unauthenticated", "malformed", "denied"]


def test_credential_query_and_failed_audit_are_never_released():
    upstream_calls = []

    def upstream(request):
        upstream_calls.append(str(request.url))
        return httpx.Response(200, headers={"content-type": "text/plain"}, content=b"safe")

    failed_audit = _Audit(acknowledge=False)
    service, audit, _ = _service(upstream, service_audit=failed_audit)
    status, body = _invoke(service, query={"url": URL + "?api_key=controller-secret"})
    assert status == 503
    assert body != b"safe"
    assert upstream_calls == []
    assert "controller-secret" not in repr(audit.events)


def test_invalid_https_port_is_audited_denial_without_upstream_fetch():
    upstream_calls = []

    def upstream(request):
        upstream_calls.append(str(request.url))
        return httpx.Response(200, content=b"unreachable")

    service, audit, _ = _service(upstream)
    status, body = _invoke(
        service,
        query={
            "url": "https://clang.llvm.org:invalid/docs/UsersManual.html",
        },
    )
    assert status == 403
    assert body == b"forbidden\n"
    assert upstream_calls == []
    assert audit.events[0].outcome == "denied"


def test_capability_audit_failure_returns_service_unavailable():
    upstream_calls = []

    def upstream(request):
        upstream_calls.append(str(request.url))
        return httpx.Response(200, content=b"unreachable")

    service, audit, _ = _service(upstream, capability_audit=_Audit(acknowledge=False))
    status, body = _invoke(service)
    assert status == 503
    assert body == b"service unavailable\n"
    assert upstream_calls == []
    assert audit.events[0].outcome == "authorization_error"


@pytest.mark.parametrize(
    "ip",
    ("127.0.0.1", "10.0.0.5", "169.254.169.254", "::1", "fe80::1"),
)
def test_dns_private_loopback_or_link_local_result_is_denied_before_fetch(ip):
    calls = []
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET

    def resolve(host, port):
        return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))]

    def upstream(request):
        calls.append(request)
        return httpx.Response(200, content=b"never")

    service, audit, _ = _service(upstream, resolver=resolve)
    status, body = _invoke(service)
    assert (status, body) == (403, b"forbidden\n")
    assert not calls
    assert audit.events[0].outcome == "denied"


def test_mixed_public_and_private_dns_answers_fail_closed():
    def resolve(host, port):
        return _public_dns(host, port) + [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("10.0.0.8", port))
        ]

    service, _, _ = _service(
        lambda request: httpx.Response(200, content=b"never"), resolver=resolve
    )
    assert _invoke(service)[0] == 403


def test_redirect_hop_re_resolves_and_rejects_rebound_private_address():
    dns_calls = []
    upstream_calls = []

    def resolve(host, port):
        dns_calls.append((host, port))
        if len(dns_calls) == 1:
            return _public_dns(host, port)
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", port))]

    def upstream(request):
        upstream_calls.append(str(request.url))
        return httpx.Response(302, headers={"location": "/docs/OtherManual.html"})

    service, audit, _ = _service(upstream, resolver=resolve)
    status, body = _invoke(service)
    assert (status, body) == (403, b"forbidden\n")
    assert dns_calls == [("clang.llvm.org", 443), ("clang.llvm.org", 443)]
    assert upstream_calls == [URL]
    assert audit.events[0].outcome == "denied"


def test_checked_public_address_is_passed_to_pinned_fetcher_without_second_dns_lookup():
    dns_calls = []
    connected = []

    def resolve(host, port):
        dns_calls.append((host, port))
        return _public_dns(host, port)

    def fetch_pinned(url, destination, max_bytes, timeout_seconds):
        connected.append((url, destination.host, destination.sockaddr, max_bytes))
        return GatewayResponse(200, "text/plain", b"safe")

    transport = VerifiedHTTPSNoRedirectTransport(resolver=resolve, fetch_pinned=fetch_pinned)
    result = transport.get_no_redirect(URL, max_bytes=32)
    assert result.body == b"safe"
    assert dns_calls == [("clang.llvm.org", 443)]
    assert connected == [(URL, "clang.llvm.org", ("93.184.216.34", 443), 32)]


def test_transport_rejects_private_dns_without_pinned_fetch():
    def resolve(host, port):
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("192.168.1.2", port))]

    transport = VerifiedHTTPSNoRedirectTransport(
        resolver=resolve,
        fetch_pinned=lambda *args: (_ for _ in ()).throw(AssertionError("must not fetch")),
    )
    with pytest.raises(NetworkDenied):
        transport.get_no_redirect(URL, max_bytes=32)


@pytest.mark.parametrize("url", ("https://localhost/docs/", "https://clang.llvm.org:0/docs/"))
def test_transport_rejects_textual_host_boundary_or_wrong_port_before_dns(url):
    transport = VerifiedHTTPSNoRedirectTransport(
        resolver=lambda host, port: (_ for _ in ()).throw(AssertionError("must not resolve")),
        fetch_pinned=lambda *args: (_ for _ in ()).throw(AssertionError("must not fetch")),
    )
    with pytest.raises(NetworkDenied):
        transport.get_no_redirect(url, max_bytes=32)


def test_real_connector_uses_checked_sockaddr_and_original_tls_hostname(monkeypatch):
    connected = []
    tls_hosts = []

    class FakeSocket:
        def settimeout(self, seconds):
            assert seconds == 5.0

        def connect(self, address):
            connected.append(address)

        def close(self):
            pass

    class FakeTLSContext:
        def wrap_socket(self, raw, *, server_hostname):
            tls_hosts.append(server_hostname)
            return raw

    monkeypatch.setattr(documentation_module.socket, "socket", lambda *args: FakeSocket())
    monkeypatch.setattr(documentation_module.ssl, "create_default_context", FakeTLSContext)
    destination = documentation_module.PinnedDestination(
        "clang.llvm.org", 443, socket.AF_INET, ("93.184.216.34", 443)
    )
    connection = documentation_module._PinnedHTTPSConnection(destination, 5.0)
    connection.connect()
    assert connected == [("93.184.216.34", 443)]
    assert tls_hosts == ["clang.llvm.org"]
    assert connection.host == "clang.llvm.org"
