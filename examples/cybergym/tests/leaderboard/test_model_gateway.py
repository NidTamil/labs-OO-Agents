# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Native model gateway tests; all upstream responses are local synthetic streams."""

import asyncio
import base64
import hashlib
import itertools
import json
import socket
import ssl
from dataclasses import replace
from pathlib import Path

import httpcore
import httpx
import pytest
from nooa_cybergym.leaderboard.deepseek import (
    AlternateModelPolicy,
    DeepSeekRole,
    FailureEvidence,
    SharedCampaignBudget,
)
from nooa_cybergym.leaderboard.model_gateway import (
    GatewayAudit,
    GatewayDeadlineExceeded,
    GatewayPolicyError,
    GatewayUpstreamError,
    HttpxStreamingTransport,
    ModelPolicy,
    NativeModelGateway,
    TrustedAdmission,
)

CONFIG = Path(__file__).resolve().parents[2] / "leaderboard/config/alternate-model.json"
TASK_TOKEN = "solver-task-token"
ZAI_TOKEN = "controller-zai-secret"
DEEPSEEK_TOKEN = "controller-deepseek-secret"
DIGEST = "a" * 64


def _dns(host, port, *addresses):
    assert host in ("api.z.ai", "api.deepseek.com")
    assert port == 443
    return [
        (
            socket.AF_INET6 if ":" in address else socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            (address, port, 0, 0) if ":" in address else (address, port),
        )
        for address in addresses
    ]


class _RecordingNetworkStream(httpcore.AsyncMockStream):
    def __init__(self, response_bytes):
        super().__init__([response_bytes])
        self.writes = []
        self.tls_hosts = []

    async def write(self, buffer, timeout=None):
        self.writes.append(buffer)

    async def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        self.tls_hosts.append(server_hostname)
        return self


class _RecordingNetworkBackend(httpcore.AsyncNetworkBackend):
    def __init__(self, response_bytes=b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"):
        self.response_bytes = response_bytes
        self.calls = []
        self.streams = []

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        self.calls.append((host, port))
        stream = _RecordingNetworkStream(self.response_bytes)
        self.streams.append(stream)
        return stream

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):
        raise AssertionError("Unix socket must not be used")

    async def sleep(self, seconds):
        pass


@pytest.mark.parametrize(
    "address", ("127.0.0.1", "10.0.0.2", "169.254.169.254", "224.0.0.1", "::1", "fe80::1")
)
def test_model_transport_rejects_nonpublic_dns_before_controller_key_dispatch(address):
    dialer = _RecordingNetworkBackend()
    transport = HttpxStreamingTransport(
        resolver=lambda host, port: _dns(host, port, address), network_backend=dialer
    )

    async def call():
        await transport.open_stream(
            "https://api.z.ai/api/anthropic/v1/messages",
            {"Authorization": "Bearer synthetic-controller-key"},
            b"{}",
            5.0,
        )

    with pytest.raises(GatewayUpstreamError):
        asyncio.run(call())
    assert dialer.calls == []


def test_model_transport_rejects_mixed_public_and_private_dns_answers():
    dialer = _RecordingNetworkBackend()
    transport = HttpxStreamingTransport(
        resolver=lambda host, port: _dns(host, port, "1.1.1.1", "10.0.0.2"),
        network_backend=dialer,
    )

    async def call():
        await transport.open_stream(
            "https://api.z.ai/api/anthropic/v1/messages",
            {"Authorization": "Bearer synthetic-controller-key"},
            b"{}",
            5.0,
        )

    with pytest.raises(GatewayUpstreamError):
        asyncio.run(call())
    assert dialer.calls == []


def test_model_transport_pins_checked_ip_but_preserves_original_host_and_tls_name():
    dialer = _RecordingNetworkBackend()
    dns_calls = []

    def resolve(host, port):
        dns_calls.append((host, port))
        return _dns(host, port, "1.1.1.1")

    transport = HttpxStreamingTransport(resolver=resolve, network_backend=dialer)

    async def call():
        response = await transport.open_stream(
            "https://api.z.ai/api/anthropic/v1/messages",
            {"Authorization": "Bearer synthetic-controller-key"},
            b"{}",
            5.0,
        )
        try:
            return response.status_code, b"".join([part async for part in response.aiter_bytes()])
        finally:
            await response.aclose()

    assert asyncio.run(call()) == (200, b"hello")
    assert dns_calls == [("api.z.ai", 443)]
    assert dialer.calls == [("1.1.1.1", 443)]
    assert dialer.streams[0].tls_hosts == ["api.z.ai"]
    sent = b"".join(dialer.streams[0].writes)
    assert b"Host: api.z.ai" in sent
    assert b"Authorization: Bearer synthetic-controller-key" in sent


def test_model_transport_pins_deepseek_despite_proxy_environment(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:8888")
    dialer = _RecordingNetworkBackend()
    dns_calls = []

    def resolve(host, port):
        dns_calls.append((host, port))
        return _dns(host, port, "1.1.1.1")

    transport = HttpxStreamingTransport(resolver=resolve, network_backend=dialer)

    async def call():
        response = await transport.open_stream(
            "https://api.deepseek.com/chat/completions",
            {"Authorization": "Bearer synthetic-controller-key"},
            b"{}",
            5.0,
        )
        try:
            return response.status_code
        finally:
            await response.aclose()

    assert asyncio.run(call()) == 200
    assert dns_calls == [("api.deepseek.com", 443)]
    assert dialer.calls == [("1.1.1.1", 443)]
    assert dialer.streams[0].tls_hosts == ["api.deepseek.com"]
    assert b"Host: api.deepseek.com" in b"".join(dialer.streams[0].writes)


def test_model_transport_does_not_follow_redirect_or_resolve_its_target():
    dialer = _RecordingNetworkBackend(
        b"HTTP/1.1 302 Found\r\nLocation: https://127.0.0.1/private\r\nContent-Length: 0\r\n\r\n"
    )
    transport = HttpxStreamingTransport(
        resolver=lambda host, port: _dns(host, port, "1.1.1.1"),
        network_backend=dialer,
    )

    async def call():
        response = await transport.open_stream(
            "https://api.z.ai/api/anthropic/v1/messages", {}, b"{}", 5.0
        )
        try:
            return response.status_code
        finally:
            await response.aclose()

    assert asyncio.run(call()) == 302
    assert dialer.calls == [("1.1.1.1", 443)]


@pytest.mark.parametrize(
    "url",
    (
        "https://127.0.0.1/api/anthropic/v1/messages",
        "http://api.z.ai/api/anthropic/v1/messages",
        "https://api.z.ai:8443/api/anthropic/v1/messages",
        "https://api.z.ai/api/anthropic/unapproved",
        "https://attacker.example/api/anthropic/v1/messages",
    ),
)
def test_model_transport_rejects_unapproved_route_before_dns(url):
    transport = HttpxStreamingTransport(
        resolver=lambda host, port: (_ for _ in ()).throw(AssertionError("must not resolve")),
        network_backend=_RecordingNetworkBackend(),
    )

    async def call():
        await transport.open_stream(
            url, {"Authorization": "Bearer synthetic-controller-key"}, b"{}", 5.0
        )

    with pytest.raises(GatewayUpstreamError):
        asyncio.run(call())


def test_model_transport_rejects_caller_host_override_before_dns():
    dns_calls = []
    dialer = _RecordingNetworkBackend()

    def resolve(host, port):
        dns_calls.append((host, port))
        return _dns(host, port, "1.1.1.1")

    transport = HttpxStreamingTransport(
        resolver=resolve,
        network_backend=dialer,
    )

    async def call():
        await transport.open_stream(
            "https://api.z.ai/api/anthropic/v1/messages",
            {"Host": "attacker.example", "Authorization": "Bearer synthetic-controller-key"},
            b"{}",
            5.0,
        )

    with pytest.raises(GatewayUpstreamError):
        asyncio.run(call())
    assert dns_calls == []
    assert dialer.calls == []


def policy():
    return ModelPolicy(
        primary="glm-5.3[1m]",
        alternate=AlternateModelPolicy.model_validate_json(CONFIG.read_text()),
        capability_policy_sha256=DIGEST,
        approved_zai_coding_plan_url="https://api.z.ai/api/anthropic",
    )


def takeover_payload():
    return {
        "model": "glm-5.3",
        "max_tokens": 128000,
        "stream": True,
        "thinking": {"type": "adaptive"},
        "output_config": {"effort": "max"},
        "messages": [{"role": "user", "content": "Inspect the task."}],
    }


def takeover_gateway(tmp_path, responses, *, observer=None, finished=None, binding=None):
    from nooa_cybergym.leaderboard.primary_takeover import PrimaryTakeoverPolicy

    class SequenceTransport:
        def __init__(self):
            self.calls = []

        async def open_stream(self, url, headers, body, timeout):
            self.calls.append((url, headers, json.loads(body)))
            if "api.deepseek.com" in url:
                assert any(
                    row["event"] == "primary_route_switched"
                    for row in rows(tmp_path / "requests.jsonl")
                )
            item = responses[len(self.calls) - 1]
            if isinstance(item, BaseException):
                raise item
            return item

    transport = SequenceTransport()
    budget = SharedCampaignBudget()
    request_numbers = itertools.count(1)
    core = NativeModelGateway(
        task_id="task-1",
        attempt_id="attempt-1",
        task_token=TASK_TOKEN,
        model_policy=replace(policy(), primary_takeover=PrimaryTakeoverPolicy()),
        zai_coding_plan_url="https://api.z.ai/api/anthropic",
        zai_coding_plan_token=ZAI_TOKEN,
        deepseek_api_key=DEEPSEEK_TOKEN,
        budget=budget,
        audit=GatewayAudit(tmp_path / "requests.jsonl", tmp_path / "usage.jsonl"),
        resolve_admission=lambda _: replace(admission(), request_id=f"req-{next(request_numbers)}"),
        mark_started=lambda *_: True,
        transport=transport,
        native_stream_observer=observer,
        native_stream_finished=finished,
        native_provider_binding=binding,
    )
    return core, transport, budget


def deepseek_native_stream():
    response = primary_stream()
    response.chunks = [part.replace(b"glm-5.3", b"deepseek-flash") for part in response.chunks]
    return response


def test_takeover_keeps_native_request_and_settles_two_primary_attempts(tmp_path):
    finished, bindings = [], []
    core, transport, budget = takeover_gateway(
        tmp_path,
        [httpx.ConnectError("synthetic unavailable"), deepseek_native_stream()],
        finished=lambda grant, complete, code: finished.append((grant.request_id, complete, code)),
        binding=lambda grant, **values: bindings.append((grant.request_id, values)),
    )
    result, headers, chunks = run(core, "/v1/messages", takeover_payload())
    assert result.request_id == "req-1" and result.usage_status == "observed"
    assert len(headers) == 1 and b"deepseek-flash" in b"".join(chunks)
    assert len(transport.calls) == 2
    assert transport.calls[1][0] == "https://api.deepseek.com/anthropic/v1/messages"
    assert transport.calls[1][1]["Authorization"] == "Bearer " + DEEPSEEK_TOKEN
    assert transport.calls[1][2]["model"] == "deepseek-flash"
    assert budget.snapshot()["glm_and_memory_auxiliary_requests"] == 2
    assert budget.snapshot()["deepseek_requests"] == 0
    assert finished == [("req-1", True, None)]
    usage = rows(tmp_path / "usage.jsonl")
    assert [entry["model"] for entry in usage] == ["glm-5.3", "deepseek-flash"]
    assert [entry["usage_status"] for entry in usage] == ["interrupted", "observed"]
    assert usage[0]["counted_tokens"] == 1_000_000
    assert len({entry["provider_attempt_id"] for entry in usage}) == 2
    assert {entry["request_id"] for entry in usage} == {"req-1"}
    assert [values["provider"] for _, values in bindings] == [
        "zai-coding-plan", "deepseek-official-api"
    ]


@pytest.mark.parametrize("status", [429, 500, 502, 503, 504])
def test_takeover_only_on_typed_availability_http_failures(tmp_path, status):
    core, transport, _ = takeover_gateway(
        tmp_path, [StreamResponse([], status=status), deepseek_native_stream()]
    )
    assert run(core, "/v1/messages", takeover_payload())[0].usage_status == "observed"
    assert len(transport.calls) == 2


@pytest.mark.parametrize("failure", [
    401,
    403,
    400,
    GatewayUpstreamError("unapproved provider destination"),
    RuntimeError("unclassified transport failure"),
    asyncio.CancelledError(),
])
def test_takeover_never_retries_unclassified_or_excluded_failures(tmp_path, failure):
    if type(failure) is int:
        failure = StreamResponse([], status=failure)
    core, transport, _ = takeover_gateway(tmp_path, [failure, deepseek_native_stream()])
    with pytest.raises((GatewayUpstreamError, asyncio.CancelledError)):
        run(core, "/v1/messages", takeover_payload())
    assert len(transport.calls) == 1


def test_takeover_count_tokens_fails_closed_after_switch_without_dispatch(tmp_path):
    core, transport, _ = takeover_gateway(
        tmp_path, [StreamResponse([], status=503), deepseek_native_stream()]
    )
    run(core, "/v1/messages", takeover_payload())
    with pytest.raises(GatewayPolicyError, match="count"):
        run(core, "/v1/messages/count_tokens", {"model": "glm-5.3", "messages": []})
    assert len(transport.calls) == 2


def test_takeover_policy_is_opt_in_and_preserves_old_digest():
    old = policy()
    expected = hashlib.sha256(json.dumps({
        "primary": old.primary,
        "alternate_sha256": old.alternate.digest,
        "capability_policy_sha256": old.capability_policy_sha256,
        "approved_zai_coding_plan_url": old.approved_zai_coding_plan_url,
    }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    assert old.primary_takeover is None
    assert old.digest == expected


def test_takeover_never_retries_after_headers_even_when_client_write_fails(tmp_path):
    core, transport, _ = takeover_gateway(tmp_path, [primary_stream(), deepseek_native_stream()])

    async def headers(_status, _headers):
        raise httpx.ReadTimeout("synthetic downstream timeout")

    async def chunk(_value):
        raise AssertionError("no chunk expected")

    async def invoke():
        await core.forward(
            path="/v1/messages", authorization="Bearer " + TASK_TOKEN,
            body=json.dumps(takeover_payload()).encode(), trusted_connection=object(),
            send_headers=headers, send_chunk=chunk,
        )

    with pytest.raises(GatewayUpstreamError):
        asyncio.run(invoke())
    assert len(transport.calls) == 1


def test_takeover_does_not_retry_failed_deepseek_or_revert_on_later_request(tmp_path):
    core, transport, budget = takeover_gateway(
        tmp_path, [StreamResponse([], status=503), StreamResponse([], status=503), primary_stream()]
    )
    with pytest.raises(GatewayUpstreamError):
        run(core, "/v1/messages", takeover_payload())
    with pytest.raises(GatewayPolicyError):
        run(core, "/v1/messages", takeover_payload())
    assert len(transport.calls) == 2 and budget.snapshot()["requests"] == 2


def test_takeover_continues_on_deepseek_without_another_transition(tmp_path):
    core, transport, budget = takeover_gateway(
        tmp_path, [StreamResponse([], status=503), deepseek_native_stream(), deepseek_native_stream()]
    )
    run(core, "/v1/messages", takeover_payload())
    run(core, "/v1/messages", takeover_payload())
    assert [call[2]["model"] for call in transport.calls] == [
        "glm-5.3", "deepseek-flash", "deepseek-flash"
    ]
    assert budget.snapshot()["glm_and_memory_auxiliary_requests"] == 3
    assert len([r for r in rows(tmp_path / "requests.jsonl") if r["event"] == "primary_route_switched"]) == 1


def test_takeover_transition_audit_failure_prevents_second_dispatch(tmp_path, monkeypatch):
    from nooa_cybergym.leaderboard.primary_takeover import PrimaryTakeoverPersistenceError

    core, transport, _ = takeover_gateway(
        tmp_path, [StreamResponse([], status=503), deepseek_native_stream()]
    )
    write = core._audit.record_request

    def fail_switch(event):
        if event["event"] == "primary_route_switched":
            raise OSError("synthetic audit failure")
        write(event)

    monkeypatch.setattr(core._audit, "record_request", fail_switch)
    with pytest.raises(PrimaryTakeoverPersistenceError):
        run(core, "/v1/messages", takeover_payload())
    assert len(transport.calls) == 1
    assert rows(tmp_path / "usage.jsonl")[0]["counted_tokens"] == 1_000_000


def test_takeover_does_not_borrow_advisory_capacity(tmp_path):
    core, transport, budget = takeover_gateway(
        tmp_path, [StreamResponse([], status=503), deepseek_native_stream()]
    )
    for _ in range(1409):
        budget.reserve_request()
    with pytest.raises(GatewayPolicyError):
        run(core, "/v1/messages", takeover_payload())
    assert len(transport.calls) == 1
    assert budget.snapshot()["requests"] == 1410
    assert budget.snapshot()["deepseek_requests"] == 0


def test_takeover_rejects_unsupported_native_payload_before_deepseek_reservation(tmp_path):
    core, transport, budget = takeover_gateway(
        tmp_path, [StreamResponse([], status=503), deepseek_native_stream()]
    )
    payload = takeover_payload() | {"thinking": {"type": "enabled", "budget_tokens": 2048}}
    with pytest.raises(GatewayPolicyError, match="unsupported"):
        run(core, "/v1/messages", payload)
    assert len(transport.calls) == 1 and budget.snapshot()["requests"] == 1


def test_takeover_failure_retains_known_provider_status_when_native_terminal_fails(tmp_path):
    def fail_finished(*args):
        raise PermissionError("synthetic invalid custody")

    core, transport, _ = takeover_gateway(
        tmp_path, [StreamResponse([], status=503), deepseek_native_stream()], finished=fail_finished
    )
    with pytest.raises(GatewayUpstreamError, match="custody"):
        run(core, "/v1/messages", takeover_payload())
    assert len(transport.calls) == 2
    terminal = rows(tmp_path / "requests.jsonl")[-1]
    assert terminal["event"] == "native_request_terminal"
    assert terminal["outcome"] == "audit_failed"
    assert terminal["failure_code"] == "native_custody_failed"
    with pytest.raises(GatewayPolicyError, match="audit"):
        run(core, "/v1/messages", takeover_payload())


def test_takeover_does_not_treat_tls_identity_failure_as_connection_unavailability(tmp_path):
    failure = httpx.ConnectError("synthetic TLS verification failed")
    failure.__cause__ = ssl.SSLCertVerificationError("synthetic certificate mismatch")
    core, transport, _ = takeover_gateway(tmp_path, [failure, deepseek_native_stream()])
    with pytest.raises(GatewayUpstreamError):
        run(core, "/v1/messages", takeover_payload())
    assert len(transport.calls) == 1


def test_takeover_cancellation_during_failed_provider_close_never_dispatches_fallback(tmp_path):
    async def invoke():
        closing = asyncio.Event()

        class ClosingResponse(StreamResponse):
            async def aclose(self):
                closing.set()
                await asyncio.Event().wait()

        core, transport, _ = takeover_gateway(
            tmp_path, [ClosingResponse([], status=503), deepseek_native_stream()]
        )

        async def discard(*_args):
            return None

        task = asyncio.create_task(core.forward(
            path="/v1/messages", authorization="Bearer " + TASK_TOKEN,
            body=json.dumps(takeover_payload()).encode(), trusted_connection=object(),
            send_headers=discard, send_chunk=discard,
        ))
        await closing.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert len(transport.calls) == 1
        assert not any(
            event["event"] == "primary_route_switched"
            for event in rows(tmp_path / "requests.jsonl")
        )

    asyncio.run(invoke())


@pytest.mark.parametrize("fallback", [False, True])
def test_takeover_unavailable_completed_usage_halts_native_request_without_retry(tmp_path, fallback):
    response = deepseek_native_stream() if fallback else primary_stream()
    response.chunks = [
        chunk.replace(b'"output_tokens": 5', b'"output_tokens": -1') for chunk in response.chunks
    ]
    finished = []
    responses = [StreamResponse([], status=503), response] if fallback else [response]
    core, transport, _ = takeover_gateway(
        tmp_path, responses, finished=lambda grant, complete, code: finished.append((complete, code))
    )
    with pytest.raises(GatewayUpstreamError, match="usage"):
        run(core, "/v1/messages", takeover_payload())
    assert finished == [(False, "provider_usage_invalid")]
    assert len(transport.calls) == (2 if fallback else 1)
    assert rows(tmp_path / "usage.jsonl")[-1]["usage_status"] == "interrupted"


def test_takeover_concurrent_late_glm_failure_uses_persisted_transition_once(tmp_path):
    async def invoke():
        release = asyncio.Event()
        waiting = asyncio.Event()

        class LateFailure(StreamResponse):
            async def aiter_bytes(self):
                waiting.set()
                await release.wait()
                raise httpx.ReadTimeout("synthetic late GLM outage")
                yield  # pragma: no cover - declares an async iterator

        class SignalSuccess(StreamResponse):
            async def aclose(self):
                release.set()

        response = deepseek_native_stream()
        core, transport, budget = takeover_gateway(tmp_path, [
            LateFailure([]), StreamResponse([], status=503),
            SignalSuccess(response.chunks), deepseek_native_stream(), deepseek_native_stream(),
        ])

        async def discard(*_args):
            return None

        async def request():
            return await core.forward(
                path="/v1/messages", authorization="Bearer " + TASK_TOKEN,
                body=json.dumps(takeover_payload()).encode(), trusted_connection=object(),
                send_headers=discard, send_chunk=discard,
            )

        first = asyncio.create_task(request())
        await waiting.wait()
        second = await request()
        assert (await first).usage_status == second.usage_status == "observed"
        assert (await request()).usage_status == "observed"
        assert [call[2]["model"] for call in transport.calls] == [
            "glm-5.3", "glm-5.3", "deepseek-flash", "deepseek-flash", "deepseek-flash",
        ]
        assert budget.snapshot()["glm_and_memory_auxiliary_requests"] == 5
        events = rows(tmp_path / "requests.jsonl")
        transitions = [event for event in events if event["event"] == "primary_route_switched"]
        continuations = [event for event in events if event["event"] == "primary_request_continued"]
        assert len(transitions) == len(continuations) == 1
        transition, continuation = transitions[0], continuations[0]
        assert continuation["transition_request_id"] == transition["request_id"] == "req-2"
        assert continuation["request_id"] == "req-1"
        assert continuation["transition_sha256"] == hashlib.sha256(
            json.dumps(transition, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        assert continuation["transition_failed_provider_attempt_id"] == transition["failed_provider_attempt_id"]
        assert continuation["transition_fallback_provider_attempt_id"] == transition["fallback_provider_attempt_id"]
        assert len({row["provider_attempt_id"] for row in rows(tmp_path / "usage.jsonl")}) == 5

    asyncio.run(invoke())


@pytest.mark.parametrize(
    "wrong_url",
    [
        "https://api.z.ai/api/coding/paas/v4",
        "https://api.z.ai/api/v1",
        "https://api.z.ai/api/anthropic/v1",
        "https://attacker.example/api/anthropic",
    ],
)
def test_primary_policy_requires_exact_anthropic_coding_plan_route(wrong_url):
    with pytest.raises(ValueError, match="Coding Plan endpoint"):
        replace(policy(), approved_zai_coding_plan_url=wrong_url)


class StreamResponse:
    def __init__(self, chunks, status=200, headers=None, pause=0):
        self.status_code = status
        self.headers = headers or {"content-type": "text/event-stream"}
        self.chunks = chunks
        self.pause = pause
        self.closed = False

    async def aiter_bytes(self):
        for chunk in self.chunks:
            if self.pause:
                await asyncio.sleep(self.pause)
            yield chunk

    async def aclose(self):
        self.closed = True


class Transport:
    def __init__(self, response):
        self.response = response
        self.calls = []

    async def open_stream(self, url, headers, body, timeout):
        self.calls.append((url, headers, body, timeout))
        return self.response


def lines(*events):
    return [("data: " + json.dumps(event) + "\n\n").encode() for event in events]


def primary_stream():
    return StreamResponse(
        lines(
            {
                "type": "message_start",
                "message": {
                    "id": "m1",
                    "model": "glm-5.3",
                    "usage": {
                        "input_tokens": 11,
                        "cache_read_input_tokens": 7,
                        "cache_creation_input_tokens": 2,
                    },
                },
            },
            {
                "type": "content_block_start",
                "content_block": {"type": "tool_use", "id": "tool-1", "name": "Read"},
            },
            {"type": "message_delta", "usage": {"output_tokens": 5}},
            {"type": "message_stop"},
        )
    )


def alternate_stream(usage=None):
    if usage is None:
        usage = {
            "prompt_tokens": 10,
            "completion_tokens": 8,
            "total_tokens": 18,
            "prompt_cache_hit_tokens": 3,
            "prompt_cache_miss_tokens": 7,
            "completion_tokens_details": {"reasoning_tokens": 5},
        }
    return StreamResponse(
        lines(
            {
                "id": "ds-1",
                "model": "deepseek-flash",
                "system_fingerprint": "fp-1",
                "choices": [{"index": 0, "delta": {"reasoning_content": "think"}}],
            },
            {
                "id": "ds-1",
                "model": "deepseek-flash",
                "choices": [
                    {
                        "index": 0,
                        "delta": {
                            "tool_calls": [
                                {"index": 0, "id": "call-1", "function": {"name": "lookup"}}
                            ]
                        },
                    }
                ],
            },
            {"id": "ds-1", "model": "deepseek-flash", "choices": [], "usage": usage},
        )
        + [b"data: [DONE]\n\n"]
    )


def admission(role=None, *, trigger=None, failure=None, task_id="task-1", attempt_id="attempt-1"):
    return TrustedAdmission(
        task_id=task_id,
        attempt_id=attempt_id,
        request_id="req-1",
        role=role,
        trigger=trigger,
        capability_policy_sha256=DIGEST,
        workflow_id="wf-1" if role else None,
        failure=failure,
    )


def gateway(
    tmp_path,
    response,
    trusted_admission=None,
    started=None,
    budget=None,
    *,
    repeat_id=False,
    zai_url="https://api.z.ai/api/anthropic",
    native_stream_observer=None,
    native_stream_finished=None,
):
    transport = Transport(response)
    audit = GatewayAudit(tmp_path / "model-request.jsonl", tmp_path / "usage.jsonl")
    starts = [] if started is None else started
    grant = trusted_admission or admission()
    request_numbers = itertools.count(1)
    core = NativeModelGateway(
        task_id="task-1",
        attempt_id="attempt-1",
        task_token=TASK_TOKEN,
        model_policy=policy(),
        zai_coding_plan_url=zai_url,
        zai_coding_plan_token=ZAI_TOKEN,
        deepseek_api_key=DEEPSEEK_TOKEN,
        budget=budget or SharedCampaignBudget(),
        audit=audit,
        resolve_admission=lambda connection: (
            grant if repeat_id else replace(grant, request_id=f"req-{next(request_numbers)}")
        ),
        mark_started=lambda task_id, attempt_id: starts.append((task_id, attempt_id)) or True,
        transport=transport,
        native_stream_observer=native_stream_observer,
        native_stream_finished=native_stream_finished,
    )
    return core, transport, starts


def run(core, path, payload, token=TASK_TOKEN):
    headers, output = [], []

    async def send_headers(status, values):
        headers.append((status, values))

    async def send_chunk(chunk):
        output.append(chunk)

    result = asyncio.run(
        core.forward(
            path=path,
            authorization="Bearer " + token,
            body=json.dumps(payload).encode(),
            trusted_connection=object(),
            send_headers=send_headers,
            send_chunk=send_chunk,
        )
    )
    return result, headers, output


def rows(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def deepseek_payload():
    return {
        "model": "deepseek-flash",
        "stream": True,
        "stream_options": {"include_usage": True},
        "thinking": {"type": "enabled"},
        "reasoning_effort": "max",
        "max_tokens": 128000,
        "messages": [{"role": "user", "content": "current task facts"}],
    }


def test_native_custody_receives_exact_checked_stream_and_terminal(tmp_path):
    observed, finished = [], []
    core, _, _ = gateway(
        tmp_path,
        primary_stream(),
        native_stream_observer=lambda grant, data: observed.append((grant.request_id, data)),
        native_stream_finished=lambda grant, complete, failure_code: finished.append(
            (grant.request_id, complete, failure_code)
        ),
    )
    _, _, output = run(
        core, "/v1/messages", {"model": "glm-5.3", "max_tokens": 128000, "stream": True}
    )
    assert b"".join(data for _, data in observed) == b"".join(output)
    assert finished == [("req-1", True, None)]


def test_client_cancel_is_named_for_native_custody_without_retry(tmp_path):
    finished = []
    core, _, _ = gateway(
        tmp_path,
        primary_stream(),
        native_stream_finished=lambda grant, complete, code: (
            finished.append((complete, code)) or False
        ),
    )

    async def cancel_on_chunk(_chunk):
        raise asyncio.CancelledError

    async def send_headers(_status, _values):
        return None

    async def invoke():
        await core.forward(
            path="/v1/messages",
            authorization="Bearer " + TASK_TOKEN,
            body=json.dumps({"model": "glm-5.3", "max_tokens": 128000, "stream": True}).encode(),
            trusted_connection=object(),
            send_headers=send_headers,
            send_chunk=cancel_on_chunk,
        )

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(invoke())
    assert finished == [(False, "client_cancelled")]
    terminal = rows(tmp_path / "model-request.jsonl")[-1]
    assert terminal["outcome"] == "cancelled"
    assert terminal["failure_code"] == "client_cancelled"
    assert terminal["retryable"] is False


def test_primary_thinking_only_failure_records_bounded_retry_custody(tmp_path):
    response = StreamResponse(
        lines(
            {"type": "message_start", "message": {"id": "m1", "model": "glm-5.3"}},
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "thinking", "thinking": ""},
            },
        )
    )
    finished = []
    core, transport, _ = gateway(
        tmp_path,
        response,
        native_stream_finished=lambda grant, complete, code: (
            finished.append((complete, code)) or code == "provider_stream_no_terminal"
        ),
    )
    with pytest.raises(GatewayUpstreamError, match="terminal event"):
        run(core, "/v1/messages", {"model": "glm-5.3", "max_tokens": 128000, "stream": True})
    assert finished == [(False, "provider_stream_no_terminal")]
    terminal = rows(tmp_path / "model-request.jsonl")[-1]
    assert terminal["failure_code"] == "provider_stream_no_terminal"
    assert terminal["retryable"] is True
    assert rows(tmp_path / "usage.jsonl")[-1]["counted_tokens"] == 1_000_000
    with pytest.raises(GatewayUpstreamError, match="terminal event"):
        run(core, "/v1/messages", {"model": "glm-5.3", "max_tokens": 128000, "stream": True})
    assert len(transport.calls) == 2


def test_nonretryable_primary_interruption_still_halts_usage(tmp_path):
    response = StreamResponse(
        lines({"type": "message_start", "message": {"id": "m1", "model": "glm-5.3"}})
    )
    core, transport, _ = gateway(
        tmp_path,
        response,
        native_stream_finished=lambda grant, complete, code: False,
    )
    with pytest.raises(GatewayUpstreamError, match="terminal event"):
        run(core, "/v1/messages", {"model": "glm-5.3", "max_tokens": 128000, "stream": True})
    with pytest.raises(GatewayPolicyError, match="usage unavailable"):
        run(core, "/v1/messages", {"model": "glm-5.3", "max_tokens": 128000, "stream": True})
    assert len(transport.calls) == 1


def test_incomplete_sse_frame_has_distinct_retryable_failure_code(tmp_path):
    response = StreamResponse(
        lines({"type": "message_start", "message": {"id": "m1", "model": "glm-5.3"}})
        + [b'data: {"type":"content_block_delta"']
    )
    finished = []
    core, _, _ = gateway(
        tmp_path,
        response,
        native_stream_finished=lambda grant, complete, code: (
            finished.append(code) or code == "provider_sse_incomplete"
        ),
    )
    with pytest.raises(GatewayUpstreamError, match="SSE frame ended incomplete"):
        run(core, "/v1/messages", {"model": "glm-5.3", "max_tokens": 128000, "stream": True})
    assert finished == ["provider_sse_incomplete"]
    assert rows(tmp_path / "model-request.jsonl")[-1]["retryable"] is True


def test_credential_fragment_failure_code_never_allows_retry(tmp_path):
    from nooa_cybergym.leaderboard.model_gateway import _failure_code

    assert (
        _failure_code(
            GatewayUpstreamError("provider response contains a controller credential fragment")
        )
        == "credential_fragment_denied"
    )
    assert (
        _failure_code(GatewayUpstreamError("provider SSE frame ended incomplete"))
        == "provider_sse_incomplete"
    )


def test_short_ambiguous_credential_prefix_is_released_at_stream_end():
    from nooa_cybergym.leaderboard.model_gateway import _SecretStreamGuard, _SemanticSSEGuard

    raw = _SecretStreamGuard(("controller-private-key",))
    assert raw.feed(b"ordinary text ending in c") == b"ordinary text ending in "
    assert raw.finish() == b"c"
    semantic = _SemanticSSEGuard(("controller-private-key",))
    frame = lines(
        {"type": "content_block_delta", "delta": {"type": "thinking_delta", "thinking": "logic"}}
    )[0]
    assert semantic.feed(frame) == []
    assert semantic.finish() == [frame]


def test_identifying_credential_prefix_still_fails_closed():
    from nooa_cybergym.leaderboard.model_gateway import _SecretStreamGuard, _SemanticSSEGuard

    raw = _SecretStreamGuard(("controller-private-key",))
    raw.feed(b"controller-priva")
    with pytest.raises(GatewayUpstreamError, match="credential fragment"):
        raw.finish()
    semantic = _SemanticSSEGuard(("controller-private-key",))
    semantic.feed(
        lines(
            {
                "type": "content_block_delta",
                "delta": {"type": "thinking_delta", "thinking": "controller-priva"},
            }
        )[0]
    )
    with pytest.raises(GatewayUpstreamError, match="credential fragment"):
        semantic.finish()


def test_native_custody_failure_stops_further_provider_admission(tmp_path):
    def fail(_grant, _data):
        raise OSError("synthetic private error")

    core, transport, _ = gateway(tmp_path, primary_stream(), native_stream_observer=fail)
    with pytest.raises(GatewayUpstreamError, match="custody"):
        run(core, "/v1/messages", {"model": "glm-5.3", "max_tokens": 128000, "stream": True})
    with pytest.raises(GatewayPolicyError, match="audit unavailable"):
        run(core, "/v1/messages", {"model": "glm-5.3", "max_tokens": 128000, "stream": True})
    assert len(transport.calls) == 1


def test_real_zai_wire_format_preserves_v1_and_settles_optional_cache_creation(tmp_path):
    # Shape observed from the Coding Plan's actual streaming response. [1m]
    # is Claude's client context selector, not the provider model identifier.
    response = primary_stream()
    chunks = b"".join(response.chunks).replace(b"glm-5.3", b"glm-5.3")
    chunks = chunks.replace(b'"cache_creation_input_tokens": 2, ', b"")
    chunks = chunks.replace(b', "cache_creation_input_tokens": 2', b"")
    response.chunks = [chunks]
    core, transport, _ = gateway(tmp_path, response)
    result, _, _ = run(
        core,
        "/v1/messages",
        {
            "model": "glm-5.3",
            "max_tokens": 128000,
            "stream": True,
            "thinking": {"type": "enabled"},
            "output_config": {"effort": "max"},
            "messages": [{"role": "user", "content": "benign probe"}],
        },
    )
    assert transport.calls[0][0] == "https://api.z.ai/api/anthropic/v1/messages"
    assert result.usage_status == "observed"
    assert rows(tmp_path / "usage.jsonl")[0]["cache_creation_tokens"] == 0


def test_primary_stream_keeps_wire_bytes_and_records_observed_usage(tmp_path):
    response = primary_stream()
    core, transport, starts = gateway(tmp_path, response)
    payload = {
        "model": "glm-5.3",
        "messages": [{"role": "user", "content": "task"}],
        "max_tokens": 128000,
        "stream": True,
    }
    result, headers, output = run(core, "/v1/messages", payload)
    assert b"".join(output) == b"".join(response.chunks)
    assert headers == [(200, {"content-type": "text/event-stream"})]
    assert starts == [("task-1", "attempt-1")]
    assert transport.calls[0][0] == "https://api.z.ai/api/anthropic/v1/messages"
    assert transport.calls[0][1]["Authorization"] == "Bearer " + ZAI_TOKEN
    assert transport.calls[0][2] == json.dumps(payload).encode()
    assert result.usage_status == "observed"
    usage = rows(tmp_path / "usage.jsonl")[0]
    assert (
        usage["input_tokens"],
        usage["cache_read_tokens"],
        usage["cache_creation_tokens"],
        usage["output_tokens"],
    ) == (11, 7, 2, 5)
    assert usage["counted_tokens"] == 25
    assert usage["tool_calls"] == [{"id": "tool-1", "name": "Read"}]
    requests = rows(tmp_path / "model-request.jsonl")
    assert requests[0]["request_sha256"] == hashlib.sha256(json.dumps(payload).encode()).hexdigest()
    assert requests[-1]["http_status"] == 200
    assert response.closed


def test_untrusted_role_and_failure_claims_cannot_admit_deepseek(tmp_path):
    core, transport, starts = gateway(tmp_path, alternate_stream())
    body = deepseek_payload() | {"role": "independent_recon", "trigger": "one_recon_lane"}
    with pytest.raises(GatewayPolicyError, match="role/trigger fields"):
        run(core, "/v1/chat/completions", body)
    with pytest.raises(GatewayPolicyError, match="role/trigger fields"):
        run(
            core,
            "/v1/chat/completions",
            deepseek_payload() | {"role": "conditional_debug_recovery", "failure": "failed"},
        )
    assert not transport.calls and not starts


def test_deepseek_uses_trusted_role_and_preserves_reasoning_and_tools(tmp_path):
    response = alternate_stream()
    core, transport, _ = gateway(
        tmp_path,
        response,
        admission(DeepSeekRole.INDEPENDENT_RECON, trigger="one_recon_lane"),
    )
    payload = deepseek_payload()
    result, _, output = run(core, "/v1/chat/completions", payload)
    assert b"".join(output) == b"".join(response.chunks)
    assert transport.calls[0][0] == "https://api.deepseek.com/chat/completions"
    assert transport.calls[0][1]["Authorization"] == "Bearer " + DEEPSEEK_TOKEN
    assert transport.calls[0][2] == json.dumps(payload).encode()
    assert result.usage_status == "observed"
    usage = rows(tmp_path / "usage.jsonl")[0]
    assert (
        usage["input_tokens"],
        usage["output_tokens"],
        usage["reasoning_tokens"],
        usage["counted_tokens"],
    ) == (10, 8, 5, 18)
    assert usage["cache_read_tokens"] == 3
    assert usage["tool_calls"] == [{"id": "call-1", "name": "lookup"}]
    event = rows(tmp_path / "model-request.jsonl")[-1]
    assert event["role"] == "independent_recon"
    assert event["returned_model"] == "deepseek-flash"
    assert event["system_fingerprint"] == "fp-1"
    assert event["official_final_selector"] == "glm_parent"
    exposed = (
        (tmp_path / "model-request.jsonl").read_text()
        + (tmp_path / "usage.jsonl").read_text()
        + repr(core)
    )
    assert all(secret not in exposed for secret in (TASK_TOKEN, ZAI_TOKEN, DEEPSEEK_TOKEN))


def test_debug_needs_controller_observed_failure_from_same_attempt(tmp_path):
    role = DeepSeekRole.CONDITIONAL_DEBUG_RECOVERY
    core, transport, _ = gateway(
        tmp_path, alternate_stream(), admission(role, trigger="observable_vulnerable_side_failure")
    )
    with pytest.raises(GatewayPolicyError, match="observed vulnerable"):
        run(core, "/v1/chat/completions", deepseek_payload())
    assert not transport.calls
    failure = FailureEvidence("task-1", "other-attempt", "vulnerable_test", 1, "b" * 64, 1)
    core, transport, _ = gateway(
        tmp_path,
        alternate_stream(),
        admission(role, trigger="observable_vulnerable_side_failure", failure=failure),
    )
    with pytest.raises(GatewayPolicyError, match="observed vulnerable"):
        run(core, "/v1/chat/completions", deepseek_payload())
    assert not transport.calls


def test_cross_task_admission_and_invalid_token_are_rejected_before_forward(tmp_path):
    core, transport, starts = gateway(tmp_path, primary_stream(), admission(task_id="task-2"))
    with pytest.raises(GatewayPolicyError, match="task.*attempt"):
        run(core, "/v1/messages", {"model": "glm-5.3"})
    with pytest.raises(GatewayPolicyError, match="task authorization"):
        run(core, "/v1/messages", {"model": "glm-5.3"}, token="wrong")
    assert not transport.calls and not starts


def test_null_usage_retains_reservation_and_stops_later_deepseek_requests(tmp_path):
    response = alternate_stream(usage={})
    core, transport, _ = gateway(
        tmp_path, response, admission(DeepSeekRole.INDEPENDENT_RECON, trigger="one_recon_lane")
    )
    result, _, _ = run(core, "/v1/chat/completions", deepseek_payload())
    assert result.usage_status == "unavailable"
    usage = rows(tmp_path / "usage.jsonl")[0]
    assert usage["input_tokens"] is None and usage["output_tokens"] is None
    assert usage["counted_tokens"] == 1048576
    assert usage["reserved_tokens"] == 1048576
    with pytest.raises(GatewayPolicyError, match="usage unavailable"):
        run(core, "/v1/chat/completions", deepseek_payload())
    assert len(transport.calls) == 1


def test_trickling_stream_is_cancelled_at_hard_total_deadline(tmp_path):
    response = StreamResponse([b"data: {}\n\n"] * 20, pause=0.02)
    now = [0.0]
    budget = SharedCampaignBudget(clock=lambda: now[0])
    core, transport, _ = gateway(
        tmp_path,
        response,
        admission(DeepSeekRole.INDEPENDENT_RECON, trigger="one_recon_lane"),
        budget=budget,
    )
    now[0] = 43199.945
    with pytest.raises(GatewayDeadlineExceeded):
        run(core, "/v1/chat/completions", deepseek_payload())
    assert response.closed
    assert len(transport.calls) == 1
    usage = rows(tmp_path / "usage.jsonl")[0]
    assert usage["usage_status"] == "interrupted"
    assert usage["counted_tokens"] == 1048576
    assert rows(tmp_path / "model-request.jsonl")[-1]["outcome"] == "deadline_exceeded"


def test_role_request_limit_is_enforced_without_borrowing(tmp_path):
    core, transport, _ = gateway(
        tmp_path,
        alternate_stream(),
        admission(DeepSeekRole.INDEPENDENT_RECON, trigger="one_recon_lane"),
    )
    for _ in range(30):
        run(core, "/v1/chat/completions", deepseek_payload())
    with pytest.raises(GatewayPolicyError, match="role request"):
        run(core, "/v1/chat/completions", deepseek_payload())
    assert len(transport.calls) == 30


def test_count_tokens_json_response_is_forwarded_and_counted_as_observed(tmp_path):
    response = StreamResponse(
        [b'{"input_', b'tokens":14}'],
        headers={"content-type": "application/json"},
    )
    core, transport, _ = gateway(tmp_path, response)
    result, headers, output = run(
        core,
        "/v1/messages/count_tokens",
        {"model": "glm-5.3", "messages": [{"role": "user", "content": "x"}]},
    )
    assert b"".join(output) == b'{"input_tokens":14}'
    assert headers == [(200, {"content-type": "application/json"})]
    assert transport.calls[0][0] == "https://api.z.ai/api/anthropic/v1/messages/count_tokens"
    assert result.usage_status == "observed"
    usage = rows(tmp_path / "usage.jsonl")[0]
    assert usage["input_tokens"] == 14 and usage["output_tokens"] is None
    assert usage["counted_tokens"] == 14


def test_missing_deepseek_provider_identity_fails_closed_with_reserved_usage(tmp_path):
    usage = {
        "prompt_tokens": 10,
        "completion_tokens": 8,
        "total_tokens": 18,
        "prompt_cache_hit_tokens": 3,
        "prompt_cache_miss_tokens": 7,
    }
    response = StreamResponse(lines({"choices": [], "usage": usage}) + [b"data: [DONE]\n\n"])
    core, transport, _ = gateway(
        tmp_path,
        response,
        admission(DeepSeekRole.INDEPENDENT_RECON, trigger="one_recon_lane"),
    )
    with pytest.raises(GatewayUpstreamError, match="provider identity"):
        run(core, "/v1/chat/completions", deepseek_payload())
    assert len(transport.calls) == 1
    assert rows(tmp_path / "usage.jsonl")[0]["counted_tokens"] == 1048576


def test_invalid_deepseek_output_usage_fails_closed(tmp_path):
    response = alternate_stream(
        usage={
            "prompt_tokens": 10,
            "completion_tokens": 128001,
            "total_tokens": 128011,
            "prompt_cache_hit_tokens": 3,
            "prompt_cache_miss_tokens": 7,
        }
    )
    core, _, _ = gateway(
        tmp_path,
        response,
        admission(DeepSeekRole.INDEPENDENT_RECON, trigger="one_recon_lane"),
    )
    with pytest.raises(GatewayUpstreamError, match="provider usage"):
        run(core, "/v1/chat/completions", deepseek_payload())
    assert rows(tmp_path / "usage.jsonl")[0]["usage_status"] == "interrupted"


def test_transport_exception_is_redacted_and_failed_dispatch_keeps_reservation(tmp_path):
    core, transport, _ = gateway(
        tmp_path,
        alternate_stream(),
        admission(DeepSeekRole.INDEPENDENT_RECON, trigger="one_recon_lane"),
    )

    async def fail(*args):
        raise OSError("network error with " + DEEPSEEK_TOKEN)

    transport.open_stream = fail
    with pytest.raises(GatewayUpstreamError, match="provider stream failed") as error:
        run(core, "/v1/chat/completions", deepseek_payload())
    assert DEEPSEEK_TOKEN not in str(error.value)
    assert error.value.__context__ is None
    usage = rows(tmp_path / "usage.jsonl")[0]
    assert usage["counted_tokens"] == 1048576
    assert usage["usage_status"] == "interrupted"
    assert rows(tmp_path / "model-request.jsonl")[-1]["outcome"] == "transport_error"


def test_duplicate_trusted_request_id_cannot_merge_distinct_usage_streams(tmp_path):
    core, transport, _ = gateway(tmp_path, primary_stream(), repeat_id=True)
    run(core, "/v1/messages", {"model": "glm-5.3", "max_tokens": 128000, "stream": True})
    with pytest.raises(GatewayPolicyError, match="duplicate request"):
        run(core, "/v1/messages", {"model": "glm-5.3", "max_tokens": 128000, "stream": True})
    assert len(transport.calls) == 1
    assert len(rows(tmp_path / "usage.jsonl")) == 1


def test_second_concurrent_request_cannot_enter_same_deepseek_role(tmp_path):
    entered, release = asyncio.Event(), asyncio.Event()

    class WaitingResponse(StreamResponse):
        async def aiter_bytes(self):
            entered.set()
            await release.wait()
            for chunk in self.chunks:
                yield chunk

    response = WaitingResponse(alternate_stream().chunks)
    core, transport, _ = gateway(
        tmp_path,
        response,
        admission(DeepSeekRole.INDEPENDENT_RECON, trigger="one_recon_lane"),
    )

    async def send_headers(status, headers):
        pass

    async def send_chunk(chunk):
        pass

    async def call():
        return await core.forward(
            path="/v1/chat/completions",
            authorization="Bearer " + TASK_TOKEN,
            body=json.dumps(deepseek_payload()).encode(),
            trusted_connection=object(),
            send_headers=send_headers,
            send_chunk=send_chunk,
        )

    async def scenario():
        first = asyncio.create_task(call())
        await asyncio.wait_for(entered.wait(), timeout=1)
        try:
            with pytest.raises(GatewayPolicyError, match="active child"):
                await asyncio.wait_for(call(), timeout=1)
        finally:
            release.set()
            await first

    asyncio.run(scenario())
    assert len(transport.calls) == 1


def test_pre_forward_audit_failure_keeps_reservation_and_never_sends_key(tmp_path):
    core, transport, _ = gateway(
        tmp_path,
        alternate_stream(),
        admission(DeepSeekRole.INDEPENDENT_RECON, trigger="one_recon_lane"),
    )
    original = core._audit.record_request
    failed = [False]

    def fail_once(event):
        if not failed[0]:
            failed[0] = True
            raise OSError("audit error with " + DEEPSEEK_TOKEN)
        original(event)

    core._audit.record_request = fail_once
    with pytest.raises(GatewayUpstreamError, match="controller audit failed") as error:
        run(core, "/v1/chat/completions", deepseek_payload())
    assert DEEPSEEK_TOKEN not in str(error.value)
    assert not transport.calls
    usage = rows(tmp_path / "usage.jsonl")[0]
    assert usage["counted_tokens"] == 1048576
    assert rows(tmp_path / "model-request.jsonl")[-1]["outcome"] == "audit_failed"
    with pytest.raises(GatewayPolicyError, match="audit unavailable"):
        run(core, "/v1/chat/completions", deepseek_payload())
    assert not transport.calls


@pytest.mark.parametrize("provider", ["primary", "deepseek"])
def test_reflected_controller_secret_split_across_chunks_is_never_released(tmp_path, provider):
    if provider == "primary":
        secret = ZAI_TOKEN.encode()
        initial = primary_stream().chunks[0]
        payload = {"model": "glm-5.3", "max_tokens": 128000, "stream": True}
        path = "/v1/messages"
        grant = admission()
        reflection = lines(
            {"type": "content_block_delta", "delta": {"type": "text_delta", "text": ZAI_TOKEN}}
        )[0]
    else:
        secret = DEEPSEEK_TOKEN.encode()
        initial = alternate_stream().chunks[0]
        payload = deepseek_payload()
        path = "/v1/chat/completions"
        grant = admission(DeepSeekRole.INDEPENDENT_RECON, trigger="one_recon_lane")
        reflection = lines(
            {
                "id": "ds-1",
                "model": "deepseek-flash",
                "choices": [{"delta": {"content": DEEPSEEK_TOKEN}}],
            }
        )[0]
    split = reflection.index(secret) + len(secret) - 3
    response = StreamResponse([initial, reflection[:split], reflection[split:]])
    core, _, _ = gateway(tmp_path, response, grant)
    released: list[bytes] = []

    async def send_headers(_status, _headers):
        return None

    async def send_chunk(chunk):
        released.append(chunk)

    with pytest.raises(GatewayUpstreamError, match="controller credential"):
        asyncio.run(
            core.forward(
                path=path,
                authorization="Bearer " + TASK_TOKEN,
                body=json.dumps(payload).encode(),
                trusted_connection=object(),
                send_headers=send_headers,
                send_chunk=send_chunk,
            )
        )
    exposed = b"".join(released)
    assert secret not in exposed
    assert secret[:-3] not in exposed
    assert response.closed


@pytest.mark.parametrize("provider", ["primary", "deepseek"])
@pytest.mark.parametrize(
    "reflection",
    ["json_escaped", "split_deltas", "base64_deltas", "hex_deltas", "mixed_hex_deltas"],
)
def test_decoded_sse_credential_reflection_is_never_released(tmp_path, provider, reflection):
    if provider == "primary":
        secret = ZAI_TOKEN
        initial = primary_stream().chunks[0]
        payload = {"model": "glm-5.3", "max_tokens": 128000, "stream": True}
        path = "/v1/messages"
        grant = admission()

        def delta(value):
            return {"type": "content_block_delta", "delta": {"type": "text_delta", "text": value}}

        ending = primary_stream().chunks[-2:]
    else:
        secret = DEEPSEEK_TOKEN
        initial = alternate_stream().chunks[0]
        payload = deepseek_payload()
        path = "/v1/chat/completions"
        grant = admission(DeepSeekRole.INDEPENDENT_RECON, trigger="one_recon_lane")

        def delta(value):
            return {
                "id": "ds-1",
                "model": "deepseek-flash",
                "choices": [{"index": 0, "delta": {"content": value}}],
            }

        ending = alternate_stream().chunks[-2:]

    protected = secret
    if reflection == "json_escaped":
        encoded = json.dumps(delta(secret)).replace(secret, "\\u0063" + secret[1:])
        assert secret.encode() not in encoded.encode()
        wire = ("data: " + encoded + "\n\n").encode()
        chunks = [initial, wire[: len(wire) // 2], wire[len(wire) // 2 :], *ending]
    else:
        if reflection == "base64_deltas":
            protected = base64.b64encode(secret.encode()).decode()
        elif reflection == "hex_deltas":
            protected = secret.encode().hex()
        elif reflection == "mixed_hex_deltas":
            protected = "".join(
                character.upper() if index % 2 else character
                for index, character in enumerate(secret.encode().hex())
            )
        chunks = [initial, *lines(delta(protected[:8]), delta(protected[8:])), *ending]
    response = StreamResponse(chunks)
    core, _, _ = gateway(tmp_path, response, grant)
    released: list[bytes] = []

    async def send_headers(_status, _headers):
        return None

    async def send_chunk(chunk):
        released.append(chunk)

    with pytest.raises(GatewayUpstreamError, match="controller credential"):
        asyncio.run(
            core.forward(
                path=path,
                authorization="Bearer " + TASK_TOKEN,
                body=json.dumps(payload).encode(),
                trusted_connection=object(),
                send_headers=send_headers,
                send_chunk=send_chunk,
            )
        )
    exposed = b"".join(released)
    assert protected.encode() not in exposed
    assert protected[:8].encode() not in exposed
    assert response.closed


def test_count_tokens_decoded_json_credential_reflection_is_never_released(tmp_path):
    encoded = json.dumps({"input_tokens": 14, "note": ZAI_TOKEN}, separators=(",", ":")).replace(
        ZAI_TOKEN, "\\u0063" + ZAI_TOKEN[1:]
    )
    response = StreamResponse(
        [encoded[:13].encode(), encoded[13:].encode()],
        headers={"content-type": "application/json"},
    )
    core, _, _ = gateway(tmp_path, response)
    released: list[bytes] = []

    async def send_headers(_status, _headers):
        return None

    async def send_chunk(chunk):
        released.append(chunk)

    with pytest.raises(GatewayUpstreamError, match="controller credential"):
        asyncio.run(
            core.forward(
                path="/v1/messages/count_tokens",
                authorization="Bearer " + TASK_TOKEN,
                body=json.dumps({"model": "glm-5.3", "messages": []}).encode(),
                trusted_connection=object(),
                send_headers=send_headers,
                send_chunk=send_chunk,
            )
        )
    assert released == []


def test_benign_prefix_frames_are_released_before_provider_finishes(tmp_path):
    chunks = [
        primary_stream().chunks[0],
        *lines(
            {"type": "content_block_delta", "delta": {"text": ZAI_TOKEN[:8]}},
            {"type": "content_block_delta", "delta": {"text": "unrelated"}},
        ),
        *primary_stream().chunks[-2:],
    ]
    released: list[bytes] = []

    class ProbeResponse(StreamResponse):
        async def aiter_bytes(self):
            for index, chunk in enumerate(self.chunks):
                yield chunk
                if index == 2:
                    assert b"".join(released) == b"".join(chunks[:3])

    response = ProbeResponse(chunks)
    core, _, _ = gateway(tmp_path, response)

    async def send_headers(_status, _headers):
        return None

    async def send_chunk(chunk):
        released.append(chunk)

    asyncio.run(
        core.forward(
            path="/v1/messages",
            authorization="Bearer " + TASK_TOKEN,
            body=json.dumps({"model": "glm-5.3", "max_tokens": 128000, "stream": True}).encode(),
            trusted_connection=object(),
            send_headers=send_headers,
            send_chunk=send_chunk,
        )
    )
    assert b"".join(released) == b"".join(chunks)


def test_oversized_semantic_sse_frame_fails_before_release(tmp_path):
    response = StreamResponse(
        [primary_stream().chunks[0], b"data: " + b"x" * (8 * 1_048_576) + b"\n\n"]
    )
    core, _, _ = gateway(tmp_path, response)
    released: list[bytes] = []

    async def send_headers(_status, _headers):
        return None

    async def send_chunk(chunk):
        released.append(chunk)

    with pytest.raises(GatewayUpstreamError, match="semantic guard limit"):
        asyncio.run(
            core.forward(
                path="/v1/messages",
                authorization="Bearer " + TASK_TOKEN,
                body=json.dumps(
                    {"model": "glm-5.3", "max_tokens": 128000, "stream": True}
                ).encode(),
                trusted_connection=object(),
                send_headers=send_headers,
                send_chunk=send_chunk,
            )
        )
    assert b"".join(released) == primary_stream().chunks[0]
    assert response.closed


def test_unacknowledged_attempt_start_keeps_reserved_usage_before_dispatch(tmp_path):
    core, transport, _ = gateway(
        tmp_path,
        alternate_stream(),
        admission(DeepSeekRole.INDEPENDENT_RECON, trigger="one_recon_lane"),
    )
    core._mark_started = lambda task_id, attempt_id: False
    with pytest.raises(GatewayUpstreamError, match="attempt start failed"):
        run(core, "/v1/chat/completions", deepseek_payload())
    assert not transport.calls
    assert core._budget.snapshot()["deepseek_requests"] == 1
    assert rows(tmp_path / "usage.jsonl")[0]["counted_tokens"] == 1048576
    assert rows(tmp_path / "model-request.jsonl")[-1]["outcome"] == "start_failed"


def test_deepseek_settings_cannot_be_weakened_by_caller(tmp_path):
    core, transport, _ = gateway(
        tmp_path,
        alternate_stream(),
        admission(DeepSeekRole.INDEPENDENT_RECON, trigger="one_recon_lane"),
    )
    with pytest.raises(GatewayPolicyError, match="request settings"):
        run(core, "/v1/chat/completions", deepseek_payload() | {"max_tokens": 64000})
    assert not transport.calls


@pytest.mark.parametrize("failed_write", ["usage", "terminal_request"])
def test_post_forward_audit_failure_latches_gateway_closed(tmp_path, failed_write):
    core, transport, _ = gateway(tmp_path, primary_stream())
    if failed_write == "usage":
        original = core._audit.record_usage

        def fail_once(event):
            core._audit.record_usage = original
            raise OSError("fsync failed with " + ZAI_TOKEN)

        core._audit.record_usage = fail_once
    else:
        original = core._audit.record_request

        def fail_once(event):
            if event["event"] == "request_terminal":
                core._audit.record_request = original
                raise OSError("fsync failed with " + ZAI_TOKEN)
            original(event)

        core._audit.record_request = fail_once
    payload = {"model": "glm-5.3", "max_tokens": 128000, "stream": True}
    with pytest.raises(GatewayUpstreamError, match="controller audit failed") as error:
        run(core, "/v1/messages", payload)
    assert ZAI_TOKEN not in str(error.value)
    with pytest.raises(GatewayPolicyError, match="audit unavailable"):
        run(core, "/v1/messages", payload)
    assert len(transport.calls) == 1
    if failed_write == "usage":
        assert rows(tmp_path / "model-request.jsonl")[-1]["outcome"] == "audit_failed"


@pytest.mark.parametrize("max_tokens", [None, 128001, True])
def test_primary_output_ceiling_is_enforced_before_forward(tmp_path, max_tokens):
    core, transport, _ = gateway(tmp_path, primary_stream())
    payload = {"model": "glm-5.3", "stream": True}
    if max_tokens is not None:
        payload["max_tokens"] = max_tokens
    with pytest.raises(GatewayPolicyError, match="primary output"):
        run(core, "/v1/messages", payload)
    assert not transport.calls


def test_primary_returned_output_ceiling_keeps_reservation(tmp_path):
    response = StreamResponse(
        lines(
            {
                "type": "message_start",
                "message": {
                    "id": "m1",
                    "model": "glm-5.3",
                    "usage": {
                        "input_tokens": 11,
                        "cache_read_input_tokens": 0,
                        "cache_creation_input_tokens": 0,
                    },
                },
            },
            {"type": "message_delta", "usage": {"output_tokens": 128001}},
            {"type": "message_stop"},
        )
    )
    core, _, _ = gateway(tmp_path, response)
    with pytest.raises(GatewayUpstreamError, match="provider usage"):
        run(core, "/v1/messages", {"model": "glm-5.3", "max_tokens": 128000, "stream": True})
    assert rows(tmp_path / "usage.jsonl")[0]["counted_tokens"] == 1000000


@pytest.mark.parametrize("model", ["glm-5.3", "deepseek-flash"])
def test_wrong_returned_model_is_rejected_before_solver_receives_bytes(tmp_path, model):
    if model == "glm-5.3":
        response = StreamResponse(
            lines(
                {"type": "message_start", "message": {"id": "m1", "model": "wrong-model"}},
                {"type": "message_stop"},
            )
        )
        grant = admission()
        path = "/v1/messages"
        payload = {"model": model, "max_tokens": 128000, "stream": True}
    else:
        response = StreamResponse(
            lines({"id": "ds-1", "model": "wrong-model", "choices": []}) + [b"data: [DONE]\n\n"]
        )
        grant = admission(DeepSeekRole.INDEPENDENT_RECON, trigger="one_recon_lane")
        path = "/v1/chat/completions"
        payload = deepseek_payload()
    core, _, _ = gateway(tmp_path, response, grant)
    sent = []

    async def send_headers(status, headers):
        sent.append(("headers", status))

    async def send_chunk(chunk):
        sent.append(("chunk", chunk))

    async def forward():
        await core.forward(
            path=path,
            authorization="Bearer " + TASK_TOKEN,
            body=json.dumps(payload).encode(),
            trusted_connection=object(),
            send_headers=send_headers,
            send_chunk=send_chunk,
        )

    with pytest.raises(GatewayUpstreamError, match="provider identity"):
        asyncio.run(forward())
    assert not sent


def test_zai_route_must_equal_explicit_approved_policy_endpoint(tmp_path):
    with pytest.raises(ValueError, match="approved Z.ai"):
        gateway(tmp_path, primary_stream(), zai_url="https://unapproved.example.test/v1")


def test_hanging_stream_close_is_aborted_within_total_deadline(tmp_path):
    now = [0.0]
    budget = SharedCampaignBudget(clock=lambda: now[0])

    class HangingClose(StreamResponse):
        async def aclose(self):
            await asyncio.Event().wait()

    response = HangingClose(primary_stream().chunks)
    core, _, _ = gateway(tmp_path, response, budget=budget)
    now[0] = 43199.95

    async def send_headers(status, headers):
        pass

    async def send_chunk(chunk):
        pass

    async def forward():
        return await core.forward(
            path="/v1/messages",
            authorization="Bearer " + TASK_TOKEN,
            body=json.dumps({"model": "glm-5.3", "max_tokens": 128000, "stream": True}).encode(),
            trusted_connection=object(),
            send_headers=send_headers,
            send_chunk=send_chunk,
        )

    with pytest.raises(GatewayDeadlineExceeded):
        asyncio.run(asyncio.wait_for(forward(), timeout=0.4))
    assert rows(tmp_path / "model-request.jsonl")[-1]["outcome"] == "deadline_exceeded"


def test_count_tokens_over_primary_context_is_not_reported_as_observed(tmp_path):
    response = StreamResponse(
        [b'{"input_tokens":1000001}'], headers={"content-type": "application/json"}
    )
    core, _, _ = gateway(tmp_path, response)
    with pytest.raises(GatewayUpstreamError, match="provider usage"):
        run(core, "/v1/messages/count_tokens", {"model": "glm-5.3"})
    usage = rows(tmp_path / "usage.jsonl")[0]
    assert usage["counted_tokens"] == 1000000


def test_initial_sse_without_identity_is_held_then_forwarded_in_original_order(tmp_path):
    response = StreamResponse([b": ping\n\n"] + primary_stream().chunks)
    core, _, _ = gateway(tmp_path, response)
    result, _, output = run(
        core,
        "/v1/messages",
        {"model": "glm-5.3", "max_tokens": 128000, "stream": True},
    )
    assert result.usage_status == "observed"
    assert output == response.chunks


def test_primary_endpoint_is_part_of_recorded_policy_identity(tmp_path):
    core, _, _ = gateway(tmp_path, primary_stream())
    run(
        core,
        "/v1/messages",
        {"model": "glm-5.3", "max_tokens": 128000, "stream": True},
    )
    request = rows(tmp_path / "model-request.jsonl")[0]
    assert request["upstream_endpoint"] == "https://api.z.ai/api/anthropic/v1/messages"
    assert request["policy_sha256"] == policy().digest
