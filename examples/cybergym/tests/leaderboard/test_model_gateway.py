"""Native model gateway tests; all upstream responses are local synthetic streams."""

import asyncio
import base64
import hashlib
import itertools
import json
import socket
from dataclasses import replace
from pathlib import Path

import httpcore
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
            "https://api.z.ai/api/anthropic/messages",
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
            "https://api.z.ai/api/anthropic/messages",
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
            "https://api.z.ai/api/anthropic/messages",
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
            "https://api.z.ai/api/anthropic/messages", {}, b"{}", 5.0
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
        "https://127.0.0.1/api/anthropic/messages",
        "http://api.z.ai/api/anthropic/messages",
        "https://api.z.ai:8443/api/anthropic/messages",
        "https://api.z.ai/api/anthropic/unapproved",
        "https://attacker.example/api/anthropic/messages",
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
            "https://api.z.ai/api/anthropic/messages",
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
                    "model": "glm-5.3[1m]",
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


def test_primary_stream_keeps_wire_bytes_and_records_observed_usage(tmp_path):
    response = primary_stream()
    core, transport, starts = gateway(tmp_path, response)
    payload = {
        "model": "glm-5.3[1m]",
        "messages": [{"role": "user", "content": "task"}],
        "max_tokens": 128000,
        "stream": True,
    }
    result, headers, output = run(core, "/v1/messages", payload)
    assert b"".join(output) == b"".join(response.chunks)
    assert headers == [(200, {"content-type": "text/event-stream"})]
    assert starts == [("task-1", "attempt-1")]
    assert transport.calls[0][0] == "https://api.z.ai/api/anthropic/messages"
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
        run(core, "/v1/messages", {"model": "glm-5.3[1m]"})
    with pytest.raises(GatewayPolicyError, match="task authorization"):
        run(core, "/v1/messages", {"model": "glm-5.3[1m]"}, token="wrong")
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
    for _ in range(12):
        run(core, "/v1/chat/completions", deepseek_payload())
    with pytest.raises(GatewayPolicyError, match="role request"):
        run(core, "/v1/chat/completions", deepseek_payload())
    assert len(transport.calls) == 12


def test_count_tokens_json_response_is_forwarded_and_counted_as_observed(tmp_path):
    response = StreamResponse(
        [b'{"input_', b'tokens":14}'],
        headers={"content-type": "application/json"},
    )
    core, transport, _ = gateway(tmp_path, response)
    result, headers, output = run(
        core,
        "/v1/messages/count_tokens",
        {"model": "glm-5.3[1m]", "messages": [{"role": "user", "content": "x"}]},
    )
    assert b"".join(output) == b'{"input_tokens":14}'
    assert headers == [(200, {"content-type": "application/json"})]
    assert transport.calls[0][0] == "https://api.z.ai/api/anthropic/messages/count_tokens"
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
    run(core, "/v1/messages", {"model": "glm-5.3[1m]", "max_tokens": 128000, "stream": True})
    with pytest.raises(GatewayPolicyError, match="duplicate request"):
        run(core, "/v1/messages", {"model": "glm-5.3[1m]", "max_tokens": 128000, "stream": True})
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
        payload = {"model": "glm-5.3[1m]", "max_tokens": 128000, "stream": True}
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
        payload = {"model": "glm-5.3[1m]", "max_tokens": 128000, "stream": True}
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
                body=json.dumps({"model": "glm-5.3[1m]", "messages": []}).encode(),
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
            body=json.dumps(
                {"model": "glm-5.3[1m]", "max_tokens": 128000, "stream": True}
            ).encode(),
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
                    {"model": "glm-5.3[1m]", "max_tokens": 128000, "stream": True}
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
    payload = {"model": "glm-5.3[1m]", "max_tokens": 128000, "stream": True}
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
    payload = {"model": "glm-5.3[1m]", "stream": True}
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
                    "model": "glm-5.3[1m]",
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
        run(core, "/v1/messages", {"model": "glm-5.3[1m]", "max_tokens": 128000, "stream": True})
    assert rows(tmp_path / "usage.jsonl")[0]["counted_tokens"] == 1000000


@pytest.mark.parametrize("model", ["glm-5.3[1m]", "deepseek-flash"])
def test_wrong_returned_model_is_rejected_before_solver_receives_bytes(tmp_path, model):
    if model == "glm-5.3[1m]":
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
            body=json.dumps(
                {"model": "glm-5.3[1m]", "max_tokens": 128000, "stream": True}
            ).encode(),
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
        run(core, "/v1/messages/count_tokens", {"model": "glm-5.3[1m]"})
    usage = rows(tmp_path / "usage.jsonl")[0]
    assert usage["counted_tokens"] == 1000000


def test_initial_sse_without_identity_is_held_then_forwarded_in_original_order(tmp_path):
    response = StreamResponse([b": ping\n\n"] + primary_stream().chunks)
    core, _, _ = gateway(tmp_path, response)
    result, _, output = run(
        core,
        "/v1/messages",
        {"model": "glm-5.3[1m]", "max_tokens": 128000, "stream": True},
    )
    assert result.usage_status == "observed"
    assert output == response.chunks


def test_primary_endpoint_is_part_of_recorded_policy_identity(tmp_path):
    core, _, _ = gateway(tmp_path, primary_stream())
    run(
        core,
        "/v1/messages",
        {"model": "glm-5.3[1m]", "max_tokens": 128000, "stream": True},
    )
    request = rows(tmp_path / "model-request.jsonl")[0]
    assert request["upstream_endpoint"] == "https://api.z.ai/api/anthropic/messages"
    assert request["policy_sha256"] == policy().digest
