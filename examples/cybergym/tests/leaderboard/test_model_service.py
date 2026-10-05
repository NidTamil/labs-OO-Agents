"""ASGI model listener tests use synthetic provider streams only."""

import asyncio
import json
from pathlib import Path

import pytest
from nooa_cybergym.leaderboard.deepseek import (
    AlternateModelPolicy,
    DeepSeekRole,
    SharedCampaignBudget,
)
from nooa_cybergym.leaderboard.model_gateway import (
    GatewayAudit,
    ModelPolicy,
    NativeModelGateway,
    TrustedAdmission,
)
from nooa_cybergym.leaderboard.model_service import (
    CONNECTION_SCOPE_KEY,
    ModelHTTPService,
    ModelStreamAborted,
)

CONFIG = Path(__file__).resolve().parents[2] / "leaderboard/config/alternate-model.json"
TASK_TOKEN = "synthetic-task-token"
ZAI_TOKEN = "synthetic-controller-zai-key"
DEEPSEEK_TOKEN = "synthetic-controller-deepseek-key"
CONNECTION = object()


def _event(payload):
    return ("data: " + json.dumps(payload) + "\n\n").encode()


PRIMARY_CHUNKS = [
    _event(
        {
            "type": "message_start",
            "message": {
                "id": "m1",
                "model": "glm-5.3",
                "usage": {
                    "input_tokens": 11,
                    "cache_read_input_tokens": 1,
                    "cache_creation_input_tokens": 2,
                },
            },
        }
    ),
    _event({"type": "message_delta", "usage": {"output_tokens": 3}}),
    _event({"type": "message_stop"}),
]
DEEPSEEK_CHUNKS = [
    _event({"id": "d1", "model": "deepseek-flash", "choices": [{"index": 0, "delta": {}}]}),
    _event(
        {
            "id": "d1",
            "model": "deepseek-flash",
            "choices": [],
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 8,
                "total_tokens": 18,
                "prompt_cache_hit_tokens": 3,
                "prompt_cache_miss_tokens": 7,
            },
        }
    ),
    b"data: [DONE]\n\n",
]


class StreamResponse:
    def __init__(self, chunks, *, status=200, headers=None, error=None, wait_after_first=None):
        self.chunks = chunks
        self.status_code = status
        self.headers = headers or {"content-type": "text/event-stream"}
        self.error = error
        self.wait_after_first = wait_after_first
        self.closed = False

    async def aiter_bytes(self):
        for index, chunk in enumerate(self.chunks):
            yield chunk
            if index == 0 and self.wait_after_first is not None:
                await self.wait_after_first.wait()
        if self.error is not None:
            raise self.error

    async def aclose(self):
        self.closed = True


class Transport:
    def __init__(self, response):
        self.response = response
        self.calls = []

    async def open_stream(self, url, headers, body, timeout):
        self.calls.append((url, headers, body, timeout))
        return self.response


def _service(tmp_path, response, *, role=None, trigger=None):
    policy = ModelPolicy(
        primary="glm-5.3[1m]",
        alternate=AlternateModelPolicy.model_validate_json(CONFIG.read_text()),
        capability_policy_sha256="a" * 64,
        approved_zai_coding_plan_url="https://api.z.ai/api/anthropic",
    )
    transport = Transport(response)
    grant = TrustedAdmission(
        task_id="task-1",
        attempt_id="attempt-1",
        request_id="request-1",
        role=role,
        trigger=trigger,
        capability_policy_sha256="a" * 64,
        workflow_id="workflow-1" if role else None,
    )
    resolved = []
    gateway = NativeModelGateway(
        task_id="task-1",
        attempt_id="attempt-1",
        task_token=TASK_TOKEN,
        model_policy=policy,
        zai_coding_plan_url="https://api.z.ai/api/anthropic",
        zai_coding_plan_token=ZAI_TOKEN,
        deepseek_api_key=DEEPSEEK_TOKEN,
        budget=SharedCampaignBudget(),
        audit=GatewayAudit(tmp_path / "model-request.jsonl", tmp_path / "usage.jsonl"),
        resolve_admission=lambda connection: resolved.append(connection) or grant,
        mark_started=lambda task_id, attempt_id: True,
        transport=transport,
    )
    service = ModelHTTPService(
        gateway,
        resolve_connection=lambda connection: connection if connection is CONNECTION else None,
    )
    return service, gateway, transport, resolved


def _scope(path="/v1/messages", *, headers=None, connection=CONNECTION, method="POST"):
    if headers is None:
        headers = [(b"x-api-key", TASK_TOKEN.encode()), (b"content-type", b"application/json")]
    return {
        "type": "http",
        "method": method,
        "path": path,
        "headers": headers,
        "query_string": b"",
        "extensions": {CONNECTION_SCOPE_KEY: connection} if connection is not None else {},
    }


async def _call(service, scope, body, *, disconnect_after=None):
    events = []
    pieces = [body[: len(body) // 2], body[len(body) // 2 :]]
    requests = [
        {"type": "http.request", "body": pieces[0], "more_body": True},
        {"type": "http.request", "body": pieces[1], "more_body": False},
    ]
    wait_forever = asyncio.Event()

    async def receive():
        if requests:
            return requests.pop(0)
        if disconnect_after is not None:
            await disconnect_after.wait()
            return {"type": "http.disconnect"}
        await wait_forever.wait()

    async def send(message):
        events.append(message)

    await service(scope, receive, send)
    return events


def _primary_body():
    return json.dumps(
        {
            "model": "glm-5.3",
            "max_tokens": 128000,
            "stream": True,
            "messages": [{"role": "user", "content": "synthetic task"}],
        }
    ).encode()


def _deepseek_body():
    return json.dumps(
        {
            "model": "deepseek-flash",
            "max_tokens": 128000,
            "stream": True,
            "stream_options": {"include_usage": True},
            "thinking": {"type": "enabled"},
            "reasoning_effort": "max",
            "messages": [{"role": "user", "content": "synthetic task"}],
        }
    ).encode()


def test_native_anthropic_stream_uses_server_connection_and_keeps_wire_bytes(tmp_path):
    response = StreamResponse(
        PRIMARY_CHUNKS,
        headers={
            "content-type": "text/event-stream",
            "x-request-id": ZAI_TOKEN,
            "authorization": ZAI_TOKEN,
        },
    )
    service, _, transport, resolved = _service(tmp_path, response)
    body = _primary_body()
    scope = _scope(
        headers=[
            (b"x-api-key", TASK_TOKEN.encode()),
            (b"content-type", b"application/json"),
            (b"anthropic-version", b"2023-06-01"),
            (b"x-stainless-arch", b"test"),
        ]
    )
    events = asyncio.run(_call(service, scope, body))
    assert events[0]["type"] == "http.response.start"
    assert events[0]["status"] == 200
    assert b"".join(item["body"] for item in events[1:]) == b"".join(PRIMARY_CHUNKS)
    assert events[-1] == {"type": "http.response.body", "body": b"", "more_body": False}
    assert resolved == [CONNECTION]
    assert transport.calls[0][0] == "https://api.z.ai/api/anthropic/v1/messages"
    assert transport.calls[0][1]["Authorization"] == "Bearer " + ZAI_TOKEN
    assert transport.calls[0][1]["anthropic-version"] == "2023-06-01"
    assert transport.calls[0][2] == body
    assert response.closed
    assert ZAI_TOKEN.encode() not in repr(events).encode()
    assert DEEPSEEK_TOKEN.encode() not in repr(events).encode()
    assert b"authorization" not in repr(events).encode().lower()


def test_bearer_task_token_is_accepted_without_provider_key_exposure(tmp_path):
    service, _, transport, _ = _service(tmp_path, StreamResponse(PRIMARY_CHUNKS))
    headers = [(b"authorization", ("Bearer " + TASK_TOKEN).encode())]
    events = asyncio.run(_call(service, _scope(headers=headers), _primary_body()))
    assert events[0]["status"] == 200
    assert transport.calls[0][1]["Authorization"] == "Bearer " + ZAI_TOKEN
    assert TASK_TOKEN not in repr(events)


@pytest.mark.parametrize(
    ("path", "body", "response", "role", "trigger", "upstream"),
    [
        (
            "/v1/messages/count_tokens",
            b'{"model":"glm-5.3","messages":[{"role":"user","content":"x"}]}',
            StreamResponse(
                [b'{"input_', b'tokens":14}'], headers={"content-type": "application/json"}
            ),
            None,
            None,
            "https://api.z.ai/api/anthropic/v1/messages/count_tokens",
        ),
        (
            "/v1/chat/completions",
            _deepseek_body(),
            StreamResponse(DEEPSEEK_CHUNKS),
            DeepSeekRole.INDEPENDENT_RECON,
            "one_recon_lane",
            "https://api.deepseek.com/chat/completions",
        ),
    ],
)
def test_other_declared_native_routes(tmp_path, path, body, response, role, trigger, upstream):
    service, _, transport, _ = _service(tmp_path, response, role=role, trigger=trigger)
    events = asyncio.run(_call(service, _scope(path), body))
    assert events[0]["status"] == 200
    assert b"".join(item["body"] for item in events[1:]) == b"".join(response.chunks)
    assert transport.calls[0][0] == upstream


@pytest.mark.parametrize(
    "headers",
    [
        [(b"x-api-key", TASK_TOKEN.encode()), (b"x-role", b"independent_recon")],
        [(b"x-api-key", TASK_TOKEN.encode()), (b"x-deepseekrole", b"independent_recon")],
        [(b"x-api-key", TASK_TOKEN.encode()), (b"x-task-id", b"task-1")],
        [(b"x-api-key", TASK_TOKEN.encode()), (b"x_task_id", b"task-1")],
        [(b"x-api-key", TASK_TOKEN.encode()), (b"x-trigger", b"one_recon_lane")],
        [(b"x-api-key", TASK_TOKEN.encode()), (b"authorization", b"Bearer duplicate")],
    ],
)
def test_solver_header_claims_and_ambiguous_auth_are_denied(tmp_path, headers):
    service, _, transport, resolved = _service(tmp_path, StreamResponse(PRIMARY_CHUNKS))
    events = asyncio.run(_call(service, _scope(headers=headers), _primary_body()))
    assert events[0]["status"] in (400, 403)
    assert not transport.calls and not resolved


@pytest.mark.parametrize("claim", ("role", "deepseek_role", "capabilityPolicy"))
def test_missing_server_identity_and_body_role_claims_are_denied(tmp_path, claim):
    service, _, transport, resolved = _service(tmp_path, StreamResponse(PRIMARY_CHUNKS))
    events = asyncio.run(_call(service, _scope(connection=None), _primary_body()))
    assert events[0]["status"] == 403
    body = json.loads(_primary_body()) | {claim: "independent_recon"}
    events = asyncio.run(_call(service, _scope(), json.dumps(body).encode()))
    assert events[0]["status"] == 403
    assert not transport.calls and not resolved


def test_deepseek_requires_controller_grant_and_route_is_exact(tmp_path):
    service, _, transport, _ = _service(tmp_path, StreamResponse(DEEPSEEK_CHUNKS))
    denied = asyncio.run(_call(service, _scope("/v1/chat/completions"), _deepseek_body()))
    absent = asyncio.run(_call(service, _scope("/v1/unknown"), _primary_body()))
    assert denied[0]["status"] == 403
    assert absent[0]["status"] == 404
    assert not transport.calls


def test_upstream_failure_before_headers_has_generic_error_without_secrets(tmp_path):
    response = StreamResponse([], status=500, headers={"x-api-key": DEEPSEEK_TOKEN})
    service, _, _, _ = _service(tmp_path, response)
    events = asyncio.run(_call(service, _scope(), _primary_body()))
    assert events[0]["status"] == 502
    wire = repr(events)
    assert all(secret not in wire for secret in (TASK_TOKEN, ZAI_TOKEN, DEEPSEEK_TOKEN))


def test_error_after_headers_aborts_stream_without_raw_error_or_clean_eof(tmp_path):
    response = StreamResponse(PRIMARY_CHUNKS[:1], error=OSError("private " + ZAI_TOKEN))
    service, _, _, _ = _service(tmp_path, response)

    async def scenario():
        events = []
        request_sent = False
        wait_forever = asyncio.Event()

        async def receive():
            nonlocal request_sent
            if not request_sent:
                request_sent = True
                return {"type": "http.request", "body": _primary_body(), "more_body": False}
            await wait_forever.wait()

        async def send(message):
            events.append(message)

        with pytest.raises(ModelStreamAborted, match="stream interrupted"):
            await service(_scope(), receive, send)
        return events

    events = asyncio.run(scenario())
    assert events[0]["status"] == 200
    assert events[-1]["more_body"] is True
    assert ZAI_TOKEN not in repr(events)
    assert response.closed


def test_provider_sse_error_frame_is_withheld_after_valid_start(tmp_path):
    error_frame = (
        b'event: error\ndata: {"error":{"message":"private ' + ZAI_TOKEN.encode() + b'"}}\n\n'
    )
    response = StreamResponse(PRIMARY_CHUNKS[:1] + [error_frame])
    service, _, _, _ = _service(tmp_path, response)

    async def scenario():
        events = []
        sent_body = False
        wait_forever = asyncio.Event()

        async def receive():
            nonlocal sent_body
            if not sent_body:
                sent_body = True
                return {"type": "http.request", "body": _primary_body(), "more_body": False}
            await wait_forever.wait()

        async def send(message):
            events.append(message)

        with pytest.raises(ModelStreamAborted, match="stream interrupted"):
            await service(_scope(), receive, send)
        return events

    events = asyncio.run(scenario())
    assert events[0]["status"] == 200
    assert b"".join(item["body"] for item in events[1:]) == PRIMARY_CHUNKS[0]
    assert ZAI_TOKEN not in repr(events)
    assert response.closed


def test_reflected_controller_secret_is_withheld_from_valid_sse_content(tmp_path):
    reflected = _event(
        {
            "type": "content_block_delta",
            "delta": {"type": "text_delta", "text": "private " + ZAI_TOKEN},
        }
    )
    response = StreamResponse(PRIMARY_CHUNKS[:1] + [reflected])
    service, _, _, _ = _service(tmp_path, response)

    async def scenario():
        events = []
        sent_body = False
        wait_forever = asyncio.Event()

        async def receive():
            nonlocal sent_body
            if not sent_body:
                sent_body = True
                return {"type": "http.request", "body": _primary_body(), "more_body": False}
            await wait_forever.wait()

        async def send(message):
            events.append(message)

        with pytest.raises(ModelStreamAborted, match="stream interrupted"):
            await service(_scope(), receive, send)
        return events

    events = asyncio.run(scenario())
    assert events[0]["status"] == 200
    assert b"".join(item["body"] for item in events[1:]) == PRIMARY_CHUNKS[0]
    assert ZAI_TOKEN not in repr(events)
    assert response.closed


def test_client_disconnect_cancels_gateway_and_closes_upstream(tmp_path):
    release = asyncio.Event()
    disconnected = asyncio.Event()
    response = StreamResponse(PRIMARY_CHUNKS, wait_after_first=release)
    service, _, _, _ = _service(tmp_path, response)

    async def scenario():
        events = []
        sent_body = False

        async def receive():
            nonlocal sent_body
            if not sent_body:
                sent_body = True
                return {"type": "http.request", "body": _primary_body(), "more_body": False}
            await disconnected.wait()
            return {"type": "http.disconnect"}

        async def send(message):
            events.append(message)
            if message["type"] == "http.response.body":
                disconnected.set()

        await service(_scope(), receive, send)
        return events

    events = asyncio.run(scenario())
    assert events[0]["status"] == 200
    assert events[-1]["more_body"] is True
    assert response.closed
    usage = json.loads((tmp_path / "usage.jsonl").read_text().splitlines()[0])
    assert usage["usage_status"] == "interrupted"


def test_oversized_body_fails_before_dispatch(tmp_path):
    service, _, transport, _ = _service(tmp_path, StreamResponse(PRIMARY_CHUNKS))
    events = asyncio.run(_call(service, _scope(), b"{" + b"x" * (16 * 1024 * 1024) + b"}"))
    assert events[0]["status"] == 413
    assert not transport.calls
