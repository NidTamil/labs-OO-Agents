"""Exercise the actual threaded HTTP-to-ASGI bridge, using a synthetic provider."""

import asyncio
import json
import time

from nooa_cybergym.leaderboard.host_boundary_runtime import AdmittedPeer, GatewayRequest
from nooa_cybergym.leaderboard.model_runtime import TaskModelRoute

from .test_model_service import CONNECTION, PRIMARY_CHUNKS, TASK_TOKEN, StreamResponse, _service


def request(peer, **kwargs):
    return GatewayRequest(
        "model-gateway",
        "POST",
        "/v1/messages",
        (),
        json.dumps(
            {
                "model": "glm-5.3",
                "max_tokens": 128000,
                "stream": True,
            }
        ).encode(),
        peer,
        **kwargs,
    )


def test_peer_bound_route_injects_controller_token_and_streams(tmp_path):
    _, core, transport, _ = _service(tmp_path, StreamResponse(PRIMARY_CHUNKS))
    peer = AdmittedPeer("a" * 64, "b" * 64, "172.20.0.2")
    with TaskModelRoute(core, TASK_TOKEN, lambda p: CONNECTION if p == peer else None) as route:
        response = route(request(peer))
        assert response.status == 200
        assert b"".join(response.body) == b"".join(PRIMARY_CHUNKS)
    assert len(transport.calls) == 1


def test_unregistered_peer_cannot_reach_provider(tmp_path):
    _, core, transport, _ = _service(tmp_path, StreamResponse(PRIMARY_CHUNKS))
    with TaskModelRoute(core, TASK_TOKEN, lambda _: None) as route:
        result = route(request(AdmittedPeer("x", "y", "172.20.0.8")))
        assert result.status == 403
    assert not transport.calls


def test_solver_credentials_and_claim_headers_are_rejected(tmp_path):
    _, core, transport, _ = _service(tmp_path, StreamResponse(PRIMARY_CHUNKS))
    peer = AdmittedPeer("a" * 64, "b" * 64, "172.20.0.2")
    from dataclasses import replace

    with TaskModelRoute(core, TASK_TOKEN, lambda _: CONNECTION) as route:
        for header in ("Authorization", "x-api-key", "x-controller-role"):
            response = route(replace(request(peer), headers=((header, "forged"),)))
            assert response.status == 403
    assert not transport.calls


def test_closed_route_denies_new_work(tmp_path):
    _, core, transport, _ = _service(tmp_path, StreamResponse(PRIMARY_CHUNKS))
    route = TaskModelRoute(core, TASK_TOKEN, lambda _: CONNECTION)
    route.close()
    assert route(request(AdmittedPeer("x", "y", "z"))).status == 503
    assert not transport.calls


def test_unconsumed_stream_close_cancels_provider_and_records_terminal_usage(tmp_path):
    response = StreamResponse(PRIMARY_CHUNKS, wait_after_first=asyncio.Event())
    _, core, _, _ = _service(tmp_path, response)
    peer = AdmittedPeer("a" * 64, "b" * 64, "172.20.0.2")
    with TaskModelRoute(core, TASK_TOKEN, lambda _: CONNECTION) as route:
        reply = route(request(peer))
        assert reply.status == 200
        reply.body.close()
        deadline = time.monotonic() + 2
        while not response.closed and time.monotonic() < deadline:
            time.sleep(0.01)
        assert response.closed, "closing an unstarted iterator must close its provider"
    rows = [json.loads(row) for row in (tmp_path / "model-request.jsonl").read_text().splitlines()]
    assert rows[-1]["event"] == "request_terminal"
    assert rows[-1]["outcome"] == "cancelled"


def test_native_socket_disconnect_cancels_stalled_provider(tmp_path):
    import socket

    from nooa_cybergym.leaderboard.host_boundary_runtime import GatewayService

    response = StreamResponse(PRIMARY_CHUNKS, wait_after_first=asyncio.Event())
    _, core, _, _ = _service(tmp_path, response)
    peer = AdmittedPeer("a" * 64, "b" * 64, "127.0.0.1")
    with TaskModelRoute(core, TASK_TOKEN, lambda _: CONNECTION) as route:
        with GatewayService(
            ("127.0.0.1", 0),
            {"model-gateway": route},
            lambda _: peer,
            tmp_path / "http-audit.jsonl",
        ) as server:
            with socket.create_connection(("127.0.0.1", server.port), timeout=3) as connection:
                body = request(peer).body
                connection.sendall(
                    b"POST /v1/messages HTTP/1.1\r\nHost: model-gateway\r\n"
                    + f"Content-Length: {len(body)}\r\n\r\n".encode()
                    + body
                )
                received = b""
                while b"200 OK" not in received:
                    received += connection.recv(4096)
            deadline = time.monotonic() + 2
            while not response.closed and time.monotonic() < deadline:
                time.sleep(0.01)
            assert response.closed, "socket EOF must cancel before the next provider chunk"
    assert json.loads((tmp_path / "http-audit.jsonl").read_text())["completed"] is False


def test_disconnect_before_provider_headers_cancels_and_shutdown_waits_for_audit(tmp_path):
    import socket

    from nooa_cybergym.leaderboard.host_boundary_runtime import GatewayService

    class WaitingResponse(StreamResponse):
        async def aiter_bytes(self):
            await asyncio.Event().wait()
            yield b"never"

        async def aclose(self):
            await asyncio.sleep(0.1)
            self.closed = True

    response = WaitingResponse([])
    _, core, transport, _ = _service(tmp_path, response)
    peer = AdmittedPeer("a" * 64, "b" * 64, "127.0.0.1")
    with TaskModelRoute(core, TASK_TOKEN, lambda _: CONNECTION) as route:
        with GatewayService(
            ("127.0.0.1", 0),
            {"model-gateway": route},
            lambda _: peer,
            tmp_path / "http-audit.jsonl",
        ) as server:
            with socket.create_connection(("127.0.0.1", server.port), timeout=3) as connection:
                body = request(peer).body
                connection.sendall(
                    b"POST /v1/messages HTTP/1.1\r\nHost: model-gateway\r\n"
                    + f"Content-Length: {len(body)}\r\n\r\n".encode()
                    + body
                )
                deadline = time.monotonic() + 2
                while not transport.calls and time.monotonic() < deadline:
                    time.sleep(0.01)
                assert transport.calls
            deadline = time.monotonic() + 2
            while not response.closed and time.monotonic() < deadline:
                time.sleep(0.01)
            assert response.closed
    rows = [json.loads(row) for row in (tmp_path / "model-request.jsonl").read_text().splitlines()]
    assert rows[-1]["event"] == "request_terminal"
    assert rows[-1]["outcome"] == "cancelled"


def test_public_sentinel_is_not_an_admission_identity(tmp_path):
    from dataclasses import replace

    from nooa_cybergym.leaderboard.model_runtime import PUBLIC_CLIENT_TOKEN

    _, core, transport, _ = _service(tmp_path, StreamResponse(PRIMARY_CHUNKS))
    peer = AdmittedPeer("a" * 64, "b" * 64, "172.20.0.2")
    seen = []
    with TaskModelRoute(core, TASK_TOKEN, lambda p: seen.append(p)) as route:
        result = route(replace(request(peer), headers=(("x-api-key", PUBLIC_CLIENT_TOKEN),)))
        assert result.status == 403
    assert seen == [peer]
    assert not transport.calls
