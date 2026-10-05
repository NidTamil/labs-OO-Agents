"""Exercise the actual HTTP boundary, including framing and peer admission."""

from __future__ import annotations

import importlib
import importlib.util
import json
import socket
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest


def _runtime():
    name = "nooa_cybergym.leaderboard.host_boundary_runtime"
    assert importlib.util.find_spec(name) is not None, "concrete boundary runtime is missing"
    return importlib.import_module(name)


def _request(port: int, request: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=3) as connection:
        connection.sendall(request)
        result = b""
        while part := connection.recv(65536):
            result += part
        return result


@pytest.mark.parametrize(
    "wire_request",
    [
        b"GET / HTTP/1.1\r\nHost: blocked.invalid\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
        b"GET http://127.0.0.1:1234/ HTTP/1.1\r\nHost: model-gateway\r\n\r\n",
        b"CONNECT 127.0.0.1:1234 HTTP/1.1\r\nHost: model-gateway\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: model-gateway\r\nHost: model-gateway\r\n\r\n",
        b"POST / HTTP/1.1\r\nHost: model-gateway\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        b"POST / HTTP/1.1\r\nHost: model-gateway\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
        b"POST / HTTP/1.1\r\nHost: model-gateway\r\nContent-Length: nope\r\n\r\n",
        b"GET //127.0.0.1/ HTTP/1.1\r\nHost: model-gateway\r\n\r\n",
        b"GET / HTTP/1.1\r\nHost: model-gateway\r\nUpgrade: websocket\r\n\r\n",
    ],
)
def test_proxy_rejects_host_tunneling_and_ambiguous_framing(tmp_path: Path, wire_request: bytes):
    runtime = _runtime()
    called = []

    def handler(value):
        called.append(value)
        return runtime.GatewayReply(200, b"unexpected")

    peer = runtime.AdmittedPeer("a" * 64, "b" * 64, "127.0.0.1")
    with runtime.GatewayService(
        ("127.0.0.1", 0),
        {"model-gateway": handler},
        lambda ip: peer,
        tmp_path / "audit.jsonl",
    ) as service:
        result = _request(service.port, wire_request)
    assert 400 <= int(result.split(b" ")[1]) <= 499
    assert called == []
    assert json.loads((tmp_path / "audit.jsonl").read_text())["allowed"] is False


def test_proxy_injects_observed_peer_and_hashes_sensitive_request(tmp_path: Path):
    runtime = _runtime()
    received = []
    peer = runtime.AdmittedPeer("a" * 64, "b" * 64, "127.0.0.1")

    def handler(request):
        received.append(request)
        return runtime.GatewayReply(200, b"permitted-result")

    audit = tmp_path / "audit.jsonl"
    with runtime.GatewayService(
        ("127.0.0.1", 0),
        {"model-gateway": handler},
        lambda ip: peer,
        audit,
    ) as service:
        result = _request(
            service.port,
            b"POST /v1/messages?key=secret HTTP/1.1\r\n"
            b"Host: model-gateway:80\r\nX-Container-ID: attacker\r\n"
            b"Authorization: Bearer sensitive-token\r\nContent-Length: 6\r\n\r\nsecret",
        )
    assert b"200 OK" in result and result.endswith(b"permitted-result")
    assert received[0].peer == peer
    assert received[0].body == b"secret"
    assert "sensitive-token" not in audit.read_text()
    assert "secret" not in audit.read_text()
    event = json.loads(audit.read_text())
    assert event["container_id"] == "a" * 64
    assert event["network_id"] == "b" * 64
    assert event["response_bytes"] == 16


def test_denied_mcp_request_records_only_bounded_header_names(tmp_path: Path):
    runtime = _runtime()
    peer = runtime.AdmittedPeer("a" * 64, "b" * 64, "127.0.0.1")
    audit = tmp_path / "audit.jsonl"

    def denied(_request):
        return runtime.GatewayReply(403, b'{"error":"memory route denied"}')

    with runtime.GatewayService(
        ("127.0.0.1", 0),
        {"gbrain-read-gateway": denied},
        lambda ip: peer,
        audit,
    ) as service:
        response = _request(
            service.port,
            b"POST /mcp HTTP/1.1\r\nHost: gbrain-read-gateway\r\n"
            b"Authorization: Bearer sensitive-token\r\n"
            b"X-Test-Name: secret-value\r\nContent-Length: 6\r\n\r\nsecret",
        )
    assert b"403 Forbidden" in response
    event = json.loads(audit.read_text())
    assert event["denied_mcp_header_names"] == [
        "authorization",
        "content-length",
        "host",
        "x-test-name",
    ]
    assert "sensitive-token" not in audit.read_text()
    assert "secret-value" not in audit.read_text()
    assert "secret" not in audit.read_text()


def test_unadmitted_source_never_calls_route_handler(tmp_path: Path):
    runtime = _runtime()
    with runtime.GatewayService(
        ("127.0.0.1", 0),
        {"model-gateway": lambda _: pytest.fail("unadmitted caller")},
        lambda ip: None,
        tmp_path / "audit.jsonl",
    ) as service:
        result = _request(service.port, b"GET / HTTP/1.1\r\nHost: model-gateway\r\n\r\n")
    assert b"403 Forbidden" in result


def test_sse_yields_first_chunk_before_producer_completes(tmp_path: Path):
    runtime = _runtime()
    proceed = threading.Event()
    peer = runtime.AdmittedPeer("a" * 64, "b" * 64, "127.0.0.1")

    def stream():
        yield b"data: first\n\n"
        assert proceed.wait(3), "server buffered stream instead of flushing"
        yield b"data: last\n\n"

    with runtime.GatewayService(
        ("127.0.0.1", 0),
        {"model-gateway": lambda _: runtime.GatewayReply(200, stream(), "text/event-stream")},
        lambda ip: peer,
        tmp_path / "audit.jsonl",
    ) as service:
        with socket.create_connection(("127.0.0.1", service.port), timeout=3) as connection:
            connection.sendall(b"GET /stream HTTP/1.1\r\nHost: model-gateway\r\n\r\n")
            first = b""
            while b"data: first\n\n" not in first:
                first += connection.recv(4096)
            proceed.set()
            rest = b""
            while data := connection.recv(4096):
                rest += data
    assert rest.endswith(b"data: last\n\n")


def test_firewall_spec_only_targets_selected_bridge_and_rejects_input_injection():
    runtime = _runtime()
    from nooa_cybergym.leaderboard.host_boundary import HostGatewayBoundary

    boundary = HostGatewayBoundary(
        "a" * 64,
        "test",
        "br-aaaaaaaaaaaa",
        "172.30.0.0/24",
        "172.30.0.1",
        "b" * 64,
        (("model-gateway", "172.30.0.1", 80),),
    )
    plan = runtime.firewall_plan(boundary, "cg_1234567890abcdef")
    rules = [entry["add"]["rule"] for entry in plan["nftables"] if "rule" in entry["add"]]
    assert len(rules) == 5
    for rule in rules:
        assert rule["expr"][0]["match"] == {
            "op": "==",
            "left": {
                "meta": {
                    "key": "iifname" if rule["chain"] == "input" or rule is rules[-2] else "oifname"
                }
            },
            "right": "br-aaaaaaaaaaaa",
        }
    assert rules[1]["expr"][-1] == {"accept": None}
    assert rules[2]["expr"][-1] == {"drop": None}
    assert rules[3]["expr"][-1] == {"drop": None}
    with pytest.raises(ValueError):
        runtime.firewall_plan(boundary, "table; flush ruleset")


def test_nft_inventory_order_is_normalized_but_rule_order_is_preserved():
    runtime = _runtime()
    chain_a = {"chain": {"name": "input", "handle": 2}}
    chain_b = {"chain": {"name": "forward", "handle": 3}}
    allow = {"rule": {"chain": "input", "expr": [{"accept": None}], "handle": 4}}
    deny = {"rule": {"chain": "input", "expr": [{"drop": None}], "handle": 5}}
    planned = {"nftables": [chain_a, chain_b, allow, deny]}
    listed = {"nftables": [chain_a, allow, deny, chain_b]}
    assert runtime._normalized_rules(planned) == runtime._normalized_rules(listed)
    assert runtime._normalized_rules(planned) != runtime._normalized_rules(
        {"nftables": [chain_a, deny, allow, chain_b]}
    )


@pytest.mark.parametrize("field,value", [("Id", "c" * 64), ("Name", "other-network")])
def test_runtime_rejects_docker_identity_mismatch(tmp_path: Path, field: str, value: str):
    runtime = _runtime()
    from nooa_cybergym.leaderboard.network import NetworkPolicy

    policy = NetworkPolicy.load(
        Path(__file__).parents[2] / "leaderboard/config/network-policy.json"
    )
    attrs = {
        "Id": "a" * 64,
        "Name": "dedicated",
        "Internal": True,
        "Driver": "bridge",
        "Labels": {"org.xeus.cybergym.boundary": "task-v1"},
        "EnableIPv6": False,
        "Containers": {},
        "IPAM": {"Config": [{"Subnet": "172.30.0.0/24", "Gateway": "172.30.0.1"}]},
    }
    attrs[field] = value
    network = SimpleNamespace(id="a" * 64, name="dedicated", attrs=attrs, reload=lambda: None)
    with pytest.raises(RuntimeError, match="network identity"):
        runtime.HostBoundaryRuntime(
            docker_client=object(),
            network=network,
            policy=policy,
            handlers=dict.fromkeys(policy.allowed_logical_endpoints, lambda _: None),
            audit_path=tmp_path / "audit.jsonl",
        )
