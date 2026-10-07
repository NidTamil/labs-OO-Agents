# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Concrete per-bridge firewall and terminating gateway owned by the controller.

Create the runtime before the task container. Keep it alive until that container
stops. Route handlers are trusted, fixed controller adapters, never user-selected
upstream URLs. The reserved challenge route proves routing, not provider health.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import select
import socket
import subprocess
import threading
import time
import uuid
from collections.abc import Callable, Iterable, Mapping
from dataclasses import asdict, dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import MappingProxyType
from typing import Any

from .host_boundary import (
    GatewayDenialProbe,
    HostGatewayBoundary,
    HostGatewayEvidence,
    ScopedFirewallObservation,
    _required_denial_requests,
)
from .network import NetworkPolicy


@dataclass(frozen=True, slots=True)
class AdmittedPeer:
    container_id: str
    network_id: str
    source_ip: str


@dataclass(frozen=True, slots=True)
class GatewayRequest:
    endpoint: str
    method: str
    path: str
    headers: tuple[tuple[str, str], ...]
    body: bytes
    peer: AdmittedPeer
    disconnected: threading.Event | None = field(default=None, compare=False, repr=False)
    source_port: int | None = field(default=None, compare=False, repr=False)


@dataclass(frozen=True, slots=True)
class GatewayReply:
    status: int
    body: bytes | Iterable[bytes]
    content_type: str = "application/json"
    headers: tuple[tuple[str, str], ...] = ()


class _Audit:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.fd = os.open(
            path, os.O_CREAT | os.O_APPEND | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600
        )
        self.lock = threading.Lock()

    def write(self, record: dict[str, Any]) -> None:
        payload = (json.dumps(record, sort_keys=True, allow_nan=False) + "\n").encode()
        with self.lock:
            view = memoryview(payload)
            while view:
                view = view[os.write(self.fd, view) :]
            os.fsync(self.fd)

    def close(self) -> None:
        os.close(self.fd)


class GatewayService:
    """HTTP dispatch with exact Host admission and streaming response support.

    No DNS lookups, CONNECT, forwarding, redirects, or URL fetching occur here.
    A handler must apply its own route/capability/authentication policy. Request
    headers are data; only ``peer`` is trusted source identity.
    """

    def __init__(
        self,
        bind: tuple[str, int],
        handlers: Mapping[str, Callable[[GatewayRequest], GatewayReply]],
        peer_lookup: Callable[[str], AdmittedPeer | None],
        audit_path: Path,
        *,
        max_request_bytes: int = 64 * 1024 * 1024,
    ):
        self.handlers = MappingProxyType(dict(handlers))
        self.peer_lookup = peer_lookup
        self.max_request_bytes = max_request_bytes
        self.failed = threading.Event()
        self.challenges: dict[str, str] = {}
        self.audit = _Audit(audit_path)
        service = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args):
                pass  # Request paths and headers may contain secrets.

            def setup(self):
                super().setup()
                self.connection.settimeout(15)

            def _dispatch(self):
                self.close_connection = True
                body = b""
                status = 403
                total = 0
                chunks = 0
                allowed = False
                completed = False
                response_started = False
                peer = None
                endpoint = ""
                kind = "route"
                disconnected = threading.Event()
                watch_stop = threading.Event()
                watcher = None
                reply = None

                def watch_socket():
                    while not watch_stop.wait(0.05):
                        try:
                            readable, _, _ = select.select([self.connection], [], [], 0)
                            if not readable:
                                continue
                            # The complete body has been read. This connection
                            # serves one request, so EOF or additional pipelined
                            # bytes both invalidate further streaming work.
                            disconnected.set()
                            if reply is not None and hasattr(reply.body, "close"):
                                reply.body.close()
                            return
                        except Exception:
                            disconnected.set()
                            return

                try:
                    peer = service.peer_lookup(self.client_address[0])
                    hosts = self.headers.get_all("Host", [])
                    raw_target = self.raw_requestline.decode("iso-8859-1").split(" ")[1]
                    names = [name.lower() for name in self.headers.keys()]
                    lengths = self.headers.get_all("Content-Length", [])
                    length_text = lengths[0] if len(lengths) == 1 else "0"
                    length = (
                        int(length_text) if re.fullmatch(r"0|[1-9][0-9]{0,8}", length_text) else -1
                    )
                    host = hosts[0] if len(hosts) == 1 else ""
                    endpoint = host.removesuffix(":80")
                    if (
                        peer is None
                        or peer.source_ip != self.client_address[0]
                        or endpoint not in service.handlers
                        or host not in (endpoint, endpoint + ":80")
                        or self.command not in {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"}
                        or not raw_target.startswith("/")
                        or raw_target.startswith("//")
                        or "\\" in raw_target
                        or "#" in raw_target
                        or len(names) != len(set(names))
                        or any(name in names for name in ("transfer-encoding", "upgrade", "expect"))
                        or len(lengths) > 1
                        or not 0 <= length <= service.max_request_bytes
                        or (lengths and not re.fullmatch(r"0|[1-9][0-9]*", lengths[0]))
                    ):
                        reply = GatewayReply(403, b'{"error":"boundary denied"}')
                    else:
                        body = self.rfile.read(length)
                        if len(body) != length:
                            raise ValueError("incomplete request")
                        request = GatewayRequest(
                            endpoint,
                            self.command,
                            self.path,
                            tuple(self.headers.items()),
                            body,
                            peer,
                            disconnected,
                            self.client_address[1],
                        )
                        watcher = threading.Thread(
                            target=watch_socket, name="cybergym-client-disconnect", daemon=True
                        )
                        watcher.start()
                        if self.path.startswith("/__cybergym_boundary/"):
                            kind = "boundary-route-probe"
                            challenge = self.path.rsplit("/", 1)[-1]
                            if (
                                self.command != "GET"
                                or service.challenges.get(peer.container_id) != challenge
                            ):
                                reply = GatewayReply(403, b'{"error":"unknown challenge"}')
                            else:
                                reply = GatewayReply(
                                    200,
                                    json.dumps(
                                        {
                                            "challenge": challenge,
                                            "endpoint": endpoint,
                                            "container_id": peer.container_id,
                                            "network_id": peer.network_id,
                                        }
                                    ).encode(),
                                )
                                allowed = True
                        else:
                            allowed = True
                            reply = service.handlers[endpoint](request)
                    if not isinstance(reply, GatewayReply) or not 200 <= reply.status <= 599:
                        raise ValueError("invalid gateway reply")
                    status = reply.status
                    headers = (("Content-Type", reply.content_type),) + reply.headers
                    for key, value in headers:
                        if (
                            not re.fullmatch(r"[A-Za-z0-9-]+", key)
                            or any(ord(c) < 32 or ord(c) > 126 for c in value)
                            or key.lower()
                            in {
                                "connection",
                                "transfer-encoding",
                                "content-length",
                                "upgrade",
                                "location",
                                "proxy-authenticate",
                            }
                        ):
                            raise ValueError("unsafe response header")
                    response_started = True
                    self.send_response(status)
                    for key, value in headers:
                        self.send_header(key, value)
                    self.send_header("Connection", "close")
                    if isinstance(reply.body, bytes):
                        self.send_header("Content-Length", str(len(reply.body)))
                    self.end_headers()
                    if self.command != "HEAD":
                        parts = (reply.body,) if isinstance(reply.body, bytes) else reply.body
                        for part in parts:
                            if not isinstance(part, bytes):
                                raise ValueError("non-byte response chunk")
                            self.wfile.write(part)
                            self.wfile.flush()
                            total += len(part)
                            chunks += 1
                    completed = not disconnected.is_set()
                except Exception:
                    # No raw exception, payload, URL or credential enters the response/log.
                    try:
                        if not response_started:
                            status = 502
                            self.send_error(502, "Gateway request failed")
                    except (OSError, ValueError):
                        pass
                finally:
                    watch_stop.set()
                    if watcher:
                        watcher.join(timeout=1)
                    if reply is not None and not isinstance(reply.body, bytes):
                        close = getattr(reply.body, "close", None)
                        if close is not None:
                            try:
                                close()
                            except Exception:
                                completed = False
                    try:
                        denied_mcp_headers = {}
                        if (
                            status in {400, 403}
                            and endpoint
                            in {
                                "gbrain-read-gateway",
                                "registered-tool-gateway",
                            }
                            and self.path in {"/mcp", "/mcp/clangd", "/mcp/documentation"}
                        ):
                            safe_names = sorted(
                                {
                                    name.lower()
                                    for name in self.headers.keys()
                                    if re.fullmatch(r"[A-Za-z0-9-]{1,64}", name)
                                }
                            )
                            denied_mcp_headers = {
                                "denied_mcp_header_names": safe_names[:32],
                                "denied_mcp_header_names_truncated": len(safe_names) > 32,
                            }
                        service.audit.write(
                            {
                                "kind": kind,
                                "at_monotonic": time.monotonic(),
                                "container_id": peer.container_id if peer else None,
                                "network_id": peer.network_id if peer else None,
                                "source_ip": self.client_address[0],
                                "endpoint": endpoint if endpoint in service.handlers else None,
                                "method": self.command,
                                "path_sha256": hashlib.sha256(self.path.encode()).hexdigest(),
                                "request_sha256": hashlib.sha256(body).hexdigest(),
                                "request_bytes": len(body),
                                "response_bytes": total,
                                "response_chunks": chunks,
                                "status": status,
                                "allowed": allowed,
                                "completed": completed,
                                **denied_mcp_headers,
                            }
                        )
                    except Exception:
                        service.failed.set()

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_CONNECT = do_OPTIONS = (
                _dispatch
            )

        try:
            self.server = ThreadingHTTPServer(bind, Handler)
        except BaseException:
            self.audit.close()
            raise
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            kwargs={"poll_interval": 0.05},
            name="cybergym-gateway",
            daemon=True,
        )
        self.port = self.server.server_port

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.audit.close()


def firewall_plan(boundary: HostGatewayBoundary, table: str) -> dict:
    """Generate one atomic nft transaction; no existing tables/chains are edited."""
    if (
        not re.fullmatch(r"cg_[a-f0-9]{16}", table)
        or boundary.bridge_interface != "br-" + boundary.network_id[:12]
        or not re.fullmatch(r"[a-f0-9]{64}", boundary.network_id)
    ):
        raise ValueError("invalid scoped firewall identity")
    gateway = str(ipaddress.IPv4Address(boundary.gateway))
    base = {"family": "inet", "table": table}
    commands = [{"add": {"table": {"family": "inet", "name": table}}}]
    for chain in ("input", "forward"):
        commands.append(
            {
                "add": {
                    "chain": {
                        **base,
                        "name": chain,
                        "type": "filter",
                        "hook": chain,
                        "prio": -10,
                        "policy": "accept",
                    }
                }
            }
        )

    def match(left, right):
        return {"match": {"op": "==", "left": left, "right": right}}

    incoming = match({"meta": {"key": "iifname"}}, boundary.bridge_interface)
    outgoing = match({"meta": {"key": "oifname"}}, boundary.bridge_interface)
    rules = [
        (
            "input",
            [
                incoming,
                match({"ct": {"key": "direction"}}, "reply"),
                match({"ct": {"key": "state"}}, {"set": ["established", "related"]}),
                {"accept": None},
            ],
        ),
        (
            "input",
            [
                incoming,
                match({"payload": {"protocol": "ip", "field": "daddr"}}, gateway),
                match({"payload": {"protocol": "tcp", "field": "dport"}}, 80),
                {"accept": None},
            ],
        ),
        ("input", [incoming, {"drop": None}]),
        ("forward", [incoming, {"drop": None}]),
        ("forward", [outgoing, {"drop": None}]),
    ]
    for chain, expressions in rules:
        commands.append({"add": {"rule": {**base, "chain": chain, "expr": expressions}}})
    return {"nftables": commands}


def _normalized_rules(document: dict) -> list:
    entries = [
        {
            kind: {
                key: value
                for key, value in item[kind].items()
                if key not in {"handle", "index", "use"}
            }
        }
        for item in document["nftables"]
        for kind in ("table", "chain", "rule")
        if kind in item
    ]
    # nft lists each chain followed by its rules; create transactions declare all
    # chains first. Stable grouping preserves the security-relevant rule order.
    return sorted(
        entries,
        key=lambda item: (
            {"table": 0, "chain": 1, "rule": 2}[next(iter(item))],
            item.get("chain", {}).get("name", item.get("rule", {}).get("chain", "")),
        ),
    )


class _NftFirewall:
    def __init__(self, boundary: HostGatewayBoundary):
        self.table = "cg_" + uuid.uuid4().hex[:16]
        self.plan = firewall_plan(boundary, self.table)
        self.expected = _normalized_rules(
            {"nftables": [item["add"] for item in self.plan["nftables"]]}
        )
        self.installed = False
        self.input_installed = False
        self.input_rule = [
            "-i",
            boundary.bridge_interface,
            "-d",
            boundary.gateway,
            "-p",
            "tcp",
            "--dport",
            "80",
            "-m",
            "comment",
            "--comment",
            self.table,
            "-j",
            "ACCEPT",
        ]

    def _command(self, arguments: list[str], payload: str | None = None) -> str:
        result = subprocess.run(
            ["nft", *arguments],
            input=payload,
            text=True,
            capture_output=True,
            timeout=5,
            check=False,
        )
        if result.returncode:
            raise RuntimeError("scoped nftables operation failed")
        return result.stdout

    def install(self) -> None:
        self._command(["-j", "-f", "-"], json.dumps(self.plan))
        self.installed = True
        # An accept verdict in our earlier nft hook does not bypass a later
        # UFW INPUT policy DROP. This exact exception has the same bridge/IP/port
        # scope, and is removed by exact rule specification, never by line number.
        self._input_command(["-I", "INPUT", "1"])
        self.input_installed = True
        self.inspect()

    def _input_command(self, operation: list[str]) -> None:
        result = subprocess.run(
            ["iptables", "-w", "5", *operation, *self.input_rule],
            text=True,
            capture_output=True,
            timeout=7,
            check=False,
        )
        if result.returncode:
            raise RuntimeError("scoped host input exception operation failed")

    def inspect(self) -> str:
        observed = _normalized_rules(
            json.loads(self._command(["-j", "list", "table", "inet", self.table]))
        )
        if observed != self.expected:
            raise RuntimeError("scoped firewall rules changed")
        self._input_command(["-C", "INPUT"])
        return hashlib.sha256(
            json.dumps(
                {"nft": observed, "input_exception": self.input_rule}, sort_keys=True
            ).encode()
        ).hexdigest()

    def close(self) -> None:
        if self.input_installed:
            self._input_command(["-D", "INPUT"])
            self.input_installed = False
        if self.installed:
            self._command(["delete", "table", "inet", self.table])
            self.installed = False


# Node is already part of the certified agent image. The controller supplies all
# parameters; no shell or agent-supplied script is evaluated for these probes.
_NODE_PROBE = r"""
const net = require('node:net');
const p = JSON.parse(process.argv[1]);
const s = net.createConnection({host:p.gateway, port:p.port});
let data = Buffer.alloc(0), finished = false;
function done(value) { if (finished) return; finished = true; s.destroy(); console.log(JSON.stringify(value)); }
s.setTimeout(1000, () => done({timeout:true,connected:!!s.readyState && s.readyState==='open'}));
s.on('error', e => done({error:e.code}));
s.on('connect', () => {
  if (!p.method) return done({connected:true});
  s.write(p.method+' '+p.target+' HTTP/1.1\r\nHost: '+p.host+'\r\nConnection: close\r\n\r\n');
});
s.on('data', b => { data = Buffer.concat([data,b]); if(data.length>131072) done({oversized:true}); });
s.on('end', () => { const t=data.toString('utf8'); const split=t.indexOf('\r\n\r\n');
  done({status:Number(t.split(' ')[1]),body:split>=0?t.slice(split+4):''}); });
"""


class HostBoundaryRuntime:
    """Sentinel, firewall and proxy lifetime for one dedicated task bridge.

    ``close`` refuses to remove protection from a running admitted container.
    Rules survive a controller crash; when the gateway exits its routes close.
    During operation a watchdog stops admitted containers on rule/topology drift.
    """

    def __init__(
        self,
        *,
        docker_client: Any,
        network: Any,
        policy: NetworkPolicy,
        handlers: Mapping[str, Callable[[GatewayRequest], GatewayReply]],
        audit_path: Path,
    ):
        if set(handlers) != policy.allowed_logical_endpoints or not all(
            callable(handler) for handler in handlers.values()
        ):
            raise ValueError("every allowed logical endpoint needs a trusted handler")
        network.reload()
        attrs = network.attrs
        if attrs.get("Id") != network.id or attrs.get("Name") != network.name:
            raise RuntimeError("Docker network identity mismatch")
        if (
            attrs.get("Internal") is not True
            or attrs.get("Driver") != "bridge"
            or attrs.get("Labels", {}).get("org.xeus.cybergym.boundary") != "task-v1"
            or attrs.get("Containers")
        ):
            raise RuntimeError("runtime needs an empty dedicated internal task network")
        self.client, self.network, self.policy = docker_client, network, policy
        self.boundary = HostGatewayBoundary.from_network(
            attrs, network_id=network.id, network_name=network.name, policy=policy
        )
        self.firewall = _NftFirewall(self.boundary)
        self.handlers, self.audit_path = handlers, Path(audit_path)
        self.peers: dict[str, AdmittedPeer] = {}
        self.containers: dict[str, Any] = {}
        self.lock = threading.RLock()
        self.stop = threading.Event()
        self.failed = threading.Event()
        self.service: GatewayService | None = None
        self.monitor: threading.Thread | None = None

    def __enter__(self):
        try:
            self.firewall.install()
            self.service = GatewayService(
                (self.boundary.gateway, 80), self.handlers, self._peer, self.audit_path
            ).__enter__()
            self.monitor = threading.Thread(
                target=self._watch, name="cybergym-boundary-watch", daemon=True
            )
            self.monitor.start()
            return self
        except BaseException:
            if self.service:
                self.service.__exit__()
            self.firewall.close()
            raise

    def _peer(self, address: str) -> AdmittedPeer | None:
        if self.failed.is_set():
            return None
        with self.lock:
            peer = self.peers.get(address)
            if peer is None:
                return None
            try:
                self._verify_container(self.containers[peer.container_id], peer)
            except Exception:
                self.failed.set()
                return None
            return peer

    def _verify_container(self, container, peer: AdmittedPeer) -> None:
        container.reload()
        nets = container.attrs["NetworkSettings"]["Networks"]
        details = nets[self.boundary.network_name]
        if (
            container.status != "running"
            or set(nets) != {self.boundary.network_name}
            or details["NetworkID"] != self.boundary.network_id
            or details["IPAddress"] != peer.source_ip
            or container.id != peer.container_id
        ):
            raise RuntimeError("admitted container identity changed")

    def _verify_network(self) -> set[str]:
        self.network.reload()
        attrs = self.network.attrs
        if (
            attrs.get("Id") != self.boundary.network_id
            or attrs.get("Name") != self.boundary.network_name
            or attrs.get("Internal") is not True
            or attrs.get("Driver") != "bridge"
            or attrs.get("Labels", {}).get("org.xeus.cybergym.boundary") != "task-v1"
            or HostGatewayBoundary.from_network(
                attrs,
                network_id=self.network.id,
                network_name=self.network.name,
                policy=self.policy,
            )
            != self.boundary
        ):
            raise RuntimeError("network identity changed")
        return set(attrs.get("Containers") or {})

    def _watch(self) -> None:
        while not self.stop.wait(0.25):
            try:
                self.firewall.inspect()
                if self.failed.is_set() or self.service.failed.is_set():
                    raise RuntimeError("gateway audit failed")
                with self.lock:
                    peers = self._verify_network()
                    if self.containers and not peers <= self.containers.keys():
                        raise RuntimeError("unregistered peer joined admitted task network")
            except Exception:
                self.failed.set()
                with self.lock:
                    for container in self.containers.values():
                        try:
                            container.kill()
                        except Exception:
                            pass
                return

    def _probe(self, container, **payload) -> dict:
        result = container.exec_run(
            ["node", "-e", _NODE_PROBE, json.dumps(payload)], user="65534:65534"
        )
        if result.exit_code != 0 or len(result.output) > 132000:
            raise RuntimeError("container boundary probe failed")
        return json.loads(result.output)

    def attest(
        self, boundary: HostGatewayBoundary, *, container_id: str, challenge: str
    ) -> HostGatewayEvidence:
        if (
            boundary != self.boundary
            or self.service is None
            or self.failed.is_set()
            or not re.fullmatch(r"[a-f0-9]{32}", challenge)
            or not re.fullmatch(r"[a-f0-9]{64}", container_id)
        ):
            raise RuntimeError("boundary runtime is not ready for this challenge")
        container = self.client.containers.get(container_id)
        container.reload()
        address = container.attrs["NetworkSettings"]["Networks"][boundary.network_name]["IPAddress"]
        peer = AdmittedPeer(container_id, boundary.network_id, address)
        self._verify_container(container, peer)
        if ipaddress.IPv4Address(address) not in ipaddress.IPv4Network(boundary.subnet):
            raise RuntimeError("container is outside pinned subnet")
        with self.lock:
            if self._verify_network() != {container_id} or set(self.containers) - {container_id}:
                raise RuntimeError("attestation requires exactly one task container")
            self.containers[container_id] = container
            self.peers[address] = peer
            self.service.challenges[container_id] = challenge
        digest = self.firewall.inspect()
        observations = []
        passed = []
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as canary:
            canary.bind((boundary.gateway, 0))
            canary.listen(4)
            port = canary.getsockname()[1]
            with socket.create_connection((boundary.gateway, port), timeout=1):
                accepted, _ = canary.accept()
                accepted.close()
            blocked = self._probe(container, gateway=boundary.gateway, port=port)
            if blocked != {"timeout": True, "connected": False}:
                raise RuntimeError("active host canary was not blocked by firewall")
            for endpoint, gateway, gateway_port in boundary.routes:
                result = self._probe(
                    container,
                    gateway=gateway,
                    port=gateway_port,
                    method="GET",
                    target="/__cybergym_boundary/" + challenge,
                    host=endpoint,
                )
                expected = {
                    "challenge": challenge,
                    "endpoint": endpoint,
                    "container_id": container_id,
                    "network_id": boundary.network_id,
                }
                if (
                    result.get("status") != 200
                    or json.loads(result.get("body", "null")) != expected
                ):
                    raise RuntimeError("logical gateway route probe failed")
                passed.append((endpoint, gateway, gateway_port))
            for probe_id, method, target, host in _required_denial_requests(boundary.gateway, port):
                result = self._probe(
                    container,
                    gateway=boundary.gateway,
                    port=80,
                    method=method,
                    target=target,
                    host=host,
                )
                status = result.get("status")
                if type(status) is not int or not 400 <= status <= 499:
                    raise RuntimeError("gateway did not reject forbidden request")
                observations.append(
                    GatewayDenialProbe(
                        probe_id,
                        container_id,
                        boundary.gateway,
                        80,
                        method,
                        target,
                        host,
                        True,
                        status,
                    )
                )
            # A second host connection proves the listener stayed active during denial probes.
            with socket.create_connection((boundary.gateway, port), timeout=1):
                accepted, _ = canary.accept()
                accepted.close()
        if self.firewall.inspect() != digest or self.failed.is_set():
            raise RuntimeError("firewall changed during attestation")
        evidence = HostGatewayEvidence(
            challenge,
            container_id,
            container_id,
            time.monotonic(),
            ScopedFirewallObservation(boundary, digest, True, True, True, (80,), boundary.routes),
            tuple(passed),
            tuple(observations),
            port,
            boundary.gateway,
            True,
            True,
        )
        self.service.audit.write({"kind": "host-gateway-attestation", "evidence": asdict(evidence)})
        return evidence

    def close(self) -> None:
        with self.lock:
            if self._verify_network():
                raise RuntimeError("stop admitted containers before removing boundary")
            for container in self.containers.values():
                try:
                    container.reload()
                except Exception as error:
                    if getattr(error, "status_code", None) == 404:
                        continue
                    raise RuntimeError("cannot verify container stop; firewall retained") from None
                if container.status in {"running", "restarting", "paused"}:
                    raise RuntimeError("stop admitted containers before removing boundary")
        self.stop.set()
        if self.monitor:
            self.monitor.join(timeout=6)
        if self.service:
            self.service.__exit__()
            self.service = None
        self.firewall.close()

    def __exit__(self, *_args):
        self.close()
