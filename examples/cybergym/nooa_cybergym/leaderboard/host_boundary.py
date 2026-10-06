# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed attestation contract for the Docker bridge's host gateway.

Docker ``internal=True`` removes external routing, but does not isolate the
bridge gateway from host listeners. A controller-owned sentinel must inspect
scoped firewall enforcement and run fresh probes from each task container.
This module validates that evidence; it does not install firewall rules.
"""

from __future__ import annotations

import ipaddress
import math
import re
from dataclasses import dataclass
from typing import Protocol

from .network import NetworkPolicy

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_NETWORK_ID = re.compile(r"[0-9a-f]{64}\Z")
_PRIVATE_RANGES = tuple(
    ipaddress.IPv4Network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


@dataclass(frozen=True, slots=True)
class HostGatewayBoundary:
    network_id: str
    network_name: str
    bridge_interface: str
    subnet: str
    gateway: str
    policy_sha256: str
    routes: tuple[tuple[str, str, int], ...]

    @classmethod
    def from_network(
        cls,
        attrs: dict[str, object],
        *,
        network_id: str,
        network_name: str,
        policy: NetworkPolicy,
    ) -> HostGatewayBoundary:
        """Pin a single private IPv4 IPAM range and Docker bridge identity."""
        try:
            if not _NETWORK_ID.fullmatch(network_id):
                raise ValueError
            ipam = attrs["IPAM"]
            assert isinstance(ipam, dict)
            configs = ipam["Config"]
            if not isinstance(configs, list) or len(configs) != 1:
                raise ValueError
            config = configs[0]
            if not isinstance(config, dict):
                raise ValueError
            subnet = ipaddress.IPv4Network(config["Subnet"], strict=True)
            gateway = ipaddress.IPv4Address(config["Gateway"])
            if (
                gateway not in subnet
                or gateway in (subnet.network_address, subnet.broadcast_address)
                or not any(subnet.subnet_of(private) for private in _PRIVATE_RANGES)
                or attrs.get("EnableIPv6") is not False
            ):
                raise ValueError
            options = attrs.get("Options") or {}
            if not isinstance(options, dict):
                raise ValueError
            bridge = f"br-{network_id[:12]}"
            if options.get("com.docker.network.bridge.name", bridge) != bridge:
                raise ValueError
            routes = tuple(
                (endpoint, str(gateway), 80)
                for endpoint in sorted(policy.allowed_logical_endpoints)
            )
            if not routes or any(
                not policy.check_endpoint("parent", f"http://{host}:80/") for host, _, _ in routes
            ):
                raise ValueError
            return cls(
                network_id,
                network_name,
                bridge,
                str(subnet),
                str(gateway),
                policy.digest,
                routes,
            )
        except (AssertionError, KeyError, TypeError, ValueError):
            raise RuntimeError("host gateway network identity could not be verified") from None


@dataclass(frozen=True, slots=True)
class ScopedFirewallObservation:
    """Controller inspection of a per-bridge rule set kept until container stop."""

    boundary: HostGatewayBoundary
    ruleset_sha256: str
    bridge_scoped: bool
    default_deny_host: bool
    enforced_until_container_stop: bool
    allowed_tcp_ports: tuple[int, ...]
    allowed_routes: tuple[tuple[str, str, int], ...]


@dataclass(frozen=True, slots=True)
class GatewayDenialProbe:
    """A live HTTP request from the task container to the gateway proxy."""

    probe_id: str
    source_container_id: str
    gateway: str
    gateway_port: int
    method: str
    request_target: str
    host_header: str
    gateway_listener_active: bool
    response_status: int


@dataclass(frozen=True, slots=True)
class HostGatewayEvidence:
    """Fresh observations made with a live task container and host canary."""

    challenge: str
    container_id: str
    probe_source_container_id: str
    observed_at_monotonic: float
    firewall: ScopedFirewallObservation
    passed_routes: tuple[tuple[str, str, int], ...]
    denied_gateway_routes: tuple[GatewayDenialProbe, ...]
    canary_port: int
    canary_host_listener_address: str
    canary_host_listener_active: bool
    canary_from_container_blocked: bool


class HostGatewaySentinel(Protocol):
    """Trusted controller adapter; performs live inspection and task probes.

    The adapter must verify an active listener on ``boundary.gateway`` at a
    disallowed port, then test that exact listener from ``container_id``.
    It must probe the port-80 proxy with unknown Host, direct-IP, host-service
    passthrough, and CONNECT-to-canary requests and observe explicit rejection
    from an active gateway listener. It must also hold or monitor scoped
    enforcement through container stop.
    A refused connection without an active listener is not denial evidence.
    """

    def attest(
        self, boundary: HostGatewayBoundary, *, container_id: str, challenge: str
    ) -> HostGatewayEvidence: ...


def _required_denial_requests(
    gateway: str, canary_port: int
) -> tuple[tuple[str, str, str, str], ...]:
    canary_authority = f"{gateway}:{canary_port}"
    return (
        ("unknown-host-header", "GET", "/", "blocked.invalid"),
        ("direct-gateway-ip", "GET", "/", gateway),
        (
            "canary-host-service-passthrough",
            "GET",
            f"http://{canary_authority}/",
            canary_authority,
        ),
        ("connect-to-canary", "CONNECT", canary_authority, canary_authority),
    )


def require_host_gateway_evidence(
    evidence: HostGatewayEvidence,
    *,
    boundary: HostGatewayBoundary,
    container_id: str,
    challenge: str,
    probe_started_at_monotonic: float,
    now_monotonic: float,
) -> None:
    """Reject stale, replayed, incomplete, or differently scoped evidence."""
    if (
        type(evidence) is not HostGatewayEvidence
        or type(evidence.firewall) is not ScopedFirewallObservation
        or evidence.challenge != challenge
        or evidence.container_id != container_id
        or evidence.probe_source_container_id != container_id
        or type(evidence.observed_at_monotonic) not in (float, int)
        or not math.isfinite(evidence.observed_at_monotonic)
        or not probe_started_at_monotonic <= evidence.observed_at_monotonic <= now_monotonic
        or now_monotonic - probe_started_at_monotonic > 30.0
        or evidence.firewall.boundary != boundary
        or type(evidence.firewall.ruleset_sha256) is not str
        or not _SHA256.fullmatch(evidence.firewall.ruleset_sha256)
        or evidence.firewall.ruleset_sha256 == "0" * 64
        or evidence.firewall.bridge_scoped is not True
        or evidence.firewall.default_deny_host is not True
        or evidence.firewall.enforced_until_container_stop is not True
        or evidence.firewall.allowed_tcp_ports != (80,)
        or evidence.firewall.allowed_routes != boundary.routes
        or evidence.passed_routes != boundary.routes
        or type(evidence.denied_gateway_routes) is not tuple
        or any(type(probe) is not GatewayDenialProbe for probe in evidence.denied_gateway_routes)
        or tuple(
            (probe.probe_id, probe.method, probe.request_target, probe.host_header)
            for probe in evidence.denied_gateway_routes
        )
        != _required_denial_requests(boundary.gateway, evidence.canary_port)
        or any(
            probe.source_container_id != container_id
            or probe.gateway != boundary.gateway
            or probe.gateway_port != 80
            or probe.gateway_listener_active is not True
            or type(probe.response_status) is not int
            or not 400 <= probe.response_status <= 499
            for probe in evidence.denied_gateway_routes
        )
        or type(evidence.canary_port) is not int
        or not 1 <= evidence.canary_port <= 65535
        or evidence.canary_port in evidence.firewall.allowed_tcp_ports
        or evidence.canary_host_listener_address != boundary.gateway
        or evidence.canary_host_listener_active is not True
        or evidence.canary_from_container_blocked is not True
    ):
        raise RuntimeError("host gateway boundary attestation failed")
