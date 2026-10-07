# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""The task container contract, without contacting Docker or a provider."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import struct
import time
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import pytest
from nooa_cybergym.leaderboard.container import build_container_kwargs, start_task_container
from nooa_cybergym.leaderboard.host_boundary import (
    GatewayDenialProbe,
    HostGatewayBoundary,
    HostGatewayEvidence,
    ScopedFirewallObservation,
    require_host_gateway_evidence,
)
from nooa_cybergym.leaderboard.network import NetworkPolicy

NETWORK_ID = "a" * 64


def test_controller_task_token_cannot_enter_container_configuration(tmp_path):
    secret = "synthetic-private-controller-token"
    with pytest.raises(ValueError, match="controller-only") as raised:
        build_container_kwargs(
            image="agent:test",
            workspace=tmp_path,
            output=tmp_path / "output",
            network="isolated",
            ssh_port=22222,
            task_token=secret,
        )
    assert secret not in str(raised.value)


def test_native_trust_mount_contains_only_ed25519_public_keys(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    public = (
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    trust = tmp_path / "native-trust.json"
    trust.write_text(json.dumps({"synthetic-controller": public}))
    kwargs = build_container_kwargs(
        image="agent:test",
        workspace=tmp_path / "workspace",
        output=tmp_path / "output",
        network="isolated",
        ssh_port=22222,
        native_trust_file=trust,
    )
    assert kwargs["volumes"][str(trust)] == {
        "bind": "/etc/sunchaser/native-launch-trust.json",
        "mode": "ro",
    }
    trust.write_text(
        json.dumps(
            {
                "key": key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ).decode()
            }
        )
    )
    with pytest.raises(ValueError, match="public"):
        build_container_kwargs(
            image="agent:test",
            workspace=tmp_path / "workspace",
            output=tmp_path / "output",
            network="isolated",
            ssh_port=22222,
            native_trust_file=trust,
        )


def test_container_has_only_reviewed_host_interfaces(tmp_path: Path) -> None:
    kwargs = build_container_kwargs(
        image="sunchaser/cybergym-agent:test",
        workspace=tmp_path / "workspace",
        output=tmp_path / "output",
        network="cybergym-internal",
        ssh_port=22222,
        ssh_public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockFixtureKey fixture",
        container_name="cybergym-task-test",
    )

    assert kwargs["user"] == "root"  # PID 1 alone prepares tmpfs and sshd.
    assert kwargs["working_dir"] == "/workspace"
    assert kwargs["network"] == "cybergym-internal"
    assert kwargs["read_only"] is True
    assert kwargs["cap_drop"] == ["ALL"]
    assert set(kwargs["cap_add"]) == {"CHOWN", "SETUID", "SETGID", "DAC_OVERRIDE", "SYS_CHROOT"}
    assert kwargs["security_opt"] == ["no-new-privileges:true"]
    assert kwargs["pids_limit"] == 2048
    assert kwargs["mem_limit"] == "16g"
    assert not kwargs.get("ports")  # Docker does not publish ports on an internal bridge.
    assert kwargs["tmpfs"] == {
        "/tmp": "rw,noexec,nosuid,size=4g",
        "/run": "rw,nosuid,size=64m",
        "/home/agent": "rw,nosuid,size=8g",
        "/workspace/src": "rw,exec,nosuid,nodev,size=12g",
    }
    assert kwargs["volumes"] == {
        str((tmp_path / "workspace").resolve()): {"bind": "/workspace", "mode": "ro"},
        str((tmp_path / "output").resolve()): {"bind": "/workspace/output", "mode": "rw"},
    }
    assert kwargs["detach"] is True
    assert kwargs.get("privileged") is not True
    assert kwargs.get("pid_mode") != "host"
    assert kwargs.get("network_mode") != "host"
    assert "/var/run/docker.sock" not in kwargs["volumes"]
    assert kwargs["environment"]["CYBERGYM_SSH_PUBLIC_KEY"].startswith("ssh-ed25519 ")
    assert "CYBERGYM_TASK_TOKEN" not in kwargs["environment"]


@pytest.mark.parametrize("ssh_port", [0, -1, 65536, True])
def test_rejects_invalid_ssh_port(tmp_path: Path, ssh_port: object) -> None:
    with pytest.raises(ValueError, match="ssh_port"):
        build_container_kwargs(
            image="agent:test",
            workspace=tmp_path / "workspace",
            output=tmp_path / "output",
            network="isolated",
            ssh_port=ssh_port,
        )


def test_rejects_newlines_in_public_key_without_echoing_it(tmp_path: Path) -> None:
    injected_key = "ssh-ed25519 AAAA fixture\nPermitRootLogin yes"
    with pytest.raises(ValueError, match="ssh_public_key") as raised:
        build_container_kwargs(
            image="agent:test",
            workspace=tmp_path / "workspace",
            output=tmp_path / "output",
            network="isolated",
            ssh_port=22222,
            ssh_public_key=injected_key,
        )
    assert "PermitRootLogin yes" not in str(raised.value)


class _FakeContainer:
    def __init__(self, logs: bytes, *, fail_remove: bool = False) -> None:
        self.id = "synthetic-container-id"
        self.name = "cybergym-task-test"
        self.status = "running"
        self._logs = logs
        self.removed = False
        self.fail_remove = fail_remove
        self.attrs = {
            "NetworkSettings": {
                "Networks": {
                    "cybergym-internal": {
                        "IPAddress": "172.18.0.2",
                        "NetworkID": NETWORK_ID,
                    }
                }
            }
        }

    def reload(self) -> None:
        pass

    def logs(self, **_kwargs: object) -> bytes:
        return self._logs

    def remove(self, **_kwargs: object) -> None:
        if self.fail_remove:
            raise OSError("synthetic Docker cleanup error with task secret")
        self.removed = True


class _FakeRelay:
    def __init__(self, port: int) -> None:
        self.port = port
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _FakeClient:
    def __init__(
        self,
        container: _FakeContainer,
        *,
        internal_network: bool = True,
        initial_peers: frozenset[str] = frozenset(),
        extra_peer_after_start: bool = False,
    ) -> None:
        self.containers = self
        self.networks = self
        self.container = container
        self.run_calls = 0
        self.extra_peer_after_start = extra_peer_after_start
        self.network = self
        self.attrs = {
            "Id": NETWORK_ID,
            "Name": "cybergym-internal",
            "Internal": internal_network,
            "Driver": "bridge",
            "EnableIPv6": False,
            "IPAM": {"Config": [{"Subnet": "172.18.0.0/16", "Gateway": "172.18.0.1"}]},
            "Options": {},
            "Labels": {"org.xeus.cybergym.boundary": "task-v1"},
            "Containers": {peer: {} for peer in initial_peers},
        }

    def get(self, _name: str):
        return self

    def reload(self) -> None:
        pass

    def run(self, **_kwargs: object) -> _FakeContainer:
        policy_path = Path(__file__).resolve().parents[2] / "leaderboard/config/network-policy.json"
        expected = dict.fromkeys(
            NetworkPolicy.load(policy_path).allowed_logical_endpoints, "172.18.0.1"
        )
        assert _kwargs["extra_hosts"] == expected
        self.run_calls += 1
        self.attrs["Containers"][self.container.id] = {}
        if self.extra_peer_after_start:
            self.attrs["Containers"]["unapproved-peer"] = {}
        return self.container


class _FakeSentinel:
    def __init__(
        self, mutate: Callable[[HostGatewayEvidence], HostGatewayEvidence] | None = None
    ) -> None:
        self.mutate = mutate or (lambda evidence: evidence)
        self.calls = 0

    def attest(
        self, boundary: HostGatewayBoundary, *, container_id: str, challenge: str
    ) -> HostGatewayEvidence:
        self.calls += 1
        evidence = HostGatewayEvidence(
            challenge=challenge,
            container_id=container_id,
            probe_source_container_id=container_id,
            observed_at_monotonic=time.monotonic(),
            firewall=ScopedFirewallObservation(
                boundary=boundary,
                ruleset_sha256="b" * 64,
                bridge_scoped=True,
                default_deny_host=True,
                enforced_until_container_stop=True,
                allowed_tcp_ports=(80,),
                allowed_routes=boundary.routes,
            ),
            passed_routes=boundary.routes,
            denied_gateway_routes=tuple(
                GatewayDenialProbe(
                    probe_id=name,
                    source_container_id=container_id,
                    gateway=boundary.gateway,
                    gateway_port=80,
                    method=method,
                    request_target=target,
                    host_header=host_header,
                    gateway_listener_active=True,
                    response_status=403,
                )
                for name, method, target, host_header in (
                    ("unknown-host-header", "GET", "/", "blocked.invalid"),
                    ("direct-gateway-ip", "GET", "/", boundary.gateway),
                    (
                        "canary-host-service-passthrough",
                        "GET",
                        f"http://{boundary.gateway}:45321/",
                        f"{boundary.gateway}:45321",
                    ),
                    (
                        "connect-to-canary",
                        "CONNECT",
                        f"{boundary.gateway}:45321",
                        f"{boundary.gateway}:45321",
                    ),
                )
            ),
            canary_port=45321,
            canary_host_listener_address=boundary.gateway,
            canary_host_listener_active=True,
            canary_from_container_blocked=True,
        )
        return self.mutate(evidence)


def test_start_requires_fresh_host_gateway_boundary_evidence_before_docker_run(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    (workspace / "output").mkdir(parents=True)
    client = _FakeClient(_FakeContainer(b""))
    with pytest.raises(RuntimeError, match="host gateway boundary attestation required"):
        start_task_container(
            workspace=workspace,
            evidence_dir=tmp_path / "evidence",
            network_name="cybergym-internal",
            expected_network_id=NETWORK_ID,
            ssh_public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockFixtureKey fixture",
            docker_client=client,
            startup_timeout_seconds=0.01,
        )
    assert client.run_calls == 0


def _host_gateway_fixture() -> tuple[HostGatewayBoundary, HostGatewayEvidence]:
    client = _FakeClient(_FakeContainer(b""))
    policy_path = Path(__file__).parents[2] / "leaderboard/config/network-policy.json"
    boundary = HostGatewayBoundary.from_network(
        client.attrs,
        network_id=NETWORK_ID,
        network_name="cybergym-internal",
        policy=NetworkPolicy.load(policy_path),
    )
    evidence = _FakeSentinel().attest(boundary, container_id="container-1", challenge="fresh")
    return boundary, evidence


@pytest.mark.parametrize(
    "mutate",
    [
        lambda e: replace(e, challenge="replayed"),
        lambda e: replace(e, container_id="other-container"),
        lambda e: replace(e, probe_source_container_id="other-container"),
        lambda e: replace(e, observed_at_monotonic=0.0),
        lambda e: replace(e, observed_at_monotonic=time.monotonic() + 60),
        lambda e: replace(
            e,
            firewall=replace(
                e.firewall, boundary=replace(e.firewall.boundary, gateway="172.18.0.99")
            ),
        ),
        lambda e: replace(e, firewall=replace(e.firewall, ruleset_sha256="0" * 64)),
        lambda e: replace(e, firewall=replace(e.firewall, bridge_scoped=False)),
        lambda e: replace(e, firewall=replace(e.firewall, default_deny_host=False)),
        lambda e: replace(e, firewall=replace(e.firewall, enforced_until_container_stop=False)),
        lambda e: replace(e, firewall=replace(e.firewall, allowed_tcp_ports=(80, 5432))),
        lambda e: replace(
            e, firewall=replace(e.firewall, allowed_routes=e.firewall.allowed_routes[:-1])
        ),
        lambda e: replace(e, passed_routes=e.passed_routes[:-1]),
        lambda e: replace(e, denied_gateway_routes=e.denied_gateway_routes[:-1]),
        lambda e: replace(
            e,
            denied_gateway_routes=(
                replace(e.denied_gateway_routes[0], response_status=200),
                *e.denied_gateway_routes[1:],
            ),
        ),
        lambda e: replace(
            e,
            denied_gateway_routes=(
                replace(e.denied_gateway_routes[0], host_header="model-gateway"),
                *e.denied_gateway_routes[1:],
            ),
        ),
        lambda e: replace(
            e,
            denied_gateway_routes=(
                replace(e.denied_gateway_routes[0], gateway_listener_active=False),
                *e.denied_gateway_routes[1:],
            ),
        ),
        lambda e: replace(e, canary_port=80),
        lambda e: replace(e, canary_host_listener_address="127.0.0.1"),
        lambda e: replace(e, canary_host_listener_active=False),
        lambda e: replace(e, canary_from_container_blocked=False),
    ],
    ids=[
        "replayed-challenge",
        "wrong-container",
        "wrong-probe-source",
        "stale-time",
        "future-time",
        "wrong-gateway",
        "no-ruleset",
        "unscoped-rules",
        "no-default-deny",
        "no-lifetime-enforcement",
        "extra-host-port",
        "missing-firewall-route",
        "missing-active-route-probe",
        "missing-negative-probe",
        "gateway-route-accepted",
        "wrong-negative-probe-request",
        "no-gateway-listener",
        "canary-allowed-port",
        "wrong-canary-target",
        "no-live-listener",
        "canary-reachable",
    ],
)
def test_host_gateway_evidence_rejects_boundary_drift(
    mutate: Callable[[HostGatewayEvidence], HostGatewayEvidence],
) -> None:
    boundary, evidence = _host_gateway_fixture()
    now = time.monotonic()
    with pytest.raises(RuntimeError, match="host gateway boundary attestation failed"):
        require_host_gateway_evidence(
            mutate(evidence),
            boundary=boundary,
            container_id="container-1",
            challenge="fresh",
            probe_started_at_monotonic=now - 1,
            now_monotonic=now,
        )


def test_host_gateway_evidence_rejects_probe_older_than_launch_window() -> None:
    boundary, evidence = _host_gateway_fixture()
    now = time.monotonic()
    with pytest.raises(RuntimeError, match="host gateway boundary attestation failed"):
        require_host_gateway_evidence(
            evidence,
            boundary=boundary,
            container_id="container-1",
            challenge="fresh",
            probe_started_at_monotonic=now - 31,
            now_monotonic=now,
        )


@pytest.mark.parametrize("gateway", ["8.8.8.8", "127.0.0.1", "172.19.0.1"])
def test_rejects_unbound_gateway_before_container_run(tmp_path: Path, gateway: str) -> None:
    workspace = tmp_path / "workspace"
    (workspace / "output").mkdir(parents=True)
    client = _FakeClient(_FakeContainer(b""))
    client.attrs["IPAM"]["Config"][0]["Gateway"] = gateway
    with pytest.raises(RuntimeError, match="host gateway network identity"):
        start_task_container(
            workspace,
            tmp_path / "evidence",
            "cybergym-internal",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockFixtureKey fixture",
            expected_network_id=NETWORK_ID,
            docker_client=client,
            host_gateway_sentinel=_FakeSentinel(),
        )
    assert client.run_calls == 0


@pytest.mark.parametrize(
    "mutate",
    [
        lambda e: replace(e, challenge="old-challenge"),
        lambda e: replace(e, observed_at_monotonic=0.0),
        lambda e: replace(e, firewall=replace(e.firewall, allowed_tcp_ports=(80, 5432))),
        lambda e: replace(e, canary_host_listener_active=False),
        lambda e: replace(e, canary_from_container_blocked=False),
    ],
)
def test_failed_gateway_probe_removes_container_before_relay(
    tmp_path: Path, mutate: Callable[[HostGatewayEvidence], HostGatewayEvidence]
) -> None:
    workspace = tmp_path / "workspace"
    (workspace / "output").mkdir(parents=True)
    container = _FakeContainer(b"")
    client = _FakeClient(container)
    relay_calls: list[int] = []

    def relay(_ip: str, _target: int, local: int) -> _FakeRelay:
        relay_calls.append(local)
        return _FakeRelay(local)

    with pytest.raises(RuntimeError, match="host gateway boundary could not be verified"):
        start_task_container(
            workspace,
            tmp_path / "evidence",
            "cybergym-internal",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockFixtureKey fixture",
            expected_network_id=NETWORK_ID,
            docker_client=client,
            host_gateway_sentinel=_FakeSentinel(mutate),
            ssh_relay_factory=relay,
        )
    assert client.run_calls == 1
    assert container.removed
    assert not relay_calls
    assert not (tmp_path / "evidence" / "host-gateway-boundary.json").exists()


def test_network_gateway_drift_during_probe_removes_container(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    (workspace / "output").mkdir(parents=True)
    container = _FakeContainer(b"")
    client = _FakeClient(container)

    def drift(evidence: HostGatewayEvidence) -> HostGatewayEvidence:
        client.attrs["IPAM"]["Config"][0]["Gateway"] = "172.18.0.254"
        return evidence

    with pytest.raises(RuntimeError, match="host gateway boundary could not be verified"):
        start_task_container(
            workspace,
            tmp_path / "evidence",
            "cybergym-internal",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockFixtureKey fixture",
            expected_network_id=NETWORK_ID,
            docker_client=client,
            host_gateway_sentinel=_FakeSentinel(drift),
        )
    assert client.run_calls == 1
    assert container.removed


def test_start_records_only_verified_public_host_identity(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    (workspace / "output").mkdir(parents=True)
    evidence = tmp_path / "evidence"
    raw_blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + bytes(range(32))
    host_blob = base64.b64encode(raw_blob).decode("ascii")
    host_key = f"ssh-ed25519 {host_blob}"
    fingerprint = "SHA256:" + base64.b64encode(
        hashlib.sha256(base64.b64decode(host_blob)).digest()
    ).decode("ascii").rstrip("=")
    token = "synthetic-private-task-token"
    container = _FakeContainer(
        f"noise containing {token}\n"
        f"CYBERGYM_SSH_HOST_KEY_PUBLIC={host_key}\n"
        f"CYBERGYM_SSH_HOST_KEY_FINGERPRINT={fingerprint}\n".encode()
    )
    relays: list[_FakeRelay] = []

    def relay_factory(target_ip: str, target_port: int, local_port: int) -> _FakeRelay:
        assert target_ip == "172.18.0.2"
        assert target_port == 2222
        relay = _FakeRelay(local_port)
        relays.append(relay)
        return relay

    result = start_task_container(
        workspace=workspace,
        evidence_dir=evidence,
        network_name="cybergym-internal",
        expected_network_id=NETWORK_ID,
        ssh_public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockFixtureKey fixture",
        image="agent:test",
        ssh_port=22222,
        container_name="cybergym-task-test",
        host_gateway_sentinel=_FakeSentinel(),
        docker_client=_FakeClient(container),
        ssh_relay_factory=relay_factory,
    )

    assert result.container_id == "synthetic-container-id"
    assert result.host_ssh_port == 22222
    assert result.workspace_path == "/workspace"
    assert result.container_ip == "172.18.0.2"
    public_evidence = json.loads((evidence / "ssh-host-key.json").read_text())
    assert public_evidence == {
        "schema_version": 1,
        "container_id": "synthetic-container-id",
        "host_ssh_port": 22222,
        "container_ip": "172.18.0.2",
        "network_id": NETWORK_ID,
        "public_key": host_key,
        "fingerprint": fingerprint,
    }
    assert (evidence / "known_hosts").read_text() == f"[127.0.0.1]:22222 {host_key}\n"
    boundary_evidence = json.loads((evidence / "host-gateway-boundary.json").read_text())
    assert boundary_evidence["evidence"]["firewall"]["boundary"]["network_id"] == NETWORK_ID
    assert boundary_evidence["evidence"]["firewall"]["allowed_tcp_ports"] == [80]
    assert len(boundary_evidence["evidence"]["passed_routes"]) == 5
    assert token not in (evidence / "ssh-host-key.json").read_text()
    assert token not in (evidence / "known_hosts").read_text()
    assert token not in (evidence / "host-gateway-boundary.json").read_text()
    result.close_relay()
    assert relays[0].closed


def test_start_fails_closed_on_unverified_host_key_and_removes_container(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    (workspace / "output").mkdir(parents=True)
    evidence = tmp_path / "evidence"
    token = "synthetic-private-task-token"
    container = _FakeContainer(
        f"CYBERGYM_SSH_HOST_KEY_PUBLIC=ssh-ed25519 YQ==\n"
        f"CYBERGYM_SSH_HOST_KEY_FINGERPRINT=SHA256:wrong\n"
        f"{token}\n".encode()
    )

    with pytest.raises(RuntimeError, match="host key") as raised:
        start_task_container(
            workspace=workspace,
            evidence_dir=evidence,
            network_name="cybergym-internal",
            expected_network_id=NETWORK_ID,
            ssh_public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockFixtureKey fixture",
            image="agent:test",
            ssh_port=22222,
            host_gateway_sentinel=_FakeSentinel(),
            docker_client=_FakeClient(container),
        )
    assert container.removed
    assert token not in str(raised.value)
    assert not (evidence / "ssh-host-key.json").exists()


def test_rejects_host_key_with_wrong_wire_format_even_when_fingerprint_matches(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    (workspace / "output").mkdir(parents=True)
    invalid_blob = b"not-an-ed25519-wire-key"
    encoded = base64.b64encode(invalid_blob).decode("ascii")
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(invalid_blob).digest()).decode(
        "ascii"
    ).rstrip("=")
    container = _FakeContainer(
        f"CYBERGYM_SSH_HOST_KEY_PUBLIC=ssh-ed25519 {encoded}\n"
        f"CYBERGYM_SSH_HOST_KEY_FINGERPRINT={fingerprint}\n".encode()
    )
    with pytest.raises(RuntimeError, match="host key"):
        start_task_container(
            workspace=workspace,
            evidence_dir=tmp_path / "evidence",
            network_name="cybergym-internal",
            expected_network_id=NETWORK_ID,
            ssh_public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockFixtureKey fixture",
            image="agent:test",
            ssh_port=22222,
            host_gateway_sentinel=_FakeSentinel(),
            docker_client=_FakeClient(container),
        )
    assert container.removed


def test_evidence_directory_cannot_be_inside_agent_workspace(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    (workspace / "output").mkdir(parents=True)
    with pytest.raises(ValueError, match="evidence_dir"):
        start_task_container(
            workspace=workspace,
            evidence_dir=workspace / "evidence",
            network_name="cybergym-internal",
            expected_network_id=NETWORK_ID,
            ssh_public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockFixtureKey fixture",
            image="agent:test",
            ssh_port=22222,
            host_gateway_sentinel=_FakeSentinel(),
            docker_client=_FakeClient(_FakeContainer(b"")),
        )


def test_cleanup_failure_is_reported_without_leaking_runtime_error(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    (workspace / "output").mkdir(parents=True)
    container = _FakeContainer(b"CYBERGYM_SSH_HOST_KEY_PUBLIC=invalid\n", fail_remove=True)
    with pytest.raises(RuntimeError, match="cleanup failed") as raised:
        start_task_container(
            workspace=workspace,
            evidence_dir=tmp_path / "evidence",
            network_name="cybergym-internal",
            expected_network_id=NETWORK_ID,
            ssh_public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockFixtureKey fixture",
            image="agent:test",
            ssh_port=22222,
            host_gateway_sentinel=_FakeSentinel(),
            docker_client=_FakeClient(container),
            startup_timeout_seconds=0.01,
        )
    assert "task secret" not in str(raised.value)
    assert container.id in str(raised.value)


def test_refuses_network_that_allows_direct_external_egress(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    (workspace / "output").mkdir(parents=True)
    container = _FakeContainer(b"")
    with pytest.raises(RuntimeError, match="network topology"):
        start_task_container(
            workspace=workspace,
            evidence_dir=tmp_path / "evidence",
            network_name="default-bridge",
            expected_network_id=NETWORK_ID,
            ssh_public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockFixtureKey fixture",
            image="agent:test",
            ssh_port=22222,
            host_gateway_sentinel=_FakeSentinel(),
            docker_client=_FakeClient(container, internal_network=False),
        )
    assert not container.removed  # Container never started.


def test_refuses_unapproved_peer_before_container_start(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    (workspace / "output").mkdir(parents=True)
    container = _FakeContainer(b"")
    with pytest.raises(RuntimeError, match="network topology"):
        start_task_container(
            workspace=workspace,
            evidence_dir=tmp_path / "evidence",
            network_name="cybergym-internal",
            expected_network_id=NETWORK_ID,
            ssh_public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockFixtureKey fixture",
            host_gateway_sentinel=_FakeSentinel(),
            docker_client=_FakeClient(container, initial_peers=frozenset({"unapproved-peer"})),
        )
    assert not container.removed


def test_removes_container_if_peer_appears_during_start(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    (workspace / "output").mkdir(parents=True)
    container = _FakeContainer(b"")
    with pytest.raises(RuntimeError, match="unable to start task container"):
        start_task_container(
            workspace=workspace,
            evidence_dir=tmp_path / "evidence",
            network_name="cybergym-internal",
            expected_network_id=NETWORK_ID,
            ssh_public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockFixtureKey fixture",
            host_gateway_sentinel=_FakeSentinel(),
            docker_client=_FakeClient(container, extra_peer_after_start=True),
        )
    assert container.removed


@pytest.mark.parametrize("timeout", [float("nan"), math.inf, True])
def test_rejects_nonfinite_or_boolean_startup_timeout(tmp_path: Path, timeout: object) -> None:
    workspace = tmp_path / "workspace"
    (workspace / "output").mkdir(parents=True)
    raw_blob = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + bytes(range(32))
    encoded = base64.b64encode(raw_blob).decode("ascii")
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(raw_blob).digest()).decode(
        "ascii"
    ).rstrip("=")
    container = _FakeContainer(
        f"CYBERGYM_SSH_HOST_KEY_PUBLIC=ssh-ed25519 {encoded}\n"
        f"CYBERGYM_SSH_HOST_KEY_FINGERPRINT={fingerprint}\n".encode()
    )
    with pytest.raises(ValueError, match="startup_timeout"):
        start_task_container(
            workspace=workspace,
            evidence_dir=tmp_path / "evidence",
            network_name="cybergym-internal",
            expected_network_id=NETWORK_ID,
            ssh_public_key="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockFixtureKey fixture",
            image="agent:test",
            ssh_port=22222,
            host_gateway_sentinel=_FakeSentinel(),
            docker_client=_FakeClient(container),
            startup_timeout_seconds=timeout,
        )
