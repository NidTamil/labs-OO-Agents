"""Controller-owned Docker boundary for one CyberGym task attempt.

The agent sees only its read-only task bundle, writable output, and fresh
tmpfs mounts. Docker configuration and host-key evidence stay in the trusted
controller, outside the SSH session.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import math
import os
import re
import socket
import struct
import time
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol

from .host_boundary import (
    HostGatewayBoundary,
    HostGatewaySentinel,
    require_host_gateway_evidence,
)
from .network import NetworkPolicy
from .ssh_relay import LoopbackRelay


class _RelayHandle(Protocol):
    port: int

    def close(self) -> None: ...


@dataclass(frozen=True, slots=True)
class TaskContainer:
    container_id: str
    container_name: str
    host_ssh_port: int
    container_ip: str
    network_id: str
    ssh_relay: _RelayHandle = field(repr=False, compare=False)
    workspace_path: str = "/workspace"

    def close_relay(self) -> None:
        self.ssh_relay.close()


_HOST_PUBLIC_PREFIX = "CYBERGYM_SSH_HOST_KEY_PUBLIC="
_HOST_FINGERPRINT_PREFIX = "CYBERGYM_SSH_HOST_KEY_FINGERPRINT="
_BOUNDARY_LABEL = "org.xeus.cybergym.boundary"
_BOUNDARY_VALUE = "task-v1"


def _one_line(value: str, name: str) -> str:
    if not isinstance(value, str) or not value or any(ord(char) < 32 for char in value):
        raise ValueError(f"{name} must be a nonempty single line")
    return value


def build_container_kwargs(
    *,
    image: str,
    workspace: Path,
    output: Path,
    network: str,
    ssh_port: int,
    task_token: str | None = None,
    ssh_public_key: str | None = None,
    container_name: str = "cybergym-task",
) -> dict[str, Any]:
    """Construct the reviewed Docker SDK run configuration without side effects."""
    if type(ssh_port) is not int or not 1 <= ssh_port <= 65535:
        raise ValueError("ssh_port must be an integer between 1 and 65535")
    for name, value in (
        ("image", image),
        ("network", network),
        ("container_name", container_name),
    ):
        _one_line(value, name)
    if task_token is not None:
        _one_line(task_token, "task_token")
    if ssh_public_key is not None:
        _one_line(ssh_public_key, "ssh_public_key")
        if (
            re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/]+={0,2}(?: [^\s\x00-\x1f]+)?", ssh_public_key)
            is None
        ):
            raise ValueError("ssh_public_key must be one SSH Ed25519 public key")

    environment: dict[str, str] = {}
    if task_token is not None:
        environment["CYBERGYM_TASK_TOKEN"] = task_token
    if ssh_public_key is not None:
        environment["CYBERGYM_SSH_PUBLIC_KEY"] = ssh_public_key

    return {
        "image": image,
        "name": container_name,
        "user": "root",
        "working_dir": "/workspace",
        "network": network,
        "read_only": True,
        "cap_drop": ["ALL"],
        "cap_add": ["CHOWN", "SETUID", "SETGID", "DAC_OVERRIDE", "SYS_CHROOT"],
        "security_opt": ["no-new-privileges:true"],
        "pids_limit": 2048,
        "mem_limit": "16g",
        "tmpfs": {
            "/tmp": "rw,noexec,nosuid,size=4g",
            "/run": "rw,nosuid,size=64m",
            "/home/agent": "rw,nosuid,size=8g",
            "/workspace/src": "rw,nosuid,nodev,size=12g",
        },
        "volumes": {
            str(workspace.resolve()): {"bind": "/workspace", "mode": "ro"},
            str(output.resolve()): {"bind": "/workspace/output", "mode": "rw"},
        },
        "environment": environment,
        "detach": True,
    }


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _container_ip(container: Any, network_name: str, network_id: str) -> str:
    """Bind the relay only to Docker's sole internal-network endpoint."""

    try:
        networks = container.attrs["NetworkSettings"]["Networks"]
        if set(networks) != {network_name}:
            raise ValueError("unexpected task container network")
        if networks[network_name]["NetworkID"] != network_id:
            raise ValueError("task container network identity changed")
        address = ipaddress.IPv4Address(networks[network_name]["IPAddress"])
        if not address.is_private or address.is_loopback or address.is_link_local:
            raise ValueError("task container address is outside private bridge")
    except (AttributeError, KeyError, TypeError, ValueError):
        raise RuntimeError("task container internal address could not be verified") from None
    return str(address)


def _verify_task_network(
    network: Any,
    *,
    network_name: str,
    network_id: str,
    expected_peer_ids: frozenset[str],
) -> None:
    """Verify an attested, dedicated bridge and its exact current peers."""

    try:
        network.reload()
        attrs = network.attrs
        if (
            attrs["Id"] != network_id
            or attrs["Name"] != network_name
            or attrs["Internal"] is not True
            or attrs["Driver"] != "bridge"
            or attrs["Labels"].get(_BOUNDARY_LABEL) != _BOUNDARY_VALUE
            or set(attrs.get("Containers") or {}) != expected_peer_ids
        ):
            raise ValueError("task network attestation mismatch")
    except (AttributeError, KeyError, TypeError, ValueError):
        raise RuntimeError("task network topology could not be verified") from None


def _host_identity(logs: bytes) -> tuple[str, str] | None:
    """Accept only one public key and its independently checked fingerprint."""
    if len(logs) > 64 * 1024:
        raise RuntimeError("task container host key evidence is oversized")
    public_lines: list[str] = []
    fingerprint_lines: list[str] = []
    for line in logs.decode("utf-8", errors="replace").splitlines():
        if line.startswith(_HOST_PUBLIC_PREFIX):
            public_lines.append(line.removeprefix(_HOST_PUBLIC_PREFIX))
        elif line.startswith(_HOST_FINGERPRINT_PREFIX):
            fingerprint_lines.append(line.removeprefix(_HOST_FINGERPRINT_PREFIX))
    if not public_lines or not fingerprint_lines:
        return None
    if len(public_lines) != 1 or len(fingerprint_lines) != 1:
        raise RuntimeError("task container host key evidence is ambiguous")
    public_key = public_lines[0]
    parts = public_key.split(" ")
    if len(parts) != 2 or parts[0] != "ssh-ed25519":
        raise RuntimeError("task container host key evidence is malformed")
    try:
        key_blob = base64.b64decode(parts[1], validate=True)
    except (binascii.Error, ValueError):
        raise RuntimeError("task container host key evidence is malformed") from None
    if (
        len(key_blob) != 51
        or key_blob[:4] != struct.pack(">I", 11)
        or key_blob[4:15] != b"ssh-ed25519"
        or key_blob[15:19] != struct.pack(">I", 32)
    ):
        raise RuntimeError("task container host key evidence is malformed")
    calculated = "SHA256:" + base64.b64encode(hashlib.sha256(key_blob).digest()).decode(
        "ascii"
    ).rstrip("=")
    if fingerprint_lines[0] != calculated:
        raise RuntimeError("task container host key fingerprint does not match")
    return public_key, calculated


def _write_private_evidence(path: Path, content: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def start_task_container(
    workspace: Path,
    evidence_dir: Path,
    network_name: str,
    ssh_public_key: str,
    *,
    expected_network_id: str,
    approved_peer_ids: frozenset[str] = frozenset(),
    task_token: str | None = None,
    image: str = "sunchaser/cybergym-agent:local",
    ssh_port: int | None = None,
    container_name: str | None = None,
    docker_client: Any | None = None,
    host_gateway_sentinel: HostGatewaySentinel | None = None,
    ssh_relay_factory: Callable[[str, int, int], _RelayHandle] | None = None,
    startup_timeout_seconds: float = 900.0,
) -> TaskContainer:
    """Start one disposable task image and save verified public SSH identity.

    No Docker exception or raw container log is returned: either may include
    the task-scoped token. Evidence is written outside the agent-visible root.
    """
    workspace = Path(workspace)
    evidence_dir = Path(evidence_dir)
    output = workspace / "output"
    if not workspace.is_dir() or workspace.is_symlink():
        raise ValueError("workspace must be a real task directory")
    if not output.is_dir() or output.is_symlink():
        raise ValueError("workspace/output must be a real directory")
    resolved_workspace = workspace.resolve()
    resolved_evidence = evidence_dir.resolve()
    if resolved_evidence == resolved_workspace or resolved_workspace in resolved_evidence.parents:
        raise ValueError("evidence_dir must be outside the agent workspace")
    if ssh_port is None:
        ssh_port = _free_loopback_port()
    if container_name is None:
        container_name = f"cybergym-task-{uuid.uuid4().hex[:16]}"
    kwargs = build_container_kwargs(
        image=image,
        workspace=workspace,
        output=output,
        network=network_name,
        ssh_port=ssh_port,
        task_token=task_token,
        ssh_public_key=ssh_public_key,
        container_name=container_name,
    )
    if (
        type(startup_timeout_seconds) not in (int, float)
        or not math.isfinite(startup_timeout_seconds)
        or startup_timeout_seconds <= 0
    ):
        raise ValueError("startup_timeout_seconds must be finite and positive")
    _one_line(expected_network_id, "expected_network_id")
    if type(approved_peer_ids) is not frozenset or any(
        type(peer) is not str or not peer for peer in approved_peer_ids
    ):
        raise ValueError("approved_peer_ids must be an exact frozen set")
    evidence_dir.mkdir(parents=True, exist_ok=True)
    if docker_client is None:
        try:
            import docker

            docker_client = docker.from_env()
        except Exception:
            raise RuntimeError("unable to connect to the task container runtime") from None
    try:
        task_network = docker_client.networks.get(network_name)
        _verify_task_network(
            task_network,
            network_name=network_name,
            network_id=expected_network_id,
            expected_peer_ids=approved_peer_ids,
        )
    except RuntimeError:
        raise
    except Exception:
        raise RuntimeError("unable to verify the task container internal network") from None
    policy_path = Path(__file__).resolve().parents[2] / "leaderboard/config/network-policy.json"
    try:
        policy = NetworkPolicy.load(policy_path)
        boundary = HostGatewayBoundary.from_network(
            task_network.attrs,
            network_id=expected_network_id,
            network_name=network_name,
            policy=policy,
        )
    except Exception:
        raise RuntimeError("host gateway network identity could not be verified") from None
    if host_gateway_sentinel is None:
        raise RuntimeError("host gateway boundary attestation required")

    container = None
    relay: _RelayHandle | None = None
    try:
        container = docker_client.containers.run(**kwargs)
        _verify_task_network(
            task_network,
            network_name=network_name,
            network_id=expected_network_id,
            expected_peer_ids=approved_peer_ids | {container.id},
        )
        challenge = uuid.uuid4().hex
        probe_started = time.monotonic()
        try:
            gateway_evidence = host_gateway_sentinel.attest(
                boundary, container_id=container.id, challenge=challenge
            )
            require_host_gateway_evidence(
                gateway_evidence,
                boundary=boundary,
                container_id=container.id,
                challenge=challenge,
                probe_started_at_monotonic=probe_started,
                now_monotonic=time.monotonic(),
            )
        except Exception:
            raise RuntimeError("host gateway boundary attestation failed") from None
        _verify_task_network(
            task_network,
            network_name=network_name,
            network_id=expected_network_id,
            expected_peer_ids=approved_peer_ids | {container.id},
        )
        if (
            HostGatewayBoundary.from_network(
                task_network.attrs,
                network_id=expected_network_id,
                network_name=network_name,
                policy=policy,
            )
            != boundary
        ):
            raise RuntimeError("host gateway boundary attestation failed")
        deadline = time.monotonic() + startup_timeout_seconds
        while True:
            container.reload()
            if container.status != "running":
                raise RuntimeError("task container stopped before SSH host key was ready")
            identity = _host_identity(container.logs(tail=32))
            if identity is not None:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("task container host key was not published")
            time.sleep(0.1)

        public_key, fingerprint = identity
        container_ip = _container_ip(container, network_name, expected_network_id)
        factory = ssh_relay_factory or (
            lambda ip, port, local_port: LoopbackRelay.start(ip, port, local_port=local_port)
        )
        relay = factory(container_ip, 2222, ssh_port)
        if relay.port != ssh_port:
            raise RuntimeError("task SSH relay bound a different host port")
        identity_path = evidence_dir / "ssh-host-key.json"
        known_hosts_path = evidence_dir / "known_hosts"
        _write_private_evidence(
            identity_path,
            json.dumps(
                {
                    "schema_version": 1,
                    "container_id": container.id,
                    "host_ssh_port": ssh_port,
                    "container_ip": container_ip,
                    "network_id": expected_network_id,
                    "public_key": public_key,
                    "fingerprint": fingerprint,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
        )
        try:
            _write_private_evidence(known_hosts_path, f"[127.0.0.1]:{ssh_port} {public_key}\n")
        except BaseException:
            identity_path.unlink(missing_ok=True)
            raise
        try:
            _write_private_evidence(
                evidence_dir / "host-gateway-boundary.json",
                json.dumps(
                    {"schema_version": 1, "evidence": asdict(gateway_evidence)},
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                )
                + "\n",
            )
        except BaseException:
            identity_path.unlink(missing_ok=True)
            known_hosts_path.unlink(missing_ok=True)
            raise
        return TaskContainer(
            container.id, container.name, ssh_port, container_ip, expected_network_id, relay
        )
    except Exception as error:
        if relay is not None:
            relay.close()
        if container is not None:
            try:
                container.remove(force=True)
            except Exception:
                raise RuntimeError(
                    f"task container startup failed and cleanup failed for container {container.id}"
                ) from None
        if "host key" in str(error):
            raise RuntimeError("task container host key could not be verified") from None
        if "host gateway boundary" in str(error):
            raise RuntimeError("host gateway boundary could not be verified") from None
        raise RuntimeError("unable to start task container") from None
