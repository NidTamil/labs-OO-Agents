# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Read-only current container host-key handoff over the allowed SunChaser SSH route."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import shlex
import subprocess
import sys
from pathlib import Path

from xeus_cybergym.canonical import canonical_json

from .native_ui_client import SshUiTransport
from .practice_campaign import PRACTICE_TASK_IDS

_RUN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")


def read_practice_host_material(
    *, evidence_root: Path, run_id: str, task_id: str, port: int
) -> dict:
    root = Path(evidence_root)
    if (
        not root.is_absolute()
        or root.is_symlink()
        or not root.is_dir()
        or type(run_id) is not str
        or _RUN.fullmatch(run_id) is None
        or task_id not in PRACTICE_TASK_IDS
        or type(port) is not int
        or not 1024 <= port <= 65535
    ):
        raise ValueError("bounded current practice connection required")
    evidence = root / (run_id + "-" + task_id.replace(":", "-"))
    connection_path = evidence / "connection.json"
    host_key_path = evidence / "known_hosts"
    if (
        evidence.is_symlink()
        or not evidence.is_dir()
        or connection_path.is_symlink()
        or not connection_path.is_file()
        or not 0 < connection_path.stat().st_size <= 8192
        or host_key_path.is_symlink()
        or not host_key_path.is_file()
        or not 0 < host_key_path.stat().st_size <= 4096
    ):
        raise RuntimeError("current practice connection or host key is unavailable")
    raw = connection_path.read_bytes()
    try:
        connection = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise RuntimeError("current practice connection is malformed") from None
    if (
        type(connection) is not dict
        or canonical_json(connection) != raw
        or connection.get("scope") != "native_practice_level1"
        or connection.get("run_id") != run_id
        or connection.get("task_id") != task_id
        or connection.get("ssh_host_port") != port
        or connection.get("known_hosts") != str(host_key_path)
        or connection.get("status") != "awaiting_signed_practice_start_intent"
    ):
        raise RuntimeError("current practice connection differs from prepared task")
    return {
        "schema_version": 1,
        "run_id": run_id,
        "task_id": task_id,
        "port": port,
        "known_hosts_base64": base64.b64encode(host_key_path.read_bytes()).decode("ascii"),
    }


class PinnedPracticeHostMaterial:
    """Fetch public key bytes through only the frozen SunChaser Tailscale SSH alias."""

    def __init__(
        self,
        *,
        ssh_exe: Path,
        ssh_config: Path,
        ssh_config_sha256: str,
        tunnel_known_hosts: Path,
        tunnel_known_hosts_sha256: str,
        ssh_alias: str,
        remote_argv: tuple[str, ...],
        run_id: str,
        run_command=subprocess.run,
    ) -> None:
        paths = (Path(ssh_exe), Path(ssh_config), Path(tunnel_known_hosts))
        if (
            any(not path.is_absolute() or path.is_symlink() or not path.is_file() for path in paths)
            or any(
                type(value) is not str or re.fullmatch(r"[a-f0-9]{64}", value) is None
                for value in (ssh_config_sha256, tunnel_known_hosts_sha256)
            )
            or hashlib.sha256(paths[1].read_bytes()).hexdigest() != ssh_config_sha256
            or hashlib.sha256(paths[2].read_bytes()).hexdigest() != tunnel_known_hosts_sha256
            or type(ssh_alias) is not str
            or re.fullmatch(r"cybergym-tunnel-[a-f0-9]{24}", ssh_alias) is None
            or type(remote_argv) is not tuple
            or not remote_argv
            or any(type(part) is not str or not part or "\x00" in part for part in remote_argv)
            or type(run_id) is not str
            or _RUN.fullmatch(run_id) is None
            or not callable(run_command)
        ):
            raise ValueError("frozen SunChaser practice host-material route required")
        config_text = paths[1].read_text(encoding="ascii")
        if (
            f"Host {ssh_alias}\n" not in config_text
            or "HostName sunchaser-20260905.cinnamon-gamut.ts.net\n" not in config_text
            or "HostKeyAlias sunchaser-20260905.cinnamon-gamut.ts.net.\n" not in config_text
            or "ProxyCommand " not in config_text
            or 'tailscale.exe" nc %h %p' not in config_text
            or "StrictHostKeyChecking yes\n" not in config_text
            or "BatchMode yes\n" not in config_text
        ):
            raise ValueError("practice SSH config is not the pinned SunChaser route")
        self.ssh_exe, self.ssh_config, self.known_hosts = paths
        self.ssh_alias, self.remote_argv, self.run_id = ssh_alias, remote_argv, run_id
        self.run_command = run_command

    def __call__(self, task_id: str, port: int) -> bytes:
        if task_id not in PRACTICE_TASK_IDS or type(port) is not int or not 1024 <= port <= 65535:
            raise ValueError("current practice task and SSH port required")
        raw = self.invoke((*self.remote_argv, "--task-id", task_id, "--port", str(port)))
        if not 0 < len(raw) <= 8192:
            raise RuntimeError("bounded practice host material required")
        try:
            value = json.loads(raw)
            if (
                type(value) is not dict
                or canonical_json(value) != raw
                or set(value)
                != {"schema_version", "run_id", "task_id", "port", "known_hosts_base64"}
                or value["schema_version"] != 1
                or value["run_id"] != self.run_id
                or value["task_id"] != task_id
                or value["port"] != port
                or type(value["known_hosts_base64"]) is not str
            ):
                raise ValueError()
            known = base64.b64decode(value["known_hosts_base64"], validate=True)
            if base64.b64encode(known).decode("ascii") != value["known_hosts_base64"]:
                raise ValueError()
        except (ValueError, UnicodeDecodeError, binascii.Error):
            raise RuntimeError("SunChaser practice host material differs") from None
        return known

    def invoke(self, remote_argv: tuple[str, ...], *, input_bytes: bytes | None = None) -> bytes:
        """One bounded call through the already verified SunChaser-only route."""
        if (
            type(remote_argv) is not tuple
            or not remote_argv
            or any(type(part) is not str or not part or "\x00" in part for part in remote_argv)
            or (
                input_bytes is not None
                and (type(input_bytes) is not bytes or len(input_bytes) > 16384)
            )
        ):
            raise ValueError("bounded SunChaser command required")
        command = shlex.join(remote_argv)
        result = self.run_command(
            [
                str(self.ssh_exe),
                "-F",
                str(self.ssh_config),
                "-o",
                "UserKnownHostsFile=" + self.known_hosts.as_posix(),
                "-o",
                "BatchMode=yes",
                self.ssh_alias,
                command,
            ],
            input=input_bytes,
            capture_output=True,
            check=True,
            timeout=30,
        )
        raw = result.stdout.strip()
        if not 0 < len(raw) <= 32768:
            raise RuntimeError("bounded SunChaser response required")
        return raw


class PinnedPracticeUiTransport(SshUiTransport):
    """Mailbox poll/ack through Windows ssh.exe and the pinned Tailscale ProxyCommand."""

    def __init__(self, *, route: PinnedPracticeHostMaterial, remote_argv: tuple[str, ...]):
        if type(route) is not PinnedPracticeHostMaterial or not remote_argv:
            raise ValueError("pinned SunChaser UI route required")
        self.route = route
        self.remote_argv = remote_argv

    def _call(self, action: str, *, input_bytes: bytes | None = None) -> dict:
        if action not in {"poll", "ack"}:
            raise ValueError("mailbox action differs")
        raw = self.route.invoke((*self.remote_argv, action), input_bytes=input_bytes)
        try:
            value = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            raise RuntimeError("SunChaser mailbox response is malformed") from None
        if type(value) is not dict or canonical_json(value) != raw:
            raise RuntimeError("SunChaser mailbox response is not canonical")
        return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args(argv)
    value = read_practice_host_material(
        evidence_root=args.evidence_root,
        run_id=args.run_id,
        task_id=args.task_id,
        port=args.port,
    )
    sys.stdout.buffer.write(canonical_json(value) + b"\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
