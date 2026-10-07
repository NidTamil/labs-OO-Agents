# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Outbound Windows client for signed, one-shot CyberGym native UI commands."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import shlex
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from xeus_cybergym.canonical import canonical_json
from xeus_cybergym.ledger import Ed25519Verifier, SignedEnvelope

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9:_.-]{0,127}\Z")
_COMMAND_ID = re.compile(r"[a-f0-9]{32}\Z")
_ALIAS = re.compile(r"[a-z][a-z0-9-]{1,63}\Z")
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")


class UiTransport(Protocol):
    def poll(self) -> bytes | None: ...

    def ack(self, raw: bytes) -> dict: ...


def _write_new(path: Path, raw: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    if os.name == "posix":
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


class NativeUiClient:
    """Verify, reserve and execute a host command once, then replay its exact ack.

    A crash after reservation but before an ack is ambiguous. It never repeats
    an action, especially Claude Code's Send. An observed attempted-Send audit
    may settle that ambiguity without clicking again.
    """

    def __init__(
        self,
        *,
        run_id: str,
        verifier,
        transport: UiTransport,
        ui,
        custody_dir: Path,
        profiles_dir: Path,
        submit: Callable[..., None],
    ):
        custody = Path(custody_dir)
        profiles = Path(profiles_dir)
        if (
            type(run_id) is not str
            or _ID.fullmatch(run_id) is None
            or not callable(getattr(verifier, "verify", None))
            or not callable(getattr(transport, "poll", None))
            or not callable(getattr(transport, "ack", None))
            or not all(callable(getattr(ui, name, None)) for name in ("open", "close", "reap"))
            or not callable(submit)
            or not custody.is_absolute()
            or custody.is_symlink()
            or not profiles.is_absolute()
            or profiles.is_symlink()
        ):
            raise ValueError("pinned outbound Windows UI client inputs required")
        custody.mkdir(parents=True, exist_ok=True)
        self.run_id = run_id
        self.verifier = verifier
        self.transport = transport
        self.ui = ui
        self.custody = custody
        self.profiles = profiles
        self.submit = submit

    def _command(self, raw: bytes) -> dict:
        if type(raw) is not bytes or not 0 < len(raw) <= 16384:
            raise ValueError("bounded signed UI command required")
        payload = self.verifier.verify(SignedEnvelope.model_validate_json(raw))
        if len(payload) > 8192:
            raise ValueError("bounded UI command payload required")
        value = json.loads(payload)
        if (
            type(value) is not dict
            or canonical_json(value) != payload
            or value.get("schema_version") != 1
            or value.get("artifact_kind") != "native_ui_command"
            or value.get("run_id") != self.run_id
            or type(value.get("command_id")) is not str
            or _COMMAND_ID.fullmatch(value["command_id"]) is None
            or type(value.get("action")) is not str
            or value["action"] not in {"open", "submit", "close", "reap"}
            or type(value.get("operation_key")) is not str
            or _ID.fullmatch(value["operation_key"]) is None
        ):
            raise ValueError("signed UI command identity differs")
        action = value["action"]
        if action == "reap":
            if any(
                value.get(key) is not None
                for key in (
                    "task_id",
                    "remote_host",
                    "port",
                    "launch_id",
                    "receipt_sha256",
                    "launch_receipt_base64",
                )
            ):
                raise ValueError("reap command must be run-scoped")
            return value
        task = value.get("task_id")
        alias = value.get("remote_host")
        if (
            type(task) is not str
            or _ID.fullmatch(task) is None
            or type(alias) is not str
            or _ALIAS.fullmatch(alias) is None
        ):
            raise ValueError("signed task and SSH alias required")
        if action == "open":
            port = value.get("port")
            if type(port) is not int or not 1024 <= port <= 65535:
                raise ValueError("signed task SSH port required")
        elif value.get("port") is not None:
            raise ValueError("only open carries an SSH port")
        if action == "submit":
            receipt_hash = value.get("receipt_sha256")
            launch_id = value.get("launch_id")
            encoded = value.get("launch_receipt_base64")
            if (
                type(receipt_hash) is not str
                or _DIGEST.fullmatch(receipt_hash) is None
                or type(launch_id) is not str
                or _ID.fullmatch(launch_id) is None
                or type(encoded) is not str
            ):
                raise ValueError("signed launch receipt required")
            try:
                receipt = base64.b64decode(encoded, validate=True)
            except (binascii.Error, ValueError):
                raise ValueError("canonical launch receipt Base64 required") from None
            if (
                base64.b64encode(receipt).decode("ascii") != encoded
                or hashlib.sha256(receipt).hexdigest() != receipt_hash
                or len(receipt) > 4096
            ):
                raise ValueError("signed launch receipt bytes differ")
            receipt_json = json.loads(receipt)
            if (
                type(receipt_json) is not dict
                or canonical_json(receipt_json) != receipt
                or receipt_json.get("event") != "launch_reserved"
                or receipt_json.get("launch_id") != launch_id
                or receipt_json.get("session_id", "missing") is not None
                or type(receipt_json.get("prompt_sha256")) is not str
                or _DIGEST.fullmatch(receipt_json["prompt_sha256"]) is None
            ):
                raise ValueError("pre-model native launch receipt required")
        elif value.get("launch_id") is not None or value.get("receipt_sha256") is not None:
            raise ValueError("non-Send command carries a launch receipt")
        return value

    def _ack(self, command: dict, *, status: str, audit: bytes | None = None) -> bytes:
        return canonical_json(
            {
                "command_id": command["command_id"],
                "status": status,
                "ui_audit_sha256": hashlib.sha256(audit).hexdigest() if audit is not None else None,
                "ui_audit_base64": base64.b64encode(audit).decode("ascii")
                if audit is not None
                else None,
            }
        )

    def _execute(self, command: dict, audit_dir: Path) -> bytes:
        action = command["action"]
        if action == "open":
            self.ui.open(self.run_id, command["task_id"], command["remote_host"], command["port"])
        elif action == "close":
            self.ui.close(self.run_id, command["task_id"], command["remote_host"])
        elif action == "reap":
            self.ui.reap(self.run_id)
        else:
            command_id = command["command_id"]
            receipt = base64.b64decode(command["launch_receipt_base64"], validate=True)
            receipt_path = self.custody / f"{command_id}.receipt.json"
            _write_new(receipt_path, receipt)
            run_key = hashlib.sha256(self.run_id.encode()).hexdigest()[:24]
            task_key = hashlib.sha256(command["task_id"].encode()).hexdigest()[:24]
            profile = self.profiles / f"cybergym-{run_key}-{task_key}" / "user-data"
            self.submit(
                remote_alias=command["remote_host"],
                profile_directory=profile,
                receipt_path=receipt_path,
                launch_id=command["launch_id"],
                audit_directory=audit_dir,
            )
        return self._settle(command, audit_dir, action_failed=False)

    def _settle(self, command: dict, audit_dir: Path, *, action_failed: bool) -> bytes:
        if command["action"] == "submit":
            attempted = audit_dir / "ui-send-attempted.json"
            reserved = audit_dir / "ui-send-reservation.json"
            if attempted.is_file() and not attempted.is_symlink():
                raw = attempted.read_bytes()
                if not 0 < len(raw) <= 8192:
                    raise RuntimeError("attempted native Send audit exceeds limit")
                return self._ack(command, status="completed", audit=raw)
            return self._ack(
                command,
                status="ambiguous"
                if reserved.exists()
                else "failed"
                if action_failed
                else "ambiguous",
            )
        return self._ack(command, status="ambiguous" if action_failed else "completed")

    def poll_once(self) -> dict | None:
        envelope = self.transport.poll()
        if envelope is None:
            return None
        command = self._command(envelope)
        command_id = command["command_id"]
        reservation = self.custody / f"{command_id}.signed.json"
        ack_path = self.custody / f"{command_id}.ack.json"
        audit_dir = self.custody / f"{command_id}.audit"
        if reservation.exists() or reservation.is_symlink():
            if reservation.is_symlink() or reservation.read_bytes() != envelope:
                raise RuntimeError("native UI reservation changed across replay")
            if ack_path.exists() or ack_path.is_symlink():
                if ack_path.is_symlink():
                    raise RuntimeError("native UI acknowledgement is linked")
                ack_raw = ack_path.read_bytes()
            else:
                ack_raw = self._settle(command, audit_dir, action_failed=True)
                _write_new(ack_path, ack_raw)
        else:
            _write_new(reservation, envelope)
            try:
                ack_raw = self._execute(command, audit_dir)
            except Exception:
                ack_raw = self._settle(command, audit_dir, action_failed=True)
            _write_new(ack_path, ack_raw)
        result = self.transport.ack(ack_raw)
        expected = json.loads(ack_raw)
        if (
            type(result) is not dict
            or result.get("command_id") != command_id
            or result.get("status") != expected["status"]
            or result.get("ui_audit_sha256") != expected["ui_audit_sha256"]
        ):
            raise RuntimeError("controller UI acknowledgement differs from host evidence")
        return result

    def run_forever(self, *, poll_interval_seconds: float = 1.0) -> None:
        if (
            type(poll_interval_seconds) not in {int, float}
            or not 0.1 <= poll_interval_seconds <= 60
        ):
            raise ValueError("bounded UI polling interval required")
        while True:
            if self.poll_once() is None:
                time.sleep(poll_interval_seconds)


class PowerShellNativeSubmit:
    """Invoke the pinned one-shot accessible Claude Code Send script."""

    def __init__(self, script: Path, *, pwsh: str = "pwsh"):
        if not Path(script).is_absolute() or not Path(script).is_file():
            raise ValueError("pinned native Send script required")
        self.script = str(script)
        self.pwsh = pwsh

    def __call__(
        self,
        *,
        remote_alias: str,
        profile_directory: Path,
        receipt_path: Path,
        launch_id: str,
        audit_directory: Path,
    ) -> None:
        subprocess.run(
            [
                self.pwsh,
                "-NoProfile",
                "-File",
                self.script,
                "-RemoteAlias",
                remote_alias,
                "-ProfileDirectory",
                str(profile_directory),
                "-ControllerReceipt",
                str(receipt_path),
                "-LaunchId",
                launch_id,
                "-AuditDirectory",
                str(audit_directory),
            ],
            check=True,
        )


class SshUiTransport:
    """Poll the controller only through an outbound authenticated Tailscale SSH call."""

    def __init__(
        self,
        *,
        tailscale_exe: Path,
        ssh_target: str,
        remote_argv: tuple[str, ...],
        timeout_seconds: int = 30,
    ):
        binary = Path(tailscale_exe)
        if (
            not binary.is_absolute()
            or not binary.is_file()
            or type(ssh_target) is not str
            or re.fullmatch(r"root@[a-z0-9][a-z0-9.-]{0,127}", ssh_target) is None
            or type(remote_argv) is not tuple
            or not remote_argv
            or any(type(part) is not str or not part or "\x00" in part for part in remote_argv)
            or type(timeout_seconds) is not int
            or not 1 <= timeout_seconds <= 120
        ):
            raise ValueError("pinned outbound controller SSH command required")
        self.binary = str(binary)
        self.target = ssh_target
        self.remote_argv = remote_argv
        self.timeout = timeout_seconds

    def _call(self, action: str, *, input_bytes: bytes | None = None) -> dict:
        result = subprocess.run(
            [self.binary, "ssh", self.target, shlex.join((*self.remote_argv, action))],
            input=input_bytes,
            capture_output=True,
            timeout=self.timeout,
            check=True,
        )
        raw = result.stdout.strip()
        if not 0 < len(raw) <= 32768:
            raise RuntimeError("bounded canonical controller SSH response required")
        value = json.loads(raw)
        if type(value) is not dict or canonical_json(value) != raw:
            raise RuntimeError("controller SSH response is not canonical")
        return value

    def poll(self) -> bytes | None:
        value = self._call("poll")
        if set(value) != {"pending", "envelope_base64"} or type(value["pending"]) is not bool:
            raise RuntimeError("controller UI poll response has unexpected shape")
        encoded = value["envelope_base64"]
        if not value["pending"]:
            if encoded is not None:
                raise RuntimeError("empty controller UI poll carried a command")
            return None
        if type(encoded) is not str:
            raise RuntimeError("controller UI poll lacks signed command")
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            raise RuntimeError("controller UI command Base64 is invalid") from None
        if base64.b64encode(raw).decode("ascii") != encoded:
            raise RuntimeError("controller UI command Base64 is not canonical")
        return raw

    def ack(self, raw: bytes) -> dict:
        if type(raw) is not bytes or not 0 < len(raw) <= 16384:
            raise ValueError("bounded canonical UI acknowledgement required")
        return self._call("ack", input_bytes=raw)


_CONFIG_FIELDS = frozenset(
    {
        "run_id",
        "ssh_target",
        "remote_argv",
        "controller_key_id",
        "controller_public_key_pem",
        "controller_public_key_sha256",
        "tailscale_exe",
        "tailscale_exe_sha256",
        "ui_script",
        "ui_script_sha256",
        "send_script",
        "send_script_sha256",
        "code_exe",
        "code_exe_sha256",
        "tunnel_known_hosts",
        "tunnel_known_hosts_sha256",
        "profiles_dir",
        "custody_dir",
        "poll_interval_seconds",
    }
)


def _pinned_file(path: str, digest: str) -> Path:
    file = Path(path)
    if (
        type(path) is not str
        or not file.is_absolute()
        or file.is_symlink()
        or not file.is_file()
        or type(digest) is not str
        or _DIGEST.fullmatch(digest) is None
    ):
        raise ValueError("absolute regular file and frozen digest required")
    actual = hashlib.sha256(file.read_bytes()).hexdigest()
    if actual != digest:
        raise RuntimeError(f"frozen host file changed: {file.name}")
    return file


def client_from_frozen_config(path: Path, expected_sha256: str) -> tuple[NativeUiClient, float]:
    """Build only from a controller-frozen, hash-pinned host configuration."""
    config_file = _pinned_file(str(path), expected_sha256)
    raw = config_file.read_bytes()
    if len(raw) > 16384:
        raise ValueError("native UI client configuration exceeds limit")
    config = json.loads(raw)
    if type(config) is not dict or set(config) != _CONFIG_FIELDS:
        raise ValueError("exact native UI client configuration required")
    if (
        type(config["controller_key_id"]) is not str
        or _ID.fullmatch(config["controller_key_id"]) is None
    ):
        raise ValueError("bounded controller key ID required")
    public_file = _pinned_file(
        config["controller_public_key_pem"], config["controller_public_key_sha256"]
    )
    public_key = load_pem_public_key(public_file.read_bytes())
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("Ed25519 controller public key required")
    ui_script = _pinned_file(config["ui_script"], config["ui_script_sha256"])
    send_script = _pinned_file(config["send_script"], config["send_script_sha256"])
    code_exe = _pinned_file(config["code_exe"], config["code_exe_sha256"])
    known_hosts = _pinned_file(config["tunnel_known_hosts"], config["tunnel_known_hosts_sha256"])
    tailscale_exe = _pinned_file(config["tailscale_exe"], config["tailscale_exe_sha256"])
    if type(config["remote_argv"]) is not list or not 1 <= len(config["remote_argv"]) <= 32:
        raise ValueError("frozen controller SSH argv required")
    from .campaign_runner import PowerShellNativeUi

    ui = PowerShellNativeUi(
        str(ui_script), code_exe=str(code_exe), tunnel_known_hosts=str(known_hosts)
    )
    transport = SshUiTransport(
        tailscale_exe=tailscale_exe,
        ssh_target=config["ssh_target"],
        remote_argv=tuple(config["remote_argv"]),
    )
    client = NativeUiClient(
        run_id=config["run_id"],
        verifier=Ed25519Verifier({config["controller_key_id"]: public_key}),
        transport=transport,
        ui=ui,
        custody_dir=Path(config["custody_dir"]),
        profiles_dir=Path(config["profiles_dir"]),
        submit=PowerShellNativeSubmit(send_script),
    )
    return client, config["poll_interval_seconds"]


def main(argv: list[str] | None = None) -> int:  # pragma: no cover - thin host CLI
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--config-sha256", required=True)
    args = parser.parse_args(argv)
    client, interval = client_from_frozen_config(args.config, args.config_sha256)
    client.run_forever(poll_interval_seconds=interval)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
