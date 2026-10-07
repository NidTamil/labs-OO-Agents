# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Durable, signed host-only commands for an outbound Windows native-UI client.

The POSIX controller never opens a connection into the workstation. A Windows
client polls this controller-custody mailbox over authenticated Tailscale SSH,
verifies the signed command, performs only its pinned UI action, and returns a
bounded acknowledgement. No task source, model credential, or evaluator input
is placed in a command. A repeated operation key replays the original command
and cannot authorize a second Send.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from uuid import uuid4

from xeus_cybergym.canonical import canonical_json
from xeus_cybergym.ledger import SignedEnvelope

_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9:_.-]{0,127}\Z")
_ALIAS = re.compile(r"[a-z][a-z0-9-]{1,63}\Z")
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")
_ACTIONS = frozenset({"open", "submit", "close", "reap"})
_STATUSES = frozenset({"completed", "failed", "ambiguous"})


@dataclass(frozen=True, slots=True)
class UiCommand:
    command_id: str
    payload: dict
    envelope: bytes = field(repr=False)


class NativeUiMailbox:
    """One serial signed command queue with durable, idempotent acknowledgements."""

    def __init__(self, root: Path, *, run_id: str, signer, verifier):
        root = Path(root)
        if (
            not root.is_absolute()
            or root.is_symlink()
            or not root.is_dir()
            or root.resolve() != root
            or type(run_id) is not str
            or _IDENTITY.fullmatch(run_id) is None
            or (signer is not None and not callable(getattr(signer, "sign", None)))
            or not callable(getattr(verifier, "verify", None))
        ):
            raise ValueError("trusted controller UI mailbox identity required")
        self.root = root
        self.run_id = run_id
        self.signer = signer
        self.verifier = verifier
        self.database = root / "native-ui-mailbox.sqlite"
        if self.database.is_symlink():
            raise RuntimeError("UI mailbox database may not be linked")
        with self._connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS commands ("
                "seq INTEGER PRIMARY KEY AUTOINCREMENT,"
                "operation_key TEXT UNIQUE NOT NULL,"
                "command_id TEXT UNIQUE NOT NULL,"
                "spec BLOB NOT NULL,"
                "payload BLOB NOT NULL,"
                "envelope BLOB NOT NULL,"
                "ack BLOB)"
            )
        if os.name == "posix":
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

    @contextmanager
    def _connect(self):
        if self.database.is_symlink() or self.root.is_symlink():
            raise RuntimeError("UI mailbox custody path changed")
        connection = sqlite3.connect(self.database, timeout=15)
        try:
            connection.execute("PRAGMA synchronous=FULL")
            with connection:
                yield connection
        finally:
            connection.close()

    def _checked_command(self, payload: bytes, envelope: bytes) -> UiCommand:
        if len(payload) > 8192 or len(envelope) > 16384:
            raise RuntimeError("UI command exceeds bounded evidence limit")
        verified = self.verifier.verify(SignedEnvelope.model_validate_json(envelope))
        if verified != payload:
            raise RuntimeError("UI command signature differs from durable payload")
        command = json.loads(payload)
        if (
            type(command) is not dict
            or canonical_json(command) != payload
            or command.get("run_id") != self.run_id
            or type(command.get("command_id")) is not str
            or re.fullmatch(r"[a-f0-9]{32}", command["command_id"]) is None
        ):
            raise RuntimeError("UI command custody is not canonical")
        return UiCommand(command["command_id"], command, envelope)

    def publish(
        self,
        *,
        operation_key: str,
        action: str,
        task_id: str | None = None,
        remote_host: str | None = None,
        port: int | None = None,
        launch_id: str | None = None,
        launch_receipt: bytes | None = None,
    ) -> UiCommand:
        if self.signer is None:
            raise RuntimeError("read-only UI mailbox cannot publish")
        if type(operation_key) is not str or _IDENTITY.fullmatch(operation_key) is None:
            raise ValueError("bounded UI operation key required")
        if type(action) is not str or action not in _ACTIONS:
            raise ValueError("supported UI action required")
        if action == "reap":
            if any(
                value is not None
                for value in (task_id, remote_host, port, launch_id, launch_receipt)
            ):
                raise ValueError("reap has run scope only")
        elif type(task_id) is not str or _IDENTITY.fullmatch(task_id) is None:
            raise ValueError("current task identity required")
        if action in {"open", "close"}:
            if type(remote_host) is not str or _ALIAS.fullmatch(remote_host) is None:
                raise ValueError("isolated SSH alias required")
            if action == "open" and (type(port) is not int or not 1024 <= port <= 65535):
                raise ValueError("bounded task SSH port required")
            if action == "close" and port is not None:
                raise ValueError("close carries no SSH port")
            if launch_id is not None or launch_receipt is not None:
                raise ValueError("window command carries no launch receipt")
        elif action == "submit":
            if (
                type(launch_id) is not str
                or _IDENTITY.fullmatch(launch_id) is None
                or type(launch_receipt) is not bytes
                or not 0 < len(launch_receipt) <= 4096
                or type(remote_host) is not str
                or _ALIAS.fullmatch(remote_host) is None
                or port is not None
            ):
                raise ValueError("frozen launch and receipt digest required for Send")
            try:
                receipt = json.loads(launch_receipt)
            except (UnicodeDecodeError, ValueError):
                raise ValueError("canonical launch receipt required for Send") from None
            if (
                type(receipt) is not dict
                or canonical_json(receipt) != launch_receipt
                or receipt.get("event") != "launch_reserved"
                or receipt.get("launch_id") != launch_id
                or receipt.get("session_id", "missing") is not None
                or type(receipt.get("prompt_sha256")) is not str
                or _DIGEST.fullmatch(receipt["prompt_sha256"]) is None
            ):
                raise ValueError("exact pre-model launch receipt required for Send")
        spec = {
            "schema_version": 1,
            "artifact_kind": "native_ui_command",
            "run_id": self.run_id,
            "operation_key": operation_key,
            "action": action,
            "task_id": task_id,
            "remote_host": remote_host,
            "port": port,
            "launch_id": launch_id,
            "receipt_sha256": (
                hashlib.sha256(launch_receipt).hexdigest() if launch_receipt is not None else None
            ),
            "launch_receipt_base64": (
                base64.b64encode(launch_receipt).decode("ascii")
                if launch_receipt is not None
                else None
            ),
        }
        spec_bytes = canonical_json(spec)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT spec,payload,envelope FROM commands WHERE operation_key=?",
                (operation_key,),
            ).fetchone()
            if existing is not None:
                if existing[0] != spec_bytes:
                    raise RuntimeError("UI operation key was reused with different inputs")
                return self._checked_command(existing[1], existing[2])
            payload = canonical_json({**spec, "command_id": uuid4().hex})
            envelope = canonical_json(self.signer.sign(payload).model_dump())
            command = self._checked_command(payload, envelope)
            connection.execute(
                "INSERT INTO commands(operation_key,command_id,spec,payload,envelope)"
                " VALUES(?,?,?,?,?)",
                (operation_key, command.command_id, spec_bytes, payload, envelope),
            )
        return command

    def pending(self) -> bytes | None:
        """Read the oldest unacknowledged signed command, with no side effect."""
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload,envelope FROM commands WHERE ack IS NULL ORDER BY seq LIMIT 1"
            ).fetchone()
        if row is None:
            return None
        return self._checked_command(*row).envelope

    def acknowledge(
        self,
        command_id: str,
        *,
        status: str,
        ui_audit_sha256: str | None = None,
        ui_audit_bytes: bytes | None = None,
    ) -> dict:
        if type(command_id) is not str or re.fullmatch(r"[a-f0-9]{32}", command_id) is None:
            raise ValueError("UI command identity required")
        if type(status) is not str or status not in _STATUSES:
            raise ValueError("bounded UI acknowledgement status required")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT seq,payload,envelope,ack FROM commands WHERE command_id=?", (command_id,)
            ).fetchone()
            if row is None:
                raise RuntimeError("unknown UI command")
            command = self._checked_command(row[1], row[2])
            if status == "completed" and command.payload["action"] == "submit":
                if (
                    type(ui_audit_sha256) is not str
                    or _DIGEST.fullmatch(ui_audit_sha256) is None
                    or type(ui_audit_bytes) is not bytes
                    or not 0 < len(ui_audit_bytes) <= 8192
                    or hashlib.sha256(ui_audit_bytes).hexdigest() != ui_audit_sha256
                ):
                    raise ValueError("completed Send requires exact UI audit digest and bytes")
                try:
                    audit = json.loads(ui_audit_bytes)
                except (UnicodeDecodeError, ValueError):
                    raise ValueError("completed Send requires valid UI audit") from None
                receipt = json.loads(base64.b64decode(command.payload["launch_receipt_base64"]))
                if (
                    type(audit) is not dict
                    or audit.get("event") != "ui_send_attempted"
                    or audit.get("launch_id") != command.payload["launch_id"]
                    or audit.get("prompt_sha256") != receipt["prompt_sha256"]
                    or audit.get("observed_prompt_sha256") != receipt["prompt_sha256"]
                    or audit.get("remote_alias") != command.payload["remote_host"]
                ):
                    raise ValueError("completed Send audit differs from signed command")
            elif ui_audit_sha256 is not None or ui_audit_bytes is not None:
                raise ValueError("UI audit belongs only to completed Send")
            ack = {
                "schema_version": 1,
                "artifact_kind": "native_ui_ack",
                "run_id": self.run_id,
                "command_id": command_id,
                "action": command.payload["action"],
                "task_id": command.payload["task_id"],
                "status": status,
                "ui_audit_sha256": ui_audit_sha256,
                "ui_audit_base64": (
                    base64.b64encode(ui_audit_bytes).decode("ascii")
                    if ui_audit_bytes is not None
                    else None
                ),
            }
            raw = canonical_json(ack)
            if row[3] is not None:
                if row[3] != raw:
                    raise RuntimeError("UI acknowledgement differs from durable result")
                return ack
            earliest = connection.execute(
                "SELECT seq FROM commands WHERE ack IS NULL ORDER BY seq LIMIT 1"
            ).fetchone()
            if earliest is None or earliest[0] != row[0]:
                raise RuntimeError("UI commands must be acknowledged in order")
            connection.execute("UPDATE commands SET ack=? WHERE command_id=?", (raw, command_id))
        return ack

    def wait_ack(self, command_id: str, *, timeout_seconds: float) -> dict:
        if type(timeout_seconds) not in {int, float} or not 0 <= timeout_seconds <= 600:
            raise ValueError("bounded UI acknowledgement wait required")
        deadline = time.monotonic() + timeout_seconds
        while True:
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT ack FROM commands WHERE command_id=?", (command_id,)
                ).fetchone()
            if row is None:
                raise RuntimeError("unknown UI command")
            if row[0] is not None:
                ack = json.loads(row[0])
                if (
                    type(ack) is not dict
                    or canonical_json(ack) != row[0]
                    or ack.get("command_id") != command_id
                    or ack.get("run_id") != self.run_id
                ):
                    raise RuntimeError("UI acknowledgement is not canonical")
                return ack
            if time.monotonic() >= deadline:
                raise TimeoutError("Windows UI command was not acknowledged")
            time.sleep(min(0.25, deadline - time.monotonic()))
