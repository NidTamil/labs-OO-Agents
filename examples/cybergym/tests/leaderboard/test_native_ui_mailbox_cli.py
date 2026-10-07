# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""The SSH entrypoint returns signed commands and exact durable acknowledgements."""

from __future__ import annotations

import base64
import io
import json
from types import SimpleNamespace

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nooa_cybergym.leaderboard import native_ui_mailbox_cli
from nooa_cybergym.leaderboard.native_ui_mailbox import NativeUiMailbox
from xeus_cybergym.canonical import canonical_json
from xeus_cybergym.ledger import Ed25519Signer, Ed25519Verifier


def test_cli_poll_and_ack_use_public_key_only(tmp_path, monkeypatch):
    key = Ed25519PrivateKey.generate()
    pem = tmp_path / "controller-public.pem"
    pem.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    box = NativeUiMailbox(
        tmp_path,
        run_id="run-1",
        signer=Ed25519Signer(private_key=key, key_id="controller"),
        verifier=Ed25519Verifier({"controller": key.public_key()}),
    )
    command = box.publish(operation_key="reap-1", action="reap")
    output = io.BytesIO()
    monkeypatch.setattr(native_ui_mailbox_cli.sys, "stdout", SimpleNamespace(buffer=output))
    argv = [
        "--mailbox-root",
        str(tmp_path),
        "--run-id",
        "run-1",
        "--public-key-pem",
        str(pem),
        "--key-id",
        "controller",
    ]
    assert native_ui_mailbox_cli.main([*argv, "poll"]) == 0
    observed = json.loads(output.getvalue())
    assert base64.b64decode(observed["envelope_base64"]) == command.envelope
    output.seek(0)
    output.truncate()
    request = canonical_json(
        {
            "command_id": command.command_id,
            "status": "completed",
            "ui_audit_sha256": None,
            "ui_audit_base64": None,
        }
    )
    monkeypatch.setattr(
        native_ui_mailbox_cli.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(request))
    )
    assert native_ui_mailbox_cli.main([*argv, "ack"]) == 0
    assert json.loads(output.getvalue())["status"] == "completed"
    assert box.pending() is None
