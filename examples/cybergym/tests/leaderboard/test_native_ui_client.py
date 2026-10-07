# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""A signed outbound UI command executes once across a lost acknowledgement."""

from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nooa_cybergym.leaderboard.native_ui_client import (
    NativeUiClient,
    client_from_frozen_config,
)
from nooa_cybergym.leaderboard.native_ui_mailbox import NativeUiMailbox
from xeus_cybergym.canonical import canonical_json
from xeus_cybergym.ledger import Ed25519Signer, Ed25519Verifier


class Transport:
    def __init__(self, box):
        self.box = box
        self.drop_ack = False

    def poll(self):
        return self.box.pending()

    def ack(self, raw):
        if self.drop_ack:
            raise ConnectionError("lost SSH acknowledgement")
        import base64
        import json

        value = json.loads(raw)
        return self.box.acknowledge(
            value["command_id"],
            status=value["status"],
            ui_audit_sha256=value["ui_audit_sha256"],
            ui_audit_bytes=(
                base64.b64decode(value["ui_audit_base64"])
                if value["ui_audit_base64"] is not None
                else None
            ),
        )


class Ui:
    def __init__(self):
        self.calls = []

    def open(self, *args):
        self.calls.append(("open", args))

    def close(self, *args):
        self.calls.append(("close", args))

    def reap(self, *args):
        self.calls.append(("reap", args))


def test_signed_open_executes_once_when_ack_transport_is_lost(tmp_path):
    key = Ed25519PrivateKey.generate()
    signer = Ed25519Signer(private_key=key, key_id="controller")
    verifier = Ed25519Verifier({"controller": key.public_key()})
    box = NativeUiMailbox(tmp_path, run_id="run-1", signer=signer, verifier=verifier)
    box.publish(
        operation_key="task-open",
        action="open",
        task_id="synthetic:length-header",
        remote_host="cybergym-task-1",
        port=32355,
    )
    transport = Transport(box)
    ui = Ui()
    client = NativeUiClient(
        run_id="run-1",
        verifier=verifier,
        transport=transport,
        ui=ui,
        custody_dir=tmp_path / "host",
        profiles_dir=tmp_path / "profiles",
        submit=lambda **_: None,
    )
    transport.drop_ack = True
    try:
        client.poll_once()
    except ConnectionError:
        pass
    else:
        raise AssertionError("expected lost SSH acknowledgement")
    assert len(ui.calls) == 1
    transport.drop_ack = False
    assert client.poll_once()["status"] == "completed"
    assert len(ui.calls) == 1
    assert box.pending() is None


def test_signed_submit_uses_exact_receipt_and_returns_attempted_audit(tmp_path):
    key = Ed25519PrivateKey.generate()
    signer = Ed25519Signer(private_key=key, key_id="controller")
    verifier = Ed25519Verifier({"controller": key.public_key()})
    box = NativeUiMailbox(tmp_path, run_id="run-1", signer=signer, verifier=verifier)
    receipt = canonical_json(
        {
            "event": "launch_reserved",
            "launch_id": "launch-1",
            "session_id": None,
            "prompt_sha256": "a" * 64,
        }
    )
    box.publish(
        operation_key="task-submit",
        action="submit",
        task_id="synthetic:length-header",
        remote_host="cybergym-task-1",
        launch_id="launch-1",
        launch_receipt=receipt,
    )
    ui = Ui()
    sends = []

    def submit(**kwargs):
        sends.append(kwargs)
        assert kwargs["receipt_path"].read_bytes() == receipt
        kwargs["audit_directory"].mkdir()
        (kwargs["audit_directory"] / "ui-send-attempted.json").write_bytes(
            canonical_json(
                {
                    "event": "ui_send_attempted",
                    "launch_id": "launch-1",
                    "prompt_sha256": "a" * 64,
                    "observed_prompt_sha256": "a" * 64,
                    "remote_alias": "cybergym-task-1",
                }
            )
        )

    client = NativeUiClient(
        run_id="run-1",
        verifier=verifier,
        transport=Transport(box),
        ui=ui,
        custody_dir=tmp_path / "host",
        profiles_dir=tmp_path / "profiles",
        submit=submit,
    )
    ack = client.poll_once()
    assert ack["status"] == "completed"
    assert (
        ack["ui_audit_sha256"]
        == hashlib.sha256(
            (sends[0]["audit_directory"] / "ui-send-attempted.json").read_bytes()
        ).hexdigest()
    )
    assert len(sends) == 1
    assert not ui.calls


def test_unsigned_or_changed_command_cannot_reach_ui(tmp_path):
    key = Ed25519PrivateKey.generate()
    verifier = Ed25519Verifier({"controller": key.public_key()})
    ui = Ui()

    class BadTransport:
        def poll(self):
            return (
                b'{"algorithm":"Ed25519","key_id":"controller","payload":"e30=","signature":"AA=="}'
            )

        def ack(self, _):
            raise AssertionError("no ack on invalid signature")

    client = NativeUiClient(
        run_id="run-1",
        verifier=verifier,
        transport=BadTransport(),
        ui=ui,
        custody_dir=tmp_path / "host",
        profiles_dir=tmp_path / "profiles",
        submit=lambda **_: None,
    )
    import pytest

    with pytest.raises(ValueError, match="signature"):
        client.poll_once()
    assert not ui.calls


def test_host_client_config_rejects_changed_pinned_binary(tmp_path):
    from cryptography.hazmat.primitives import serialization

    key = Ed25519PrivateKey.generate()
    files = {}
    for name in (
        "tailscale_exe",
        "ui_script",
        "send_script",
        "code_exe",
        "tunnel_known_hosts",
        "controller_public_key_pem",
    ):
        path = tmp_path / name
        data = (
            key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            if name == "controller_public_key_pem"
            else name.encode()
        )
        path.write_bytes(data)
        files[name] = str(path)
        digest_name = (
            "controller_public_key_sha256"
            if name == "controller_public_key_pem"
            else f"{name}_sha256"
        )
        files[digest_name] = hashlib.sha256(data).hexdigest()
    config = {
        **files,
        "run_id": "run-1",
        "ssh_target": "root@sunchaser-20260905",
        "remote_argv": ["env", "PYTHONPATH=/frozen", "python", "-m", "mailbox"],
        "controller_key_id": "controller",
        "profiles_dir": str(tmp_path / "profiles"),
        "custody_dir": str(tmp_path / "custody"),
        "poll_interval_seconds": 1,
    }
    config_path = tmp_path / "client-config.json"
    raw = canonical_json(config)
    config_path.write_bytes(raw)
    client, interval = client_from_frozen_config(config_path, hashlib.sha256(raw).hexdigest())
    assert client.run_id == "run-1"
    assert interval == 1
    (tmp_path / "send_script").write_bytes(b"changed")
    import pytest

    with pytest.raises(RuntimeError, match="frozen host file changed"):
        client_from_frozen_config(config_path, hashlib.sha256(raw).hexdigest())
