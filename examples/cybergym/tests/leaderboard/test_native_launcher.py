# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Launch custody tests use actual signed envelopes and durable files."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def test_native_launcher_module_exists():
    assert importlib.util.find_spec("nooa_cybergym.leaderboard.native_launcher") is not None


@pytest.fixture
def subject():
    from nooa_cybergym.leaderboard import native_launcher

    return native_launcher


@pytest.fixture
def manifest(subject):
    return subject.build_launch_manifest(
        scope="synthetic",
        run_id="synthetic-1",
        task_id="synthetic:overflow",
        launch_id="launch-1",
        ordinal=1,
        harness_sha256="a" * 64,
        task_manifest_bytes=b'{"synthetic":true}',
        file_hashes={"CLAUDE.md": "e" * 64},
        container_id="c" * 64,
        hostname="c" * 12,
        uid=1000,
        pid_namespace="pid:[100]",
        mount_namespace="mnt:[200]",
        vscode_version="1.140.0",
        claude_extension_version="2.1.289",
        claude_extension_sha256="d" * 64,
        native_launch_url="http://registered-tool-gateway/native-launch",
    )


def signed(manifest):
    from xeus_cybergym.canonical import canonical_json
    from xeus_cybergym.ledger import Ed25519Signer

    key = Ed25519PrivateKey.generate()
    envelope = Ed25519Signer(private_key=key, key_id="controller").sign(canonical_json(manifest))
    return envelope.model_dump_json().encode(), {"controller": key.public_key()}


def receipt(manifest):
    return {
        "schema_version": 1,
        "event": "launch_reserved",
        "run_id": manifest["run_id"],
        "task_id": manifest["task_id"],
        "launch_id": manifest["launch_id"],
        "manifest_sha256": hashlib.sha256(
            json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        ).hexdigest(),
        "prompt_sha256": manifest["prompt_sha256"],
        "session_id": None,
        "timestamp": "2026-10-05T00:00:00.000Z",
        "observed": {
            "platform": "linux",
            "workspace": "/workspace",
            "remote_name": "ssh-remote",
            "uid": 1000,
            "hostname": "c" * 12,
            "pid_namespace": "pid:[100]",
            "mount_namespace": "mnt:[200]",
            "pid": 321,
            "ppid": 300,
            "vscode_version": "1.140.0",
            "claude_extension_version": "2.1.289",
            "claude_extension_sha256": "d" * 64,
            "claude_extension_kind": 2,
            "launcher_version": "0.1.0",
            "use_terminal": False,
            "config_dir": "/home/agent/.claude",
            "prior_session_state": False,
            "claude_extension_path": "/home/agent/.vscode-server/extensions/anthropic.claude-code-2.1.289",
            "environment_key_names": ["HOME", "PATH"],
        },
    }


def test_rejects_invalid_signature_before_authority_creation(subject, manifest, tmp_path):
    envelope, keys = signed(manifest)
    broken = json.loads(envelope)
    broken["signature"] = "AAAA"
    with pytest.raises(ValueError, match="signature"):
        subject.NativeLaunchAuthority.from_signed_envelope(
            json.dumps(broken).encode(), keys, tmp_path
        )
    assert not list(tmp_path.iterdir())


def test_builder_rejects_unscoped_endpoint_and_paths(subject, manifest):
    subject.validate_manifest(manifest)
    for patch in [
        {"native_launch_url": "http://example.com/native-launch"},
        {"file_hashes": {"../secret": "e" * 64}},
        {"ordinal": True},
        {"extra": "unexpected"},
    ]:
        with pytest.raises(ValueError, match="manifest"):
            subject.validate_manifest({**manifest, **patch})


@pytest.mark.skipif(
    os.name != "posix", reason="controller authority requires POSIX directory fsync"
)
def test_reservation_is_atomic_durable_and_rejected_after_restart(subject, manifest, tmp_path):
    envelope, keys = signed(manifest)
    authority = subject.NativeLaunchAuthority.from_signed_envelope(envelope, keys, tmp_path)

    def reserve():
        try:
            return authority.reserve(receipt(manifest))["status"]
        except RuntimeError:
            return "rejected"

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: reserve(), range(8)))
    assert results.count("reserved") == 1
    restarted = subject.NativeLaunchAuthority.from_signed_envelope(envelope, keys, tmp_path)
    with pytest.raises(RuntimeError, match="already reserved"):
        restarted.reserve(receipt(manifest))
    assert len(list(tmp_path.rglob("launcher-receipt.json"))) == 1


@pytest.mark.skipif(
    os.name != "posix", reason="controller authority requires POSIX directory fsync"
)
def test_receipt_mismatch_and_claimed_session_id_fail_before_reservation(
    subject, manifest, tmp_path
):
    envelope, keys = signed(manifest)
    authority = subject.NativeLaunchAuthority.from_signed_envelope(envelope, keys, tmp_path)
    for patch in [{"session_id": "invented"}, {"run_id": "other"}, {"secret": "must never log"}]:
        with pytest.raises(ValueError):
            authority.reserve({**receipt(manifest), **patch})
    observed = receipt(manifest)
    observed["observed"]["hostname"] = "wrong"
    with pytest.raises(ValueError):
        authority.reserve(observed)
    assert not list(tmp_path.iterdir())


@pytest.mark.skipif(
    os.name != "posix", reason="controller authority requires POSIX directory fsync"
)
def test_events_are_bound_to_one_reserved_launch_and_never_assert_started(
    subject, manifest, tmp_path
):
    envelope, keys = signed(manifest)
    authority = subject.NativeLaunchAuthority.from_signed_envelope(envelope, keys, tmp_path)
    event = {
        key: receipt(manifest)[key]
        for key in (
            "schema_version",
            "run_id",
            "task_id",
            "launch_id",
            "manifest_sha256",
            "timestamp",
        )
    }
    event["event"] = "command_returned"
    with pytest.raises(RuntimeError, match="not reserved"):
        authority.record(event)
    authority.reserve(receipt(manifest))
    assert authority.record(event)["status"] == "recorded"
    with pytest.raises(ValueError):
        authority.record({**event, "event": "started"})
    with pytest.raises(ValueError):
        authority.record({**event, "error": "secret"})


def test_python_and_javascript_frozen_prompt_match(subject):
    import shutil
    import subprocess

    if not shutil.which("node"):
        pytest.skip("cross-language parity requires Node (covered by launcher Node suite)")
    source = Path(__file__).resolve().parents[2] / "leaderboard/native-launcher/extension.js"
    result = subprocess.run(
        ["node", "-e", "process.stdout.write(require(process.argv[1]).promptHash())", str(source)],
        check=True,
        capture_output=True,
        text=True,
    )
    assert result.stdout == subject.PROMPT_SHA256


def test_gateway_handler_requires_actual_container_and_network_peer(subject, manifest, tmp_path):
    from nooa_cybergym.leaderboard.host_boundary_runtime import AdmittedPeer, GatewayRequest

    envelope, keys = signed(manifest)
    authority = subject.NativeLaunchAuthority.from_signed_envelope(envelope, keys, tmp_path)
    handler = subject.native_launch_handler(authority, network_id="net-1")
    request = GatewayRequest(
        "registered-tool-gateway",
        "POST",
        "/native-launch/reserve",
        (),
        json.dumps(receipt(manifest)).encode(),
        AdmittedPeer("wrong-container", "net-1", "172.30.0.2"),
    )
    assert handler(request).status == 403
    from dataclasses import replace

    assert (
        handler(replace(request, peer=AdmittedPeer("c" * 64, "wrong-network", "172.30.0.2"))).status
        == 403
    )
    assert not list(tmp_path.iterdir())
