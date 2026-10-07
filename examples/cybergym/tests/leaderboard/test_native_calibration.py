# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import pytest
from nooa_cybergym.leaderboard.native_calibration_driver import _source_files
from nooa_cybergym.leaderboard.host_boundary_runtime import AdmittedPeer, GatewayRequest
from nooa_cybergym.leaderboard.native_hook_runtime import NativeHookCollector, project_hook_input
from nooa_cybergym.leaderboard.native_launcher import NativeLaunchAuthority, build_launch_manifest

from .test_native_launcher import receipt, signed


def test_calibration_source_has_required_synthetic_workspace_files():
    repo = Path(__file__).resolve().parents[4]
    files = _source_files(repo)
    assert files["README.md"].startswith(b"Synthetic native certification fixture")
    assert files["submit.sh"].startswith(b"#!/bin/sh\n")
    assert b"repo-fix" not in files["submit.sh"]


@pytest.fixture
def setup(tmp_path):
    from nooa_cybergym.leaderboard.native_calibration import NativeCalibration

    manifest = build_launch_manifest(
        scope="synthetic",
        run_id="calibration-1",
        task_id="synthetic:length-header",
        launch_id="calibration-launch-1",
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
    envelope, keys = signed(manifest)
    authority = NativeLaunchAuthority.from_signed_envelope(envelope, keys, tmp_path)
    # Existing controller launch receipt, not a synthesized native session event.
    authority.launch_dir.mkdir()
    (authority.launch_dir / "launcher-receipt.json").write_text(json.dumps(receipt(manifest)))
    collector = NativeHookCollector(
        tmp_path / "hooks.db",
        run_id="calibration-1",
        task_id=manifest["task_id"],
        launch_id=manifest["launch_id"],
    )
    peer = AdmittedPeer("c" * 64, "network-1", "172.20.0.2")
    image = "sha256:" + "f" * 64
    inspection = {"Id": peer.container_id, "Image": image, "State": {"Running": True}}
    arguments = {
        "authority": authority,
        "collector": collector,
        "peer": peer,
        "image_id": image,
        "binary_sha256": "b" * 64,
        "evidence_dir": tmp_path / "capture",
        "inspect_container": lambda: inspection,
        "redact": lambda value: value.replace("SECRET", "[redacted]"),
    }
    calibration = NativeCalibration(**arguments)
    body = {
        "model": "glm-5.3[1m]",
        "metadata": {
            "user_id": json.dumps({"session_id": "session-1", "account_uuid": "SECRET-ACCOUNT"})
        },
        "messages": [{"role": "user", "content": "SECRET data"}],
        "tools": [
            {
                "name": "Read",
                "description": "Read source",
                "input_schema": {"type": "object", "properties": {"file_path": {"type": "string"}}},
            }
        ],
    }
    request = GatewayRequest(
        "model-gateway",
        "POST",
        "/v1/messages",
        (("Authorization", "Bearer SECRET"), ("anthropic-version", "2023-06-01")),
        json.dumps(body).encode(),
        peer,
    )
    return calibration, arguments, collector, request, body, inspection


def start(collector):
    collector.ingest(
        {
            "schema_version": 1,
            "event_id": str(uuid4()),
            **collector.identity,
            "hook": project_hook_input(
                {
                    "hook_event_name": "SessionStart",
                    "session_id": "session-1",
                    "cwd": "/workspace",
                    "source": "startup",
                    "transcript_path": "/home/agent/.claude/projects/-workspace/session-1.jsonl",
                }
            ),
        }
    )


def test_capture_requires_observed_session_then_preserves_actual_schemas(setup):
    calibration, args, collector, request, body, _ = setup
    assert calibration(request).status == 403
    assert not list(args["evidence_dir"].glob("request-*.json"))
    start(collector)
    assert calibration(request).status == 503
    artifact = json.loads(next(args["evidence_dir"].glob("request-*.json")).read_bytes())
    assert artifact["tools"] == body["tools"]
    assert artifact["provider_dispatched"] is False
    assert artifact["scope"] == "native_schema_discovery_no_provider"
    assert artifact["role"] == "parent"
    assert artifact["binary_sha256"] == "b" * 64
    assert artifact["request_sha256"] == hashlib.sha256(request.body).hexdigest()
    assert "SECRET" not in json.dumps(artifact)
    assert artifact["payload"]["metadata"] == {
        "user_id": {
            "session_id": "session-1",
            "agent_id": None,
            "parent_agent_id": None,
            "parent_session_id": None,
        }
    }


def test_wrong_peer_changed_image_unknown_child_and_unreserved_launch_rejected(setup):
    calibration, args, collector, request, _, inspection = setup
    start(collector)
    assert (
        calibration(replace(request, peer=replace(request.peer, source_ip="172.20.0.9"))).status
        == 403
    )
    assert (
        calibration(replace(request, headers=(("x-claude-code-agent-id", "unknown"),))).status
        == 403
    )
    inspection["Image"] = "sha256:" + "9" * 64
    assert calibration(request).status == 403
    inspection["Image"] = args["image_id"]
    (args["authority"].launch_dir / "launcher-receipt.json").unlink()
    assert calibration(request).status == 403


def test_calibration_cannot_reopen_consumed_evidence_or_rewrite_schema(setup):
    from nooa_cybergym.leaderboard.native_calibration import NativeCalibration

    calibration, args, collector, request, body, _ = setup
    with pytest.raises((ValueError, FileExistsError)):
        NativeCalibration(**args)
    start(collector)
    body["tools"][0]["description"] = "SECRET"
    assert calibration(replace(request, body=json.dumps(body).encode())).status == 403
    assert not list(args["evidence_dir"].glob("request-*.json"))


def test_cli_verifies_artifact_digest_and_reports_no_child_claim(setup, capsys):
    from nooa_cybergym.leaderboard.native_calibration import main

    calibration, args, collector, request, _, _ = setup
    start(collector)
    calibration(request)
    path = next(args["evidence_dir"].glob("request-*.json"))
    main(["inspect", str(path), "--sha256", hashlib.sha256(path.read_bytes()).hexdigest()])
    result = json.loads(capsys.readouterr().out)
    assert result["role"] == "parent"
    assert result["provider_dispatched"] is False
    assert result["tool_names"] == ["Read"]
    with pytest.raises(ValueError, match="digest"):
        main(["inspect", str(path), "--sha256", "0" * 64])
