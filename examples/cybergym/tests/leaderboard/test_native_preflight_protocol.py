# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""The native preflight wire protocol is one-shot and process-bound."""

from __future__ import annotations

import json
from pathlib import Path

from nooa_cybergym.leaderboard.host_boundary_runtime import AdmittedPeer, GatewayRequest
from nooa_cybergym.leaderboard.native_preflight_gate import NativePreflightAdmission
from nooa_cybergym.leaderboard.native_process import NativeSocketProcess
from nooa_cybergym.leaderboard.network import NetworkPolicy

CONFIG = Path(__file__).resolve().parents[2] / "leaderboard/config/network-policy.json"


def test_native_protocol_runs_one_exact_parent_report_before_model_admission(tmp_path: Path):
    from nooa_cybergym.leaderboard.native_preflight_protocol import NativePreflightProtocol

    evidence, workspace = tmp_path / "evidence", tmp_path / "workspace"
    evidence.mkdir()
    workspace.mkdir()
    manifest = evidence / "task-manifest.json"
    manifest.write_bytes(b"{}")
    peer = AdmittedPeer("c" * 64, "n" * 64, "172.30.0.2")
    policy = NetworkPolicy.load(CONFIG)
    observed = []

    def verify(request):
        observed.append((request.path, request.source_port))
        return NativeSocketProcess(200, 150, "555")

    gate = NativePreflightAdmission(
        container_id=peer.container_id,
        policy=policy,
        workspace_manifest=manifest,
        evidence_root=evidence,
        observed_role=lambda session, agent: "child" if agent else "parent",
        audit=lambda event: None,
    )
    protocol = NativePreflightProtocol(
        peer=peer,
        run_id="run-1",
        task_id="synthetic:1",
        launch_id="launch-1",
        policy=policy,
        workspace_root=workspace,
        workspace_manifest=manifest,
        evidence_root=evidence,
        gate=gate,
        verify_parent=verify,
        verify_child=verify,
        audit=lambda event: None,
    )
    identity = {
        "schema_version": 1,
        "run_id": "run-1",
        "task_id": "synthetic:1",
        "launch_id": "launch-1",
        "context": "parent",
        "agent_id": None,
    }

    def request(path, body):
        return GatewayRequest(
            "registered-tool-gateway",
            "POST",
            "/native-launch/preflight/" + path,
            (),
            json.dumps(body).encode(),
            peer,
            source_port=42424,
        )

    assert gate.model_role("session", None) is None
    started = protocol(request("begin", identity))
    assert started.status == 200
    issued = json.loads(started.body)
    assert len(issued["nonce"]) == 32
    assert len(issued["probes"]) > 30
    assert all(item["command"][0] == "/usr/bin/python3" for item in issued["probes"])
    assert protocol(request("begin", identity)).status == 403
    assert gate.model_role("session", None) is None
    submitted = protocol(
        request(
            "submit",
            {
                **identity,
                "nonce": issued["nonce"],
                "results": [{"name": item["name"], "exit_code": 0} for item in issued["probes"]],
            },
        )
    )
    assert submitted.status == 200
    assert json.loads(submitted.body)["passed"] is True
    assert gate.model_role("session", None) == "parent"
    assert (
        protocol(request("submit", {**identity, "nonce": issued["nonce"], "results": []})).status
        == 403
    )
    assert observed == [
        ("/native-launch/preflight/begin", 42424),
        ("/native-launch/preflight/submit", 42424),
    ]


def test_native_protocol_rejects_process_swap_before_report(tmp_path: Path):
    from nooa_cybergym.leaderboard.native_preflight_protocol import NativePreflightProtocol

    evidence, workspace = tmp_path / "evidence", tmp_path / "workspace"
    evidence.mkdir()
    workspace.mkdir()
    manifest = evidence / "task-manifest.json"
    manifest.write_bytes(b"{}")
    peer = AdmittedPeer("c" * 64, "n" * 64, "172.30.0.2")
    policy = NetworkPolicy.load(CONFIG)
    count = 0

    def verify(request):
        nonlocal count
        count += 1
        return NativeSocketProcess(200 + count, 150, "555")

    gate = NativePreflightAdmission(
        container_id=peer.container_id,
        policy=policy,
        workspace_manifest=manifest,
        evidence_root=evidence,
        observed_role=lambda session, agent: "parent",
        audit=lambda event: None,
    )
    protocol = NativePreflightProtocol(
        peer=peer,
        run_id="run-1",
        task_id="synthetic:1",
        launch_id="launch-1",
        policy=policy,
        workspace_root=workspace,
        workspace_manifest=manifest,
        evidence_root=evidence,
        gate=gate,
        verify_parent=verify,
        verify_child=verify,
        audit=lambda event: None,
    )
    identity = {
        "schema_version": 1,
        "run_id": "run-1",
        "task_id": "synthetic:1",
        "launch_id": "launch-1",
        "context": "parent",
        "agent_id": None,
    }

    def request(path, body):
        return GatewayRequest(
            "registered-tool-gateway",
            "POST",
            "/native-launch/preflight/" + path,
            (),
            json.dumps(body).encode(),
            peer,
            source_port=42424,
        )

    started = json.loads(protocol(request("begin", identity)).body)
    attempted = protocol(
        request(
            "submit",
            {
                **identity,
                "nonce": started["nonce"],
                "results": [{"name": item["name"], "exit_code": 0} for item in started["probes"]],
            },
        )
    )
    assert attempted.status == 403
    assert gate.model_role("session", None) is None
    assert not (evidence / "preflight" / "parent").exists()
    assert (
        protocol(request("begin", {**identity, "context": "child", "agent_id": "agent-1"})).status
        == 403
    )
