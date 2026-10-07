# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""A report for one native context must not admit a different model role."""

from __future__ import annotations

import hashlib
import importlib
import json
from dataclasses import asdict
from pathlib import Path

import pytest
from nooa_cybergym.leaderboard.network import NetworkPolicy
from nooa_cybergym.leaderboard.preflight import PreflightReport, ProbeRecord, _specs

CONFIG = Path(__file__).resolve().parents[2] / "leaderboard/config/network-policy.json"


def _report(evidence: Path, *, context: str, container_id: str, manifest: Path, policy):
    folder = evidence / context
    folder.mkdir(parents=True)
    report = PreflightReport(
        passed=True,
        failures=(),
        probes=tuple(
            ProbeRecord(
                spec.name,
                context,
                spec.command,
                0,
                True,
                "0" * 64,
                "0" * 64,
                context,
                container_id,
                "2026-10-07T00:00:00Z",
            )
            for spec in _specs(policy, context, ())
        ),
        contexts=(context,),
        execution_mode="native",
        container_id=container_id,
        workspace_manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
        policy_sha256=policy.digest,
        evidence_path=folder / f"preflight-{context}-report.json",
    )
    payload = asdict(report)
    payload["evidence_path"] = str(report.evidence_path)
    report.evidence_path.write_bytes(
        (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    )
    return report


def test_model_role_requires_matching_native_preflight_report(tmp_path: Path):
    gate_module = importlib.import_module("nooa_cybergym.leaderboard.native_preflight_gate")
    manifest = tmp_path / "task-manifest.json"
    manifest.write_bytes(b"{}")
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    policy = NetworkPolicy.load(CONFIG)
    container_id = "c" * 64

    def roles(session, agent):
        return "child" if agent else "parent"

    audit = []
    gate = gate_module.NativePreflightAdmission(
        container_id=container_id,
        policy=policy,
        workspace_manifest=manifest,
        evidence_root=evidence,
        observed_role=roles,
        audit=lambda event: audit.append(event),
    )
    assert gate.model_role("session", None) is None
    assert gate.model_role("session", "child-a") is None

    parent = _report(
        evidence, context="parent", container_id=container_id, manifest=manifest, policy=policy
    )
    gate.record(parent)
    assert gate.model_role("session", None) == "parent"
    assert gate.model_role("session", "child-a") is None

    child = _report(
        evidence, context="child", container_id=container_id, manifest=manifest, policy=policy
    )
    gate.record(child, agent_id="child-a")
    assert gate.model_role("session", "child-a") == "child"
    assert gate.model_role("session", "child-b") is None
    assert [event["event"] for event in audit] == [
        "native_preflight_admitted",
        "native_preflight_admitted",
    ]
    with pytest.raises(ValueError, match="duplicate"):
        gate.record(child, agent_id="child-b")


def test_report_drift_or_synthetic_mode_cannot_open_gate(tmp_path: Path):
    from dataclasses import replace

    gate_module = importlib.import_module("nooa_cybergym.leaderboard.native_preflight_gate")
    manifest = tmp_path / "task-manifest.json"
    manifest.write_bytes(b"{}")
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    policy = NetworkPolicy.load(CONFIG)
    container_id = "c" * 64
    gate = gate_module.NativePreflightAdmission(
        container_id=container_id,
        policy=policy,
        workspace_manifest=manifest,
        evidence_root=evidence,
        observed_role=lambda session, agent: "parent",
        audit=lambda event: None,
    )
    report = _report(
        evidence, context="parent", container_id=container_id, manifest=manifest, policy=policy
    )
    with pytest.raises(ValueError, match="native"):
        gate.record(replace(report, execution_mode="synthetic"))
    report.evidence_path.write_bytes(b"{}")
    with pytest.raises(ValueError, match="evidence"):
        gate.record(report)
    assert gate.model_role("session", None) is None
