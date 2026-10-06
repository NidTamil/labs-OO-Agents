# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Static GBrain readiness stays blocked until real native evidence is bound."""

import hashlib
import json
from pathlib import Path

from nooa_cybergym.leaderboard.memory_readiness import audit_memory_readiness, main


def _fixture(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    controller = root / "examples" / "cybergym" / "nooa_cybergym" / "leaderboard"
    controller.mkdir(parents=True)
    (controller / "memory.py").write_bytes(b"synthetic read facade")
    (controller / "memory_transport.py").write_bytes(b"synthetic MCP adapter")
    return root


def test_static_memory_audit_hashes_only_local_adapter_and_blocks_missing_native_evidence(
    tmp_path: Path, monkeypatch
) -> None:
    root = _fixture(tmp_path)
    secret = "synthetic-secret-never-print"
    monkeypatch.setenv("GBRAIN_AUTH_TOKEN", secret)

    report = audit_memory_readiness(repo_root=root)

    assert report.gate == "blocked"
    assert report.scope == "read_only_memory_readiness"
    assert report.observed["adapter_sha256"] == {
        "memory.py": hashlib.sha256(b"synthetic read facade").hexdigest(),
        "memory_transport.py": hashlib.sha256(b"synthetic MCP adapter").hexdigest(),
    }
    assert report.observed["memory_policy_present"] is False
    assert "frozen_memory_policy_and_backend_identity" in report.missing_interfaces
    assert "exact_source_oauth_grant" in report.missing_interfaces
    assert "native_ai_invocation_guard_budget_binding" in report.missing_interfaces
    assert secret not in report.to_json()


def test_missing_native_contracts_name_the_exact_scored_scope_and_settlement(
    tmp_path: Path,
) -> None:
    report = audit_memory_readiness(repo_root=_fixture(tmp_path))

    assert set(report.missing_interfaces) == set(report.missing_contracts)
    oauth = report.missing_contracts["exact_source_oauth_grant"]
    assert "xeus-cybergym-workspace" in oauth
    assert "default" in oauth
    assert "authenticated" in oauth
    guard = report.missing_contracts["native_ai_invocation_guard_budget_binding"]
    assert "withAIInvocationGuard" in guard
    assert "chat" in guard and "embed" in guard and "rerank" in guard
    assert "settle" in guard and "failure" in guard and "null usage" in guard
    assert "2000" in report.missing_contracts["audited_read_and_oracle_write_paths"]
    assert "12" in report.missing_contracts["audited_read_and_oracle_write_paths"]


def test_adapter_absence_is_reported_without_claiming_backend_identity(tmp_path: Path) -> None:
    root = _fixture(tmp_path)
    (root / "examples/cybergym/nooa_cybergym/leaderboard/memory_transport.py").unlink()

    report = audit_memory_readiness(repo_root=root)

    assert report.observed["adapter_sha256"]["memory_transport.py"] is None
    assert "local_memory_adapter_sources" in report.missing_interfaces
    assert report.gate == "blocked"


def test_policy_file_presence_does_not_certify_native_oauth_or_guard(tmp_path: Path) -> None:
    root = _fixture(tmp_path)
    config = root / "examples/cybergym/leaderboard/config"
    config.mkdir(parents=True)
    (config / "memory-policy.json").write_text("{}")

    report = audit_memory_readiness(repo_root=root)

    assert report.observed["memory_policy_present"] is True
    assert report.gate == "blocked"
    assert "exact_source_oauth_grant" in report.missing_interfaces
    assert "native_ai_invocation_guard_budget_binding" in report.missing_interfaces


def test_cli_emits_machine_readable_blocked_report(tmp_path: Path, capsys) -> None:
    root = _fixture(tmp_path)

    assert main(["--repo-root", str(root)]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["gate"] == "blocked"
    assert report["missing_interfaces"]
