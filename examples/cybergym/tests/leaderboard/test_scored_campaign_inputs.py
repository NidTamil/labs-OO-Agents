# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Scored CLI input custody rejects missing or changed signed files."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from nooa_cybergym.leaderboard.scored_campaign_inputs import (
    admit_signed_campaign,
    read_signed_campaign_inputs,
)


def _bundle(root: Path) -> None:
    root.mkdir()
    for name in ("decision", "certification", "harness_lock", "cohort"):
        (root / f"{name}.signed.json").write_bytes(f"signed:{name}".encode())
    (root / "tasks.json").write_bytes(b'["arvo:47101"]')
    (root / "campaign-policy.json").write_text('{"max_parallel_tasks":1}', encoding="utf-8")


def test_read_scored_inputs_requires_all_regular_bounded_files(tmp_path: Path):
    root = tmp_path / "scored"
    _bundle(root)
    inputs = read_signed_campaign_inputs(root)
    assert inputs.decision == b"signed:decision"
    assert inputs.campaign_policy == {"max_parallel_tasks": 1}
    assert inputs.tasks_json == b'["arvo:47101"]'

    (root / "decision.signed.json").unlink()
    with pytest.raises(RuntimeError, match="decision"):
        read_signed_campaign_inputs(root)
    (root / "decision.signed.json").write_bytes(b"x" * (1024 * 1024 + 1))
    with pytest.raises(RuntimeError, match="decision"):
        read_signed_campaign_inputs(root)


def test_scored_inputs_reject_duplicate_policy_keys_and_linked_input(tmp_path: Path):
    root = tmp_path / "scored"
    _bundle(root)
    (root / "campaign-policy.json").write_text(
        '{"max_parallel_tasks":1,"max_parallel_tasks":2}', encoding="utf-8"
    )
    with pytest.raises(RuntimeError, match="campaign-policy"):
        read_signed_campaign_inputs(root)
    (root / "campaign-policy.json").write_text('{"max_parallel_tasks":1}', encoding="utf-8")
    target = root / "original.json"
    target.write_bytes(b"signed:decision")
    (root / "decision.signed.json").unlink()
    (root / "decision.signed.json").symlink_to(target)
    with pytest.raises(RuntimeError, match="decision"):
        read_signed_campaign_inputs(root)


def test_scored_admission_passes_exact_signed_bytes_without_signing(tmp_path: Path, monkeypatch):
    import nooa_cybergym.leaderboard.scored_campaign_inputs as module

    root = tmp_path / "scored"
    _bundle(root)
    inputs = read_signed_campaign_inputs(root)
    calls = []
    authority = object()
    evidence = tmp_path / "ledger"
    evidence.mkdir()
    monkeypatch.setattr(
        module,
        "check_go_live",
        lambda **kw: calls.append(kw) or "verified-state",
    )
    assert (
        admit_signed_campaign(
            inputs,
            authority=authority,
            run_id="scored-1",
            evidence_root=evidence,
        )
        == "verified-state"
    )
    assert len(calls) == 1
    assert calls[0]["decision"] == b"signed:decision"
    assert calls[0]["cohort"] == b"signed:cohort"
    assert calls[0]["authority"] is authority
    assert calls[0]["run_id"] == "scored-1"
    assert calls[0]["evidence_root"] == evidence
    assert calls[0]["campaign_policy"] == json.loads('{"max_parallel_tasks":1}')
