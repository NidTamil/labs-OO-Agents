# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tamper tests for the read-only native fixture evidence verifier."""

from __future__ import annotations

import hashlib
import json

import pytest
from nooa_cybergym.leaderboard.raw_fixture_attestor import (
    RawEvidenceError,
    _evidence_child,
    verify_audit_chain,
)
from xeus_cybergym.canonical import canonical_json


def _row(sequence, prior, event):
    row = {
        "sequence": sequence,
        "previous_sha256": prior,
        "task_id": "synthetic:chunk-table",
        "attempt_id": "attempt-one",
        "timestamp": "2026-10-08T00:00:00Z",
        "event": event,
    }
    row["sha256"] = hashlib.sha256(canonical_json(row)).hexdigest()
    return row


def test_chained_audit_requires_oracle_before_controller_memory(tmp_path):
    first = _row(
        1,
        "0" * 64,
        {"event": "synthetic_oracle_observed", "oracle_true": True, "evidence_sha256": "a" * 64},
    )
    second = _row(
        2,
        first["sha256"],
        {"event": "memory_oracle_episode_written", "actor": "controller"},
    )
    path = tmp_path / "runtime-events.jsonl"
    path.write_bytes(b"\n".join(canonical_json(row) for row in (first, second)) + b"\n")
    result = verify_audit_chain(path, task_id="synthetic:chunk-table", attempt_id="attempt-one")
    assert result.row_count == 2
    assert result.tail_sha256 == second["sha256"]


@pytest.mark.parametrize("change", ["digest", "sequence", "identity", "order"])
def test_chained_audit_rejects_tampering_and_claim_reordering(tmp_path, change):
    first = _row(
        1,
        "0" * 64,
        {"event": "synthetic_oracle_observed", "oracle_true": True, "evidence_sha256": "a" * 64},
    )
    second = _row(
        2,
        first["sha256"],
        {"event": "memory_oracle_episode_written", "actor": "controller"},
    )
    if change == "digest":
        first["sha256"] = "f" * 64
    elif change == "sequence":
        second["sequence"] = 3
    elif change == "identity":
        second["attempt_id"] = "attempt-other"
    else:
        first["event"], second["event"] = second["event"], first["event"]
        first["sha256"] = hashlib.sha256(
            canonical_json({k: v for k, v in first.items() if k != "sha256"})
        ).hexdigest()
        second["previous_sha256"] = first["sha256"]
        second["sha256"] = hashlib.sha256(
            canonical_json({k: v for k, v in second.items() if k != "sha256"})
        ).hexdigest()
    path = tmp_path / "runtime-events.jsonl"
    path.write_text("\n".join(json.dumps(row) for row in (first, second)) + "\n")
    with pytest.raises(RawEvidenceError):
        verify_audit_chain(path, task_id="synthetic:chunk-table", attempt_id="attempt-one")


def test_receipt_path_cannot_escape_evidence_root(tmp_path):
    root = tmp_path / "evidence"
    root.mkdir()
    child = root / "receipt.json"
    child.write_text("{}")
    assert _evidence_child(root, str(child)) == child
    with pytest.raises(RawEvidenceError):
        _evidence_child(root, str(root / ".." / "outside.json"))
    with pytest.raises(RawEvidenceError):
        _evidence_child(root, 7)
