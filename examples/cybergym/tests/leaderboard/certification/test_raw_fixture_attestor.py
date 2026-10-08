# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tamper tests for the read-only native fixture evidence verifier."""

from __future__ import annotations

import hashlib
import json
import sqlite3

import pytest
from nooa_cybergym.leaderboard.capabilities import (
    Capability,
    CapabilityRegistry,
    ControlLabel,
    Effect,
    Role,
    Status,
    ToolIdentity,
)
from nooa_cybergym.leaderboard.raw_fixture_attestor import (
    RawEvidenceError,
    _evidence_child,
    verify_audit_chain,
    verify_completed_capability_uses,
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


def _registry():
    entries = []
    for name in ("Read", "Grep", "advisory__local_read"):
        identity = ToolIdentity(
            "synthetic-service",
            "1",
            "a" * 64,
            name,
            "1",
            "b" * 64,
            "synthetic-adapter",
            "1",
            "c" * 64,
        )
        entries.append(
            Capability(
                "cap." + name,
                identity,
                "read",
                Status.APPROVED,
                ControlLabel.PERFORMANCE_OPTIMISATION,
                "Synthetic evidence test",
                (Role.CHILD,),
                (Effect.READ,),
                ("synthetic-task-data",),
                (),
                (),
                (),
                (),
                (),
                "one call",
                "test-v1",
                ("synthetic-only",),
                "d" * 64,
            )
        )
    return CapabilityRegistry(tuple(entries))


def test_capability_use_requires_exact_completed_invocation(tmp_path):
    registry = _registry()

    def authorized(name, request_id, invocation_id):
        return {
            "registry_digest": registry.digest,
            "capability_id": "cap." + name,
            "tool_id": name,
            "role": "child",
            "task_id": "synthetic:chunk-table",
            "attempt_id": "attempt-one",
            "request_id": request_id,
            "disposition": "allowed",
            "request": {"request_id": request_id, "invocation_id": invocation_id},
        }

    events = [
        authorized("Read", "model-1", "tool-1"),
        authorized("Grep", "model-1", "tool-2"),
        authorized("advisory__local_read", "action-1", "action-1"),
        {"event": "synthetic_oracle_observed", "oracle_true": True, "evidence_sha256": "a" * 64},
        {"event": "memory_oracle_episode_written", "actor": "controller"},
    ]

    def write_events():
        rows = []
        prior = "0" * 64
        for index, event in enumerate(events, start=1):
            row = _row(index, prior, event)
            rows.append(row)
            prior = row["sha256"]
        (tmp_path / "runtime-events.jsonl").write_bytes(
            b"\n".join(canonical_json(row) for row in rows) + b"\n"
        )

    write_events()
    with sqlite3.connect(tmp_path / "native-tools.sqlite") as db:
        db.executescript("""
            CREATE TABLE requests(id TEXT PRIMARY KEY, role TEXT NOT NULL);
            CREATE TABLE tools(id TEXT PRIMARY KEY, request TEXT NOT NULL,
                               name TEXT NOT NULL, status TEXT NOT NULL);
            INSERT INTO requests VALUES('model-1','child');
            INSERT INTO tools VALUES('tool-1','model-1','Read','completed');
            INSERT INTO tools VALUES('tool-2','model-1','Grep','failed');
            INSERT INTO tools VALUES('tool-3','model-1','Grep','completed');
        """)
    with sqlite3.connect(tmp_path / "advisory.sqlite") as db:
        db.executescript("""
            CREATE TABLE events(role TEXT NOT NULL, event TEXT NOT NULL,
                                payload BLOB NOT NULL);
        """)
        db.execute(
            "INSERT INTO events VALUES(?,?,?)",
            (
                "independent_recon",
                "tool_result",
                canonical_json({"action": "local_read", "observation": {"action_id": "action-1"}}),
            ),
        )

    counts = verify_completed_capability_uses(
        tmp_path, registry=registry, task_id="synthetic:chunk-table", attempt_id="attempt-one"
    )
    assert counts == {"cap.Read": 1, "cap.advisory__local_read": 1}

    del events[0]["request"]["invocation_id"]
    write_events()
    with pytest.raises(RawEvidenceError, match="allowed capability audit identity invalid"):
        verify_completed_capability_uses(
            tmp_path,
            registry=registry,
            task_id="synthetic:chunk-table",
            attempt_id="attempt-one",
        )
