# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Synthetic recorded failures; no oracle, official task or provider execution."""

import hashlib
import json

import pytest
from nooa_cybergym.leaderboard.raw_fixture_attestor import RawEvidenceError
from xeus_cybergym.canonical import canonical_json

from . import test_raw_request_accounting as fixture

TASK, RUN = "arvo:47101", "synthetic-budget-run"


def write(root, *, empty=False, extra=(), advisory=False):
    events, requests, usage = fixture._fixture()
    advice = [event for event in events if event.get("role") == fixture.ROLES[0]]
    events = [
        event
        | {"event": "run_request_reserved", "run_id": RUN, "run_ordinal": event["task_ordinal"]}
        for event in events
        if event["event"] == "task_request_reserved"
        and event["task_ordinal"] <= (4 if advisory else 3)
    ]
    if advisory:
        events.extend(advice)
    if empty:
        events, requests, usage = [{"event": "controller_prepared"}], [], []
    events.extend(extra)
    fixture._write(root, events, requests, usage)
    # Rebind the synthetic log fixture to one official-shaped task identity.
    for name in ("runtime-events.jsonl", "model-requests.jsonl", "model-usage.jsonl"):
        raw = (root / name).read_bytes().replace(fixture.TASK.encode(), TASK.encode())
        if name == "runtime-events.jsonl":
            rows, previous = [], "0" * 64
            for line in raw.splitlines():
                row = json.loads(line)
                row.pop("sha256")
                row["previous_sha256"] = previous
                previous = hashlib.sha256(canonical_json(row)).hexdigest()
                rows.append(row | {"sha256": previous})
            raw = b"".join(canonical_json(row) + b"\n" for row in rows)
        (root / name).write_bytes(raw)


def inputs(root):
    return {
        "evidence_root": root,
        "task_id": TASK,
        "attempt_id": fixture.ATTEMPT,
        "takeover_policy": fixture.POLICY,
        "registry_sha256": "b" * 64,
        "alternate_policy_sha256": "c" * 64,
        "memory_model_bindings": fixture.BINDINGS,
        "budget_run_id": RUN,
    }


def test_pre_oracle_accounting_keeps_failed_attempts_without_inventing_oracle(tmp_path):
    from nooa_cybergym.leaderboard.raw_request_accounting import (
        VerifiedPreOracleAccounting,
        verify_pre_oracle_request_accounting,
        verify_request_accounting,
    )

    write(tmp_path)
    result = verify_pre_oracle_request_accounting(**inputs(tmp_path))
    assert type(result) is VerifiedPreOracleAccounting
    assert result.manifest["scope"] == "pre_oracle_attempt_accounting"
    assert result.manifest["totals"]["model_requests"] == 3
    assert result.manifest["totals"]["unknown_usage_requests"] == 1
    assert result.manifest["totals"]["unmatched_reservations"] == 0
    assert (
        not {"certification_gate_passed", "terminal", "cleanup_complete"} & result.manifest.keys()
    )
    with pytest.raises(RawEvidenceError, match="oracle"):
        verify_request_accounting(**inputs(tmp_path))


def test_zero_dispatch_is_accounting_only_and_requires_actual_runtime_chain(tmp_path):
    from nooa_cybergym.leaderboard.raw_request_accounting import (
        verify_pre_oracle_request_accounting,
    )

    write(tmp_path, empty=True)
    result = verify_pre_oracle_request_accounting(**inputs(tmp_path))
    assert result.manifest["totals"]["model_requests"] == 0
    (tmp_path / "runtime-events.jsonl").write_bytes(b"")
    with pytest.raises(RawEvidenceError):
        verify_pre_oracle_request_accounting(**inputs(tmp_path))


@pytest.mark.parametrize(
    "event",
    [
        "synthetic_oracle_observed",
        "memory_oracle_episode_attempted",
        "memory_oracle_episode_written",
        "post_oracle_memory_model_reserved",
    ],
)
def test_pre_oracle_path_rejects_oracle_and_post_oracle_activity(tmp_path, event):
    from nooa_cybergym.leaderboard.raw_request_accounting import (
        verify_pre_oracle_request_accounting,
    )

    write(tmp_path, extra=({"event": event},))
    with pytest.raises(RawEvidenceError, match="oracle"):
        verify_pre_oracle_request_accounting(**inputs(tmp_path))


@pytest.mark.parametrize(
    "mutation", ["tail", "attempt", "sequence", "no_run", "wrong_run", "synthetic_task"]
)
def test_exact_attempt_chain_and_run_reservations_are_required(tmp_path, mutation):
    from nooa_cybergym.leaderboard.raw_request_accounting import (
        verify_pre_oracle_request_accounting,
    )

    write(tmp_path)
    args = inputs(tmp_path)
    if mutation in {"tail", "attempt", "sequence"}:
        path = tmp_path / "runtime-events.jsonl"
        rows = [json.loads(line) for line in path.read_bytes().splitlines()]
        if mutation == "tail":
            rows[-1]["sha256"] = "f" * 64
        elif mutation == "attempt":
            rows[0]["attempt_id"] = "other"
        else:
            rows[0]["sequence"] = True
        path.write_bytes(b"".join(canonical_json(row) + b"\n" for row in rows))
    elif mutation == "no_run":
        args["budget_run_id"] = None
    elif mutation == "wrong_run":
        args["budget_run_id"] = "other"
    else:
        args["task_id"] = fixture.TASK
    with pytest.raises((RawEvidenceError, ValueError)):
        verify_pre_oracle_request_accounting(**args)


def test_partial_advisory_history_does_not_require_unperformed_roles(tmp_path):
    from nooa_cybergym.leaderboard.raw_request_accounting import (
        verify_pre_oracle_request_accounting,
    )

    write(tmp_path, advisory=True)
    report = verify_pre_oracle_request_accounting(**inputs(tmp_path)).manifest
    assert report["totals"]["model_requests"] == 4
    assert report["requests"][-1]["role"] == fixture.ROLES[0]
    assert report["requests"][-1]["usage_status"] == "observed"


def test_unmatched_debit_is_retained_as_unbounded_unknown_usage(tmp_path):
    from nooa_cybergym.leaderboard.raw_request_accounting import (
        verify_pre_oracle_request_accounting,
    )

    write(
        tmp_path,
        extra=(
            {
                "event": "run_request_reserved",
                "run_id": RUN,
                "run_ordinal": 4,
                "task_id": fixture.TASK,
                "attempt_id": fixture.ATTEMPT,
                "request_id": "undispatched",
                "task_ordinal": 4,
                "allocation": "primary_and_memory",
                "allocation_ordinal": 4,
            },
        ),
    )
    report = verify_pre_oracle_request_accounting(**inputs(tmp_path)).manifest
    assert report["totals"]["model_requests"] == 4
    assert report["totals"]["unknown_usage_requests"] == 2
    assert report["totals"]["unbounded_unknown_usage_requests"] == 1
    assert report["totals"]["unmatched_reservations"] == 1
    assert report["reconciled"] is False
    assert report["requests"][-1]["counted_tokens"] is None


def test_exact_captured_runtime_bytes_are_used_once_for_all_checks(tmp_path, monkeypatch):
    from nooa_cybergym.leaderboard import raw_fixture_attestor as raw
    from nooa_cybergym.leaderboard import raw_request_accounting as accounting

    write(tmp_path, advisory=True)
    reads = []
    original = raw._read

    def capture(path):
        if path.name == "runtime-events.jsonl":
            reads.append(path)
            assert len(reads) == 1, "accounting must never verify different runtime bytes"
        return original(path)

    monkeypatch.setattr(raw, "_read", capture)
    monkeypatch.setattr(accounting, "_read", capture)
    result = accounting.verify_pre_oracle_request_accounting(**inputs(tmp_path))
    assert len(reads) == 1
    assert (
        result.manifest["evidence_sha256"]["runtime-events.jsonl"]
        == hashlib.sha256(reads[0].read_bytes()).hexdigest()
    )


@pytest.mark.parametrize("event", [None, [], {}, 42, True])
def test_malformed_event_names_fail_closed(tmp_path, event):
    from nooa_cybergym.leaderboard.raw_request_accounting import (
        verify_pre_oracle_request_accounting,
    )

    write(tmp_path, extra=({"event": event},))
    with pytest.raises(RawEvidenceError):
        verify_pre_oracle_request_accounting(**inputs(tmp_path))


def test_empty_primary_log_cannot_hide_a_usage_row(tmp_path):
    from nooa_cybergym.leaderboard.raw_request_accounting import (
        verify_pre_oracle_request_accounting,
    )

    write(tmp_path, empty=True)
    (tmp_path / "model-usage.jsonl").write_bytes(canonical_json({"event": "usage"}) + b"\n")
    with pytest.raises(RawEvidenceError):
        verify_pre_oracle_request_accounting(**inputs(tmp_path))
