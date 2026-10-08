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
from nooa_cybergym.leaderboard.preflight import _FORBIDDEN_ENV, _FORBIDDEN_PATHS
from nooa_cybergym.leaderboard.raw_fixture_attestor import (
    RawEvidenceError,
    _evidence_child,
    _verify_preflights,
    verify_audit_chain,
    verify_completed_capability_uses,
    verify_deepseek_model_usage,
    verify_primary_model_usage,
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


def test_native_preflight_checks_each_recorded_boundary_denial(tmp_path):
    negative = {
        *("path:" + path for path in _FORBIDDEN_PATHS),
        *("env:" + name for name in _FORBIDDEN_ENV),
        *(
            "route:" + name
            for name in (
                "external-target-repository",
                "external-target-patch",
                "target-issue-or-changelog",
                "cve-or-published-poc",
            )
        ),
    }
    names = sorted(negative) + [f"other:{index}" for index in range(62 - len(negative))]
    for index, context in enumerate(("parent", "child", "child")):
        location = tmp_path / "preflight" / str(index)
        location.mkdir(parents=True)
        (location / "report.json").write_bytes(
            canonical_json(
                {
                    "passed": True,
                    "execution_mode": "native",
                    "failures": [],
                    "contexts": [context],
                    "container_id": "container-one",
                    "probes": [
                        {
                            "name": name,
                            "passed": True,
                            "exit_code": 0,
                            "observed_context": context,
                            "observed_container_id": "container-one",
                        }
                        for name in names
                    ],
                }
            )
        )
    assert _verify_preflights(tmp_path) == 3

    path = tmp_path / "preflight" / "1" / "report.json"
    report = json.loads(path.read_bytes())
    next(probe for probe in report["probes"] if probe["name"] == "route:external-target-patch")[
        "name"
    ] = "other:substituted"
    path.write_bytes(canonical_json(report))
    with pytest.raises(RawEvidenceError, match="native isolation preflight invalid"):
        _verify_preflights(tmp_path)


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


def test_primary_model_totals_require_matching_request_and_usage_rows(tmp_path):
    request = {
        "task_id": "synthetic:chunk-table",
        "attempt_id": "attempt-one",
        "request_id": "model-1",
        "role": "primary",
        "configured_model": "glm-5.3[1m]",
    }
    reserved = {**request, "event": "request_reserved"}
    terminal = {
        **request,
        "event": "request_terminal",
        "outcome": "completed",
        "usage_status": "observed",
        "returned_model": "glm-5.3",
        "provider_request_id": "provider-1",
    }
    usage = {
        "event": "usage",
        "request_id": "model-1",
        "usage_status": "observed",
        "returned_model": "glm-5.3",
        "provider_request_id": "provider-1",
        "input_tokens": 10,
        "output_tokens": 3,
        "cache_read_tokens": 4,
        "cache_creation_tokens": 2,
        "counted_tokens": 19,
    }
    (tmp_path / "model-requests.jsonl").write_bytes(
        canonical_json(reserved) + b"\n" + canonical_json(terminal) + b"\n"
    )
    usage_path = tmp_path / "model-usage.jsonl"
    usage_path.write_bytes(canonical_json(usage) + b"\n")

    result = verify_primary_model_usage(
        tmp_path, task_id="synthetic:chunk-table", attempt_id="attempt-one"
    )
    assert result.completed_requests == 1
    assert result.incomplete_requests == 0
    assert (result.input_tokens, result.output_tokens, result.cache_tokens) == (10, 3, 6)
    assert result.provider_request_ids == ("provider-1",)

    usage["provider_request_id"] = "provider-other"
    usage_path.write_bytes(canonical_json(usage) + b"\n")
    with pytest.raises(RawEvidenceError, match="primary model usage mismatch"):
        verify_primary_model_usage(
            tmp_path, task_id="synthetic:chunk-table", attempt_id="attempt-one"
        )

    usage["provider_request_id"] = "provider-1"
    terminal["model_version"] = "release-one"
    usage["model_version"] = "release-other"
    (tmp_path / "model-requests.jsonl").write_bytes(
        canonical_json(reserved) + b"\n" + canonical_json(terminal) + b"\n"
    )
    usage_path.write_bytes(canonical_json(usage) + b"\n")
    with pytest.raises(RawEvidenceError, match="primary model usage mismatch"):
        verify_primary_model_usage(
            tmp_path, task_id="synthetic:chunk-table", attempt_id="attempt-one"
        )


def test_deepseek_roles_require_paired_requests_and_observed_tokens(tmp_path):
    registry_digest = "b" * 64
    policy_digest = "c" * 64
    roles = (
        "independent_recon",
        "conditional_debug_recovery",
        "final_adversarial_critic",
    )
    events = []
    for index, role in enumerate(roles, start=1):
        request = {
            "event": "request",
            "role": role,
            "task_id": "synthetic:chunk-table",
            "attempt_id": "attempt-one",
            "request_id": f"deepseek-{index}",
            "request_number": 1,
            "shared_request_number": index,
            "request_sha256": "e" * 64,
            "registry_digest": registry_digest,
            "policy_digest": policy_digest,
            "endpoint": "https://api.deepseek.com/chat/completions",
            "requested_model": "deepseek-flash",
            "request_settings": {
                "model": "deepseek-flash",
                "thinking": {"type": "enabled"},
                "reasoning_effort": "max",
                "max_tokens": 128000,
            },
            "failure_evidence_digest": "d" * 64 if role == "conditional_debug_recovery" else None,
        }
        events.append(request)
        events.append(
            {
                **request,
                "event": "response",
                "returned_model": "deepseek-flash",
                "provider_request_id": f"provider-{index}",
                "model_version": None,
                "system_fingerprint": None,
                "duration_seconds": 2.0,
                "http_status": 200,
                "usage": {
                    "input_tokens": 10,
                    "output_tokens": 3,
                    "counted_tokens": 13,
                    "cache_hit_input_tokens": 4,
                    "cache_miss_input_tokens": 6,
                    "reasoning_tokens": 1,
                    "provider_usage": {
                        "prompt_tokens": 10,
                        "completion_tokens": 3,
                        "total_tokens": 13,
                        "prompt_cache_hit_tokens": 4,
                        "prompt_cache_miss_tokens": 6,
                    },
                },
            }
        )
    events.extend(
        (
            {
                "event": "synthetic_oracle_observed",
                "oracle_true": True,
                "evidence_sha256": "a" * 64,
            },
            {"event": "memory_oracle_episode_written", "actor": "controller"},
        )
    )

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
    result = verify_deepseek_model_usage(
        tmp_path,
        task_id="synthetic:chunk-table",
        attempt_id="attempt-one",
        registry_sha256=registry_digest,
        policy_sha256=policy_digest,
    )
    assert set(result) == set(roles)
    assert all(item.requests == 1 and item.input_tokens == 10 for item in result.values())
    assert sum(item.cache_tokens for item in result.values()) == 12

    events[1]["usage"]["provider_usage"]["prompt_tokens"] = 11
    write_events()
    with pytest.raises(RawEvidenceError, match="DeepSeek usage mismatch"):
        verify_deepseek_model_usage(
            tmp_path,
            task_id="synthetic:chunk-table",
            attempt_id="attempt-one",
            registry_sha256=registry_digest,
            policy_sha256=policy_digest,
        )

    events[1]["usage"]["provider_usage"]["prompt_tokens"] = 10
    events[1]["request_sha256"] = "f" * 64
    write_events()
    with pytest.raises(RawEvidenceError, match="DeepSeek response identity mismatch"):
        verify_deepseek_model_usage(
            tmp_path,
            task_id="synthetic:chunk-table",
            attempt_id="attempt-one",
            registry_sha256=registry_digest,
            policy_sha256=policy_digest,
        )
