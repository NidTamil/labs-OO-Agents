# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Completed capability rows are raw facts, never readiness gate decisions."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from dataclasses import asdict, replace
from uuid import uuid4

import pytest
from nooa_cybergym.leaderboard.capabilities import (
    AuthorizationEvent,
    Capability,
    CapabilityRegistry,
    CapabilityRequest,
    ControlLabel,
    Effect,
    Role,
    Status,
    ToolIdentity,
)
from nooa_cybergym.leaderboard.native_hook_runtime import project_hook_input
from nooa_cybergym.leaderboard.raw_capability_projection import (
    project_fixture_capability_uses,
    project_pair_capability_uses,
)
from nooa_cybergym.leaderboard.raw_pair_manifest import build_raw_pair_manifest
from nooa_cybergym.leaderboard.subset_readiness_inventory import load_subset_readiness_inventory
from xeus_cybergym.canonical import canonical_json

TASK = "synthetic:chunk-table"
ATTEMPT = "attempt-one"


def _registry() -> CapabilityRegistry:
    entries = []
    for capability_id, tool_id, route in (
        ("cap.read", "Read", "local/files"),
        ("cap.advisory", "advisory__local_read", "local/advisory"),
    ):
        entries.append(
            Capability(
                capability_id,
                ToolIdentity(
                    "synthetic-service",
                    "1",
                    "a" * 64,
                    tool_id,
                    "1",
                    "b" * 64,
                    "synthetic-adapter",
                    "1",
                    "c" * 64,
                ),
                "read",
                Status.APPROVED,
                ControlLabel.PERFORMANCE_OPTIMISATION,
                "Synthetic read-only evidence",
                (Role.CHILD,),
                (Effect.READ,),
                ("synthetic-task-data",),
                (),
                (route,),
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


def _allowed(
    entry: Capability,
    *,
    request_id: str,
    invocation_id: str,
    task_id: str = TASK,
    attempt_id: str = ATTEMPT,
) -> dict:
    request = CapabilityRequest(
        entry.capability_id,
        entry.identity.tool_id,
        entry.identity,
        entry.operation,
        entry.identity.adapter_digest,
        entry.effects,
        entry.data_scopes,
        (),
        entry.routes,
        (),
        (),
        task_id,
        attempt_id,
        request_id,
        invocation_id,
    )
    return asdict(
        AuthorizationEvent(
            "",
            entry.capability_id,
            entry.identity.tool_id,
            entry.operation,
            Role.CHILD,
            task_id,
            attempt_id,
            request_id,
            "allowed",
            "approved audited operation within declared scope",
            request,
        )
    )


def _write_audit(root, events, *, task_id=TASK, attempt_id=ATTEMPT):
    prior = "0" * 64
    rows = []
    for sequence, event in enumerate(events, 1):
        body = {
            "sequence": sequence,
            "previous_sha256": prior,
            "timestamp": "2026-10-21T00:00:00Z",
            "task_id": task_id,
            "attempt_id": attempt_id,
            "event": event,
        }
        digest = hashlib.sha256(canonical_json(body)).hexdigest()
        rows.append(canonical_json({**body, "sha256": digest}))
        prior = digest
    (root / "runtime-events.jsonl").write_bytes(b"\n".join(rows) + b"\n")


def _fixture(
    root,
    registry,
    *,
    task_id=TASK,
    attempt_id=ATTEMPT,
    included=("native", "advisory"),
    suffix="1",
):
    root.mkdir()
    approved = {entry.capability_id: entry for entry in registry.entries}
    events = [
        *(
            [
                _allowed(
                    approved["cap.read"],
                    request_id=f"model-{suffix}",
                    invocation_id=f"native-{suffix}",
                    task_id=task_id,
                    attempt_id=attempt_id,
                )
            ]
            if "native" in included
            else []
        ),
        *(
            [
                _allowed(
                    approved["cap.advisory"],
                    request_id=f"advisory-{suffix}",
                    invocation_id=f"advisory-{suffix}",
                    task_id=task_id,
                    attempt_id=attempt_id,
                )
            ]
            if "advisory" in included
            else []
        ),
        {"event": "synthetic_oracle_observed", "oracle_true": True, "evidence_sha256": "e" * 64},
        {"event": "memory_oracle_episode_written", "actor": "controller"},
    ]
    for event in events:
        if event.get("disposition") == "allowed":
            event["registry_digest"] = registry.digest
    _write_audit(root, events, task_id=task_id, attempt_id=attempt_id)
    (root / "result.json").write_bytes(
        canonical_json({"task_id": task_id, "attempt_id": attempt_id})
    )
    with sqlite3.connect(root / "native-tools.sqlite") as db:
        db.executescript("""
            CREATE TABLE identity(id INTEGER PRIMARY KEY, value BLOB NOT NULL);
            CREATE TABLE requests(id TEXT PRIMARY KEY, session TEXT NOT NULL,
                                  agent TEXT NOT NULL, role TEXT NOT NULL,
                                  roster BLOB NOT NULL, native_roster BLOB NOT NULL,
                                  schema_drift BLOB NOT NULL, payload BLOB NOT NULL);
            CREATE TABLE tools(id TEXT PRIMARY KEY, request TEXT NOT NULL,
                               name TEXT NOT NULL, input BLOB NOT NULL,
                               input_hash TEXT NOT NULL, status TEXT NOT NULL, result BLOB);
            CREATE TABLE request_lifecycle(request TEXT PRIMARY KEY, status TEXT NOT NULL);
        """)
        db.execute(
            "INSERT INTO identity VALUES(1,?)",
            (
                canonical_json(
                    {
                        "run_id": "synthetic-run",
                        "task_id": task_id,
                        "attempt_id": attempt_id,
                        "launch_id": "synthetic-launch",
                    }
                ),
            ),
        )
        if "native" in included:
            db.execute(
                "INSERT INTO requests VALUES(?,?,?,?,?,?,?,?)",
                (f"model-{suffix}", f"session-{suffix}", "", "child", b"[]", b"[]", b"[]", b"{}"),
            )
            db.execute(
                "INSERT INTO request_lifecycle VALUES(?,?)",
                (f"model-{suffix}", "completed"),
            )
            db.execute(
                "INSERT INTO tools VALUES(?,?,?,?,?,?,?)",
                (
                    f"native-{suffix}",
                    f"model-{suffix}",
                    "Read",
                    b"{}",
                    hashlib.sha256(b"{}").hexdigest(),
                    "completed",
                    canonical_json(
                        {
                            "hook_event_name": "PostToolUse",
                            "tool_use_id": f"native-{suffix}",
                            "tool_name": "Read",
                            "session_id": f"session-{suffix}",
                            "agent_id": "",
                            "tool_input": {},
                        }
                    ),
                ),
            )
    with sqlite3.connect(root / "native-hooks.sqlite") as db:
        db.executescript("""
            CREATE TABLE identity(id INTEGER PRIMARY KEY, value BLOB NOT NULL);
            CREATE TABLE events(sequence INTEGER PRIMARY KEY, payload BLOB NOT NULL);
            CREATE TABLE tools(session TEXT NOT NULL, agent TEXT NOT NULL, id TEXT NOT NULL,
                               name TEXT NOT NULL, closed INTEGER NOT NULL);
        """)
        db.execute(
            "INSERT INTO identity VALUES(1,?)",
            (
                canonical_json(
                    {"run_id": "synthetic-run", "task_id": task_id, "launch_id": "synthetic-launch"}
                ),
            ),
        )
        if "native" in included:
            db.execute(
                "INSERT INTO tools VALUES(?,?,?,?,?)",
                (f"session-{suffix}", "", f"native-{suffix}", "Read", 1),
            )
            for sequence, kind in enumerate(("PreToolUse", "PostToolUse"), 1):
                hook = project_hook_input(
                    {
                        "hook_event_name": kind,
                        "tool_use_id": f"native-{suffix}",
                        "tool_name": "Read",
                        "session_id": f"session-{suffix}",
                        "tool_input": {},
                        "cwd": "/workspace",
                        "transcript_path": "/home/agent/.claude/projects/synthetic.jsonl",
                    }
                )
                db.execute(
                    "INSERT INTO events VALUES(?,?)",
                    (
                        sequence,
                        canonical_json(
                            {
                                "schema_version": 1,
                                "run_id": "synthetic-run",
                                "task_id": task_id,
                                "launch_id": "synthetic-launch",
                                "event_id": str(uuid4()),
                                "hook": hook,
                            }
                        ),
                    ),
                )
    with sqlite3.connect(root / "advisory.sqlite") as db:
        db.executescript("""
            CREATE TABLE identity(id INTEGER PRIMARY KEY, payload BLOB NOT NULL);
            CREATE TABLE roles(role TEXT PRIMARY KEY, status TEXT NOT NULL);
            CREATE TABLE events(sequence INTEGER PRIMARY KEY, role TEXT NOT NULL,
                                event TEXT NOT NULL, payload BLOB NOT NULL);
        """)
        db.execute(
            "INSERT INTO identity VALUES(1,?)",
            (
                canonical_json(
                    {
                        "run_id": "synthetic-run",
                        "task_id": task_id,
                        "attempt_id": attempt_id,
                        "launch_id": "synthetic-launch",
                    }
                ),
            ),
        )
        if "advisory" in included:
            action = {"action": "local_read", "arguments": {}}
            observation = {
                "action_id": f"advisory-{suffix}",
                "provider_request_id": f"provider-{suffix}",
                "task_id": task_id,
                "attempt_id": attempt_id,
                "role": "independent_recon",
                "name": "local_read",
                "arguments_sha256": hashlib.sha256(canonical_json({})).hexdigest(),
            }
            db.execute("INSERT INTO roles VALUES(?,?)", ("independent_recon", "complete"))
            db.execute(
                "INSERT INTO events VALUES(?,?,?,?)",
                (
                    1,
                    "independent_recon",
                    "model_response",
                    canonical_json(
                        {
                            "provider_request_id": f"provider-{suffix}",
                            "content": canonical_json(action).decode(),
                        }
                    ),
                ),
            )
            db.execute(
                "INSERT INTO events VALUES(?,?,?,?)",
                (
                    2,
                    "independent_recon",
                    "tool_requested",
                    canonical_json({**action, "observation": observation}),
                ),
            )
            db.execute(
                "INSERT INTO events VALUES(?,?,?,?)",
                (
                    3,
                    "independent_recon",
                    "tool_result",
                    canonical_json(
                        {
                            "action": "local_read",
                            "arguments": {},
                            "result": {},
                            "observation": observation,
                        }
                    ),
                ),
            )
    return events


def test_projection_derives_exact_immutable_rows_from_completed_results(tmp_path):
    registry = _registry()
    _fixture(tmp_path / "fixture", registry)

    facts = project_fixture_capability_uses(
        tmp_path / "fixture",
        registry=registry,
        expected_registry_sha256=registry.digest,
        task_id=TASK,
        attempt_id=ATTEMPT,
    )

    assert facts.task_id == TASK
    assert facts.attempt_id == ATTEMPT
    assert tuple(asdict(row) for row in facts.rows) == (
        {
            "capability_id": "cap.advisory",
            "tool_id": "advisory__local_read",
            "authorized_routes": ("local/advisory",),
            "authorized_role": "child",
            "count": 1,
            "provider_input_hash_verified": False,
        },
        {
            "capability_id": "cap.read",
            "tool_id": "Read",
            "authorized_routes": ("local/files",),
            "authorized_role": "child",
            "count": 1,
            "provider_input_hash_verified": False,
        },
    )
    assert facts.completed_capability_ids == frozenset({"cap.read", "cap.advisory"})
    assert not hasattr(facts, "verified")
    assert not hasattr(facts, "gates")


def _inventory(tmp_path, registry, *, second_capability="advisory"):
    repetitions = []
    manifests = {}
    fixture_paths = {}
    for run_index, run_id in enumerate(("repeat-one", "repeat-two"), 1):
        run_root = tmp_path / run_id
        run_root.mkdir()
        fixtures = {}
        for fixture_index, task_id in enumerate(("synthetic:length-header", TASK), 1):
            attempt_id = f"attempt-{run_index}-{fixture_index}"
            root = run_root / f"fixture-{fixture_index}"
            included = ("native",) if fixture_index == 1 else (second_capability,)
            _fixture(
                root,
                registry,
                task_id=task_id,
                attempt_id=attempt_id,
                included=included,
                suffix=f"{run_index}-{fixture_index}",
            )
            fixtures[task_id] = root
            fixture_paths[(run_id, task_id)] = root
        manifest = canonical_json(build_raw_pair_manifest(run_id, fixtures))
        manifests[run_id] = manifest
        repetitions.append(
            {
                "run_id": run_id,
                "root": str(run_root),
                "pair_manifest_sha256": hashlib.sha256(manifest).hexdigest(),
                "fixtures": {task_id: str(root) for task_id, root in fixtures.items()},
                "files": [
                    {
                        "path": path.relative_to(run_root).as_posix(),
                        "bytes": path.stat().st_size,
                        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                    }
                    for path in sorted(run_root.rglob("*"))
                    if path.is_file()
                ],
            }
        )
    controls = []
    for kind in (
        "primary_takeover",
        "interruption_reconnection",
        "timeout_failure",
        "version_drift",
        "memory_write_denial",
    ):
        root = tmp_path / kind
        root.mkdir()
        raw = canonical_json({"kind": kind})
        (root / "control.json").write_bytes(raw)
        controls.append(
            {
                "kind": kind,
                "control_id": f"control-{kind}",
                "root": str(root),
                "files": [
                    {
                        "path": "control.json",
                        "bytes": len(raw),
                        "sha256": hashlib.sha256(raw).hexdigest(),
                    }
                ],
            }
        )
    descriptor = canonical_json(
        {
            "schema_version": 1,
            "scope": "subset_raw_readiness_inventory",
            "repetitions": repetitions,
            "controls": controls,
        }
    )
    inventory = load_subset_readiness_inventory(
        descriptor,
        expected_sha256=hashlib.sha256(descriptor).hexdigest(),
        pair_manifests=manifests,
        deadline_monotonic=time.monotonic() + 60,
    )
    return inventory, fixture_paths


def test_pair_projection_rejects_registry_without_signed_35_id_baseline(tmp_path):
    registry = _registry()
    inventory, _ = _inventory(tmp_path, registry)

    with pytest.raises(ValueError, match="independently bound pair"):
        project_pair_capability_uses(
            inventory,
            run_id="repeat-one",
            registry=registry,
            expected_registry_sha256=registry.digest,
            fixture_attempt_ids={"synthetic:length-header": "attempt-1-1", TASK: "attempt-1-2"},
            expected_approved_capability_ids=frozenset({"cap.read", "cap.advisory"}),
        )


def test_pair_projection_rejects_missing_approved_capability(tmp_path):
    registry = _registry()
    inventory, _ = _inventory(tmp_path, registry, second_capability="native")

    with pytest.raises(ValueError, match="coverage incomplete"):
        project_pair_capability_uses(
            inventory,
            run_id="repeat-one",
            registry=registry,
            expected_registry_sha256=registry.digest,
            fixture_attempt_ids={
                "synthetic:length-header": "attempt-1-1",
                TASK: "attempt-1-2",
            },
            expected_approved_capability_ids=frozenset(f"locked-{n}" for n in range(35)),
        )


@pytest.mark.parametrize(
    ("change", "reason"),
    (
        ("orphan_native", "lacks matching start"),
        ("orphan_advisory", "lacks allowed audit"),
        ("missing_native_result", "result absent"),
        ("duplicate_allowed_id", "invocation duplicated"),
        ("wrong_route", "scope differs"),
        ("wrong_role", "role differs"),
    ),
)
def test_projection_rejects_unjoined_or_mismatched_completion(tmp_path, change, reason):
    registry = _registry()
    root = tmp_path / "fixture"
    events = _fixture(root, registry)
    if change == "orphan_native":
        with sqlite3.connect(root / "native-tools.sqlite") as db:
            db.execute(
                "INSERT INTO tools VALUES(?,?,?,?,?,?,?)",
                (
                    "orphan",
                    "model-1",
                    "Read",
                    b"{}",
                    "f" * 64,
                    "completed",
                    canonical_json(
                        {
                            "hook_event_name": "PostToolUse",
                            "tool_use_id": "orphan",
                            "tool_name": "Read",
                            "session_id": "session-1",
                            "agent_id": "",
                        }
                    ),
                ),
            )
    elif change == "orphan_advisory":
        with sqlite3.connect(root / "advisory.sqlite") as db:
            action = {"action": "local_read", "arguments": {}}
            observation = {
                "action_id": "orphan",
                "provider_request_id": "provider-orphan",
                "task_id": TASK,
                "attempt_id": ATTEMPT,
                "role": "independent_recon",
                "name": "local_read",
                "arguments_sha256": hashlib.sha256(canonical_json({})).hexdigest(),
            }
            for sequence, event, payload in (
                (
                    4,
                    "model_response",
                    {
                        "provider_request_id": "provider-orphan",
                        "content": canonical_json(action).decode(),
                    },
                ),
                (5, "tool_requested", {**action, "observation": observation}),
                (6, "tool_result", {**action, "observation": observation, "result": {}}),
            ):
                db.execute(
                    "INSERT INTO events VALUES(?,?,?,?)",
                    (sequence, "independent_recon", event, canonical_json(payload)),
                )
    elif change == "missing_native_result":
        with sqlite3.connect(root / "native-tools.sqlite") as db:
            db.execute("UPDATE tools SET result=NULL WHERE id='native-1'")
    else:
        if change == "duplicate_allowed_id":
            events.insert(1, events[0].copy())
        elif change == "wrong_route":
            events[0]["request"]["routes"] = ["unapproved/route"]
        else:
            events[0]["role"] = "parent"
        _write_audit(root, events)

    with pytest.raises(ValueError, match=reason):
        project_fixture_capability_uses(
            root,
            registry=registry,
            expected_registry_sha256=registry.digest,
            task_id=TASK,
            attempt_id=ATTEMPT,
        )


def test_pair_projection_rechecks_inventory_after_interpretation(tmp_path):
    registry = _registry()
    inventory, paths = _inventory(tmp_path, registry)
    target = paths[("repeat-one", TASK)] / "result.json"
    target.write_bytes(canonical_json({"changed": True}))

    with pytest.raises(ValueError, match="changed"):
        project_pair_capability_uses(
            inventory,
            run_id="repeat-one",
            registry=registry,
            expected_registry_sha256=registry.digest,
            fixture_attempt_ids={
                "synthetic:length-header": "attempt-1-1",
                TASK: "attempt-1-2",
            },
            expected_approved_capability_ids=frozenset(f"locked-{n}" for n in range(35)),
        )


def test_projection_rejects_gap_in_advisory_result_sequence(tmp_path):
    registry = _registry()
    root = tmp_path / "fixture"
    _fixture(root, registry)
    with sqlite3.connect(root / "advisory.sqlite") as db:
        db.execute("UPDATE events SET sequence=4 WHERE sequence=3")

    with pytest.raises(ValueError, match="advisory event sequence"):
        project_fixture_capability_uses(
            root,
            registry=registry,
            expected_registry_sha256=registry.digest,
            task_id=TASK,
            attempt_id=ATTEMPT,
        )


def test_projection_rejects_result_without_advisory_request(tmp_path):
    registry = _registry()
    root = tmp_path / "fixture"
    _fixture(root, registry)
    with sqlite3.connect(root / "advisory.sqlite") as db:
        db.execute("DELETE FROM events WHERE event='tool_requested'")
        db.execute("UPDATE events SET sequence=2 WHERE sequence=3")
    with pytest.raises(ValueError, match="advisory.*requested"):
        project_fixture_capability_uses(
            root,
            registry=registry,
            expected_registry_sha256=registry.digest,
            task_id=TASK,
            attempt_id=ATTEMPT,
        )


def test_projection_rejects_native_result_without_input_and_start(tmp_path):
    registry = _registry()
    root = tmp_path / "fixture"
    _fixture(root, registry, included=("native",))
    with sqlite3.connect(root / "native-tools.sqlite") as db:
        db.execute(
            "UPDATE tools SET result=? WHERE id='native-1'",
            (
                canonical_json(
                    {
                        "hook_event_name": "PostToolUse",
                        "tool_use_id": "native-1",
                        "tool_name": "Read",
                        "session_id": "session-1",
                        "agent_id": "",
                    }
                ),
            ),
        )
    with pytest.raises(ValueError, match="native.*(input|start)"):
        project_fixture_capability_uses(
            root,
            registry=registry,
            expected_registry_sha256=registry.digest,
            task_id=TASK,
            attempt_id=ATTEMPT,
        )


def test_projection_rejects_empty_path_for_scoped_capability(tmp_path):
    entries = list(_registry().entries)
    entries = [
        replace(entry, path_scopes=("/workspace",)) if entry.capability_id == "cap.read" else entry
        for entry in entries
    ]
    registry = CapabilityRegistry(tuple(entries))
    root = tmp_path / "fixture"
    _fixture(root, registry, included=("native",))
    with pytest.raises(ValueError, match="path"):
        project_fixture_capability_uses(
            root,
            registry=registry,
            expected_registry_sha256=registry.digest,
            task_id=TASK,
            attempt_id=ATTEMPT,
        )


def test_projection_preserves_unfinished_native_disposition(tmp_path):
    registry = _registry()
    root = tmp_path / "fixture"
    _fixture(root, registry, included=("native",))
    with sqlite3.connect(root / "native-tools.sqlite") as db:
        db.execute("UPDATE tools SET status='allowed',result=NULL WHERE id='native-1'")
    with sqlite3.connect(root / "native-hooks.sqlite") as db:
        db.execute("DELETE FROM events WHERE sequence=2")
        db.execute("UPDATE tools SET closed=0 WHERE id='native-1'")
    facts = project_fixture_capability_uses(
        root,
        registry=registry,
        expected_registry_sha256=registry.digest,
        task_id=TASK,
        attempt_id=ATTEMPT,
    )
    assert facts.rows == ()
    assert tuple((item.invocation_id, item.source, item.status) for item in facts.noncompleted) == (
        ("native-1", "native", "allowed"),
    )


@pytest.mark.parametrize("status", ("observed", "denied", "dispatched"))
def test_projection_preserves_other_native_noncompletion_dispositions(tmp_path, status):
    registry = _registry()
    root = tmp_path / "fixture"
    _fixture(root, registry, included=("native",))
    with sqlite3.connect(root / "native-tools.sqlite") as db:
        db.execute("UPDATE tools SET status=?,result=NULL WHERE id='native-1'", (status,))
    with sqlite3.connect(root / "native-hooks.sqlite") as db:
        db.execute("DELETE FROM events WHERE sequence=2")
        db.execute("UPDATE tools SET closed=0 WHERE id='native-1'")
    facts = project_fixture_capability_uses(
        root,
        registry=registry,
        expected_registry_sha256=registry.digest,
        task_id=TASK,
        attempt_id=ATTEMPT,
    )
    assert facts.rows == ()
    assert ("native-1", "native", status) in {
        (item.invocation_id, item.source, item.status) for item in facts.noncompleted
    }


def test_projection_rejects_uri_fragment_path_confusion(tmp_path):
    registry = _registry()
    root = tmp_path / "fixture#other"
    _fixture(root, registry, included=("native",))
    facts = project_fixture_capability_uses(
        root,
        registry=registry,
        expected_registry_sha256=registry.digest,
        task_id=TASK,
        attempt_id=ATTEMPT,
    )
    assert facts.completed_capability_ids == frozenset({"cap.read"})


def test_projection_rejects_native_input_hash_mismatch(tmp_path):
    registry = _registry()
    root = tmp_path / "fixture"
    _fixture(root, registry, included=("native",))
    with sqlite3.connect(root / "native-tools.sqlite") as db:
        db.execute("UPDATE tools SET input_hash=? WHERE id='native-1'", ("f" * 64,))
    with pytest.raises(ValueError, match="native result input"):
        project_fixture_capability_uses(
            root,
            registry=registry,
            expected_registry_sha256=registry.digest,
            task_id=TASK,
            attempt_id=ATTEMPT,
        )


def test_projection_marks_redacted_native_input_hash_unverified(tmp_path):
    registry = _registry()
    root = tmp_path / "fixture"
    _fixture(root, registry, included=("native",))
    original = canonical_json({"secret": "hidden-value"})
    redacted = canonical_json({"secret": "[REDACTED]"})
    with sqlite3.connect(root / "native-tools.sqlite") as db:
        result = json.loads(
            db.execute("SELECT result FROM tools WHERE id='native-1'").fetchone()[0]
        )
        result["tool_input"] = {"secret": "[REDACTED]"}
        db.execute(
            "UPDATE tools SET input=?,input_hash=?,result=? WHERE id='native-1'",
            (redacted, hashlib.sha256(original).hexdigest(), canonical_json(result)),
        )
    facts = project_fixture_capability_uses(
        root,
        registry=registry,
        expected_registry_sha256=registry.digest,
        task_id=TASK,
        attempt_id=ATTEMPT,
    )
    assert facts.completed_capability_ids == frozenset({"cap.read"})
    assert facts.rows[0].provider_input_hash_verified is False


def test_projection_rejects_native_completion_without_hook_start(tmp_path):
    registry = _registry()
    root = tmp_path / "fixture"
    _fixture(root, registry, included=("native",))
    with sqlite3.connect(root / "native-hooks.sqlite") as db:
        db.execute("DELETE FROM events WHERE sequence=1")
        db.execute("UPDATE events SET sequence=1 WHERE sequence=2")
    with pytest.raises(ValueError, match="native hook completion lacks matching start"):
        project_fixture_capability_uses(
            root,
            registry=registry,
            expected_registry_sha256=registry.digest,
            task_id=TASK,
            attempt_id=ATTEMPT,
        )


def test_projection_rejects_failure_hook_as_native_success(tmp_path):
    registry = _registry()
    root = tmp_path / "fixture"
    _fixture(root, registry, included=("native",))
    with sqlite3.connect(root / "native-hooks.sqlite") as db:
        observed = json.loads(
            db.execute("SELECT payload FROM events WHERE sequence=2").fetchone()[0]
        )
        observed["hook"]["hook_event_name"] = "PostToolUseFailure"
        db.execute("UPDATE events SET payload=? WHERE sequence=2", (canonical_json(observed),))
    with pytest.raises(ValueError, match="success hook"):
        project_fixture_capability_uses(
            root,
            registry=registry,
            expected_registry_sha256=registry.digest,
            task_id=TASK,
            attempt_id=ATTEMPT,
        )


def test_projection_preserves_failed_native_hook_disposition(tmp_path):
    registry = _registry()
    root = tmp_path / "fixture"
    _fixture(root, registry, included=("native",))
    with sqlite3.connect(root / "native-tools.sqlite") as db:
        result = json.loads(
            db.execute("SELECT result FROM tools WHERE id='native-1'").fetchone()[0]
        )
        result["hook_event_name"] = "PostToolUseFailure"
        db.execute(
            "UPDATE tools SET status='failed',result=? WHERE id='native-1'",
            (canonical_json(result),),
        )
    with sqlite3.connect(root / "native-hooks.sqlite") as db:
        event = json.loads(db.execute("SELECT payload FROM events WHERE sequence=2").fetchone()[0])
        event["hook"]["hook_event_name"] = "PostToolUseFailure"
        db.execute("UPDATE events SET payload=? WHERE sequence=2", (canonical_json(event),))
    facts = project_fixture_capability_uses(
        root,
        registry=registry,
        expected_registry_sha256=registry.digest,
        task_id=TASK,
        attempt_id=ATTEMPT,
    )
    assert facts.rows == ()
    assert ("native-1", "native", "failed") in {
        (item.invocation_id, item.source, item.status) for item in facts.noncompleted
    }


def test_projection_rejects_cross_session_native_hook_join(tmp_path):
    registry = _registry()
    root = tmp_path / "fixture"
    _fixture(root, registry, included=("native",))
    with sqlite3.connect(root / "native-hooks.sqlite") as db:
        for sequence in (1, 2):
            event = json.loads(
                db.execute("SELECT payload FROM events WHERE sequence=?", (sequence,)).fetchone()[0]
            )
            event["hook"]["session_id"] = "other-session"
            db.execute(
                "UPDATE events SET payload=? WHERE sequence=?", (canonical_json(event), sequence)
            )
        db.execute("UPDATE tools SET session='other-session' WHERE id='native-1'")
    with pytest.raises(ValueError, match="native completion.*hook"):
        project_fixture_capability_uses(
            root,
            registry=registry,
            expected_registry_sha256=registry.digest,
            task_id=TASK,
            attempt_id=ATTEMPT,
        )


def test_projection_allows_same_hook_tool_id_in_other_session(tmp_path):
    registry = _registry()
    root = tmp_path / "fixture"
    _fixture(root, registry, included=("native",))
    with sqlite3.connect(root / "native-hooks.sqlite") as db:
        original = json.loads(
            db.execute("SELECT payload FROM events WHERE sequence=1").fetchone()[0]
        )
        original["hook"]["session_id"] = "other-session"
        original["event_id"] = str(uuid4())
        db.execute("INSERT INTO events VALUES(?,?)", (3, canonical_json(original)))
        db.execute(
            "INSERT INTO tools VALUES(?,?,?,?,?)", ("other-session", "", "native-1", "Read", 0)
        )
    facts = project_fixture_capability_uses(
        root,
        registry=registry,
        expected_registry_sha256=registry.digest,
        task_id=TASK,
        attempt_id=ATTEMPT,
    )
    assert facts.completed_capability_ids == frozenset({"cap.read"})


def test_projection_rejects_terminal_hook_without_native_tool_row(tmp_path):
    registry = _registry()
    root = tmp_path / "fixture"
    _fixture(root, registry, included=("native",))
    with sqlite3.connect(root / "native-hooks.sqlite") as db:
        for sequence, source_sequence in ((3, 1), (4, 2)):
            event = json.loads(
                db.execute(
                    "SELECT payload FROM events WHERE sequence=?", (source_sequence,)
                ).fetchone()[0]
            )
            event["event_id"] = str(uuid4())
            event["hook"]["tool_use_id"] = "extra-terminal"
            db.execute("INSERT INTO events VALUES(?,?)", (sequence, canonical_json(event)))
        db.execute(
            "INSERT INTO tools VALUES(?,?,?,?,?)",
            ("session-1", "", "extra-terminal", "Read", 1),
        )

    with pytest.raises(ValueError, match="terminal hook lacks native tool row"):
        project_fixture_capability_uses(
            root,
            registry=registry,
            expected_registry_sha256=registry.digest,
            task_id=TASK,
            attempt_id=ATTEMPT,
        )


@pytest.mark.parametrize("status", ("observed", "allowed", "denied", "dispatched"))
@pytest.mark.parametrize("terminal_kind", ("PostToolUse", "PostToolUseFailure"))
def test_projection_rejects_terminal_hook_with_unfinished_native_row(
    tmp_path, status, terminal_kind
):
    registry = _registry()
    root = tmp_path / "fixture"
    _fixture(root, registry, included=("native",))
    with sqlite3.connect(root / "native-tools.sqlite") as db:
        db.execute("UPDATE tools SET status=?,result=NULL WHERE id='native-1'", (status,))
    with sqlite3.connect(root / "native-hooks.sqlite") as db:
        event = json.loads(db.execute("SELECT payload FROM events WHERE sequence=2").fetchone()[0])
        event["hook"]["hook_event_name"] = terminal_kind
        db.execute("UPDATE events SET payload=? WHERE sequence=2", (canonical_json(event),))

    with pytest.raises(ValueError, match="native terminal hook status differs"):
        project_fixture_capability_uses(
            root,
            registry=registry,
            expected_registry_sha256=registry.digest,
            task_id=TASK,
            attempt_id=ATTEMPT,
        )


def test_projection_preserves_allowed_audit_without_producer_terminal(tmp_path):
    registry = _registry()
    root = tmp_path / "fixture"
    events = _fixture(root, registry, included=("native",))
    advisory = next(entry for entry in registry.entries if entry.capability_id == "cap.advisory")
    events.insert(1, _allowed(advisory, request_id="phantom", invocation_id="phantom"))
    events[1]["registry_digest"] = registry.digest
    _write_audit(root, events)
    facts = project_fixture_capability_uses(
        root,
        registry=registry,
        expected_registry_sha256=registry.digest,
        task_id=TASK,
        attempt_id=ATTEMPT,
    )
    assert ("phantom", "audit", "allowed_unmatched") in {
        (item.invocation_id, item.source, item.status) for item in facts.noncompleted
    }


def test_projection_rejects_advisory_launch_identity_mismatch(tmp_path):
    registry = _registry()
    root = tmp_path / "fixture"
    _fixture(root, registry, included=("advisory",))
    with sqlite3.connect(root / "advisory.sqlite") as db:
        identity = json.loads(db.execute("SELECT payload FROM identity WHERE id=1").fetchone()[0])
        identity["launch_id"] = "another-launch"
        db.execute("UPDATE identity SET payload=? WHERE id=1", (canonical_json(identity),))
    with pytest.raises(ValueError, match="advisory producer identity differs"):
        project_fixture_capability_uses(
            root,
            registry=registry,
            expected_registry_sha256=registry.digest,
            task_id=TASK,
            attempt_id=ATTEMPT,
        )


@pytest.mark.parametrize("corruption", ("provider", "role", "arguments"))
def test_projection_rejects_advisory_observation_mismatch(tmp_path, corruption):
    registry = _registry()
    root = tmp_path / "fixture"
    _fixture(root, registry, included=("advisory",))
    with sqlite3.connect(root / "advisory.sqlite") as db:
        raw = db.execute("SELECT payload FROM events WHERE sequence=2").fetchone()[0]
        requested = json.loads(raw)
        if corruption == "provider":
            requested["observation"]["provider_request_id"] = "unknown-provider"
        elif corruption == "role":
            requested["observation"]["role"] = "final_adversarial_critic"
        else:
            requested["observation"]["arguments_sha256"] = "f" * 64
        db.execute("UPDATE events SET payload=? WHERE sequence=2", (canonical_json(requested),))
    with pytest.raises(ValueError, match="advisory (observed action|tool requested)"):
        project_fixture_capability_uses(
            root,
            registry=registry,
            expected_registry_sha256=registry.digest,
            task_id=TASK,
            attempt_id=ATTEMPT,
        )


def test_projection_preserves_allowed_advisory_without_result(tmp_path):
    registry = _registry()
    root = tmp_path / "fixture"
    _fixture(root, registry, included=("advisory",))
    with sqlite3.connect(root / "advisory.sqlite") as db:
        db.execute("DELETE FROM events WHERE event='tool_result'")
        db.execute("UPDATE roles SET status='reserved' WHERE role='independent_recon'")
    facts = project_fixture_capability_uses(
        root,
        registry=registry,
        expected_registry_sha256=registry.digest,
        task_id=TASK,
        attempt_id=ATTEMPT,
    )
    assert facts.rows == ()
    assert tuple((item.invocation_id, item.source, item.status) for item in facts.noncompleted) == (
        ("advisory-1", "advisory", "requested_without_result"),
    )


def test_projection_rejects_duplicate_provider_action_key(tmp_path):
    registry = _registry()
    root = tmp_path / "fixture"
    _fixture(root, registry, included=("advisory",))
    with sqlite3.connect(root / "advisory.sqlite") as db:
        payload = json.loads(
            db.execute("SELECT payload FROM events WHERE sequence=1").fetchone()[0]
        )
        payload["content"] = '{"action":"undeclared","action":"local_read","arguments":{}}'
        db.execute("UPDATE events SET payload=? WHERE sequence=1", (canonical_json(payload),))
    with pytest.raises(ValueError, match="advisory provider action malformed"):
        project_fixture_capability_uses(
            root,
            registry=registry,
            expected_registry_sha256=registry.digest,
            task_id=TASK,
            attempt_id=ATTEMPT,
        )


def test_projection_rejects_one_advisory_response_reused_for_two_actions(tmp_path):
    registry = _registry()
    root = tmp_path / "fixture"
    events = _fixture(root, registry, included=("advisory",))
    advisory = next(entry for entry in registry.entries if entry.capability_id == "cap.advisory")
    second_allowed = _allowed(advisory, request_id="advisory-two", invocation_id="advisory-two")
    second_allowed["registry_digest"] = registry.digest
    events.insert(1, second_allowed)
    _write_audit(root, events)
    with sqlite3.connect(root / "advisory.sqlite") as db:
        requested = json.loads(
            db.execute("SELECT payload FROM events WHERE sequence=2").fetchone()[0]
        )
        requested["observation"]["action_id"] = "advisory-two"
        result = {**requested, "result": {}}
        db.execute(
            "INSERT INTO events VALUES(?,?,?,?)",
            (4, "independent_recon", "tool_requested", canonical_json(requested)),
        )
        db.execute(
            "INSERT INTO events VALUES(?,?,?,?)",
            (5, "independent_recon", "tool_result", canonical_json(result)),
        )
    with pytest.raises(ValueError, match="provider response.*reused"):
        project_fixture_capability_uses(
            root,
            registry=registry,
            expected_registry_sha256=registry.digest,
            task_id=TASK,
            attempt_id=ATTEMPT,
        )
