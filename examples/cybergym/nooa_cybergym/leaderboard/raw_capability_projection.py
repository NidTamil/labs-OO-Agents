# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Project authorization/completion correlations from native and advisory evidence.

These are fixture facts, not a capability gate or a readiness attestation.
Routes and roles here are authorization scopes, not observed effects or lanes.
The source evidence cannot independently prove every observed route/lane or
redacted input hash. A full twelve-gate interpreter requires a stronger producer
contract, signed source and registry pins, stopped writers, and independent
raw-byte custody; this module never returns PASS.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from collections import Counter
from collections.abc import Mapping
from contextlib import closing
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from uuid import UUID

from xeus_cybergym.canonical import canonical_json

from .advisory_runtime import _strict_json
from .capabilities import (
    Capability,
    CapabilityRegistry,
    CapabilityRequest,
    Effect,
    Role,
    Status,
    ToolIdentity,
)
from .native_hook_runtime import validate_projection
from .raw_fixture_attestor import _read, _verified_audit_rows, verify_audit_chain
from .subset_readiness_inventory import ReadinessInventory

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_ADVISORY_ROLES = frozenset(
    {"independent_recon", "conditional_debug_recovery", "final_adversarial_critic"}
)
_NATIVE_STATUSES = frozenset({"observed", "allowed", "denied", "dispatched", "completed", "failed"})
_FIXTURES = ("synthetic:length-header", "synthetic:chunk-table")
_REQUEST_KEYS = frozenset(
    {
        "capability_id",
        "tool_id",
        "identity",
        "operation",
        "adapter_digest",
        "effects",
        "data_scopes",
        "paths",
        "routes",
        "provider_ids",
        "model_ids",
        "task_id",
        "attempt_id",
        "request_id",
        "invocation_id",
    }
)
_EVENT_KEYS = frozenset(
    {
        "registry_digest",
        "capability_id",
        "tool_id",
        "operation",
        "role",
        "task_id",
        "attempt_id",
        "request_id",
        "disposition",
        "reason",
        "request",
    }
)


class RawCapabilityProjectionError(ValueError):
    """A completed capability use cannot be uniquely derived from raw evidence."""


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise RawCapabilityProjectionError(reason)


@dataclass(frozen=True, slots=True)
class CapabilityUse:
    """One authorized invocation correlated with a completed producer result."""

    capability_id: str
    tool_id: str
    authorized_routes: tuple[str, ...]
    authorized_role: str
    count: int
    provider_input_hash_verified: bool = False


@dataclass(frozen=True, slots=True)
class CapabilityDisposition:
    """A producer/audit lifecycle that did not yield a completed use fact."""

    invocation_id: str
    source: str
    status: str


@dataclass(frozen=True, slots=True)
class CapabilityFixtureProjection:
    task_id: str
    attempt_id: str
    registry_sha256: str
    rows: tuple[CapabilityUse, ...]
    completed_capability_ids: frozenset[str]
    noncompleted: tuple[CapabilityDisposition, ...]


@dataclass(frozen=True, slots=True)
class CapabilityPairProjection:
    run_id: str
    registry_sha256: str
    fixtures: tuple[CapabilityFixtureProjection, CapabilityFixtureProjection]
    completed_capability_ids: frozenset[str]


def _sequence(raw: Any, *, nonempty: bool = False) -> tuple[str, ...]:
    _require(
        type(raw) is list
        and (not nonempty or bool(raw))
        and all(type(item) is str and bool(item) for item in raw)
        and len(raw) == len(set(raw)),
        "authorization scope malformed",
    )
    return tuple(raw)


def _authorized_request(raw: Any, entry: Capability, *, task_id: str, attempt_id: str):
    _require(type(raw) is dict and set(raw) == _REQUEST_KEYS, "allowed request malformed")
    try:
        identity = ToolIdentity(**raw["identity"])
        request = CapabilityRequest(
            raw["capability_id"],
            raw["tool_id"],
            identity,
            raw["operation"],
            raw["adapter_digest"],
            tuple(Effect(value) for value in raw["effects"]),
            _sequence(raw["data_scopes"], nonempty=True),
            _sequence(raw["paths"]),
            _sequence(raw["routes"]),
            _sequence(raw["provider_ids"]),
            _sequence(raw["model_ids"]),
            raw["task_id"],
            raw["attempt_id"],
            raw["request_id"],
            raw["invocation_id"],
        )
    except (KeyError, TypeError, ValueError) as error:
        raise RawCapabilityProjectionError("allowed request malformed") from error
    _require(canonical_json(asdict(request)) == canonical_json(raw), "allowed request changed")
    _require(
        request.task_id == task_id
        and request.attempt_id == attempt_id
        and type(request.invocation_id) is str
        and bool(request.invocation_id)
        and request.capability_id == entry.capability_id
        and request.tool_id == entry.identity.tool_id
        and request.identity == entry.identity
        and request.operation == entry.operation
        and request.adapter_digest == entry.identity.adapter_digest,
        "allowed request identity differs",
    )
    for name in ("effects", "data_scopes", "routes", "provider_ids", "model_ids"):
        _require(
            set(getattr(request, name)) <= set(getattr(entry, name)),
            "allowed request scope differs",
        )
    _require(not entry.routes or bool(request.routes), "authorized route absent")
    _require(not entry.path_scopes or bool(request.paths), "scoped capability path absent")
    for path in request.paths:
        _require(
            any(path == root or path.startswith(root + "/") for root in entry.path_scopes),
            "allowed request path differs",
        )
    return request


def _allowed_events(
    rows: list[dict], registry: CapabilityRegistry, *, task_id: str, attempt_id: str
):
    approved = {
        entry.capability_id: entry for entry in registry.entries if entry.status is Status.APPROVED
    }
    result: dict[str, tuple[Capability, CapabilityRequest, Role]] = {}
    for row in rows:
        event = row["event"]
        if event.get("disposition") != "allowed":
            continue
        _require(type(event) is dict and set(event) == _EVENT_KEYS, "allowed event malformed")
        entry = approved.get(event.get("capability_id"))
        _require(entry is not None, "unapproved capability allowed")
        try:
            role = Role(event["role"])
        except (TypeError, ValueError) as error:
            raise RawCapabilityProjectionError("allowed role invalid") from error
        request = _authorized_request(
            event["request"], entry, task_id=task_id, attempt_id=attempt_id
        )
        _require(
            event["registry_digest"] == registry.digest
            and event["tool_id"] == entry.identity.tool_id
            and event["operation"] == entry.operation
            and event["task_id"] == task_id
            and event["attempt_id"] == attempt_id
            and event["request_id"] == request.request_id
            and event["reason"] == "approved audited operation within declared scope"
            and role in entry.roles,
            "allowed event identity or role differs",
        )
        _require(request.invocation_id not in result, "capability invocation duplicated")
        result[request.invocation_id] = (entry, request, role)
    return result


def _evidence_file(root: Path, name: str) -> Path:
    path = root / name
    _require(
        path.is_file() and not path.is_symlink() and path.resolve(strict=True) == path,
        "capability evidence file absent or linked",
    )
    return path


def _database(path: Path) -> sqlite3.Connection:
    _require(path.stat().st_size <= 512 * 1024 * 1024, "capability database too large")
    db = None
    try:
        db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
        main = [row[2] for row in db.execute("PRAGMA database_list") if row[1] == "main"]
        _require(
            len(main) == 1 and os.path.samefile(main[0], path),
            "capability database identity differs",
        )
        db.execute("PRAGMA query_only=ON")
        _require(
            db.execute("PRAGMA integrity_check").fetchall() == [("ok",)],
            "capability database integrity invalid",
        )
    except (OSError, sqlite3.DatabaseError, RawCapabilityProjectionError) as error:
        if db is not None:
            db.close()
        raise RawCapabilityProjectionError("capability database invalid") from error
    return db


def _result_payload(
    raw: Any,
    *,
    tool_id: str,
    name: str,
    session: str,
    agent: str,
    input_raw: bytes,
    input_hash: str,
    event_name: str,
) -> None:
    _require(
        type(raw) is bytes and 0 < len(raw) <= 4 * 1024 * 1024, "completed native result absent"
    )
    try:
        value = json.loads(raw)
        canonical = canonical_json(value)
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise RawCapabilityProjectionError("completed native result malformed") from error
    _require(
        canonical == raw
        and type(value) is dict
        and value.get("hook_event_name") == event_name
        and value.get("tool_use_id") == tool_id
        and value.get("tool_name") == name
        and value.get("session_id") == session
        and (value.get("agent_id") or "") == agent
        and type(value.get("tool_input")) is dict
        and canonical_json(value["tool_input"]) == input_raw
        and (hashlib.sha256(input_raw).hexdigest() == input_hash or b"[REDACTED]" in input_raw),
        "completed native result input or identity differs",
    )


def _canonical_object(raw: Any, reason: str) -> dict:
    _require(type(raw) is bytes and 0 < len(raw) <= 4 * 1024 * 1024, reason)
    try:
        value = json.loads(raw)
        _require(type(value) is dict and canonical_json(value) == raw, reason)
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise RawCapabilityProjectionError(reason) from error
    return value


def _native_hook_completions(
    root: Path, *, task_id: str, run_id: str, launch_id: str
) -> dict[tuple[str, str, str, str], str]:
    """Require recorded PreToolUse and matching terminal hook for each native use."""
    with closing(_database(_evidence_file(root, "native-hooks.sqlite"))) as db:
        identity = db.execute("SELECT value FROM identity WHERE id=1").fetchone()
        _require(identity is not None, "native hook identity absent")
        value = _canonical_object(identity[0], "native hook identity malformed")
        _require(
            value.get("task_id") == task_id
            and value.get("launch_id") == launch_id
            and value.get("run_id") == run_id,
            "native hook identity differs",
        )
        started: set[tuple[str, str, str, str]] = set()
        completed: dict[tuple[str, str, str, str], str] = {}
        expected_sequence = 1
        for sequence, raw in db.execute("SELECT sequence,payload FROM events ORDER BY sequence"):
            _require(sequence == expected_sequence, "native hook sequence invalid")
            expected_sequence += 1
            observation = _canonical_object(raw, "native hook event malformed")
            hook = observation.get("hook")
            _require(
                set(observation)
                == {"schema_version", "run_id", "task_id", "launch_id", "event_id", "hook"}
                and observation["schema_version"] == 1
                and observation.get("task_id") == task_id
                and observation.get("launch_id") == launch_id
                and observation.get("run_id") == value["run_id"]
                and type(hook) is dict,
                "native hook event identity differs",
            )
            try:
                _require(
                    str(UUID(observation["event_id"])) == observation["event_id"]
                    and validate_projection(hook) == hook,
                    "native hook projection malformed",
                )
            except (TypeError, ValueError) as error:
                raise RawCapabilityProjectionError("native hook projection malformed") from error
            kind = hook.get("hook_event_name")
            if kind not in {"PreToolUse", "PostToolUse", "PostToolUseFailure"}:
                continue
            tool_id = hook.get("tool_use_id")
            identity_tuple = (
                hook.get("session_id"),
                hook.get("agent_id") or "",
                tool_id,
                hook.get("tool_name"),
            )
            _require(
                type(tool_id) is str
                and bool(tool_id)
                and all(type(part) is str for part in identity_tuple),
                "native hook tool identity malformed",
            )
            if kind == "PreToolUse":
                _require(identity_tuple not in started, "native hook start duplicated")
                started.add(identity_tuple)
            else:
                _require(
                    identity_tuple in started and identity_tuple not in completed,
                    "native hook completion lacks matching start",
                )
                completed[identity_tuple] = kind
        ledger_rows = db.execute("SELECT id,session,agent,name,closed FROM tools").fetchall()
        ledger = {(row[1], row[2] or "", row[0], row[3]): row[4] for row in ledger_rows}
        _require(
            len(ledger) == len(ledger_rows)
            and set(ledger) == started
            and all(ledger[key] == (1 if key in completed else 0) for key in started),
            "native hook start/terminal ledger differs",
        )
        return completed


def _native_completed(
    root: Path, allowed: dict, *, task_id: str, attempt_id: str
) -> tuple[dict, dict, tuple[CapabilityDisposition, ...], set[str]]:
    completed = {}
    noncompleted = []
    seen: set[str] = set()
    native_rows: dict[tuple[str, str, str, str], str] = {}
    try:
        with closing(_database(_evidence_file(root, "native-tools.sqlite"))) as db:
            identity_row = db.execute("SELECT value FROM identity WHERE id=1").fetchone()
            _require(identity_row is not None, "native producer identity absent")
            producer = _canonical_object(identity_row[0], "native producer identity malformed")
            _require(
                producer.get("task_id") == task_id
                and producer.get("attempt_id") == attempt_id
                and type(producer.get("run_id")) is str
                and bool(producer["run_id"])
                and type(producer.get("launch_id")) is str
                and bool(producer["launch_id"]),
                "native producer identity differs",
            )
            hook_completed = _native_hook_completions(
                root, task_id=task_id, run_id=producer["run_id"], launch_id=producer["launch_id"]
            )
            rows = db.execute(
                "SELECT t.id,t.request,t.name,t.input,t.input_hash,t.status,t.result,r.session,r.agent,r.role,l.status "
                "FROM tools t LEFT JOIN requests r ON r.id=t.request "
                "LEFT JOIN request_lifecycle l ON l.request=t.request ORDER BY t.id"
            )
            for (
                tool_id,
                request_id,
                name,
                input_raw,
                input_hash,
                status,
                result,
                session,
                agent,
                role,
                lifecycle,
            ) in rows:
                _require(
                    type(tool_id) is str
                    and bool(tool_id)
                    and type(request_id) is str
                    and bool(request_id)
                    and type(name) is str
                    and bool(name)
                    and status in _NATIVE_STATUSES
                    and type(session) is str
                    and type(agent) is str
                    and type(role) is str,
                    "native tool lifecycle malformed",
                )
                _require(tool_id not in seen, "native tool invocation duplicated")
                seen.add(tool_id)
                _require(
                    type(input_raw) is bytes
                    and 0 < len(input_raw) <= 4 * 1024 * 1024
                    and type(input_hash) is str
                    and _DIGEST.fullmatch(input_hash) is not None,
                    "native input custody malformed",
                )
                hook_key = (session, agent, tool_id, name)
                native_rows[hook_key] = status
                if status in {"completed", "failed"}:
                    expected_hook = "PostToolUse" if status == "completed" else "PostToolUseFailure"
                    _require(
                        hook_completed.get(hook_key) == expected_hook,
                        "native completion lacks matching start or success hook",
                    )
                    _result_payload(
                        result,
                        tool_id=tool_id,
                        name=name,
                        session=session,
                        agent=agent,
                        input_raw=input_raw,
                        input_hash=input_hash,
                        event_name=expected_hook,
                    )
                if status != "completed":
                    noncompleted.append(CapabilityDisposition(tool_id, "native", status))
                    continue
                _require(tool_id not in completed, "native completion identity duplicated")
                _require(lifecycle == "completed", "native provider request terminal absent")
                bound = allowed.get(tool_id)
                _require(bound is not None, "completed native tool lacks allowed audit")
                entry, request, trusted_role = bound
                _require(
                    not entry.identity.tool_id.startswith("advisory__")
                    and request.request_id == request_id
                    and entry.identity.tool_id == name
                    and trusted_role.value == role,
                    "completed native tool differs from allowed audit",
                )
                completed[tool_id] = bound
            _require(
                set(hook_completed).issubset(native_rows),
                "native terminal hook lacks native tool row",
            )
            _require(
                all(
                    native_rows[key] == ("completed" if kind == "PostToolUse" else "failed")
                    for key, kind in hook_completed.items()
                ),
                "native terminal hook status differs",
            )
    except sqlite3.DatabaseError as error:
        raise RawCapabilityProjectionError("native completion ledger invalid") from error
    return completed, producer, tuple(noncompleted), seen


def _advisory_completed(
    root: Path,
    allowed: dict,
    occupied: set[str],
    *,
    task_id: str,
    attempt_id: str,
    run_id: str,
    launch_id: str,
) -> tuple[dict[str, tuple], tuple[CapabilityDisposition, ...], set[str]]:
    completed = {}
    try:
        with closing(_database(_evidence_file(root, "advisory.sqlite"))) as db:
            identity_row = db.execute("SELECT payload FROM identity WHERE id=1").fetchone()
            _require(identity_row is not None, "advisory producer identity absent")
            identity = _canonical_object(identity_row[0], "advisory producer identity malformed")
            _require(
                identity.get("task_id") == task_id
                and identity.get("attempt_id") == attempt_id
                and identity.get("run_id") == run_id
                and identity.get("launch_id") == launch_id,
                "advisory producer identity differs",
            )
            rows = db.execute("SELECT sequence,role,event,payload FROM events ORDER BY sequence")
            expected_sequence = 1
            provider_replies: dict[str, tuple[str, dict]] = {}
            consumed_provider_replies: set[str] = set()
            requested: dict[str, tuple[str, dict]] = {}
            for sequence, role, event, raw in rows:
                _require(
                    type(sequence) is int and sequence == expected_sequence,
                    "advisory event sequence invalid",
                )
                expected_sequence += 1
                if event not in {"model_response", "tool_requested", "tool_result"}:
                    continue
                _require(role in _ADVISORY_ROLES, "advisory role invalid")
                value = _canonical_object(raw, "advisory event malformed")
                if event == "model_response":
                    provider_id = value.get("provider_request_id")
                    _require(
                        type(provider_id) is str
                        and bool(provider_id)
                        and type(value.get("content")) is str
                        and provider_id not in provider_replies,
                        "advisory provider response identity invalid",
                    )
                    provider_replies[provider_id] = (role, value)
                    continue
                observation = value.get("observation")
                action_id = observation.get("action_id") if type(observation) is dict else None
                _require(
                    type(action_id) is str
                    and bool(action_id)
                    and type(value.get("action")) is str
                    and bool(value["action"])
                    and action_id not in occupied
                    and action_id not in completed,
                    "advisory action identity invalid",
                )
                _require(
                    set(observation)
                    == {
                        "action_id",
                        "provider_request_id",
                        "task_id",
                        "attempt_id",
                        "role",
                        "name",
                        "arguments_sha256",
                    }
                    and observation["task_id"] == task_id
                    and observation["attempt_id"] == attempt_id
                    and observation["role"] == role
                    and observation["name"] == value["action"]
                    and type(value.get("arguments")) is dict
                    and hashlib.sha256(canonical_json(value["arguments"])).hexdigest()
                    == observation["arguments_sha256"],
                    "advisory observed action differs",
                )
                if event == "tool_requested":
                    provider_id = observation["provider_request_id"]
                    _require(
                        action_id not in requested
                        and type(provider_id) is str
                        and provider_id in provider_replies,
                        "advisory tool requested without provider response",
                    )
                    _require(
                        provider_id not in consumed_provider_replies,
                        "advisory provider response reused",
                    )
                    reply_role, reply = provider_replies[provider_id]
                    try:
                        parsed_action = _strict_json(reply["content"])
                    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
                        raise RawCapabilityProjectionError(
                            "advisory provider action malformed"
                        ) from error
                    _require(
                        reply_role == role
                        and parsed_action
                        == {"action": value["action"], "arguments": value["arguments"]},
                        "advisory requested action differs from provider response",
                    )
                    requested[action_id] = (role, value)
                    consumed_provider_replies.add(provider_id)
                    continue
                _require(action_id in requested, "advisory result lacks matching tool_requested")
                prior_role, prior = requested[action_id]
                _require(
                    prior_role == role
                    and prior["action"] == value["action"]
                    and prior["arguments"] == value["arguments"]
                    and prior["observation"] == observation
                    and "result" in value,
                    "advisory result differs from requested action",
                )
                bound = allowed.get(action_id)
                _require(bound is not None, "completed advisory tool lacks allowed audit")
                entry, request, trusted_role = bound
                _require(
                    trusted_role is Role.CHILD
                    and entry.identity.tool_id == "advisory__" + value["action"]
                    and request.request_id == action_id,
                    "completed advisory tool differs from allowed audit",
                )
                completed[action_id] = bound
            noncompleted = tuple(
                CapabilityDisposition(action_id, "advisory", "requested_without_result")
                for action_id in sorted(set(requested) - set(completed))
            )
            for role in {item[0] for item in requested.values()}:
                status_row = db.execute("SELECT status FROM roles WHERE role=?", (role,)).fetchone()
                _require(
                    status_row is not None and status_row[0] in {"reserved", "complete", "failed"},
                    "advisory role status absent or malformed",
                )
                _require(
                    status_row[0] != "complete"
                    or all(
                        action_id in completed
                        for action_id, (requested_role, _) in requested.items()
                        if requested_role == role
                    ),
                    "advisory completed role has unfinished action",
                )
    except sqlite3.DatabaseError as error:
        raise RawCapabilityProjectionError("advisory completion ledger invalid") from error
    return completed, noncompleted, set(requested)


def project_fixture_capability_uses(
    evidence_root: Path,
    *,
    registry: CapabilityRegistry,
    expected_registry_sha256: str,
    task_id: str,
    attempt_id: str,
) -> CapabilityFixtureProjection:
    """Derive only completed capability facts for one independently bound fixture."""
    root = Path(evidence_root)
    _require(
        type(registry) is CapabilityRegistry
        and type(expected_registry_sha256) is str
        and _DIGEST.fullmatch(expected_registry_sha256) is not None
        and registry.digest == expected_registry_sha256
        and root.is_absolute()
        and root.is_dir()
        and not root.is_symlink()
        and root.resolve(strict=True) == root
        and type(task_id) is str
        and bool(task_id)
        and type(attempt_id) is str
        and bool(attempt_id),
        "independently pinned capability inputs required",
    )
    audit_path = _evidence_file(root, "runtime-events.jsonl")
    audit = verify_audit_chain(audit_path, task_id=task_id, attempt_id=attempt_id)
    rows = _verified_audit_rows(_read(audit_path), task_id=task_id, attempt_id=attempt_id)
    _require(
        len(rows) == audit.row_count and rows[-1]["sha256"] == audit.tail_sha256,
        "runtime audit changed while projecting",
    )
    allowed = _allowed_events(rows, registry, task_id=task_id, attempt_id=attempt_id)
    native, producer, native_noncompleted, native_seen = _native_completed(
        root, allowed, task_id=task_id, attempt_id=attempt_id
    )
    advisory, advisory_noncompleted, advisory_seen = _advisory_completed(
        root,
        allowed,
        native_seen,
        task_id=task_id,
        attempt_id=attempt_id,
        run_id=producer["run_id"],
        launch_id=producer["launch_id"],
    )
    unmatched_allowed = (
        CapabilityDisposition(invocation_id, "audit", "allowed_unmatched")
        for invocation_id in set(allowed) - native_seen - advisory_seen
    )
    noncompleted = tuple(
        sorted(
            (*native_noncompleted, *advisory_noncompleted, *unmatched_allowed),
            key=lambda item: (item.invocation_id, item.source, item.status),
        )
    )
    counts = Counter(
        (entry.capability_id, entry.identity.tool_id, request.routes, role.value)
        for entry, request, role in (*native.values(), *advisory.values())
    )
    projected = tuple(CapabilityUse(*identity, count) for identity, count in sorted(counts.items()))
    return CapabilityFixtureProjection(
        task_id,
        attempt_id,
        registry.digest,
        projected,
        frozenset(row.capability_id for row in projected),
        noncompleted,
    )


def project_pair_capability_uses(
    inventory: ReadinessInventory,
    *,
    run_id: str,
    registry: CapabilityRegistry,
    expected_registry_sha256: str,
    fixture_attempt_ids: Mapping[str, str],
    expected_approved_capability_ids: frozenset[str],
) -> CapabilityPairProjection:
    """Project a pair's entire approved registry, without attesting a gate.

    The caller must derive attempt IDs from independently verified fixture
    custody; this function never treats a supplied ID or inventoried root as a
    signed fixture result. The inventory brackets all reads for byte custody.
    """
    _require(
        type(inventory) is ReadinessInventory
        and type(run_id) is str
        and run_id in inventory.repetition_ids
        and type(registry) is CapabilityRegistry
        and isinstance(fixture_attempt_ids, Mapping)
        and set(fixture_attempt_ids) == set(_FIXTURES)
        and all(
            type(fixture_attempt_ids[task_id]) is str and bool(fixture_attempt_ids[task_id])
            for task_id in _FIXTURES
        )
        and len(set(fixture_attempt_ids.values())) == len(_FIXTURES)
        and type(expected_approved_capability_ids) is frozenset
        and len(expected_approved_capability_ids) == 35
        and all(
            type(capability_id) is str and bool(capability_id)
            for capability_id in expected_approved_capability_ids
        ),
        "independently bound pair inputs required",
    )
    with inventory.observed_bytes():
        fixtures = tuple(
            project_fixture_capability_uses(
                inventory.fixture_root(run_id, task_id),
                registry=registry,
                expected_registry_sha256=expected_registry_sha256,
                task_id=task_id,
                attempt_id=fixture_attempt_ids[task_id],
            )
            for task_id in _FIXTURES
        )
        observed = frozenset().union(*(fixture.completed_capability_ids for fixture in fixtures))
        approved = frozenset(
            entry.capability_id for entry in registry.entries if entry.status is Status.APPROVED
        )
        _require(
            approved == expected_approved_capability_ids and observed == approved,
            "pair capability coverage incomplete or signed baseline differs",
        )
    return CapabilityPairProjection(run_id, registry.digest, fixtures, observed)
