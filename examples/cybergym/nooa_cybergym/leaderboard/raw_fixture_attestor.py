# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Independent read-only checks of one native synthetic fixture's raw evidence.

This is a building block for certification, not a certification record. The
verifier and expected identities must come from frozen controller inputs, never
from the evidence directory being inspected. In particular, this does not
attest 35-capability coverage, negative probes, or interruption recovery.
"""

from __future__ import annotations

import hashlib
import json
import math
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from xeus_cybergym.canonical import canonical_json
from xeus_cybergym.ledger import SignedEnvelope

from .capabilities import CapabilityRegistry, Role, Status
from .deepseek import CONTEXT_TOKENS as _DEEPSEEK_CONTEXT_TOKENS
from .deepseek import ENDPOINT as _DEEPSEEK_ENDPOINT
from .deepseek import MAX_OUTPUT_TOKENS as _DEEPSEEK_MAX_OUTPUT_TOKENS
from .deepseek import MODEL as _DEEPSEEK_MODEL
from .preflight import _FORBIDDEN_ENV, _FORBIDDEN_PATHS
from .primary_takeover import PrimaryTakeoverPolicy

if TYPE_CHECKING:
    from .raw_request_accounting import VerifiedRequestAccounting

_MAX_JSON = 16 * 1024 * 1024
_ZERO = "0" * 64
_ADVISORY_ROLES = frozenset(
    {"independent_recon", "conditional_debug_recovery", "final_adversarial_critic"}
)
_NEGATIVE_PREFLIGHT_NAMES = frozenset(
    {*("path:" + path for path in _FORBIDDEN_PATHS), *("env:" + name for name in _FORBIDDEN_ENV)}
    | {
        "route:external-target-repository",
        "route:external-target-patch",
        "route:target-issue-or-changelog",
        "route:cve-or-published-poc",
    }
)


class RawEvidenceError(ValueError):
    """A raw fixture claim could not be independently verified."""


class SignatureVerifier(Protocol):
    def verify(self, envelope: Any) -> bytes: ...


@dataclass(frozen=True, slots=True)
class AuditChain:
    row_count: int
    tail_sha256: str
    oracle_evidence_sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedFixture:
    """Verified facts from one fixture, never a full certification verdict."""

    run_id: str
    task_id: str
    attempt_id: str
    evidence_root: str
    oracle_key_id: str
    result_sha256: str
    oracle_payload_sha256: str
    candidate_sha256: str
    audit_rows: int
    audit_tail_sha256: str
    native_preflight_reports: int
    primary_completed_requests: int
    request_accounting: VerifiedRequestAccounting | None = None
    primary_final_selection: bytes | None = None


@dataclass(frozen=True, slots=True)
class VerifiedPrimaryUsage:
    """Observed GLM requests and tokens; failed requests remain separately counted."""

    completed_requests: int
    incomplete_requests: int
    input_tokens: int
    output_tokens: int
    cache_tokens: int
    provider_request_ids: tuple[str, ...]
    observed_version: str | None
    system_fingerprint: str | None


@dataclass(frozen=True, slots=True)
class VerifiedDeepSeekRoleUsage:
    """Controller-observed provider requests and tokens for one advisory role."""

    requests: int
    incomplete_requests: int
    input_tokens: int
    output_tokens: int
    cache_tokens: int
    elapsed_seconds: float
    provider_request_ids: tuple[str, ...]
    observed_version: str | None
    system_fingerprint: str | None


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise RawEvidenceError(reason)


def _read(path: Path, *, limit: int = _MAX_JSON) -> bytes:
    _require(path.is_file() and not path.is_symlink(), "raw evidence file absent or linked")
    _require(path.stat().st_size <= limit, "raw evidence file exceeds bound")
    return path.read_bytes()


def _json(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = _read(path)
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeError) as error:
        raise RawEvidenceError("raw evidence JSON malformed") from error
    _require(type(data) is dict, "raw evidence object required")
    return data, raw


def _json_lines(path: Path):
    raw = _read(path)
    _require(raw.endswith(b"\n"), "raw evidence log incomplete")
    for line in raw.splitlines():
        try:
            data = json.loads(line)
        except (ValueError, UnicodeError) as error:
            raise RawEvidenceError("raw evidence log malformed") from error
        _require(type(data) is dict, "raw evidence log object required")
        yield data


def _evidence_child(root: Path, value: Any) -> Path:
    _require(type(value) is str, "evidence child path invalid")
    path = Path(value)
    _require(path.is_absolute() and path.is_relative_to(root), "evidence child outside root")
    _require(
        path.is_file() and not path.is_symlink() and path.resolve(strict=True) == path,
        "evidence child linked or ambiguous",
    )
    return path


def _verified_audit_rows(raw: bytes, *, task_id: str, attempt_id: str) -> list[dict]:
    """Verify the exact captured bytes, independently of an attempt's outcome."""
    _require(
        type(raw) is bytes and 0 < len(raw) <= _MAX_JSON and raw.endswith(b"\n"),
        "runtime audit bytes absent, oversized or incomplete",
    )

    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result, "duplicate runtime audit key")
            result[key] = value
        return result

    previous = _ZERO
    rows = []
    for sequence, line in enumerate(raw.splitlines(), 1):
        try:
            row = json.loads(line, object_pairs_hook=pairs)
            _require(type(row) is dict, "runtime audit row malformed")
            body = {key: value for key, value in row.items() if key != "sha256"}
            actual = hashlib.sha256(canonical_json(body)).hexdigest()
        except (ValueError, UnicodeError, TypeError, RecursionError) as error:
            raise RawEvidenceError("runtime audit row malformed") from error
        digest = row.get("sha256")
        _require(
            type(digest) is str
            and len(digest) == 64
            and type(row.get("sequence")) is int
            and row["sequence"] == sequence
            and row.get("previous_sha256") == previous
            and row.get("task_id") == task_id
            and row.get("attempt_id") == attempt_id
            and actual == digest,
            "runtime audit chain invalid",
        )
        _require(type(row.get("event")) is dict, "runtime audit event malformed")
        rows.append(row)
        previous = digest
    return rows


def _synthetic_audit_order(rows: list[dict]) -> AuditChain:
    oracle_at = memory_at = None
    oracle_digest = None
    for index, row in enumerate(rows, 1):
        event = row.get("event")
        if event.get("event") == "synthetic_oracle_observed":
            _require(oracle_at is None and event.get("oracle_true") is True, "oracle audit invalid")
            oracle_at = index
            oracle_digest = event.get("evidence_sha256")
        elif event.get("event") == "memory_oracle_episode_written":
            _require(
                memory_at is None and event.get("actor") == "controller",
                "controller memory audit invalid",
            )
            memory_at = index
    _require(
        bool(rows)
        and oracle_at is not None
        and memory_at is not None
        and oracle_at < memory_at
        and type(oracle_digest) is str
        and len(oracle_digest) == 64,
        "oracle-before-memory evidence absent",
    )
    return AuditChain(len(rows), rows[-1]["sha256"], oracle_digest)


def verify_audit_chain(path: Path, *, task_id: str, attempt_id: str) -> AuditChain:
    """Verify every hash link and the synthetic oracle-before-memory invariant."""
    return _synthetic_audit_order(
        _verified_audit_rows(_read(Path(path)), task_id=task_id, attempt_id=attempt_id)
    )


def _verify_oracle(root: Path, verifier: SignatureVerifier, expected: dict) -> tuple[str, str]:
    try:
        envelope = SignedEnvelope.model_validate_json(_read(root / "synthetic-oracle.signed.json"))
        payload = verifier.verify(envelope)
        oracle = json.loads(payload)
    except Exception as error:
        raise RawEvidenceError("synthetic oracle signature invalid") from error
    _require(
        type(oracle) is dict and canonical_json(oracle) == payload, "oracle payload not canonical"
    )
    request = oracle.get("request")
    observations = oracle.get("observations")
    _require(type(request) is dict and type(observations) is dict, "oracle structure invalid")
    for key, value in expected.items():
        _require(request.get(key) == value, f"oracle {key} mismatch")
    vulnerable = observations.get("vulnerable")
    fixed = observations.get("fixed")
    _require(type(vulnerable) is dict and type(fixed) is dict, "oracle pair absent")
    _require(
        oracle.get("oracle_true") is True
        and vulnerable.get("build_exit") == 0
        and fixed.get("build_exit") == 0
        and type(vulnerable.get("test_exit")) is int
        and vulnerable["test_exit"] not in (0, 300)
        and vulnerable.get("sanitizer") is True
        and fixed.get("test_exit") == 0
        and fixed.get("sanitizer") is False,
        "private vulnerable/fixed oracle verdict invalid",
    )
    return envelope.key_id, hashlib.sha256(payload).hexdigest()


def _verify_preflights(root: Path) -> int:
    paths = sorted(root.glob("preflight/**/*report.json"))
    contexts = []
    for path in paths:
        report, _ = _json(path)
        contexts_for_report = report.get("contexts")
        context = (
            contexts_for_report[0]
            if type(contexts_for_report) is list and len(contexts_for_report) == 1
            else None
        )
        probes = report.get("probes")
        container_id = report.get("container_id")
        names = (
            [item.get("name") if type(item) is dict else None for item in probes]
            if type(probes) is list
            else []
        )
        _require(
            report.get("passed") is True
            and report.get("execution_mode") == "native"
            and type(probes) is list
            and len(probes) == 62
            and report.get("failures") == [],
            "native isolation preflight invalid",
        )
        _require(
            type(context) is str
            and context in {"parent", "child"}
            and type(container_id) is str
            and bool(container_id)
            and all(type(name) is str for name in names)
            and len(names) == len(set(names))
            and _NEGATIVE_PREFLIGHT_NAMES <= set(names)
            and all(
                type(probe) is dict
                and probe.get("passed") is True
                and type(probe.get("exit_code")) is int
                and probe["exit_code"] == 0
                and probe.get("observed_context") == context
                and probe.get("observed_container_id") == container_id
                for probe in probes
            ),
            "native isolation preflight invalid",
        )
        contexts.append(contexts_for_report)
    _require(
        contexts.count(["parent"]) == 1 and contexts.count(["child"]) >= 2,
        "parent/child native preflight evidence absent",
    )
    return len(paths)


def _verify_live_activity(
    root: Path,
    *,
    task_id: str,
    attempt_id: str,
    accounting: VerifiedRequestAccounting | None = None,
) -> int:
    primary = [
        row
        for row in _json_lines(root / "model-requests.jsonl")
        if row.get("event") == "request_terminal"
        and row.get("role") == "primary"
        and row.get("outcome") == "completed"
    ]
    if accounting is not None:
        primary = [
            row
            for row in accounting.manifest["requests"]
            if row["lane"] == "primary" and row["outcome"] == "completed"
        ]
        _require(bool(primary), "audited primary native response absent")
    else:
        _require(
            bool(primary)
            and all(
                row.get("task_id") == task_id
                and row.get("attempt_id") == attempt_id
                and row.get("configured_model") == "glm-5.3[1m]"
                and row.get("returned_model") == "glm-5.3"
                and row.get("usage_status") == "observed"
                and type(row.get("provider_request_id")) is str
                and bool(row["provider_request_id"])
                for row in primary
            ),
            "audited GLM native response absent",
        )
    with sqlite3.connect(f"file:{(root / 'advisory.sqlite').as_posix()}?mode=ro", uri=True) as db:
        roles = dict(db.execute("select role,status from roles"))
    _require(
        all(roles.get(role) == "complete" for role in _ADVISORY_ROLES),
        "DeepSeek advisory roles incomplete",
    )
    with sqlite3.connect(
        f"file:{(root / 'native-tools.sqlite').as_posix()}?mode=ro", uri=True
    ) as db:
        tools = dict(
            db.execute("select name,count(*) from tools where status='completed' group by name")
        )
    _require(
        all(
            tools.get(name, 0) > 0
            for name in (
                "Bash",
                "mcp__vulnerable__run_test",
                "mcp__gbrain__recall",
                "mcp__gbrain__search",
            )
        ),
        "native model, test, or memory tool evidence absent",
    )
    return len(primary)


def verify_primary_model_usage(
    evidence_root: Path, *, task_id: str, attempt_id: str
) -> VerifiedPrimaryUsage:
    """Join every reserved GLM request, terminal result, and provider usage row."""
    root = Path(evidence_root)
    _require(
        root.is_absolute() and root.is_dir() and not root.is_symlink(),
        "model evidence root invalid",
    )
    _require(root.resolve(strict=True) == root, "model evidence root not canonical")
    requests_path = _evidence_child(root, str(root / "model-requests.jsonl"))
    usage_path = _evidence_child(root, str(root / "model-usage.jsonl"))
    reserved: dict[str, dict[str, Any]] = {}
    terminal: dict[str, dict[str, Any]] = {}
    for row in _json_lines(requests_path):
        if row.get("role") != "primary" or row.get("event") not in {
            "request_reserved",
            "request_terminal",
        }:
            continue
        request_id = row.get("request_id")
        _require(
            type(request_id) is str
            and bool(request_id)
            and row.get("task_id") == task_id
            and row.get("attempt_id") == attempt_id
            and row.get("configured_model") == "glm-5.3[1m]",
            "primary model request identity invalid",
        )
        destination = reserved if row["event"] == "request_reserved" else terminal
        _require(request_id not in destination, "primary model request duplicated")
        destination[request_id] = row
    _require(
        bool(reserved) and reserved.keys() == terminal.keys(),
        "primary model request lifecycle incomplete",
    )
    usage: dict[str, dict[str, Any]] = {}
    for row in _json_lines(usage_path):
        request_id = row.get("request_id")
        if request_id not in reserved:
            continue
        _require(
            row.get("event") == "usage" and request_id not in usage,
            "primary model usage duplicated or malformed",
        )
        usage[request_id] = row
    _require(usage.keys() == terminal.keys(), "primary model usage absent")

    input_tokens = output_tokens = cache_tokens = incomplete = 0
    provider_ids: list[str] = []
    metadata: list[tuple[str | None, str | None]] = []
    for request_id, result in terminal.items():
        observed = usage[request_id]
        if result.get("outcome") != "completed":
            incomplete += 1
            continue
        numbers = (
            observed.get("input_tokens"),
            observed.get("output_tokens"),
            observed.get("cache_read_tokens"),
            observed.get("cache_creation_tokens"),
        )
        provider_id = result.get("provider_request_id")
        model_version = result.get("model_version")
        system_fingerprint = result.get("system_fingerprint")
        _require(
            result.get("usage_status") == "observed"
            and result.get("returned_model") == "glm-5.3"
            and observed.get("usage_status") == "observed"
            and observed.get("returned_model") == "glm-5.3"
            and type(provider_id) is str
            and bool(provider_id)
            and provider_id == observed.get("provider_request_id")
            and provider_id not in provider_ids
            and (model_version is None or (type(model_version) is str and bool(model_version)))
            and (
                system_fingerprint is None
                or (type(system_fingerprint) is str and bool(system_fingerprint))
            )
            and model_version == observed.get("model_version")
            and system_fingerprint == observed.get("system_fingerprint")
            and all(type(value) is int and value >= 0 for value in numbers)
            and type(observed.get("counted_tokens")) is int
            and observed["counted_tokens"] == sum(numbers),
            "primary model usage mismatch",
        )
        input_tokens += numbers[0]
        output_tokens += numbers[1]
        cache_tokens += numbers[2] + numbers[3]
        provider_ids.append(provider_id)
        metadata.append((model_version, system_fingerprint))
    _require(len(set(metadata)) <= 1, "primary provider metadata drift")
    version, fingerprint = metadata[0] if metadata else (None, None)
    return VerifiedPrimaryUsage(
        len(provider_ids),
        incomplete,
        input_tokens,
        output_tokens,
        cache_tokens,
        tuple(provider_ids),
        version,
        fingerprint,
    )


def verify_deepseek_model_usage(
    evidence_root: Path,
    *,
    task_id: str,
    attempt_id: str,
    registry_sha256: str,
    policy_sha256: str,
) -> dict[str, VerifiedDeepSeekRoleUsage]:
    """Verify all three controller-owned DeepSeek roles from the chained log."""
    root = Path(evidence_root)
    _require(
        root.is_absolute() and root.is_dir() and not root.is_symlink(),
        "DeepSeek evidence root invalid",
    )
    _require(root.resolve(strict=True) == root, "DeepSeek evidence root not canonical")
    for digest in (registry_sha256, policy_sha256):
        _require(
            type(digest) is str
            and len(digest) == 64
            and all(char in "0123456789abcdef" for char in digest),
            "DeepSeek frozen digest invalid",
        )
    audit_path = _evidence_child(root, str(root / "runtime-events.jsonl"))
    rows = _verified_audit_rows(_read(audit_path), task_id=task_id, attempt_id=attempt_id)
    _synthetic_audit_order(rows)
    return _deepseek_usage_from_rows(
        rows,
        task_id=task_id,
        attempt_id=attempt_id,
        registry_sha256=registry_sha256,
        policy_sha256=policy_sha256,
        require_all_roles=True,
    )


def _deepseek_usage_from_rows(
    rows,
    *,
    task_id,
    attempt_id,
    registry_sha256,
    policy_sha256,
    require_all_roles,
):
    """Validate advisory settlements in already verified, captured audit rows."""
    requested: dict[str, dict[str, Any]] = {}
    terminal: dict[str, dict[str, Any]] = {}
    settings = {
        "model": _DEEPSEEK_MODEL,
        "thinking": {"type": "enabled"},
        "reasoning_effort": "max",
        "max_tokens": _DEEPSEEK_MAX_OUTPUT_TOKENS,
    }
    for row in rows:
        event = row.get("event")
        if type(event) is not dict or event.get("event") not in {"request", "response", "failure"}:
            continue
        if event.get("role") not in _ADVISORY_ROLES:
            continue
        request_id = event.get("request_id")
        failure_digest = event.get("failure_evidence_digest")
        request_digest = event.get("request_sha256")
        _require(
            type(request_id) is str
            and bool(request_id)
            and type(event.get("request_number")) is int
            and event["request_number"] > 0
            and type(event.get("shared_request_number")) is int
            and event["shared_request_number"] > 0
            and type(request_digest) is str
            and len(request_digest) == 64
            and all(char in "0123456789abcdef" for char in request_digest)
            and event.get("task_id") == task_id
            and event.get("attempt_id") == attempt_id
            and event.get("registry_digest") == registry_sha256
            and event.get("policy_digest") == policy_sha256
            and event.get("endpoint") == _DEEPSEEK_ENDPOINT
            and event.get("requested_model") == _DEEPSEEK_MODEL
            and event.get("request_settings") == settings
            and (
                (
                    type(failure_digest) is str
                    and len(failure_digest) == 64
                    and all(char in "0123456789abcdef" for char in failure_digest)
                )
                if event["role"] == "conditional_debug_recovery"
                else failure_digest is None
            ),
            "DeepSeek request identity or settings invalid",
        )
        destination = requested if event["event"] == "request" else terminal
        _require(request_id not in destination, "DeepSeek request duplicated")
        destination[request_id] = event
    _require(
        requested.keys() == terminal.keys()
        and (
            not require_all_roles or {row["role"] for row in requested.values()} == _ADVISORY_ROLES
        ),
        "DeepSeek role request lifecycle incomplete",
    )

    used_provider_ids: set[str] = set()
    metadata: set[tuple[str | None, str | None]] = set()
    accumulators = {
        role: {
            "requests": 0,
            "incomplete": 0,
            "input": 0,
            "output": 0,
            "cache": 0,
            "seconds": 0.0,
            "provider_ids": [],
        }
        for role in _ADVISORY_ROLES
    }
    for request_id, request in requested.items():
        response = terminal[request_id]
        role = request["role"]
        _require(
            response.get("role") == role
            and response.get("request_settings") == request.get("request_settings")
            and response.get("failure_evidence_digest") == request.get("failure_evidence_digest")
            and response.get("request_sha256") == request.get("request_sha256")
            and response.get("request_number") == request.get("request_number")
            and response.get("shared_request_number") == request.get("shared_request_number"),
            "DeepSeek response identity mismatch",
        )
        state = accumulators[role]
        if response["event"] == "failure":
            state["incomplete"] += 1
            continue
        usage = response.get("usage")
        raw = usage.get("provider_usage") if type(usage) is dict else None
        provider_id = response.get("provider_request_id")
        version = response.get("model_version")
        fingerprint = response.get("system_fingerprint")
        duration = response.get("duration_seconds")
        _require(
            response.get("returned_model") == _DEEPSEEK_MODEL
            and response.get("http_status") == 200
            and type(provider_id) is str
            and bool(provider_id)
            and provider_id not in used_provider_ids
            and type(duration) in (int, float)
            and math.isfinite(duration)
            and duration > 0
            and (version is None or (type(version) is str and bool(version)))
            and (fingerprint is None or (type(fingerprint) is str and bool(fingerprint)))
            and type(usage) is dict
            and type(raw) is dict,
            "DeepSeek response metadata invalid",
        )
        names = (
            "input_tokens",
            "output_tokens",
            "counted_tokens",
            "cache_hit_input_tokens",
            "cache_miss_input_tokens",
        )
        _require(
            all(type(usage.get(name)) is int and usage[name] >= 0 for name in names)
            and usage["input_tokens"] + usage["output_tokens"] == usage["counted_tokens"]
            and usage["cache_hit_input_tokens"] + usage["cache_miss_input_tokens"]
            == usage["input_tokens"]
            and usage["output_tokens"] <= _DEEPSEEK_MAX_OUTPUT_TOKENS
            and usage["counted_tokens"] <= _DEEPSEEK_CONTEXT_TOKENS
            and all(
                raw.get(source) == usage[target]
                for source, target in (
                    ("prompt_tokens", "input_tokens"),
                    ("completion_tokens", "output_tokens"),
                    ("total_tokens", "counted_tokens"),
                    ("prompt_cache_hit_tokens", "cache_hit_input_tokens"),
                    ("prompt_cache_miss_tokens", "cache_miss_input_tokens"),
                )
            )
            and (
                usage.get("reasoning_tokens") is None
                or (
                    type(usage["reasoning_tokens"]) is int
                    and 0 <= usage["reasoning_tokens"] <= usage["output_tokens"]
                )
            ),
            "DeepSeek usage mismatch",
        )
        state["requests"] += 1
        state["input"] += usage["input_tokens"]
        state["output"] += usage["output_tokens"]
        state["cache"] += usage["cache_hit_input_tokens"]
        state["seconds"] += duration
        state["provider_ids"].append(provider_id)
        used_provider_ids.add(provider_id)
        metadata.add((version, fingerprint))
    _require(len(metadata) <= 1, "DeepSeek provider metadata drift")
    version, fingerprint = next(iter(metadata)) if metadata else (None, None)
    return {
        role: VerifiedDeepSeekRoleUsage(
            state["requests"],
            state["incomplete"],
            state["input"],
            state["output"],
            state["cache"],
            state["seconds"],
            tuple(state["provider_ids"]),
            version,
            fingerprint,
        )
        for role, state in accumulators.items()
    }


def verify_completed_capability_uses(
    evidence_root: Path,
    *,
    registry: CapabilityRegistry,
    task_id: str,
    attempt_id: str,
) -> dict[str, int]:
    """Count only audited invocations with an exact completed result.

    This proves per-fixture use, not full registry coverage across an epoch.
    The caller must pin the registry and independently verify the fixture's
    signed oracle and frozen identities before using these counts.
    """
    root = Path(evidence_root)
    _require(
        type(registry) is CapabilityRegistry
        and root.is_absolute()
        and root.is_dir()
        and not root.is_symlink()
        and root.resolve(strict=True) == root,
        "capability evidence inputs invalid",
    )
    audit_path = _evidence_child(root, str(root / "runtime-events.jsonl"))
    verify_audit_chain(audit_path, task_id=task_id, attempt_id=attempt_id)
    native_path = _evidence_child(root, str(root / "native-tools.sqlite"))
    advisory_path = _evidence_child(root, str(root / "advisory.sqlite"))
    approved = {
        entry.capability_id: entry for entry in registry.entries if entry.status is Status.APPROVED
    }

    try:
        with sqlite3.connect(f"file:{native_path.as_posix()}?mode=ro", uri=True) as db:
            native = {}
            for row in db.execute(
                "SELECT t.id,t.request,t.name,t.status,r.role "
                "FROM tools t JOIN requests r ON r.id=t.request"
            ):
                _require(row[0] not in native, "native completion identity duplicated")
                native[row[0]] = row[1:]
        with sqlite3.connect(f"file:{advisory_path.as_posix()}?mode=ro", uri=True) as db:
            advisory = {}
            for role, payload in db.execute(
                "SELECT role,payload FROM events WHERE event='tool_result'"
            ):
                item = json.loads(payload)
                observation = item.get("observation") if type(item) is dict else None
                action_id = observation.get("action_id") if type(observation) is dict else None
                _require(
                    type(action_id) is str
                    and bool(action_id)
                    and action_id not in advisory
                    and type(item.get("action")) is str,
                    "advisory completion identity invalid",
                )
                advisory[action_id] = (item["action"], role)
    except (sqlite3.DatabaseError, ValueError, TypeError) as error:
        raise RawEvidenceError("capability result ledger invalid") from error

    counts: dict[str, int] = {}
    seen: dict[str, tuple[str, str, str, str]] = {}
    for row in _json_lines(audit_path):
        event = row.get("event")
        if type(event) is not dict or event.get("disposition") != "allowed":
            continue
        request = event.get("request")
        capability_id = event.get("capability_id")
        entry = approved.get(capability_id) if type(capability_id) is str else None
        role_name = event.get("role")
        try:
            role = Role(role_name)
        except (TypeError, ValueError):
            role = None
        _require(
            entry is not None
            and type(request) is dict
            and type(request.get("invocation_id")) is str
            and bool(request["invocation_id"])
            and type(event.get("request_id")) is str
            and event["request_id"] == request.get("request_id")
            and event.get("registry_digest") == registry.digest
            and event.get("tool_id") == entry.identity.tool_id
            and event.get("task_id") == task_id
            and event.get("attempt_id") == attempt_id
            and role in entry.roles,
            "allowed capability audit identity invalid",
        )
        invocation_id = request["invocation_id"]
        identity = (capability_id, event["request_id"], event["tool_id"], role_name)
        prior = seen.get(invocation_id)
        _require(prior is None or prior == identity, "capability invocation reused ambiguously")
        if prior is not None:
            continue
        seen[invocation_id] = identity
        if event["tool_id"].startswith("advisory__"):
            result = advisory.get(invocation_id)
            completed = (
                role is Role.CHILD
                and event["request_id"] == invocation_id
                and result is not None
                and result[0] == event["tool_id"].removeprefix("advisory__")
                and result[1] in _ADVISORY_ROLES
            )
        else:
            result = native.get(invocation_id)
            completed = result == (event["request_id"], event["tool_id"], "completed", role_name)
        if completed:
            counts[capability_id] = counts.get(capability_id, 0) + 1
    return counts


def _verify_final_stream(
    chunks, declaration: dict, arguments: dict, provider_request_id: str
) -> None:
    """Recover the selecting tool from persisted bytes, without trusting DB role claims."""
    raw = bytearray()
    for (chunk,) in chunks:
        _require(
            type(chunk) is bytes and len(raw) + len(chunk) <= _MAX_JSON,
            "native final stream invalid or excessive",
        )
        raw.extend(chunk)
    frames = bytes(raw).replace(b"\r\n", b"\n").split(b"\n\n")
    _require(not frames[-1].strip(), "native final stream frame truncated")
    started = False
    selected = False
    blocks = {}
    ids = set()
    for frame in frames[:-1]:
        data = b"\n".join(
            line[5:].lstrip(b" ") for line in frame.splitlines() if line.startswith(b"data:")
        )
        if not data or data == b"[DONE]":
            continue
        event = json.loads(data)
        _require(type(event) is dict, "native final stream event invalid")
        kind = event.get("type")
        if kind == "message_start":
            message = event.get("message")
            _require(
                not started
                and type(message) is dict
                and message.get("model") == declaration["provider_model"]
                and message.get("id") == provider_request_id,
                "native final stream provider identity invalid",
            )
            started = True
        elif kind == "content_block_start":
            index, block = event.get("index"), event.get("content_block")
            _require(
                started
                and type(index) is int
                and index >= 0
                and index not in blocks
                and type(block) is dict,
                "native final stream block invalid",
            )
            blocks[index] = {"block": block, "partial": "", "closed": False}
            if block.get("type") == "tool_use":
                tool_id = block.get("id")
                _require(
                    type(tool_id) is str and tool_id not in ids, "native final tool ID duplicated"
                )
                ids.add(tool_id)
        elif kind == "content_block_delta":
            state = blocks.get(event.get("index"))
            delta = event.get("delta")
            _require(
                state is not None and not state["closed"] and type(delta) is dict,
                "native final stream delta invalid",
            )
            if delta.get("type") == "input_json_delta":
                _require(
                    type(delta.get("partial_json")) is str, "native final tool arguments malformed"
                )
                state["partial"] += delta["partial_json"]
        elif kind == "content_block_stop":
            state = blocks.get(event.get("index"))
            _require(
                state is not None and not state["closed"], "native final stream block stop invalid"
            )
            state["closed"] = True
            block = state["block"]
            if block.get("id") == declaration["tool_id"]:
                recovered = json.loads(state["partial"]) if state["partial"] else block.get("input")
                _require(
                    not selected
                    and block.get("type") == "tool_use"
                    and block.get("name") == "mcp__finalizer__select_final"
                    and recovered == arguments,
                    "native final tool arguments disagree",
                )
                selected = True
    _require(started and selected, "native parent final selection stream absent")


def verify_primary_final_selection(
    evidence_root: Path,
    *,
    task_id: str,
    attempt_id: str,
    takeover_policy: PrimaryTakeoverPolicy,
    accounting: VerifiedRequestAccounting,
) -> dict[str, Any]:
    """Join v2 final proof, durable parent grant, provider binding, and raw SSE."""
    from .finalize import _PRIMARY_IDENTITY_FIELDS, _primary_event_digest, _validate_declaration
    from .raw_request_accounting import VerifiedRequestAccounting

    root = Path(evidence_root)
    _require(
        type(accounting) is VerifiedRequestAccounting
        and type(takeover_policy) is PrimaryTakeoverPolicy,
        "trusted primary final verification inputs required",
    )
    facts = accounting.manifest
    _require(
        facts["task_id"] == task_id
        and facts["attempt_id"] == attempt_id
        and facts["takeover_policy_sha256"] == takeover_policy.digest,
        "primary final accounting identity mismatch",
    )
    raw = _read(_evidence_child(root, str(root / "final/agent-final.json")))
    try:
        declaration = _validate_declaration(raw, task_id, takeover_policy=takeover_policy)
        _require(declaration["attempt_id"] == attempt_id, "primary final attempt mismatch")
        candidate = _read(_evidence_child(root, str(root / "final/poc")), limit=8 * 1024 * 1024)
        _require(
            declaration["sha256"] == hashlib.sha256(candidate).hexdigest()
            and declaration["byte_length"] == len(candidate),
            "primary final bytes mismatch",
        )
        selected = [
            row
            for row in facts["requests"]
            if row["provider_attempt_id"] == declaration["provider_attempt_id"]
        ]
        _require(
            len(selected) == 1 and selected[0]["lane"] == "primary",
            "primary final provider attempt absent",
        )
        selected = selected[0]
        _require(
            all(
                selected[key] == declaration[key]
                for key in ("request_id", "provider", "configured_model")
            )
            and selected["returned_model"] == declaration["provider_model"]
            and type(selected["provider_request_id"]) is str
            and bool(selected["provider_request_id"]),
            "primary final provider attempt disagrees",
        )
        proof = {
            "schema_version": 2,
            "task_id": task_id,
            "declaration_sha256": hashlib.sha256(raw).hexdigest(),
            "candidate_sha256": declaration["sha256"],
            "model": declaration["configured_model"],
            "role": "primary_parent",
            "event_digest": _primary_event_digest(declaration),
            **{key: declaration[key] for key in _PRIMARY_IDENTITY_FIELDS - {"configured_model"}},
        }
        final_path = _evidence_child(root, str(root / "native-final.sqlite"))
        with sqlite3.connect(f"file:{final_path.as_posix()}?mode=ro", uri=True) as db:
            _verify_primary_database_identity(
                db,
                task_id,
                attempt_id,
                "takeover_policy_sha256",
                takeover_policy.digest,
            )
            rows = db.execute("SELECT id,task,attempt,declaration,proof FROM selection").fetchall()
            _require(
                len(rows) == 1
                and rows[0][:4] == (1, task_id, attempt_id, raw)
                and json.loads(rows[0][4]) == proof,
                "primary final durable proof mismatch",
            )
            _require(
                db.execute("SELECT id,status FROM declaration_state").fetchall()
                == [(1, "declared")]
                and db.execute("SELECT id,status FROM lock_attempt").fetchall() == [(1, "locked")],
                "primary final declaration not locked",
            )
        arguments = {
            key: declaration[key]
            for key in ("candidate_path", "sha256", "byte_length", "selection_reason")
        }
        argument_hash = hashlib.sha256(
            json.dumps(
                arguments,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode()
        ).hexdigest()
        native_path = _evidence_child(root, str(root / "native-tools.sqlite"))
        with sqlite3.connect(f"file:{native_path.as_posix()}?mode=ro", uri=True) as db:
            _verify_primary_database_identity(
                db,
                task_id,
                attempt_id,
                "primary_takeover_sha256",
                takeover_policy.digest,
            )
            parent = db.execute(
                "SELECT session,agent,role FROM requests WHERE id=?", (declaration["request_id"],)
            ).fetchall()
            _require(
                parent == [(declaration["session_id"], "", "parent")],
                "primary final did not originate from parent request",
            )
            tools = db.execute(
                "SELECT request,name,input_hash,status FROM tools WHERE id=?",
                (declaration["tool_id"],),
            ).fetchall()
            _require(
                len(tools) == 1
                and tools[0][:3]
                == (declaration["request_id"], "mcp__finalizer__select_final", argument_hash)
                and tools[0][3] in {"dispatched", "completed"},
                "primary final tool admission invalid",
            )
            bindings = db.execute(
                "SELECT provider_attempt_id,provider,configured_model,provider_model,takeover_policy_sha256 "
                "FROM provider_bindings WHERE request=? ORDER BY sequence",
                (declaration["request_id"],),
            ).fetchall()
            attempts = [
                row for row in facts["requests"] if row["request_id"] == declaration["request_id"]
            ]
            expected = [
                (
                    row["provider_attempt_id"],
                    row["provider"],
                    row["configured_model"],
                    next(
                        route.wire_model
                        for route in (takeover_policy.initial, takeover_policy.fallback)
                        if route.provider == row["provider"]
                    ),
                    takeover_policy.digest,
                )
                for row in attempts
            ]
            _require(
                bindings == expected and bindings[-1][0] == declaration["provider_attempt_id"],
                "primary final durable provider binding disagrees",
            )
            _verify_final_stream(
                db.execute(
                    "SELECT data FROM streams WHERE request=? ORDER BY sequence",
                    (declaration["request_id"],),
                ),
                declaration,
                arguments,
                selected["provider_request_id"],
            )
        return declaration
    except (ValueError, UnicodeError, TypeError, KeyError, sqlite3.DatabaseError) as error:
        raise RawEvidenceError("primary final raw custody invalid") from error


def _verify_primary_database_identity(db, task_id, attempt_id, policy_field, policy_digest):
    identities = db.execute("SELECT id,value FROM identity").fetchall()
    _require(
        len(identities) == 1
        and identities[0][0] == 1
        and type(identities[0][1]) is bytes
        and len(identities[0][1]) <= _MAX_JSON,
        "primary custody database identity absent",
    )
    identity = json.loads(identities[0][1])
    _require(
        type(identity) is dict
        and identity.get("task_id") == task_id
        and identity.get("attempt_id") == attempt_id
        and identity.get(policy_field) == policy_digest,
        "primary custody database task or policy mismatch",
    )


def verify_live_synthetic_fixture(
    evidence_root: Path,
    *,
    verifier: SignatureVerifier,
    run_id: str,
    task_id: str,
    freeze_sha256: str,
    image_id: str,
    registry_sha256: str,
    bindings_sha256: str,
    takeover_policy: PrimaryTakeoverPolicy | None = None,
    alternate_policy_sha256: str | None = None,
    memory_model_bindings: Mapping | None = None,
    budget_run_id: str | None = None,
) -> VerifiedFixture:
    """Verify one actual native fixture without treating it as an epoch record."""
    root = Path(evidence_root)
    _require(
        root.is_absolute() and root.is_dir() and not root.is_symlink(), "raw evidence root invalid"
    )
    _require(root.resolve(strict=True) == root, "raw evidence root is not canonical")
    result, raw_result = _json(root / "result.json")
    connection, _ = _json(root / "connection.json")
    manifest, _ = _json(root / "task-manifest.json")
    for row in (result, connection, manifest):
        _require(
            row.get("run_id") == run_id and row.get("task_id") == task_id,
            "fixture identity mismatch",
        )
        _require(row.get("configuration_sha256") == freeze_sha256, "fixture freeze mismatch")
    _require(
        result.get("scope") == "synthetic_native_live"
        and result.get("oracle_true") is True
        and result.get("provider_dispatched") is True
        and result.get("memory_episode_written") is True
        and result.get("boundary_failed") is False,
        "native fixture terminal result invalid",
    )
    _require(
        connection.get("image_id") == image_id
        and connection.get("capability_registry_sha256") == registry_sha256
        and connection.get("capability_bindings_sha256") == bindings_sha256,
        "native fixture inventory mismatch",
    )
    attempt_id = connection.get("attempt_id")
    _require(type(attempt_id) is str and bool(attempt_id), "native attempt ID absent")
    receipt_path = _evidence_child(root, connection.get("launch_receipt"))
    receipt, _ = _json(receipt_path)
    _require(
        receipt.get("event") == "launch_reserved"
        and receipt.get("run_id") == run_id
        and receipt.get("task_id") == task_id
        and receipt.get("launch_id") == connection.get("launch_id"),
        "native launcher receipt invalid",
    )
    final, _ = _json(root / "final/agent-final.json")
    candidate = _read(root / "final/poc", limit=8 * 1024 * 1024)
    digest = hashlib.sha256(candidate).hexdigest()
    accounting = None
    if takeover_policy is not None:
        from .raw_request_accounting import verify_request_accounting

        accounting = verify_request_accounting(
            root,
            task_id=task_id,
            attempt_id=attempt_id,
            takeover_policy=takeover_policy,
            registry_sha256=registry_sha256,
            alternate_policy_sha256=alternate_policy_sha256,
            memory_model_bindings=memory_model_bindings,
            budget_run_id=budget_run_id,
        )
        final = verify_primary_final_selection(
            root,
            task_id=task_id,
            attempt_id=attempt_id,
            takeover_policy=takeover_policy,
            accounting=accounting,
        )
    _require(
        final.get("selected_by") == ("glm_parent" if takeover_policy is None else "primary_parent")
        and final.get("final_declaration") is True
        and final.get("task_id") == task_id
        and final.get("sha256") == digest
        and final.get("byte_length") == len(candidate)
        and result.get("candidate_sha256") == digest,
        "single primary final or candidate digest invalid",
    )
    key_id, oracle_digest = _verify_oracle(
        root,
        verifier,
        {
            "run_id": run_id,
            "task_id": task_id,
            "attempt_id": attempt_id,
            "freeze_sha256": freeze_sha256,
            "image_id": image_id,
            "candidate_sha256": digest,
        },
    )
    _require(result.get("oracle_evidence_sha256") == oracle_digest, "oracle result digest mismatch")
    audit = verify_audit_chain(
        root / "runtime-events.jsonl", task_id=task_id, attempt_id=attempt_id
    )
    _require(audit.oracle_evidence_sha256 == oracle_digest, "oracle audit digest mismatch")
    preflights = _verify_preflights(root)
    primary = _verify_live_activity(
        root, task_id=task_id, attempt_id=attempt_id, accounting=accounting
    )
    return VerifiedFixture(
        run_id,
        task_id,
        attempt_id,
        str(root),
        key_id,
        hashlib.sha256(raw_result).hexdigest(),
        oracle_digest,
        digest,
        audit.row_count,
        audit.tail_sha256,
        preflights,
        primary,
        accounting,
        canonical_json(final) if takeover_policy is not None else None,
    )
