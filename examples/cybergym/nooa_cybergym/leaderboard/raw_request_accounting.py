# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Version-two independent accounting of all controller model reservations.

Unknown usage is never zero. A debit without a dispatch or settlement is retained
in the manifest and prevents a reconciled verdict. This module reads evidence;
it does not admit requests, infer provider identities, or certify a live run.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from xeus_cybergym.canonical import canonical_json

from .deepseek import CONTEXT_TOKENS, ROLE_LIMITS, DeepSeekRole
from .primary_takeover import PrimaryTakeoverPolicy
from .raw_fixture_attestor import (
    RawEvidenceError,
    _evidence_child,
    _read,
    _require,
    verify_audit_chain,
    verify_deepseek_model_usage,
)

_ALLOCATIONS = {"primary_and_memory": 1410, "deepseek_advisory": 90}
_ROLES = {role.value for role in DeepSeekRole}


def _identity(value: Any) -> bool:
    return (
        type(value) is str
        and 0 < len(value) <= 512
        and value == value.strip()
        and value.isprintable()
    )


def _digest(value: Any) -> bool:
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _integer(value: Any, *, positive=False) -> bool:
    return type(value) is int and value >= (1 if positive else 0)


def _duration(value: Any) -> bool:
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def validate_memory_model_bindings(bindings: Mapping) -> dict[str, dict[str, str]]:
    """Copy exact model/provider/kind bindings supplied by frozen controller inputs."""
    if not isinstance(bindings, Mapping) or not bindings:
        raise ValueError("frozen memory model bindings required")
    result = {}
    for model, binding in bindings.items():
        if (
            not _identity(model)
            or not isinstance(binding, Mapping)
            or set(binding) != {"provider", "kind"}
            or not all(_identity(binding[key]) for key in ("provider", "kind"))
        ):
            raise ValueError("frozen memory model binding invalid")
        result[model] = dict(binding)
    return result


@dataclass(frozen=True, slots=True)
class VerifiedRequestAccounting:
    """Immutable canonical facts; ``reconciled`` is not a certification verdict."""

    _canonical: bytes

    @property
    def manifest(self) -> dict[str, Any]:
        return json.loads(self._canonical)

    @property
    def digest(self) -> str:
        return hashlib.sha256(self._canonical).hexdigest()


def _lines(raw: bytes) -> list[dict]:
    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result, "duplicate raw accounting JSON key")
            result[key] = value
        return result

    _require(not raw or raw.endswith(b"\n"), "raw accounting log incomplete")
    result = []
    for line in raw.splitlines():
        try:
            row = json.loads(line, object_pairs_hook=pairs)
            canonical_json(row)
        except (ValueError, UnicodeError, TypeError) as error:
            raise RawEvidenceError("raw accounting JSON malformed") from error
        _require(type(row) is dict, "raw accounting object required")
        result.append(row)
    return result


def _reservations(events, *, task_id, attempt_id, budget_run_id):
    reservations, counts, request_ids, run_ordinals = (
        {},
        dict.fromkeys(_ALLOCATIONS, 0),
        set(),
        set(),
    )
    oracle = next(
        (i for i, row in enumerate(events) if row["event"] == "synthetic_oracle_observed"), None
    )
    for index, event in enumerate(events):
        kind = event.get("event")
        if kind not in {
            "task_request_reserved",
            "run_request_reserved",
            "post_oracle_memory_model_reserved",
        }:
            continue
        post = kind == "post_oracle_memory_model_reserved"
        allocation = event.get("run_allocation") if post else event.get("allocation")
        number, allocation_number = event.get("task_ordinal"), event.get("allocation_ordinal")
        request_id = event.get("request_id")
        _require(
            event.get("task_id") == task_id
            and event.get("attempt_id") == attempt_id
            and _identity(request_id)
            and request_id not in request_ids
            and _integer(number, positive=True)
            and number == len(reservations) + 1
            and allocation in _ALLOCATIONS
            and _integer(allocation_number, positive=True)
            and allocation_number == counts[allocation] + 1
            and number <= 1500
            and allocation_number <= _ALLOCATIONS[allocation],
            "request reservation identity, order or allocation invalid",
        )
        if post:
            _require(
                event.get("request_number") == number
                and event.get("allocation") == "glm_and_memory_auxiliary"
                and allocation == "primary_and_memory"
                and oracle is not None
                and index > oracle,
                "post-oracle reservation order invalid",
            )
        run_id, run_number = event.get("run_id"), event.get("run_ordinal")
        if kind == "run_request_reserved" or run_id is not None:
            _require(
                _identity(budget_run_id)
                and run_id == budget_run_id
                and _integer(run_number, positive=True)
                and run_number <= 15000
                and run_number not in run_ordinals
                and (not run_ordinals or run_number > max(run_ordinals)),
                "run request reservation identity or ordinal invalid",
            )
            run_ordinals.add(run_number)
        else:
            _require(budget_run_id is None and run_number is None, "run reservation absent")
        request_ids.add(request_id)
        counts[allocation] += 1
        reservations[number] = {
            "task_ordinal": number,
            "allocation": allocation,
            "allocation_ordinal": allocation_number,
            "reservation_request_id": request_id,
            "run_id": run_id,
            "epoch": None,
            "run_ordinal": run_number,
            "_event_index": index,
            "_post": post,
        }
    _require(bool(reservations), "durable request reservations absent")
    return reservations, counts


def _unknown_row(**values):
    return {
        "lane": "unmatched_reservation",
        "request_id": None,
        "provider_attempt_id": None,
        "permit_id": None,
        "provider": None,
        "configured_model": None,
        "returned_model": None,
        "provider_request_id": None,
        "model_version": None,
        "system_fingerprint": None,
        "role": None,
        "outcome": "unmatched",
        "usage_status": "unknown",
        "input_tokens": None,
        "output_tokens": None,
        "cache_tokens": None,
        "counted_tokens": None,
        "conservative_tokens": None,
        "elapsed_seconds": None,
        **values,
    }


def _primary_attempts(requests, usage_rows, policy, task_id, attempt_id, claim):
    reserved, terminal, native, positions, transitions = {}, {}, {}, {}, []
    for index, row in enumerate(requests):
        event = row.get("event")
        if event in {"primary_route_switched", "primary_request_continued"}:
            transitions.append((index, row))
        elif event == "native_request_terminal":
            request_id = row.get("request_id")
            _require(
                _identity(request_id)
                and request_id not in native
                and row.get("task_id") == task_id
                and row.get("attempt_id") == attempt_id
                and row.get("takeover_policy_sha256") == policy.digest
                and row.get("outcome") in {"completed", "interrupted"},
                "native terminal custody invalid",
            )
            native[request_id] = (index, row)
        elif event in {"request_reserved", "request_terminal"}:
            _require(row.get("role") == "primary", "unrecognized gateway model lane")
            provider_attempt = row.get("provider_attempt_id")
            _require(
                _identity(provider_attempt)
                and _identity(row.get("request_id"))
                and provider_attempt != row["request_id"]
                and row.get("task_id") == task_id
                and row.get("attempt_id") == attempt_id
                and row.get("takeover_policy_sha256") == policy.digest
                and row.get("allocation") == "primary_and_memory",
                "primary provider attempt identity invalid",
            )
            destination = reserved if event == "request_reserved" else terminal
            _require(provider_attempt not in destination, "duplicate provider attempt event")
            destination[provider_attempt] = row
            positions[(event, provider_attempt)] = index
    _require(
        reserved and reserved.keys() == terminal.keys(), "primary attempt lifecycle incomplete"
    )
    usage = {}
    for row in usage_rows:
        provider_attempt = row.get("provider_attempt_id")
        _require(
            row.get("event") == "usage"
            and provider_attempt in reserved
            and provider_attempt not in usage,
            "unmatched or duplicate provider usage",
        )
        usage[provider_attempt] = row
    _require(usage.keys() == reserved.keys(), "primary provider usage absent")
    native_attempts = {}
    for provider_attempt, request in reserved.items():
        result, observed = terminal[provider_attempt], usage[provider_attempt]
        route = next(
            (
                route
                for route in (policy.initial, policy.fallback)
                if (
                    request.get("provider"),
                    request.get("configured_model"),
                    request.get("requested_model"),
                )
                == (route.provider, route.model, route.wire_model)
            ),
            None,
        )
        _require(route is not None, "primary provider route invalid")
        count = request.get("upstream_endpoint") == route.base_url + "/v1/messages/count_tokens"
        _require(
            request.get("upstream_endpoint") == route.base_url + "/v1/messages"
            or (count and route == policy.initial),
            "primary provider endpoint invalid",
        )
        for key in (
            "request_id",
            "provider_attempt_id",
            "provider",
            "configured_model",
            "takeover_policy_sha256",
            "allocation",
            "shared_request_number",
        ):
            _require(
                result.get(key) == observed.get(key) == request.get(key),
                "primary provider attempt join mismatch",
            )
        _require(
            positions[("request_reserved", provider_attempt)]
            < positions[("request_terminal", provider_attempt)]
            and observed.get("task_id") == task_id
            and observed.get("attempt_id") == attempt_id
            and observed.get("model") == route.wire_model
            and result.get("requested_model") == route.wire_model
            and result.get("upstream_endpoint") == request["upstream_endpoint"]
            and result.get("request_sha256") == request.get("request_sha256")
            and _digest(request.get("request_sha256"))
            and _duration(result.get("duration_seconds")),
            "primary provider dispatch evidence invalid",
        )
        for key in (
            "usage_status",
            "counted_tokens",
            "returned_model",
            "provider_request_id",
            "model_version",
            "system_fingerprint",
        ):
            _require(result.get(key) == observed.get(key), "primary usage settlement mismatch")
        fields = _unknown_row(
            lane="count_tokens" if count else "primary",
            request_id=request["request_id"],
            provider_attempt_id=provider_attempt,
            provider=route.provider,
            configured_model=route.model,
            role="primary",
            outcome=result.get("outcome"),
            returned_model=observed.get("returned_model"),
            provider_request_id=observed.get("provider_request_id"),
            model_version=observed.get("model_version"),
            system_fingerprint=observed.get("system_fingerprint"),
            elapsed_seconds=result["duration_seconds"],
        )
        if result.get("outcome") == "completed":
            numbers = (
                [observed.get("input_tokens")]
                if count
                else [
                    observed.get(name)
                    for name in (
                        "input_tokens",
                        "output_tokens",
                        "cache_read_tokens",
                        "cache_creation_tokens",
                    )
                ]
            )
            _require(
                observed.get("usage_status") == "observed"
                and all(_integer(value) for value in numbers)
                and observed.get("counted_tokens") == sum(numbers) <= 1_000_000
                and (
                    count
                    or (
                        _identity(observed.get("provider_request_id"))
                        and observed.get("returned_model") == route.wire_model
                    )
                )
                and (not count or observed.get("returned_model") in {None, route.wire_model}),
                "primary observed usage invalid",
            )
            fields.update(
                usage_status="observed",
                input_tokens=numbers[0],
                output_tokens=0 if count else numbers[1],
                cache_tokens=0 if count else numbers[2] + numbers[3],
                counted_tokens=sum(numbers),
                conservative_tokens=0,
            )
        else:
            _require(
                result.get("outcome")
                in {
                    "provider_error",
                    "transport_error",
                    "cancelled",
                    "deadline_exceeded",
                    "start_failed",
                }
                and observed.get("usage_status") in {"interrupted", "unavailable"}
                and observed.get("reserved_tokens") == observed.get("counted_tokens") == 1_000_000,
                "unknown primary usage lost its conservative reservation",
            )
            fields["conservative_tokens"] = 1_000_000
        claim(request["shared_request_number"], "primary_and_memory", fields)
        native_attempts.setdefault(request["request_id"], []).append(provider_attempt)
    _require(
        native.keys() == native_attempts.keys(), "native request terminal missing or unmatched"
    )
    _verify_transitions(
        transitions, reserved, terminal, positions, native_attempts, policy, task_id, attempt_id
    )
    for request_id, attempts in native_attempts.items():
        final = max(attempts, key=lambda value: positions[("request_terminal", value)])
        _require(
            native[request_id][0] > positions[("request_terminal", final)]
            and (
                native[request_id][1]["outcome"] != "completed"
                or terminal[final]["outcome"] == "completed"
            ),
            "native terminal precedes or contradicts provider settlement",
        )
    return [row for _, row in transitions]


def _verify_transitions(
    transitions, reserved, terminal, positions, native_attempts, policy, task_id, attempt_id
):
    switches = [
        (index, row) for index, row in transitions if row["event"] == "primary_route_switched"
    ]
    _require(len(switches) <= 1, "repeated primary route switch")
    switched = switches[0] if switches else None
    continuations = {}
    for index, event in transitions:
        failed, fallback, native_id = (
            event.get("failed_provider_attempt_id"),
            event.get("fallback_provider_attempt_id"),
            event.get("request_id"),
        )
        _require(
            event.get("task_id") == task_id
            and event.get("attempt_id") == attempt_id
            and event.get("policy_sha256") == policy.digest
            and event.get("response_started") is False
            and event.get("failure_kind") in policy.eligible_failure_kinds
            and failed in reserved
            and fallback in reserved
            and native_id in native_attempts
            and failed != fallback
            and native_id not in continuations,
            "primary takeover evidence identity invalid",
        )
        _require(
            reserved[failed]["request_id"] == reserved[fallback]["request_id"] == native_id
            and reserved[failed]["provider"] == policy.initial.provider
            and reserved[fallback]["provider"] == policy.fallback.provider
            and terminal[failed].get("takeover_eligible") is True
            and terminal[failed].get("response_started") is False
            and terminal[failed].get("outcome") in {"provider_error", "transport_error"}
            and terminal[failed].get("failure_code") == event["failure_kind"]
            and positions[("request_terminal", failed)]
            < index
            < positions[("request_reserved", fallback)],
            "primary takeover is ineligible or follows response exposure",
        )
        if event["event"] == "primary_route_switched":
            _require(
                event.get("schema_version") == 1
                and event.get("from_route") == asdict(policy.initial)
                and event.get("to_route") == asdict(policy.fallback),
                "primary route transition policy changed",
            )
        else:
            _require(
                switched is not None and switched[0] < index,
                "continuation lacks preceding transition",
            )
            original = switched[1]
            _require(
                event.get("transition_request_id") == original["request_id"]
                and event.get("transition_failed_provider_attempt_id")
                == original["failed_provider_attempt_id"]
                and event.get("transition_fallback_provider_attempt_id")
                == original["fallback_provider_attempt_id"]
                and event.get("transition_sha256")
                == hashlib.sha256(
                    json.dumps(
                        original,
                        sort_keys=True,
                        separators=(",", ":"),
                        allow_nan=False,
                    ).encode()
                ).hexdigest(),
                "continuation transition reference invalid",
            )
        continuations[native_id] = (failed, fallback)
    for native_id, attempts in native_attempts.items():
        _require(
            len(attempts) == 1
            or (len(attempts) == 2 and set(attempts) == set(continuations.get(native_id, ()))),
            "unexplained native provider retry",
        )
        for provider_attempt in attempts:
            initial = reserved[provider_attempt]["provider"] == policy.initial.provider
            index = positions[("request_reserved", provider_attempt)]
            _require(
                (initial and (switched is None or index < switched[0]))
                or (not initial and switched is not None and index > switched[0]),
                "primary route dispatch lacks prior transition or reverted",
            )


def _advisory_attempts(events, root, task_id, attempt_id, registry, alternate, reservations, claim):
    verify_deepseek_model_usage(
        root,
        task_id=task_id,
        attempt_id=attempt_id,
        registry_sha256=registry,
        policy_sha256=alternate,
    )
    requested, completed, positions = {}, {}, {}
    for index, event in enumerate(events):
        if event.get("event") not in {"request", "response", "failure"}:
            continue
        if any(
            key in event for key in ("role", "requested_model", "shared_request_number", "endpoint")
        ):
            _require(event.get("role") in _ROLES, "unrecognized runtime model lane")
            kind = "request" if event["event"] == "request" else "terminal"
            (requested if kind == "request" else completed)[event["request_id"]] = event
            positions[(kind, event["request_id"])] = index
    states = {role: {"requests": 0, "tokens": 0, "seconds": 0.0} for role in _ROLES}
    for request_id, request in requested.items():
        result, role = completed[request_id], request["role"]
        ordinal = request.get("shared_request_number")
        _require(
            _integer(ordinal, positive=True)
            and ordinal in reservations
            and reservations[ordinal]["_event_index"]
            < positions[("request", request_id)]
            < positions[("terminal", request_id)],
            "advisory debit or settlement order invalid",
        )
        _require(_duration(result.get("duration_seconds")), "advisory duration invalid")
        row = _unknown_row(
            lane="advisory",
            request_id=request_id,
            provider="deepseek-official-api",
            configured_model="deepseek-flash",
            role=role,
            outcome="completed" if result["event"] == "response" else "failed",
            returned_model=result.get("returned_model"),
            provider_request_id=result.get("provider_request_id"),
            model_version=result.get("model_version"),
            system_fingerprint=result.get("system_fingerprint"),
            conservative_tokens=CONTEXT_TOKENS,
            elapsed_seconds=result["duration_seconds"],
        )
        if result["event"] == "response":
            usage = result["usage"]
            row.update(
                usage_status="observed",
                input_tokens=usage["input_tokens"],
                output_tokens=usage["output_tokens"],
                cache_tokens=usage["cache_hit_input_tokens"],
                counted_tokens=usage["counted_tokens"],
                conservative_tokens=0,
            )
        state = states[role]
        state["requests"] += 1
        _require(
            request["request_number"] == state["requests"], "advisory role request sequence invalid"
        )
        state["tokens"] += (
            row["counted_tokens"] if row["usage_status"] == "observed" else CONTEXT_TOKENS
        )
        state["seconds"] += result["duration_seconds"]
        _, calls, tokens, seconds = ROLE_LIMITS[DeepSeekRole(role)]
        _require(
            state["requests"] <= calls
            and state["tokens"] <= tokens
            and state["seconds"] <= seconds,
            "advisory role allocation exceeded",
        )
        claim(request["shared_request_number"], "deepseek_advisory", row)


def _memory_attempts(events, reservations, bindings, claim):
    admitted, settled, reconciled = {}, {}, True
    for index, event in enumerate(events):
        if event.get("event") not in {"memory_model_admitted", "memory_model_settled"}:
            continue
        key = event.get("request_id"), event.get("permit_id")
        _require(all(_identity(value) for value in key), "memory invocation identity invalid")
        target = admitted if event["event"] == "memory_model_admitted" else settled
        _require(key not in target, "duplicate memory invocation event")
        target[key] = (index, event)
    _require(settled.keys() <= admitted.keys(), "memory settlement lacks admission")
    for key, (admission_index, event) in admitted.items():
        ordinal, model = event.get("reservation_id"), event.get("model_id")
        _require(
            _integer(ordinal, positive=True)
            and ordinal in reservations
            and model in bindings
            and event.get("kind") == bindings[model]["kind"]
            and _identity(event.get("operation"))
            and _duration(event.get("started_monotonic"))
            and reservations[ordinal]["_event_index"] < admission_index,
            "memory admission binding or reservation invalid",
        )
        row = _unknown_row(
            lane="post_oracle_memory" if reservations[ordinal]["_post"] else "memory",
            request_id=key[0],
            permit_id=key[1],
            provider=bindings[model]["provider"],
            configured_model=model,
            role=bindings[model]["kind"],
            outcome="unsettled",
        )
        if key not in settled:
            reconciled = False
        else:
            settlement_index, result = settled[key]
            _require(
                settlement_index > admission_index
                and all(
                    result.get(field) == event.get(field)
                    for field in (
                        "request_id",
                        "permit_id",
                        "reservation_id",
                        "model_id",
                        "kind",
                        "operation",
                        "started_monotonic",
                    )
                )
                and _duration(result.get("duration_seconds")),
                "memory settlement identity or duration invalid",
            )
            row.update(outcome="failed", elapsed_seconds=result["duration_seconds"])
            usage = result.get("usage")
            if usage is not None:
                names = ("inputTokens", "outputTokens", "cacheReadTokens", "cacheWriteTokens")
                _require(
                    type(usage) is dict
                    and set(usage) == set(names)
                    and all(
                        _duration(usage[name]) and float(usage[name]).is_integer() for name in names
                    ),
                    "memory token usage invalid",
                )
                values = [int(usage[name]) for name in names]
                row.update(
                    outcome="completed",
                    usage_status="observed",
                    input_tokens=values[0],
                    output_tokens=values[1],
                    cache_tokens=values[2] + values[3],
                    counted_tokens=sum(values),
                    conservative_tokens=0,
                )
        claim(ordinal, "primary_and_memory", row)
    return reconciled


def verify_request_accounting(
    evidence_root: Path,
    *,
    task_id: str,
    attempt_id: str,
    takeover_policy: PrimaryTakeoverPolicy,
    registry_sha256: str,
    alternate_policy_sha256: str,
    memory_model_bindings: Mapping,
    budget_run_id: str | None = None,
) -> VerifiedRequestAccounting:
    """Reconcile all raw request lanes under explicit new frozen policy inputs."""
    _require(
        type(takeover_policy) is PrimaryTakeoverPolicy
        and all(_digest(value) for value in (registry_sha256, alternate_policy_sha256)),
        "frozen accounting policy identity required",
    )
    bindings = validate_memory_model_bindings(memory_model_bindings)
    root = Path(evidence_root)
    _require(
        root.is_absolute()
        and root.is_dir()
        and not root.is_symlink()
        and root.resolve(strict=True) == root,
        "raw accounting root invalid",
    )
    files = {
        name: _read(_evidence_child(root, str(root / name)))
        for name in ("runtime-events.jsonl", "model-requests.jsonl", "model-usage.jsonl")
    }
    logs = {name: _lines(raw) for name, raw in files.items()}
    verify_audit_chain(root / "runtime-events.jsonl", task_id=task_id, attempt_id=attempt_id)
    events = [row["event"] for row in logs["runtime-events.jsonl"]]
    _require(
        all(type(row) is dict and _identity(row.get("event")) for row in events),
        "runtime event malformed",
    )
    reservations, counts = _reservations(
        events,
        task_id=task_id,
        attempt_id=attempt_id,
        budget_run_id=budget_run_id,
    )
    claimed = {}

    def claim(number, allocation, row):
        _require(
            _integer(number, positive=True)
            and number in reservations
            and number not in claimed
            and reservations[number]["allocation"] == allocation,
            "dispatch reservation unmatched, duplicated or misallocated",
        )
        _require(
            not reservations[number]["_post"] or row["lane"] == "post_oracle_memory",
            "non-memory dispatch consumed post-oracle debit",
        )
        claimed[number] = row

    transitions = _primary_attempts(
        logs["model-requests.jsonl"],
        logs["model-usage.jsonl"],
        takeover_policy,
        task_id,
        attempt_id,
        claim,
    )
    _advisory_attempts(
        events,
        root,
        task_id,
        attempt_id,
        registry_sha256,
        alternate_policy_sha256,
        reservations,
        claim,
    )
    reconciled = _memory_attempts(events, reservations, bindings, claim)
    rows, provider_ids = [], set()
    for number, reservation in reservations.items():
        row = claimed.get(number, _unknown_row())
        provider_id = row["provider_request_id"]
        if provider_id is not None:
            _require(
                _identity(provider_id) and provider_id not in provider_ids,
                "provider request identity reused",
            )
            provider_ids.add(provider_id)
        for field in ("model_version", "system_fingerprint"):
            _require(row[field] is None or _identity(row[field]), "provider metadata malformed")
        rows.append(
            {key: value for key, value in reservation.items() if not key.startswith("_")} | row
        )
    totals = {
        "model_requests": len(rows),
        "observed_requests": sum(row["usage_status"] == "observed" for row in rows),
        "unknown_usage_requests": sum(row["usage_status"] == "unknown" for row in rows),
        "unmatched_reservations": sum(row["lane"] == "unmatched_reservation" for row in rows),
        **{
            field: sum(row[field] or 0 for row in rows)
            for field in (
                "input_tokens",
                "output_tokens",
                "cache_tokens",
                "counted_tokens",
                "conservative_tokens",
            )
        },
        "unbounded_unknown_usage_requests": sum(
            row["usage_status"] == "unknown" and row["conservative_tokens"] is None for row in rows
        ),
    }
    manifest = {
        "schema_version": 2,
        "task_id": task_id,
        "attempt_id": attempt_id,
        "takeover_policy_sha256": takeover_policy.digest,
        "registry_sha256": registry_sha256,
        "alternate_policy_sha256": alternate_policy_sha256,
        "memory_model_bindings_sha256": hashlib.sha256(canonical_json(bindings)).hexdigest(),
        "evidence_sha256": {name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()},
        "requests": rows,
        "allocations": counts,
        "totals": totals,
        "reconciled": reconciled and not totals["unmatched_reservations"],
        "transitions": transitions,
    }
    return VerifiedRequestAccounting(canonical_json(manifest))
