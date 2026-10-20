# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed comparison and Xeus-signable payload for two synthetic runs.

This validates reported evidence and independently attested raw-run identities;
it neither executes the native harness nor proves that a unit fixture is live.
The controller must inject an attestor that reads the real raw evidence and
the existing Xeus Ed25519 signer/verifier. A report never authorises launch.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Any, Protocol

from .capabilities import CapabilityRegistry, ControlLabel, Role, Status
from .certification import CertificationBinding, CertificationPolicy
from .model_gateway import PRIMARY_WIRE_MODEL
from .primary_takeover import PrimaryTakeoverPolicy

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,191}\Z")
_FROZEN_HASH_KEYS = frozenset(
    {
        "harness_sha256",
        "image_sha256",
        "prompt_sha256",
        "skill_sha256",
        "workflow_sha256",
        "extension_sha256",
        "memory_seed_sha256",
        "memory_policy_sha256",
    }
)
_GATES = frozenset(
    {
        "native_vscode",
        "isolation_preflight",
        "model_gateway",
        "deepseek_roles",
        "capability_registry",
        "hybrid_memory",
        "single_final",
        "private_oracle",
        "interruption_reconnection",
        "timeout_failure",
        "version_drift",
        "negative_leakage_probes",
    }
)
_MODEL_ROLES = frozenset(
    {
        "glm_parent",
        "independent_recon",
        "conditional_debug_recovery",
        "final_adversarial_critic",
    }
)
_TRIGGERS = {
    "glm_parent": "native_parent",
    "independent_recon": "independent",
    "conditional_debug_recovery": "controller_observed_vulnerable_failure",
    "final_adversarial_critic": "final_review",
}


def _digest(value: Any) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _safe_identifier(value: Any) -> bool:
    return type(value) is str and _SAFE_IDENTIFIER.fullmatch(value) is not None


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _positive_int(value: Any) -> bool:
    return type(value) is int and value > 0


def _nonnegative_int(value: Any) -> bool:
    return type(value) is int and value >= 0


def _safe_evidence_path(path: Any, root: str) -> bool:
    if type(path) is not str or type(root) is not str or not path.startswith(root + "/"):
        return False
    parsed = PurePosixPath(path)
    return (
        path.startswith("/")
        and not path.startswith("//")
        and str(parsed) == path
        and ".." not in path.split("/")
    )


@dataclass(frozen=True, slots=True)
class CertificationExpectations:
    """Independent frozen inputs and a controller-owned raw evidence verifier."""

    policy: CertificationPolicy
    binding: CertificationBinding
    registry: CapabilityRegistry
    required_approved_capability_ids: frozenset[str]
    frozen_hashes: Mapping[str, str]
    cohort_sha256: str
    campaign_policy_sha256: str
    official_cohort_ids: frozenset[str]
    primary_provider: str
    attest_raw_run: Callable[[Mapping[str, Any]], Mapping[str, Any] | None]
    takeover_policy: PrimaryTakeoverPolicy | None = None
    memory_model_bindings: Mapping[str, Mapping[str, str]] | None = None

    def __post_init__(self) -> None:
        if type(self.policy) is not CertificationPolicy:
            raise TypeError("frozen certification policy required")
        if type(self.binding) is not CertificationBinding:
            raise TypeError("certification policy binding required")
        if type(self.registry) is not CapabilityRegistry:
            raise TypeError("frozen capability registry required")
        if self.binding.policy_sha256 != self.policy.sha256:
            raise ValueError("certification policy hash differs from binding")
        if self.binding.capability_registry_sha256 != self.registry.digest:
            raise ValueError("capability registry hash differs from binding")
        approved_ids = {
            entry.capability_id
            for entry in self.registry.entries
            if entry.status is Status.APPROVED
        }
        if (
            type(self.required_approved_capability_ids) is not frozenset
            or not self.required_approved_capability_ids
            or any(not _safe_identifier(item) for item in self.required_approved_capability_ids)
            or not self.required_approved_capability_ids <= approved_ids
        ):
            raise ValueError("nonempty frozen approved capability baseline required")
        if (
            not isinstance(self.frozen_hashes, Mapping)
            or set(self.frozen_hashes) != _FROZEN_HASH_KEYS
            or any(not _digest(value) for value in self.frozen_hashes.values())
        ):
            raise ValueError("complete frozen harness hashes required")
        if any(
            not _digest(value)
            for value in (
                self.binding.alternate_policy_sha256,
                self.binding.network_policy_sha256,
                self.cohort_sha256,
                self.campaign_policy_sha256,
            )
        ):
            raise ValueError("alternate, network, cohort, and campaign policy hashes required")
        if type(self.official_cohort_ids) is not frozenset:
            raise TypeError("official cohort identities must be frozen")
        if type(self.primary_provider) is not str or not self.primary_provider.startswith(
            "https://"
        ):
            raise ValueError("frozen primary provider required")
        if not callable(self.attest_raw_run):
            raise TypeError("independent raw evidence attestor required")
        object.__setattr__(self, "frozen_hashes", MappingProxyType(dict(self.frozen_hashes)))
        if self.takeover_policy is None:
            if self.memory_model_bindings is not None:
                raise ValueError("memory model bindings require explicit takeover policy")
        else:
            if type(self.takeover_policy) is not PrimaryTakeoverPolicy:
                raise TypeError("frozen primary takeover policy required")
            from .raw_request_accounting import validate_memory_model_bindings

            bindings = validate_memory_model_bindings(self.memory_model_bindings)
            object.__setattr__(
                self,
                "memory_model_bindings",
                MappingProxyType(
                    {key: MappingProxyType(dict(value)) for key, value in bindings.items()}
                ),
            )

    @property
    def memory_model_bindings_sha256(self) -> str | None:
        if self.memory_model_bindings is None:
            return None
        return hashlib.sha256(
            _canonical({key: dict(value) for key, value in self.memory_model_bindings.items()})
        ).hexdigest()

    @property
    def all_hashes(self) -> dict[str, str]:
        hashes = {
            **self.frozen_hashes,
            "policy_sha256": self.binding.policy_sha256,
            "alternate_policy_sha256": self.binding.alternate_policy_sha256,
            "capability_registry_sha256": self.binding.capability_registry_sha256,
            "network_policy_sha256": self.binding.network_policy_sha256,
            "cohort_sha256": self.cohort_sha256,
            "campaign_policy_sha256": self.campaign_policy_sha256,
        }
        if self.takeover_policy is not None:
            hashes["takeover_policy_sha256"] = self.takeover_policy.digest
            hashes["memory_model_bindings_sha256"] = self.memory_model_bindings_sha256
        return hashes


@dataclass(frozen=True, slots=True)
class ComparisonReport:
    passed: bool
    failures: tuple[str, ...]
    payload: dict[str, Any]
    payload_sha256: str


@dataclass(frozen=True, slots=True)
class SignedReport:
    payload_json: bytes
    envelope_json: bytes


class XeusSigner(Protocol):
    def sign(self, payload: bytes) -> Any: ...


class XeusVerifier(Protocol):
    def verify(self, envelope: Any) -> bytes: ...


def _required_bool(value: Any, *, expected: bool) -> bool:
    return type(value) is bool and value is expected


def _validate_hashes(
    run: Mapping[str, Any], expected: CertificationExpectations, label: str, failures: list[str]
) -> None:
    hashes = run.get("hashes")
    if type(hashes) is not dict:
        failures.append(f"{label}:frozen hashes absent")
        return
    for name, digest in expected.all_hashes.items():
        if hashes.get(name) != digest or not _digest(hashes.get(name)):
            failures.append(f"{name} mismatch")
    if set(hashes) != set(expected.all_hashes):
        failures.append(f"{label}:undeclared or missing frozen hash")


def _validate_gates(run: Mapping[str, Any], label: str, failures: list[str]) -> None:
    gates = run.get("gates")
    root = run.get("evidence_root")
    if type(gates) is not dict:
        failures.extend(f"{label}:{gate} gate absent" for gate in sorted(_GATES))
        return
    for gate in sorted(_GATES):
        item = gates.get(gate)
        if type(item) is not dict:
            failures.append(f"{label}:{gate} gate absent")
            continue
        if (
            item.get("status") != "PASS"
            or not _required_bool(item.get("observed"), expected=True)
            or not _safe_evidence_path(item.get("evidence_path"), root)
            or not _digest(item.get("sha256"))
        ):
            failures.append(f"{label}:{gate} gate not observed PASS")
    if set(gates) != _GATES:
        failures.append(f"{label}:undeclared or missing gate")


def _valid_tool_route(routes: tuple[str, ...], row: Mapping[str, Any]) -> bool:
    if "route" not in row:
        return False
    route = row["route"]
    if not routes:
        return route is None
    if len(routes) == 1:
        return type(route) is str and route == routes[0]
    # Native Bash/run_test and Workflow reserve a bundle of logical routes at
    # admission. Naming one arbitrary member would misstate what was enabled.
    return type(route) is list and route == sorted(routes)


def _valid_version_metadata(row: Mapping[str, Any]) -> bool:
    version = row.get("observed_version")
    fingerprint = row.get("system_fingerprint")
    if not _safe_identifier(row.get("returned_model")):
        return False
    if version is not None and not _safe_identifier(version):
        return False
    if fingerprint is not None and not _safe_identifier(fingerprint):
        return False
    status = (
        "version_observed"
        if version is not None
        else "fingerprint_only"
        if fingerprint is not None
        else "provider_omitted"
    )
    return row.get("version_metadata_status") == status


def _validate_capabilities(
    run: Mapping[str, Any], expected: CertificationExpectations, label: str, failures: list[str]
) -> int:
    raw = run.get("capabilities")
    if type(raw) is not dict:
        failures.append(f"{label}:capability evidence absent")
        return 0
    enabled = {
        entry.capability_id: entry
        for entry in expected.registry.entries
        if entry.status is Status.APPROVED
    }
    expected_ids = set(enabled)
    seen_enabled = raw.get("enabled_ids")
    exercised = raw.get("exercised_ids")
    if (
        type(seen_enabled) is not list
        or any(type(item) is not str for item in seen_enabled)
        or len(seen_enabled) != len(set(seen_enabled))
        or set(seen_enabled) != expected_ids
    ):
        failures.append(f"{label}:enabled capability registry mismatch")
    if (
        type(exercised) is not list
        or any(type(item) is not str for item in exercised)
        or len(exercised) != len(set(exercised))
        or set(exercised) != expected_ids
    ):
        failures.append(f"{label}:enabled capability not exercised")
    if raw.get("undeclared_calls") != []:
        failures.append(f"{label}:undeclared tool or MCP route")
    calls = raw.get("tool_calls")
    if type(calls) is not list:
        failures.append(f"{label}:tool and MCP call log absent")
        return 0
    used_ids = set()
    total = 0
    for row in calls:
        if type(row) is not dict:
            failures.append(f"{label}:undeclared tool or MCP route")
            continue
        capability_id = row.get("capability_id")
        entry = enabled.get(capability_id) if type(capability_id) is str else None
        role_name = row.get("role")
        try:
            role = Role(role_name)
        except (ValueError, TypeError):
            role = None
        if (
            entry is None
            or row.get("tool_id") != entry.identity.tool_id
            or not _valid_tool_route(entry.routes, row)
            or role not in entry.roles
            or not _positive_int(row.get("count"))
        ):
            failures.append(f"{label}:undeclared tool or MCP route")
            continue
        used_ids.add(entry.capability_id)
        total += row["count"]
    if used_ids != expected_ids:
        failures.append(f"{label}:enabled capability not exercised")
    return total


def _validate_models(
    run: Mapping[str, Any], expected: CertificationExpectations, label: str, failures: list[str]
) -> dict[str, int]:
    rows = run.get("models")
    if type(rows) is not list:
        failures.append(f"{label}:model request log absent")
        return {}
    policy = expected.policy
    assignments = [
        (row.get("fixture_id"), row.get("role")) if type(row) is dict else (None, None)
        for row in rows
    ]
    required_assignments = {
        (fixture_id, role) for fixture_id in policy.fixture_ids for role in _MODEL_ROLES
    }
    if (
        len(assignments) != len(required_assignments)
        or any(
            type(fixture_id) is not str or type(role) is not str for fixture_id, role in assignments
        )
        or set(assignments) != required_assignments
    ):
        failures.append(f"{label}:undeclared model role")
    totals = {"model_requests": 0, "input_tokens": 0, "output_tokens": 0, "cache_tokens": 0}
    request_ids = set()
    requests_by_fixture = dict.fromkeys(policy.fixture_ids, 0)
    deepseek_by_fixture = dict.fromkeys(policy.fixture_ids, 0)
    for row in rows:
        if (
            type(row) is not dict
            or type(row.get("fixture_id")) is not str
            or row.get("fixture_id") not in policy.fixture_ids
            or type(row.get("role")) is not str
            or row.get("role") not in _MODEL_ROLES
        ):
            continue
        fixture_id = row["fixture_id"]
        role = row["role"]
        deepseek = role != "glm_parent"
        if deepseek:
            settings_good = (
                row.get("model") == policy.alternate_model
                and row.get("provider") == policy.alternate_provider
                and row.get("thinking") == policy.alternate_thinking
                and row.get("reasoning_effort") == policy.alternate_reasoning_effort
                and row.get("context_tokens") == policy.alternate_context_tokens
            )
            if not settings_good:
                failures.append(f"{label}:DeepSeek role settings")
            if row.get("trigger") != _TRIGGERS[role]:
                failures.append(
                    f"{label}:DeepSeek debug trigger"
                    if role == "conditional_debug_recovery"
                    else f"{label}:DeepSeek role trigger"
                )
        elif (
            row.get("model") != policy.primary_model
            or row.get("provider") != expected.primary_provider
            or row.get("reasoning_effort") != policy.reasoning_effort
            or row.get("thinking") != {"level": "max"}
            or row.get("context_tokens") != policy.context_tokens
            or row.get("trigger") != _TRIGGERS[role]
        ):
            failures.append(f"{label}:GLM parent settings")
        if not _valid_version_metadata(row):
            failures.append(f"{label}:provider version metadata absent")
        expected_returned_model = policy.alternate_model if deepseek else PRIMARY_WIRE_MODEL
        if (
            row.get("alias_drift") is not False
            or row.get("returned_model") != expected_returned_model
        ):
            failures.append(f"{label}:model alias drift")
        ids = row.get("provider_request_ids")
        requests = row.get("requests")
        if (
            type(ids) is not list
            or any(not _safe_identifier(item) for item in ids)
            or not _positive_int(requests)
            or len(ids) != requests
            or len(set(ids)) != len(ids)
            or request_ids.intersection(ids)
        ):
            failures.append(f"{label}:provider request metadata absent")
        else:
            request_ids.update(ids)
        for field in ("input_tokens", "output_tokens", "cache_tokens"):
            if not _nonnegative_int(row.get(field)):
                failures.append(f"{label}:model token counts absent")
            else:
                totals[field] += row[field]
        if _positive_int(requests):
            totals["model_requests"] += requests
            requests_by_fixture[fixture_id] += requests
            if deepseek:
                deepseek_by_fixture[fixture_id] += requests
        if deepseek and _positive_int(requests):
            token_sum = (
                row["input_tokens"] + row["output_tokens"]
                if _nonnegative_int(row.get("input_tokens"))
                and _nonnegative_int(row.get("output_tokens"))
                else -1
            )
            if (
                requests > policy.alternate_max_requests_by_role[role]
                or token_sum < 0
                or token_sum > policy.alternate_max_tokens_by_role[role]
                or type(row.get("elapsed_seconds")) not in (int, float)
                or not 0 < row["elapsed_seconds"] <= policy.alternate_max_seconds_by_role[role]
            ):
                failures.append(f"{label}:DeepSeek role budget")
    if any(count > policy.max_model_requests_per_task for count in requests_by_fixture.values()):
        failures.append(f"{label}:shared model request budget")
    alternate_allocation = sum(policy.alternate_max_requests_by_role.values())
    primary_allocation = policy.max_model_requests_per_task - alternate_allocation
    if any(
        requests_by_fixture[fixture_id] - deepseek_by_fixture[fixture_id] > primary_allocation
        for fixture_id in policy.fixture_ids
    ):
        failures.append(f"{label}:GLM and memory request allocation")
    if any(count > alternate_allocation for count in deepseek_by_fixture.values()):
        failures.append(f"{label}:DeepSeek request allocation")
    return totals


def _validate_memory(run: Mapping[str, Any], label: str, failures: list[str]) -> None:
    memory = run.get("memory")
    if type(memory) is not dict or memory.get("mode") != "audited_hybrid":
        failures.append(f"{label}:audited hybrid memory evidence absent")
        return
    for name in (
        "automatic_recall_exercised",
        "parent_child_recall_search_exercised",
        "native_started_empty",
        "agent_write_denied",
    ):
        if not _required_bool(memory.get(name), expected=True):
            failures.append(f"{label}:{name} absent")
    if not _required_bool(memory.get("native_prior_task_mounted"), expected=False):
        failures.append(f"{label}:native memory carryover")
    retrievals = memory.get("retrieval_events")
    if (
        type(retrievals) is not list
        or {item.get("role") for item in retrievals if type(item) is dict} != {"parent", "child"}
        or any(item.get("source") != "isolated-gbrain" for item in retrievals if type(item) is dict)
    ):
        failures.append(f"{label}:parent and child GBrain retrieval evidence absent")
    writes = memory.get("write_events")
    if (
        type(writes) is not list
        or not writes
        or any(
            type(item) is not dict
            or item.get("actor") != "controller"
            or item.get("oracle_true") is not True
            or not item.get("verdict_id")
            for item in writes
        )
    ):
        failures.append(f"{label}:unsafe GBrain write")


_ACCOUNTING_TOTALS = frozenset(
    {
        "model_requests",
        "observed_requests",
        "unknown_usage_requests",
        "unmatched_reservations",
        "input_tokens",
        "output_tokens",
        "cache_tokens",
        "counted_tokens",
        "conservative_tokens",
        "unbounded_unknown_usage_requests",
    }
)


def _validate_accounting(
    run: Mapping[str, Any], expected: CertificationExpectations, label: str, failures: list[str]
) -> dict[str, int]:
    """Validate all-lane summaries; raw log joins remain the independent attestor's job."""
    totals = dict.fromkeys(_ACCOUNTING_TOTALS, 0)
    accounting = run.get("request_accounting")
    if (
        "models" in run
        or type(accounting) is not dict
        or set(accounting) != set(expected.policy.fixture_ids)
    ):
        failures.append(f"{label}:explicit all-lane request accounting required")
        return totals
    provider_ids, attempt_ids, reservation_ids = set(), set(), set()
    for fixture, entry in accounting.items():
        if type(entry) is not dict or set(entry) != {"manifest", "sha256"}:
            raise ValueError("accounting entry malformed")
        manifest = entry["manifest"]
        if (
            type(manifest) is not dict
            or entry["sha256"] != hashlib.sha256(_canonical(manifest)).hexdigest()
        ):
            raise ValueError("accounting digest mismatch")
        if (
            type(manifest.get("schema_version")) is not int
            or manifest["schema_version"] != 2
            or manifest.get("task_id") != fixture
            or not _safe_identifier(manifest.get("attempt_id"))
            or manifest["attempt_id"] in attempt_ids
            or manifest.get("takeover_policy_sha256") != expected.takeover_policy.digest
            or manifest.get("registry_sha256") != expected.registry.digest
            or manifest.get("alternate_policy_sha256") != expected.binding.alternate_policy_sha256
            or manifest.get("memory_model_bindings_sha256") != expected.memory_model_bindings_sha256
        ):
            raise ValueError("accounting frozen identity mismatch")
        attempt_ids.add(manifest["attempt_id"])
        evidence = manifest.get("evidence_sha256")
        if (
            type(evidence) is not dict
            or set(evidence)
            != {"runtime-events.jsonl", "model-requests.jsonl", "model-usage.jsonl"}
            or any(not _digest(value) for value in evidence.values())
        ):
            raise ValueError("accounting raw log identities absent")
        seen = manifest.get("totals")
        if (
            type(seen) is not dict
            or set(seen) != _ACCOUNTING_TOTALS
            or any(not _nonnegative_int(value) for value in seen.values())
        ):
            raise ValueError("accounting totals malformed")
        if (
            manifest.get("reconciled") is not True
            or seen["unmatched_reservations"]
            or seen["unbounded_unknown_usage_requests"]
        ):
            failures.append(f"{label}:request accounting unreconciled")
        rows = manifest.get("requests")
        if type(rows) is not list or len(rows) != seen["model_requests"] or not rows:
            raise ValueError("accounting request count mismatch")
        allocations = {"primary_and_memory": 0, "deepseek_advisory": 0}
        computed = dict.fromkeys(_ACCOUNTING_TOTALS, 0)
        role_counts = dict.fromkeys(expected.policy.alternate_max_requests_by_role, 0)
        role_tokens, role_seconds = dict.fromkeys(role_counts, 0), dict.fromkeys(role_counts, 0)
        primary_count = 0
        for index, row in enumerate(rows, 1):
            if type(row) is not dict or row.get("task_ordinal") != index:
                raise ValueError("accounting reservation order mismatch")
            allocation = row.get("allocation")
            if allocation not in allocations:
                raise ValueError("accounting allocation absent")
            allocations[allocation] += 1
            if row.get("allocation_ordinal") != allocations[allocation]:
                raise ValueError("accounting allocation order mismatch")
            reservation = row.get("reservation_request_id")
            if not _safe_identifier(reservation) or reservation in reservation_ids:
                raise ValueError("accounting reservation reused")
            reservation_ids.add(reservation)
            lane = row.get("lane")
            if lane in {"primary", "count_tokens"}:
                routes = (expected.takeover_policy.initial, expected.takeover_policy.fallback)
                if (
                    allocation != "primary_and_memory"
                    or row.get("role") != "primary"
                    or not _safe_identifier(row.get("provider_attempt_id"))
                    or not any(
                        row.get("provider") == route.provider
                        and row.get("configured_model") == route.model
                        and row.get("returned_model") in (None, route.wire_model)
                        for route in routes
                    )
                ):
                    raise ValueError("primary provider attribution mismatch")
                primary_count += lane == "primary"
            elif lane == "advisory":
                role = row.get("role")
                if (
                    allocation != "deepseek_advisory"
                    or role not in role_counts
                    or row.get("configured_model") != expected.policy.alternate_model
                    or row.get("provider") != expected.takeover_policy.fallback.provider
                ):
                    raise ValueError("advisory attribution mismatch")
                role_counts[role] += 1
                if (
                    row.get("usage_status") != "observed"
                    or type(row.get("elapsed_seconds")) not in (int, float)
                    or not 0 < row["elapsed_seconds"]
                ):
                    raise ValueError("advisory usage not observed")
                role_tokens[role] += row["input_tokens"] + row["output_tokens"]
                role_seconds[role] += row["elapsed_seconds"]
            elif lane in {"memory", "post_oracle_memory"}:
                binding = expected.memory_model_bindings.get(row.get("configured_model"))
                if (
                    allocation != "primary_and_memory"
                    or binding is None
                    or row.get("provider") != binding["provider"]
                    or row.get("role") != binding["kind"]
                ):
                    raise ValueError("memory attribution mismatch")
            else:
                raise ValueError("unmatched or undeclared accounting lane")
            computed["model_requests"] += 1
            if row.get("usage_status") == "observed":
                computed["observed_requests"] += 1
                provider_id = row.get("provider_request_id")
                if provider_id is not None:
                    if not _safe_identifier(provider_id) or provider_id in provider_ids:
                        raise ValueError("provider request identity reused or absent")
                    provider_ids.add(provider_id)
                elif lane in {"primary", "advisory"}:
                    raise ValueError("provider request identity absent")
                if lane in {"primary", "advisory"} and not _safe_identifier(
                    row.get("returned_model")
                ):
                    raise ValueError("returned model identity absent")
            elif row.get("usage_status") == "unknown":
                computed["unknown_usage_requests"] += 1
                if not _positive_int(row.get("conservative_tokens")):
                    raise ValueError("unknown usage lacks conservative bound")
            else:
                raise ValueError("request usage status absent")
            for field in (
                "input_tokens",
                "output_tokens",
                "cache_tokens",
                "counted_tokens",
                "conservative_tokens",
            ):
                value = row.get(field)
                if (
                    value is None
                    and row["usage_status"] == "unknown"
                    and field != "conservative_tokens"
                ):
                    continue
                if not _nonnegative_int(value):
                    raise ValueError("request token accounting malformed")
                computed[field] += value
        if computed != seen or manifest.get("allocations") != allocations:
            raise ValueError("accounting totals differ from requests")
        if (
            not primary_count
            or any(count < 1 for count in role_counts.values())
            or seen["model_requests"] > expected.policy.max_model_requests_per_task
            or allocations["primary_and_memory"]
            > expected.policy.max_model_requests_per_task
            - sum(expected.policy.alternate_max_requests_by_role.values())
            or allocations["deepseek_advisory"]
            > sum(expected.policy.alternate_max_requests_by_role.values())
            or any(
                role_counts[role] > expected.policy.alternate_max_requests_by_role[role]
                or role_tokens[role] > expected.policy.alternate_max_tokens_by_role[role]
                or role_seconds[role] > expected.policy.alternate_max_seconds_by_role[role]
                for role in role_counts
            )
        ):
            failures.append(f"{label}:request allocation or advisory coverage invalid")
        for key in totals:
            totals[key] += seen[key]
    return totals


def _valid_primary_selection(
    item: Mapping[str, Any], run: Mapping[str, Any], expected: CertificationExpectations
) -> bool:
    from .finalize import _validate_declaration

    selection = item.get("final_selection")
    entry = run.get("request_accounting", {}).get(item.get("fixture_id"), {})
    manifest = entry.get("manifest", {})
    if (
        item.get("final_selected_by") != "primary_parent"
        or type(selection) is not dict
        or selection.get("schema_version") != 2
        or selection.get("takeover_policy_sha256") != expected.takeover_policy.digest
        or item.get("attempt_id") != manifest.get("attempt_id")
    ):
        return False
    try:
        _validate_declaration(
            _canonical(selection), item["fixture_id"], takeover_policy=expected.takeover_policy
        )
    except (TypeError, ValueError, KeyError):
        return False
    if selection["attempt_id"] != item.get("attempt_id") or selection["sha256"] != item.get(
        "final_sha256"
    ):
        return False
    return any(
        row.get("lane") == "primary"
        and row.get("usage_status") == "observed"
        and all(
            selection.get(selected) == row.get(recorded)
            for selected, recorded in (
                ("provider", "provider"),
                ("configured_model", "configured_model"),
                ("provider_model", "returned_model"),
                ("provider_attempt_id", "provider_attempt_id"),
                ("request_id", "request_id"),
            )
        )
        for row in manifest.get("requests", [])
        if type(row) is dict
    )


def _independent_final_selections(
    run: Mapping[str, Any], attested: Mapping[str, Any], expected: CertificationExpectations
) -> dict[str, Any]:
    """Bind the report to the exact locked declaration returned by the raw verifier."""
    from .finalize import _validate_declaration

    selections = attested.get("primary_final_selections")
    if type(selections) is not dict or set(selections) != set(expected.policy.fixture_ids):
        raise ValueError("independent final selections absent")
    for attempt in run["attempts"]:
        fixture = attempt["fixture_id"]
        entry = selections[fixture]
        if type(entry) is not dict or set(entry) != {"declaration", "sha256"}:
            raise ValueError("independent final declaration absent")
        raw = _canonical(entry["declaration"])
        declaration = _validate_declaration(raw, fixture, takeover_policy=expected.takeover_policy)
        if (
            not _digest(entry["sha256"])
            or entry["sha256"] != hashlib.sha256(raw).hexdigest()
            or raw != _canonical(attempt.get("final_selection"))
            or declaration["attempt_id"] != attempt.get("attempt_id")
            or declaration["sha256"] != attempt.get("final_sha256")
        ):
            raise ValueError("independent final declaration differs from report")
    return json.loads(_canonical(selections))


def _validate_attempts(
    run: Mapping[str, Any], expected: CertificationExpectations, label: str, failures: list[str]
) -> None:
    attempts = run.get("attempts")
    if type(attempts) is not list:
        failures.append(f"{label}:synthetic attempt evidence absent")
        return
    ids = [item.get("fixture_id") if type(item) is dict else None for item in attempts]
    if (
        len(ids) != len(expected.policy.fixture_ids)
        or any(type(item) is not str for item in ids)
        or set(ids) != set(expected.policy.fixture_ids)
    ):
        failures.append(f"{label}:official or undeclared fixture")
    for item in attempts:
        if type(item) is not dict:
            continue
        if item.get("start_count") != 1 or item.get("launcher_receipts") != 1:
            failures.append(f"{label}:second start or missing native receipt")
        if (
            (
                not _valid_primary_selection(item, run, expected)
                if expected.takeover_policy is not None
                else item.get("final_selected_by") != expected.policy.primary_model
                or "final_selection" in item
            )
            or item.get("agent_selected") is not True
            or item.get("controller_selected_candidate") is not False
            or not _digest(item.get("final_sha256"))
        ):
            failures.append(
                f"{label}:non-primary final or missing single final"
                if expected.takeover_policy is not None
                else f"{label}:non-GLM final or missing single final"
            )
        oracle = item.get("oracle")
        if (
            type(oracle) is not dict
            or oracle.get("source") != "private-oracle"
            or type(oracle.get("vulnerable_exit")) is not int
            or oracle["vulnerable_exit"] in (0, 300)
            or type(oracle.get("fixed_exit")) is not int
            or oracle["fixed_exit"] not in (0, 300)
        ):
            failures.append(f"{label}:private vulnerable/fixed oracle pair absent")


def _validate_run(
    run: Any, expected: CertificationExpectations, label: str, failures: list[str]
) -> dict[str, Any]:
    if type(run) is not dict:
        failures.append(f"{label}:run evidence absent")
        return {"run_id": label}
    run_id = run.get("run_id")
    if type(run_id) is not str or not run_id or run_id != label:
        failures.append(f"{label}:run identity mismatch")
    if (
        type(run.get("schema_version")) is not int
        or run.get("schema_version") != (2 if expected.takeover_policy is not None else 1)
        or run.get("scope") != "live_native"
        or run.get("execution_source") != "native-vscode-extension"
    ):
        failures.append(f"{label}:live native source absent")
    if expected.takeover_policy is None and "request_accounting" in run:
        failures.append(f"{label}:new accounting in legacy report")
    fixture_ids = run.get("fixture_ids")
    if (
        type(fixture_ids) is not list
        or any(type(task_id) is not str for task_id in fixture_ids)
        or tuple(fixture_ids) != expected.policy.fixture_ids
        or any(task_id in expected.official_cohort_ids for task_id in fixture_ids)
    ):
        failures.append(f"{label}:official or undeclared fixture")
    if type(run.get("epoch")) is not str or not run["epoch"]:
        failures.append(f"{label}:certification epoch absent")
    root = run.get("evidence_root")
    manifest = run.get("manifest_sha256")
    if (
        type(root) is not str
        or not root.startswith("/")
        or root.startswith("//")
        or ".." in root.split("/")
        or not _digest(manifest)
    ):
        failures.append(f"{label}:raw evidence path or digest absent")
    _validate_hashes(run, expected, label, failures)
    _validate_gates(run, label, failures)
    tool_total = _validate_capabilities(run, expected, label, failures)
    model_totals = (
        _validate_accounting(run, expected, label, failures)
        if expected.takeover_policy is not None
        else _validate_models(run, expected, label, failures)
    )
    totals = run.get("totals")
    if type(totals) is not dict or any(
        totals.get(key) != value
        for key, value in {**model_totals, "tool_calls": tool_total}.items()
    ):
        failures.append(f"{label}:request, token, or tool totals mismatch")
    orchestration = run.get("orchestration")
    if type(orchestration) is not dict:
        failures.append(f"{label}:bounded orchestration absent")
    else:
        counts = orchestration.get("workflow_counts")
        children = orchestration.get("children")
        if (
            orchestration.get("mode") != expected.policy.required_orchestration_mode
            or type(counts) is not dict
            or counts.get("recon") != 1
            or counts.get("review") != 1
            or counts.get("debug") != 1
            or type(children) is not list
            or not children
            or len(children) > expected.policy.max_concurrent_children
            or not _nonnegative_int(orchestration.get("max_concurrent_children"))
            or orchestration["max_concurrent_children"] > expected.policy.max_concurrent_children
            or any(
                type(child) is not dict
                or child.get("model")
                not in {expected.policy.primary_model, expected.policy.alternate_model}
                or not child.get("terminal_state")
                or child.get("read_only") is not True
                for child in children
            )
            or {child.get("model") for child in children if type(child) is dict}
            != {expected.policy.primary_model, expected.policy.alternate_model}
        ):
            failures.append(f"{label}:bounded orchestration or child provenance absent")
    _validate_memory(run, label, failures)
    _validate_attempts(run, expected, label, failures)
    probes = run.get("negative_probes")
    if type(probes) is not dict:
        failures.extend(
            f"{label}:{name} denial absent" for name in expected.policy.required_denials
        )
    else:
        for name in expected.policy.required_denials:
            if probes.get(name) is not True:
                failures.append(f"{label}:{name} denial absent")
        if any(value is not True for value in probes.values()):
            failures.append(f"{label}:red negative probe")
    if run.get("provider_secret_exposure_surfaces") != []:
        failures.append(f"{label}:provider secret exposure")
    interruption = run.get("interruption")
    if type(interruption) is not dict or any(
        interruption.get(name) is not True
        for name in (
            "reconnected_same_attempt",
            "timeout_without_final_terminal",
            "version_drift_paused",
        )
    ):
        failures.append(f"{label}:interruption or drift gate absent")
    try:
        attested = expected.attest_raw_run(run)
    except Exception:
        attested = None
    if (
        not isinstance(attested, Mapping)
        or attested.get("verified") is not True
        or attested.get("run_id") != run_id
        or attested.get("evidence_root") != root
        or attested.get("manifest_sha256") != manifest
        or type(attested.get("signature_key_id")) is not str
        or not attested["signature_key_id"]
    ):
        failures.append(f"{label}:raw evidence attestation absent or invalid")
    if expected.takeover_policy is not None and (
        not isinstance(attested, Mapping)
        or type(attested.get("schema_version")) is not int
        or attested.get("schema_version") != 2
        or _canonical(attested.get("request_accounting"))
        != _canonical(run.get("request_accounting"))
    ):
        failures.append(f"{label}:independent all-lane accounting attestation absent or different")
    independent_finals = None
    if expected.takeover_policy is not None:
        try:
            independent_finals = _independent_final_selections(run, attested, expected)
        except (AttributeError, KeyError, TypeError, ValueError):
            failures.append(f"{label}:independent final selection absent or different")
    summary = {
        "run_id": run_id,
        "evidence_root": root,
        "manifest_sha256": manifest,
        "epoch": run.get("epoch"),
        "gates": {
            name: {
                key: gates[name].get(key)
                for key in ("status", "observed", "evidence_path", "sha256")
            }
            for name in sorted(_GATES)
        }
        if type(gates := run.get("gates")) is dict
        else {},
        "enabled_capability_ids": sorted(run["capabilities"]["enabled_ids"]),
        "exercised_capability_ids": sorted(run["capabilities"]["exercised_ids"]),
        "models": [
            {
                key: row.get(key)
                for key in (
                    "fixture_id",
                    "role",
                    "model",
                    "provider",
                    "reasoning_effort",
                    "thinking",
                    "context_tokens",
                    "observed_version",
                    "system_fingerprint",
                    "version_metadata_status",
                    "returned_model",
                    "alias_drift",
                    "requests",
                    "input_tokens",
                    "output_tokens",
                    "cache_tokens",
                    "elapsed_seconds",
                    "provider_request_ids",
                )
            }
            for row in run.get("models", [])
            if type(row) is dict
        ]
        if type(run.get("models")) is list
        else [],
        "totals": {
            key: totals.get(key)
            for key in (
                "model_requests",
                "input_tokens",
                "output_tokens",
                "cache_tokens",
                "tool_calls",
            )
        }
        if type(totals) is dict
        else {},
        "tool_calls": [
            {key: row.get(key) for key in ("capability_id", "tool_id", "route", "role", "count")}
            for row in run.get("capabilities", {}).get("tool_calls", [])
            if type(row) is dict
        ]
        if type(run.get("capabilities")) is dict
        and type(run["capabilities"].get("tool_calls")) is list
        else [],
        "memory_retrieval_events": [
            {key: item.get(key) for key in ("role", "source")}
            for item in run["memory"]["retrieval_events"]
        ],
        "memory_write_events": [
            {key: item.get(key) for key in ("actor", "oracle_true", "verdict_id")}
            for item in run["memory"]["write_events"]
        ],
        "child_count": len(run["orchestration"]["children"]),
        "children": [
            {key: child.get(key) for key in ("model", "terminal_state", "read_only")}
            for child in run["orchestration"]["children"]
        ],
        "negative_probes": {name: probes.get(name) for name in expected.policy.required_denials}
        if type(probes) is dict
        else {},
        "interruption": {
            name: interruption.get(name)
            for name in (
                "reconnected_same_attempt",
                "timeout_without_final_terminal",
                "version_drift_paused",
            )
        },
        "attempts": [
            {
                "fixture_id": row.get("fixture_id"),
                "start_count": row.get("start_count"),
                "final_sha256": row.get("final_sha256"),
                "oracle": {
                    key: row["oracle"].get(key)
                    for key in ("source", "vulnerable_exit", "fixed_exit")
                }
                if type(row.get("oracle")) is dict
                else {},
            }
            for row in run.get("attempts", [])
            if type(row) is dict
        ]
        if type(run.get("attempts")) is list
        else [],
        "raw_attestation_key_id": attested.get("signature_key_id")
        if isinstance(attested, Mapping)
        else None,
    }
    if expected.takeover_policy is not None:
        summary.pop("models", None)
        summary["request_accounting"] = json.loads(_canonical(run.get("request_accounting")))
        summary["primary_final_selections"] = independent_finals
        summary["totals"] = {
            key: totals.get(key) for key in (*sorted(_ACCOUNTING_TOTALS), "tool_calls")
        }
        for item, source in zip(summary["attempts"], run["attempts"], strict=True):
            item.update(
                attempt_id=source.get("attempt_id"),
                final_selected_by=source.get("final_selected_by"),
                final_selection=source.get("final_selection"),
            )
    return summary


def compare_runs(
    run_a: Any,
    run_b: Any,
    *,
    expected: CertificationExpectations | None = None,
) -> ComparisonReport:
    """Require two complete, independently attested live-native synthetic runs.

    A passing comparison is a report-preparation result, not a claim that this
    function executed or independently witnessed the native harness itself.
    """
    if type(expected) is not CertificationExpectations:
        payload = {
            "schema_version": 1,
            "status": "rejected",
            "scope": "unverified",
            "official_launch_authorised": False,
            "failures": ["frozen expectations and raw evidence attestor absent"],
        }
        return ComparisonReport(
            False,
            tuple(payload["failures"]),
            payload,
            hashlib.sha256(_canonical(payload)).hexdigest(),
        )
    labels = []
    for index, run in enumerate((run_a, run_b), start=1):
        run_id = run.get("run_id") if type(run) is dict else None
        labels.append(run_id if _safe_identifier(run_id) else f"run-{index}")
    failures = []
    if labels[0] == labels[1]:
        failures.append("two distinct certification runs required")
    if type(run_a) is dict and type(run_b) is dict:
        if run_a.get("evidence_root") == run_b.get("evidence_root"):
            failures.append("certification evidence root reused")
        if run_a.get("manifest_sha256") == run_b.get("manifest_sha256"):
            failures.append("certification manifest reused")
        if expected.takeover_policy is not None:

            def identifiers(run):
                result = set()
                accounting = run.get("request_accounting")
                if type(accounting) is dict:
                    for entry in accounting.values():
                        if type(entry) is dict and type(entry.get("manifest")) is dict:
                            manifest = entry["manifest"]
                            result.add(("attempt", manifest.get("attempt_id")))
                            for row in manifest.get("requests", []):
                                if type(row) is dict:
                                    for key in (
                                        "reservation_request_id",
                                        "provider_attempt_id",
                                        "provider_request_id",
                                        "permit_id",
                                    ):
                                        if type(row.get(key)) is str:
                                            result.add((key, row[key]))
                return result

            if identifiers(run_a) & identifiers(run_b):
                failures.append("request or attempt identity reused across repetitions")
    if expected.policy.sha256 != expected.binding.policy_sha256:
        failures.append("certification policy changed after binding")
    if expected.registry.digest != expected.binding.capability_registry_sha256:
        failures.append("capability registry changed after binding")
    summaries = []
    for run, label in zip((run_a, run_b), labels, strict=True):
        try:
            summaries.append(_validate_run(run, expected, label, failures))
        except (TypeError, ValueError, KeyError, AttributeError):
            failures.append(f"{label}:malformed evidence")
            summaries.append({"run_id": label})
    if type(run_a) is dict and type(run_b) is dict:
        for name in expected.all_hashes:
            left = run_a.get("hashes", {}).get(name) if type(run_a.get("hashes")) is dict else None
            right = run_b.get("hashes", {}).get(name) if type(run_b.get("hashes")) is dict else None
            if left != right:
                failures.append(f"{name} mismatch")
        if run_a.get("epoch") != run_b.get("epoch"):
            failures.append("certification epoch mismatch")
    failures = list(dict.fromkeys(failures))
    passed = not failures
    if not passed:
        # Raw evidence is untrusted on a rejected run. Preserve failure codes,
        # never echo invalid provider/tool/oracle fields into a signed report.
        summaries = [{"run_id": label} for label in labels]
    enabled = sorted(
        entry.capability_id
        for entry in expected.registry.entries
        if entry.status is Status.APPROVED
    )
    payload = {
        "schema_version": 2 if expected.takeover_policy is not None else 1,
        "status": "accepted" if passed else "rejected",
        "scope": "live_native" if passed else "unverified",
        "official_launch_authorised": False,
        "control_labels": {
            "single_agent_final_and_private_oracle": ControlLabel.OFFICIAL_REQUIREMENT.value,
            "answer_secret_and_host_denials": ControlLabel.LEAKAGE_BOUNDARY.value,
            "two_run_parity_and_capability_coverage": ControlLabel.PERFORMANCE_OPTIMISATION.value,
            "client_observation": ControlLabel.OPTIONAL.value,
        },
        "failures": failures,
        "epoch": run_a.get("epoch") if passed and type(run_a) is dict else None,
        "frozen_hashes": expected.all_hashes,
        "harness_sha256": expected.frozen_hashes["harness_sha256"],
        "cohort_sha256": expected.cohort_sha256,
        "campaign_policy_sha256": expected.campaign_policy_sha256,
        "policy_sha256": expected.binding.policy_sha256,
        "alternate_policy_sha256": expected.binding.alternate_policy_sha256,
        "capability_registry_sha256": expected.binding.capability_registry_sha256,
        "network_policy_sha256": expected.binding.network_policy_sha256,
        "memory_policy_sha256": expected.frozen_hashes["memory_policy_sha256"],
        "enabled_capability_ids": enabled,
        "required_approved_capability_ids": sorted(expected.required_approved_capability_ids),
        "capability_coverage": "all_enabled_exercised" if passed else "incomplete",
        "memory_mode": expected.policy.memory_mode if passed else "unverified",
        "controller_writes_after_true_oracle": passed,
        "deepseek": {
            "status": "active" if passed else "unverified",
            "provider": expected.policy.alternate_provider,
            "model": expected.policy.alternate_model,
            "api": expected.policy.alternate_api,
            "thinking": expected.policy.alternate_thinking,
            "reasoning_effort": expected.policy.alternate_reasoning_effort,
            "context_tokens": expected.policy.alternate_context_tokens,
            "max_output_tokens": expected.policy.max_output_tokens,
            "max_requests": sum(expected.policy.alternate_max_requests_by_role.values()),
            "role_requests": expected.policy.alternate_max_requests_by_role,
            "role_tokens": expected.policy.alternate_max_tokens_by_role,
            "role_seconds": expected.policy.alternate_max_seconds_by_role,
        },
        "runs": summaries,
        "no_provider_weight_freeze_guarantee": True,
    }
    if expected.takeover_policy is not None:
        payload["takeover_policy_sha256"] = expected.takeover_policy.digest
        payload["memory_model_bindings_sha256"] = expected.memory_model_bindings_sha256
        payload["primary_takeover"] = json.loads(expected.takeover_policy.manifest_json)
        payload["deepseek"]["max_requests"] = None
        payload["deepseek"]["advisory_max_requests"] = sum(
            expected.policy.alternate_max_requests_by_role.values()
        )
        payload["deepseek"]["primary_allocation"] = "shared_primary_and_memory"
    return ComparisonReport(
        passed,
        tuple(failures),
        payload,
        hashlib.sha256(_canonical(payload)).hexdigest(),
    )


def sign_report(
    report: ComparisonReport,
    *,
    signer: XeusSigner,
    verifier: XeusVerifier,
) -> SignedReport:
    """Sign exact canonical report bytes with injected Xeus signer and verify.

    FAIL reports may also be signed for audit. Neither case changes the
    separate official launch decision, which remains false in the payload.
    """
    if (
        type(report) is not ComparisonReport
        or report.payload.get("official_launch_authorised") is not False
    ):
        raise ValueError("report cannot authorise official launch")
    payload_json = _canonical(report.payload)
    if (
        hashlib.sha256(payload_json).hexdigest() != report.payload_sha256
        or report.payload.get("status") != ("accepted" if report.passed else "rejected")
        or report.payload.get("failures") != list(report.failures)
    ):
        raise ValueError("report changed after comparison")
    if not callable(getattr(signer, "sign", None)) or not callable(
        getattr(verifier, "verify", None)
    ):
        raise TypeError("injected Xeus signer and verifier required")
    try:
        envelope = signer.sign(payload_json)
        verified = verifier.verify(envelope)
        envelope_data = envelope.model_dump(mode="json")
        envelope_json = _canonical(envelope_data)
    except Exception:
        raise RuntimeError("report signature verification failed") from None
    if verified != payload_json or not isinstance(envelope_data, Mapping):
        raise RuntimeError("report signature verification failed")
    return SignedReport(payload_json, envelope_json)
