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

    @property
    def all_hashes(self) -> dict[str, str]:
        return {
            **self.frozen_hashes,
            "policy_sha256": self.binding.policy_sha256,
            "alternate_policy_sha256": self.binding.alternate_policy_sha256,
            "capability_registry_sha256": self.binding.capability_registry_sha256,
            "network_policy_sha256": self.binding.network_policy_sha256,
            "cohort_sha256": self.cohort_sha256,
            "campaign_policy_sha256": self.campaign_policy_sha256,
        }


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
    return (type(route) is str and route in routes) if routes else route is None


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
    if any(count > 36 for count in deepseek_by_fixture.values()):
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
            item.get("final_selected_by") != expected.policy.primary_model
            or item.get("agent_selected") is not True
            or item.get("controller_selected_candidate") is not False
            or not _digest(item.get("final_sha256"))
        ):
            failures.append(f"{label}:non-GLM final or missing single final")
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
        run.get("schema_version") != 1
        or run.get("scope") != "live_native"
        or run.get("execution_source") != "native-vscode-extension"
    ):
        failures.append(f"{label}:live native source absent")
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
    model_totals = _validate_models(run, expected, label, failures)
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
    return {
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
        "schema_version": 1,
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
