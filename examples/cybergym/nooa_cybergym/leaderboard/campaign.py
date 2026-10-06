# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Signed go-live admission and serial, ledger-replayed campaign scheduling.

The Xeus authority adapter verifies signatures and supplies atomic, durable,
hash-chain-verified events. This module never signs, launches a task, retries a
started attempt, or substitutes local files for that authority.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from nooa_cybergym.leaderboard.deepseek import AlternateModelPolicy

if TYPE_CHECKING:
    from .workspace import ControllerPaths

_CONFIG = Path(__file__).resolve().parents[2] / "leaderboard/config/campaign-policy.json"
_ALTERNATE_CONFIG = _CONFIG.with_name("alternate-model.json")
_TASK_ID = re.compile(r"(?:arvo|oss-fuzz):[0-9]+\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_MAX_TERMINAL_RECEIPT_BYTES = 65536
_ORACLE_TERMINAL_FIELDS = frozenset(
    {
        "schema_version",
        "artifact_kind",
        "run_id",
        "epoch",
        "task_id",
        "status",
        "final_sha256",
        "final_declaration_sha256",
        "parent_event_digest",
        "oracle_request_sha256",
        "oracle_verdict_sha256",
        "oracle_true",
    }
)
_FAILURE_TERMINAL_FIELDS = frozenset(
    {
        "schema_version",
        "artifact_kind",
        "run_id",
        "epoch",
        "task_id",
        "status",
        "evidence_sha256",
    }
)


class CampaignAuthority(Protocol):
    """Trusted Xeus signature and ledger adapter; no fallback implementation."""

    def attest_signed(self, kind: str, envelope: bytes) -> Mapping[str, Any] | None: ...

    def create_campaign_once(
        self, evidence_root: Path, run_id: str, event: Mapping[str, Any]
    ) -> bool: ...

    def read_verified_events(
        self, evidence_root: Path, run_id: str
    ) -> Sequence[Mapping[str, Any]]: ...

    def append_event(
        self,
        evidence_root: Path,
        run_id: str,
        event: Mapping[str, Any],
        expected_revision: int,
    ) -> bool: ...


def _json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _digest(value: Any) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _attest(authority: CampaignAuthority, kind: str, envelope: bytes) -> Mapping[str, Any]:
    if type(envelope) is not bytes or not envelope:
        raise RuntimeError(f"signed {kind} is absent")
    try:
        payload = authority.attest_signed(kind, envelope)
    except Exception:
        payload = None
    if (
        not isinstance(payload, Mapping)
        or type(payload.get("schema_version")) is not int
        or payload["schema_version"] != 1
    ):
        raise RuntimeError(f"signed {kind} verification failed")
    return payload


def _expect_hash(value: Any, expected: str, label: str) -> None:
    if not _digest(value) or value != expected:
        raise RuntimeError(f"{label} hash mismatch")


def _cohort_inputs(payload: Mapping[str, Any]) -> tuple[str, str, str, str]:
    asset_digest = payload.get("asset_hashes_sha256")
    benchmark_commit = payload.get("benchmark_commit")
    dataset_commit = payload.get("dataset_commit")
    mask_digest = payload.get("mask_map_sha256")
    if (
        not _digest(asset_digest)
        or type(benchmark_commit) is not str
        or not _COMMIT.fullmatch(benchmark_commit)
        or type(dataset_commit) is not str
        or not _COMMIT.fullmatch(dataset_commit)
        or not _digest(mask_digest)
    ):
        raise RuntimeError("signed cohort input identity is incomplete")
    return asset_digest, benchmark_commit, dataset_commit, mask_digest


def _terminal_receipt(
    payload: Mapping[str, Any], *, state: CampaignState, task_id: str
) -> dict[str, str]:
    if (
        payload.get("artifact_kind") != "terminal_receipt"
        or payload.get("run_id") != state.run_id
        or payload.get("epoch") != state.epoch
        or payload.get("task_id") != task_id
    ):
        raise RuntimeError("signed terminal receipt identity differs from campaign")
    status = payload.get("status")
    if status in ("oracle_true", "oracle_false"):
        if (
            set(payload) != _ORACLE_TERMINAL_FIELDS
            or payload.get("oracle_true") is not (status == "oracle_true")
            or any(
                not _digest(payload.get(key))
                for key in (
                    "final_sha256",
                    "final_declaration_sha256",
                    "parent_event_digest",
                    "oracle_request_sha256",
                    "oracle_verdict_sha256",
                )
            )
        ):
            raise RuntimeError("signed terminal oracle receipt is incomplete")
        return {
            "status": status,
            "final_sha256": payload["final_sha256"],
            "final_declaration_sha256": payload["final_declaration_sha256"],
            "parent_event_digest": payload["parent_event_digest"],
            "oracle_request_sha256": payload["oracle_request_sha256"],
            "oracle_verdict_sha256": payload["oracle_verdict_sha256"],
        }
    if status in ("timeout", "failure"):
        if set(payload) != _FAILURE_TERMINAL_FIELDS or not _digest(payload.get("evidence_sha256")):
            raise RuntimeError("signed terminal failure receipt is incomplete")
        return {"status": status, "evidence_sha256": payload["evidence_sha256"]}
    raise RuntimeError("signed terminal receipt status is unsupported")


def _tasks_json_order(data: bytes) -> tuple[str, ...]:
    if type(data) is not bytes or not data:
        raise RuntimeError("tasks.json bytes required")
    try:
        rows = json.loads(data)
    except (ValueError, UnicodeDecodeError):
        raise RuntimeError("tasks.json is malformed") from None
    if not isinstance(rows, list):
        raise RuntimeError("tasks.json order is absent")
    task_ids = tuple(row.get("task_id") if isinstance(row, dict) else None for row in rows)
    if (
        len(task_ids) != 1507
        or any(type(task_id) is not str or not _TASK_ID.fullmatch(task_id) for task_id in task_ids)
        or len(set(task_ids)) != 1507
    ):
        raise RuntimeError("tasks.json must contain 1507 unique supported tasks")
    return task_ids


def _certified_policy(certification: Mapping[str, Any], harness: Mapping[str, Any]) -> None:
    try:
        alternate = AlternateModelPolicy.model_validate_json(_ALTERNATE_CONFIG.read_text())
    except Exception:
        raise RuntimeError("frozen alternate-model policy is unavailable") from None
    provider = alternate.models[0]
    routes = {route.role.value: route for route in alternate.routes}
    role_requests = {name: route.max_calls for name, route in routes.items()}
    role_tokens = {name: route.max_tokens for name, route in routes.items()}
    role_seconds = {name: route.max_seconds for name, route in routes.items()}
    deepseek = certification.get("deepseek")
    if (
        certification.get("memory_mode") != "audited_hybrid"
        or certification.get("controller_writes_after_true_oracle") is not True
        or certification.get("capability_coverage") != "all_enabled_exercised"
        or not isinstance(deepseek, Mapping)
        or deepseek.get("status") != alternate.status
        or deepseek.get("provider") != provider.base_url
        or deepseek.get("model") != provider.model
        or deepseek.get("api") != provider.api
        or deepseek.get("thinking") != provider.thinking.model_dump()
        or deepseek.get("reasoning_effort") != provider.reasoning_effort
        or type(deepseek.get("context_tokens")) is not int
        or deepseek["context_tokens"] != provider.context_tokens
        or type(deepseek.get("max_output_tokens")) is not int
        or deepseek["max_output_tokens"] != provider.max_output_tokens
        or type(deepseek.get("max_requests")) is not int
        or deepseek["max_requests"] != alternate.deepseek_max_requests
        or deepseek.get("role_requests") != role_requests
        or deepseek.get("role_tokens") != role_tokens
        or deepseek.get("role_seconds") != role_seconds
    ):
        raise RuntimeError(
            "certified policy lacks audited memory, capabilities, or active DeepSeek"
        )
    for name, limits in (
        ("role_requests", role_requests),
        ("role_tokens", role_tokens),
        ("role_seconds", role_seconds),
    ):
        observed = deepseek[name]
        if any(type(observed[role]) is not int for role in limits):
            raise RuntimeError("certified policy has non-integer DeepSeek role limits")
    if (
        sum(role_requests.values()) != 36
        or sum(role_tokens.values()) != 37748736
        or sum(role_seconds.values()) != 9000
    ):
        raise RuntimeError("frozen alternate-model role budgets are invalid")
    for name in (
        "alternate_policy_sha256",
        "capability_registry_sha256",
        "memory_policy_sha256",
    ):
        if not _digest(certification.get(name)) or certification[name] != harness.get(name):
            raise RuntimeError("certified policy hash differs from harness")
    if certification["alternate_policy_sha256"] != alternate.digest:
        raise RuntimeError("certified policy differs from frozen alternate-model policy")


@dataclass(frozen=True, slots=True)
class CampaignAction:
    kind: str
    task_id: str | None


@dataclass(frozen=True, slots=True)
class CampaignState:
    run_id: str
    epoch: str
    evidence_root: Path
    task_ids: tuple[str, ...]
    policy_sha256: str
    cohort_sha256: str
    asset_hashes_sha256: str
    benchmark_commit: str
    dataset_commit: str
    mask_map_sha256: str
    cohort_envelope: bytes = field(repr=False)
    authority: CampaignAuthority = field(repr=False)

    def load_asset_registry(self, path: Path):
        """Load only the 1,507 inputs pinned by this signed campaign."""
        from .cohort import FrozenAssetRegistry

        _verified_cohort(self)
        registry = FrozenAssetRegistry.load(
            path,
            expected_sha256=self.asset_hashes_sha256,
            expected_benchmark_commit=self.benchmark_commit,
            expected_dataset_commit=self.dataset_commit,
        )
        if registry.task_ids != self.task_ids:
            raise RuntimeError("asset manifest order differs from signed cohort")
        return registry

    def assert_mask_map(self, path: Path) -> None:
        """Check the controller-only generation mask before staging a task."""
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("mask map is missing or linked")
        _expect_hash(self.mask_map_sha256, _sha256(path.read_bytes()), "mask map")

    def verified_staging_paths(
        self, task_id: str, paths: ControllerPaths, asset_manifest: Path
    ) -> ControllerPaths:
        """Build workspace inputs for only the current signed campaign task."""
        from .workspace import ControllerPaths

        if next_action(self) != CampaignAction("prepare", task_id):
            raise RuntimeError("staging is limited to the current campaign task")
        if type(paths) is not ControllerPaths:
            raise TypeError("controller staging paths required")
        signed_cohort = _verified_cohort(self)
        for name in (
            "mask_map_sha256",
            "generator_sha256",
            "harness_manifest_sha256",
        ):
            expected = signed_cohort.get(name)
            if not _digest(expected) or getattr(paths, name) != expected:
                raise RuntimeError(f"{name} differs from signed cohort")
        self.assert_mask_map(paths.mask_map_path)
        registry = self.load_asset_registry(asset_manifest)
        registry.inputs_for(task_id)
        return replace(paths, official_registry=registry)

    def _append(self, task_id: str, kind: str, **details: str) -> None:
        action, revision = _next_action_and_revision(self)
        expected = {
            "prepared": "prepare",
            "started": "observe_prepared",
            "terminal": "observe_started",
        }[kind]
        if action.kind != expected or action.task_id != task_id:
            raise RuntimeError("task already terminal or transition out of cohort order")
        event = {"type": kind, "task_id": task_id, **details}
        try:
            accepted = self.authority.append_event(
                self.evidence_root, self.run_id, event, expected_revision=revision
            )
        except Exception:
            accepted = False
        if accepted is not True:
            # An ambiguous acknowledgement is never retried. A fresh verified
            # ledger read on restart resolves whether the append committed.
            raise RuntimeError("ledger append acknowledgement unavailable; inspect on restart")

    def mark_prepared(self, task_id: str) -> None:
        self._append(task_id, "prepared")

    def mark_started(self, task_id: str, *, request_id: str) -> None:
        """Durably record first-request intent before issuing that model request."""
        if type(request_id) is not str or not request_id:
            raise ValueError("first model request identity required")
        self._append(task_id, "started", request_id=request_id)

    def mark_terminal(self, task_id: str, signed_receipt: bytes) -> None:
        """Advance only from an attested oracle outcome or documented failure."""
        if type(signed_receipt) is not bytes or not signed_receipt:
            raise RuntimeError("signed terminal receipt required")
        if len(signed_receipt) > _MAX_TERMINAL_RECEIPT_BYTES:
            raise RuntimeError("signed terminal receipt size exceeds controller limit")
        payload = _attest(self.authority, "terminal_receipt", signed_receipt)
        details = _terminal_receipt(payload, state=self, task_id=task_id)
        self._append(
            task_id,
            "terminal",
            receipt_sha256=_sha256(signed_receipt),
            receipt_envelope_b64=base64.b64encode(signed_receipt).decode("ascii"),
            **details,
        )


def check_go_live(
    *,
    decision: bytes,
    certification: bytes,
    harness_lock: bytes,
    cohort: bytes,
    campaign_policy: Mapping[str, Any],
    tasks_json: bytes,
    authority: CampaignAuthority,
    run_id: str,
    evidence_root: Path,
) -> CampaignState:
    """Admit one approved campaign without dispatching an official task."""
    if authority is None or type(run_id) is not str or not run_id:
        raise RuntimeError("trusted campaign authority and run identity required")
    if not isinstance(evidence_root, Path):
        raise RuntimeError("controller evidence root required")
    frozen_policy = json.loads(_CONFIG.read_text())
    try:
        supplied_policy = _json_bytes(dict(campaign_policy))
    except (TypeError, ValueError):
        supplied_policy = b""
    if supplied_policy != _json_bytes(frozen_policy):
        raise RuntimeError("campaign policy differs from frozen controls")
    policy_sha = _sha256(_json_bytes(frozen_policy))
    signed = {
        "decision": _attest(authority, "decision", decision),
        "certification": _attest(authority, "certification", certification),
        "harness_lock": _attest(authority, "harness_lock", harness_lock),
        "cohort": _attest(authority, "cohort", cohort),
    }
    approval = signed["decision"]
    certified = signed["certification"]
    harness = signed["harness_lock"]
    frozen_cohort = signed["cohort"]
    if approval.get("official_launch_authorised") is not True:
        raise RuntimeError("official launch is not authorised")
    if approval.get("run_id") != run_id:
        raise RuntimeError("official launch run identity mismatch")
    _expect_hash(approval.get("certification_sha256"), _sha256(certification), "certification")
    _expect_hash(approval.get("harness_sha256"), _sha256(harness_lock), "harness")
    _expect_hash(approval.get("cohort_sha256"), _sha256(cohort), "cohort")
    _expect_hash(approval.get("campaign_policy_sha256"), policy_sha, "campaign policy")
    _expect_hash(certified.get("harness_sha256"), _sha256(harness_lock), "certification harness")
    _expect_hash(certified.get("cohort_sha256"), _sha256(cohort), "certification cohort")
    _expect_hash(certified.get("campaign_policy_sha256"), policy_sha, "certification policy")
    _expect_hash(harness.get("campaign_policy_sha256"), policy_sha, "harness policy")
    epoch = harness.get("epoch")
    if (
        type(epoch) is not str
        or not epoch
        or approval.get("epoch") != epoch
        or certified.get("epoch") != epoch
    ):
        raise RuntimeError("certified harness epoch mismatch")
    if certified.get("status") != "accepted" or certified.get("scope") != "live_native":
        raise RuntimeError("accepted live certification required")
    _certified_policy(certified, harness)
    task_ids = _tasks_json_order(tasks_json)
    _expect_hash(frozen_cohort.get("tasks_json_sha256"), _sha256(tasks_json), "tasks.json")
    frozen_ids = frozen_cohort.get("task_ids")
    if not isinstance(frozen_ids, list) or len(frozen_ids) != 1507:
        raise RuntimeError("signed cohort must contain 1507 tasks")
    if tuple(frozen_ids) != task_ids:
        raise RuntimeError("signed cohort differs from tasks.json order")
    asset_digest, benchmark_commit, dataset_commit, mask_digest = _cohort_inputs(frozen_cohort)
    event = {
        "type": "campaign_created",
        "run_id": run_id,
        "epoch": epoch,
        "policy_sha256": policy_sha,
        "cohort_sha256": _sha256(cohort),
        "asset_hashes_sha256": asset_digest,
        "benchmark_commit": benchmark_commit,
        "dataset_commit": dataset_commit,
        "mask_map_sha256": mask_digest,
        "task_count": 1507,
    }
    try:
        created = authority.create_campaign_once(evidence_root, run_id, event)
    except Exception:
        created = False
    if created is not True:
        raise RuntimeError("campaign already exists or creation acknowledgement unavailable")
    return CampaignState(
        run_id=run_id,
        epoch=epoch,
        evidence_root=evidence_root,
        task_ids=task_ids,
        policy_sha256=policy_sha,
        cohort_sha256=_sha256(cohort),
        asset_hashes_sha256=asset_digest,
        benchmark_commit=benchmark_commit,
        dataset_commit=dataset_commit,
        mask_map_sha256=mask_digest,
        cohort_envelope=cohort,
        authority=authority,
    )


def _verified_cohort(state: CampaignState) -> Mapping[str, Any]:
    _expect_hash(state.cohort_sha256, _sha256(state.cohort_envelope), "signed cohort")
    frozen_cohort = _attest(state.authority, "cohort", state.cohort_envelope)
    if (
        len(state.task_ids) != 1507
        or not isinstance(frozen_cohort.get("task_ids"), list)
        or tuple(frozen_cohort["task_ids"]) != state.task_ids
    ):
        raise RuntimeError("signed cohort differs from scheduler state")
    if _cohort_inputs(frozen_cohort) != (
        state.asset_hashes_sha256,
        state.benchmark_commit,
        state.dataset_commit,
        state.mask_map_sha256,
    ):
        raise RuntimeError("signed cohort input identity differs from scheduler state")
    return frozen_cohort


def _valid_terminal_event(event: Mapping[str, Any], state: CampaignState) -> bool:
    encoded = event.get("receipt_envelope_b64")
    if type(encoded) is not str or len(encoded) > 4 * ((_MAX_TERMINAL_RECEIPT_BYTES + 2) // 3):
        return False
    try:
        signed_receipt = base64.b64decode(encoded, validate=True)
        if (
            not signed_receipt
            or len(signed_receipt) > _MAX_TERMINAL_RECEIPT_BYTES
            or base64.b64encode(signed_receipt).decode("ascii") != encoded
            or event.get("receipt_sha256") != _sha256(signed_receipt)
        ):
            return False
        payload = _attest(state.authority, "terminal_receipt", signed_receipt)
        details = _terminal_receipt(payload, state=state, task_id=event["task_id"])
    except (KeyError, RuntimeError, ValueError):
        return False
    return event == {
        "type": "terminal",
        "task_id": event["task_id"],
        "receipt_sha256": _sha256(signed_receipt),
        "receipt_envelope_b64": encoded,
        **details,
    }


def _next_action_and_revision(state: CampaignState) -> tuple[CampaignAction, int]:
    _verified_cohort(state)
    try:
        events = state.authority.read_verified_events(state.evidence_root, state.run_id)
    except Exception:
        raise RuntimeError("verified campaign ledger unavailable") from None
    if not isinstance(events, (list, tuple)) or not events:
        raise RuntimeError("verified campaign ledger unavailable")
    first = events[0]
    if not isinstance(first, Mapping) or first != {
        "type": "campaign_created",
        "run_id": state.run_id,
        "epoch": state.epoch,
        "policy_sha256": state.policy_sha256,
        "cohort_sha256": state.cohort_sha256,
        "asset_hashes_sha256": state.asset_hashes_sha256,
        "benchmark_commit": state.benchmark_commit,
        "dataset_commit": state.dataset_commit,
        "mask_map_sha256": state.mask_map_sha256,
        "task_count": 1507,
    }:
        raise RuntimeError("verified campaign creation event is invalid")
    cursor = 0
    phase = "unseen"
    for event in events[1:]:
        if not isinstance(event, Mapping) or cursor >= len(state.task_ids):
            raise RuntimeError("campaign ledger has an invalid task transition")
        if event.get("task_id") != state.task_ids[cursor]:
            raise RuntimeError("campaign ledger task order or retry violation")
        kind = event.get("type")
        if kind == "prepared" and phase == "unseen" and set(event) == {"type", "task_id"}:
            phase = "prepared"
        elif (
            kind == "started"
            and phase == "prepared"
            and set(event) == {"type", "task_id", "request_id"}
            and type(event.get("request_id")) is str
            and event["request_id"]
        ):
            phase = "started"
        elif kind == "terminal" and phase == "started" and _valid_terminal_event(event, state):
            cursor += 1
            phase = "unseen"
        else:
            raise RuntimeError("campaign ledger has an invalid or repeated transition")
    if cursor == len(state.task_ids):
        return CampaignAction("complete", None), len(events)
    task_id = state.task_ids[cursor]
    kind = {"unseen": "prepare", "prepared": "observe_prepared", "started": "observe_started"}[
        phase
    ]
    return CampaignAction(kind, task_id), len(events)


def next_action(state: CampaignState) -> CampaignAction:
    """Read a fresh verified ledger; never infer a retry from process memory."""
    if type(state) is not CampaignState:
        raise TypeError("verified campaign state required")
    return _next_action_and_revision(state)[0]
