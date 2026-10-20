# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Explicit budgeted subset admission and fail-closed recovery state.

This module never signs, starts a native process, sends a request, or creates a
ledger. Full raw readiness verification remains a required trusted dependency;
an accepted report summary is insufficient. Task terminal semantics are kept
separate from run stops and post-terminal controller/accounting quiescence.
"""

from __future__ import annotations

import base64
import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from .campaign import (
    CampaignAction,
    CampaignAuthority,
    _attest,
    _json_bytes,
    _terminal_receipt,
    _valid_terminal_event,
)
from .subset_dry_run_admission import (
    OFFICIAL_SUBSET_REGISTRY_SHA256,
    OFFICIAL_SUBSET_TASK_IDS,
    PREVIOUSLY_EXPOSED_TASK_IDS,
)
from .subset_run_budget import VerifiedSubsetBudget, verify_subset_run_budget

_HASH = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_MAX_ENVELOPE = 65536
# Unlike small control receipts, schema-two certificates inline accounting for
# two repetitions of two fixtures: up to 6,000 request rows. Raw identities may
# contain 512 Unicode characters, and the signed envelope base64-encodes JSON.
# Keep a separate bounded transport allowance for those rows and transitions;
# the independent readiness verifier still enforces every semantic limit.
_MAX_SIGNED_CERTIFICATION = 256 * 1024 * 1024
_SCOPE = "native_subset_dry_run_level1"


class SubsetReadinessVerifier(Protocol):
    """Controller verifier of full raw two-repetition, twelve-gate evidence.

    Implementations must independently verify the signed report against its raw
    evidence and the exact finished source/harness. A caller's ready flag or
    signed summary-only check does not implement this contract.
    """

    def verify_subset_readiness(
        self,
        *,
        signed_freeze: bytes,
        signed_certification: bytes,
        source_commit: str,
        epoch: str,
        campaign_policy_sha256: str,
        model_policy_sha256: str,
        cohort_sha256: str,
    ) -> bool: ...


class ResourceBudgetView(Protocol):
    """Read-only view of independently sealed resource accounting.

    Before a completion is submitted here, the driver must stop all owned
    writers, finish owned cleanup, sign its snapshot, then atomically close the
    task against that snapshot digest and signed envelope SHA. A raced debit
    must make that close fail. Replaying this state never closes the store.
    """

    def snapshot(self) -> Mapping[str, Any]: ...


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digest(value: Any) -> bool:
    return type(value) is str and _HASH.fullmatch(value) is not None


def _identity(value: Any) -> bool:
    return type(value) is str and _ID.fullmatch(value) is not None


def _signed(raw: bytes) -> bool:
    return type(raw) is bytes and 0 < len(raw) <= _MAX_ENVELOPE


@dataclass(frozen=True, slots=True)
class BudgetedSubsetPreview:
    run_id: str
    epoch: str
    evidence_root: Path
    source_commit: str
    cohort_sha256: str
    freeze_sha256: str
    certification_sha256: str
    admission_sha256: str
    payload_sha256: str
    signed_admission: bytes = field(repr=False)
    budget: VerifiedSubsetBudget = field(repr=False)
    task_ids: tuple[str, ...] = OFFICIAL_SUBSET_TASK_IDS
    previously_exposed_task_ids: tuple[str, ...] = PREVIOUSLY_EXPOSED_TASK_IDS


def _admission_payload(preview: BudgetedSubsetPreview) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "artifact_kind": "budgeted_subset_admission",
        "scope": _SCOPE,
        "run_id": preview.run_id,
        "epoch": preview.epoch,
        "source_commit": preview.source_commit,
        "task_ids": list(OFFICIAL_SUBSET_TASK_IDS),
        "previously_exposed_task_ids": list(PREVIOUSLY_EXPOSED_TASK_IDS),
        "max_parallel_tasks": 1,
        "official_registry_sha256": OFFICIAL_SUBSET_REGISTRY_SHA256,
        "cohort_sha256": preview.cohort_sha256,
        "freeze_sha256": preview.freeze_sha256,
        "certification_sha256": preview.certification_sha256,
        "budget_sha256": preview.budget.envelope_sha256,
        "campaign_policy_sha256": preview.budget.campaign_policy_sha256,
        "model_policy_sha256": preview.budget.model_policy_sha256,
        "metering_policy_sha256": preview.budget.metering_policy_sha256,
        "recovery_policy": "terminal_and_sealed_driver_quiescence",
    }


def _verify_preview(preview: BudgetedSubsetPreview, authority: CampaignAuthority) -> None:
    if (
        type(preview) is not BudgetedSubsetPreview
        or type(preview.budget) is not VerifiedSubsetBudget
        or preview.task_ids != OFFICIAL_SUBSET_TASK_IDS
        or preview.previously_exposed_task_ids != PREVIOUSLY_EXPOSED_TASK_IDS
        or preview.run_id != preview.budget.run_id
        or preview.epoch != preview.budget.epoch
        or preview.budget.max_elapsed_seconds != 432000
        or preview.budget.max_spend_units != 500000000
        or not _signed(preview.signed_admission)
        or _sha(preview.signed_admission) != preview.admission_sha256
    ):
        raise RuntimeError("verified budgeted subset preview changed")
    preview.budget.reverify(authority)
    expected = _admission_payload(preview)
    payload = _attest(authority, "budgeted_subset_admission", preview.signed_admission)
    if (
        _json_bytes(payload) != _json_bytes(expected)
        or _sha(_json_bytes(expected)) != preview.payload_sha256
    ):
        raise RuntimeError("signed budgeted subset admission changed")


def preview_budgeted_subset_admission(
    *,
    signed_admission: bytes,
    signed_budget: bytes,
    authority: CampaignAuthority,
    run_id: str,
    epoch: str,
    evidence_root: Path,
    expected_admission_sha256: str,
    expected_budget_sha256: str,
    expected_cohort_sha256: str,
    expected_freeze_sha256: str,
    expected_certification_sha256: str,
    campaign_policy_sha256: str,
    model_policy_sha256: str,
    metering_policy_sha256: str,
    source_commit: str,
) -> BudgetedSubsetPreview:
    """Verify actual admission/budget signatures without creating run state."""
    if (
        authority is None
        or not _signed(signed_admission)
        or not _identity(run_id)
        or not _identity(epoch)
        or type(source_commit) is not str
        or _COMMIT.fullmatch(source_commit) is None
        or not isinstance(evidence_root, Path)
        or not evidence_root.is_absolute()
        or not evidence_root.is_dir()
        or evidence_root.is_symlink()
        or evidence_root.resolve(strict=True) != evidence_root
        or any(
            not _digest(value)
            for value in (
                expected_admission_sha256,
                expected_budget_sha256,
                expected_cohort_sha256,
                expected_freeze_sha256,
                expected_certification_sha256,
            )
        )
        or _sha(signed_admission) != expected_admission_sha256
    ):
        raise RuntimeError("actual signed budgeted subset admission and independent pins required")
    budget = verify_subset_run_budget(
        signed_budget=signed_budget,
        authority=authority,
        expected_envelope_sha256=expected_budget_sha256,
        run_id=run_id,
        epoch=epoch,
        campaign_policy_sha256=campaign_policy_sha256,
        model_policy_sha256=model_policy_sha256,
        metering_policy_sha256=metering_policy_sha256,
    )
    payload = _attest(authority, "budgeted_subset_admission", signed_admission)
    preview = BudgetedSubsetPreview(
        run_id=run_id,
        epoch=epoch,
        evidence_root=evidence_root,
        source_commit=source_commit,
        cohort_sha256=expected_cohort_sha256,
        freeze_sha256=expected_freeze_sha256,
        certification_sha256=expected_certification_sha256,
        admission_sha256=expected_admission_sha256,
        payload_sha256=_sha(_json_bytes(payload)),
        signed_admission=signed_admission,
        budget=budget,
    )
    _verify_preview(preview, authority)
    return preview


def _decode(event: Mapping[str, Any], prefix: str) -> bytes:
    encoded = event.get(f"{prefix}_envelope_b64")
    if type(encoded) is not str or len(encoded) > 4 * ((_MAX_ENVELOPE + 2) // 3):
        raise RuntimeError("signed quiescence envelope absent")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except ValueError:
        raise RuntimeError("signed quiescence envelope malformed") from None
    if (
        not _signed(raw)
        or base64.b64encode(raw).decode("ascii") != encoded
        or _sha(raw) != event.get(f"{prefix}_sha256")
    ):
        raise RuntimeError("signed quiescence envelope digest differs")
    return raw


def _envelope_event(kind: str, task_id: str, raw: bytes) -> dict[str, Any]:
    if not _signed(raw):
        raise RuntimeError("bounded signed quiescence envelope required")
    return {
        "type": kind,
        "task_id": task_id,
        "completion_sha256": _sha(raw),
        "completion_envelope_b64": base64.b64encode(raw).decode("ascii"),
    }


@dataclass(frozen=True, slots=True)
class BudgetedSubsetState:
    preview: BudgetedSubsetPreview = field(repr=False)
    authority: CampaignAuthority = field(repr=False, compare=False)
    signed_freeze: bytes = field(repr=False)
    signed_certification: bytes = field(repr=False)
    readiness_verifier: SubsetReadinessVerifier = field(repr=False, compare=False)
    resource_budget: ResourceBudgetView = field(repr=False, compare=False)

    @property
    def run_id(self) -> str:
        return self.preview.run_id

    @property
    def epoch(self) -> str:
        return self.preview.epoch

    @property
    def evidence_root(self) -> Path:
        return self.preview.evidence_root

    @property
    def task_ids(self) -> tuple[str, ...]:
        return OFFICIAL_SUBSET_TASK_IDS

    def _resources(self) -> Mapping[str, Any]:
        try:
            snapshot = self.resource_budget.snapshot()
        except Exception:
            raise RuntimeError("independent resource accounting unavailable") from None
        if (
            not isinstance(snapshot, Mapping)
            or snapshot.get("run_id") != self.run_id
            or snapshot.get("epoch") != self.epoch
            or snapshot.get("budget_sha256") != self.preview.budget.envelope_sha256
            or not isinstance(snapshot.get("closures"), Mapping)
            or not _digest(snapshot.get("accounting_sha256"))
            or "stop" not in snapshot
        ):
            raise RuntimeError("independent resource accounting identity differs")
        if snapshot["stop"] is not None and (
            not isinstance(snapshot["stop"], dict) or not snapshot["stop"]
        ):
            raise RuntimeError("independent resource stop evidence invalid")
        return snapshot

    def _readiness(self) -> None:
        _verify_preview(self.preview, self.authority)
        if (
            not _signed(self.signed_freeze)
            or type(self.signed_certification) is not bytes
            or not 0 < len(self.signed_certification) <= _MAX_SIGNED_CERTIFICATION
            or _sha(self.signed_freeze) != self.preview.freeze_sha256
            or _sha(self.signed_certification) != self.preview.certification_sha256
        ):
            raise RuntimeError("actual fresh signed readiness bytes required")
        harness = _attest(self.authority, "harness_lock", self.signed_freeze)
        try:
            certified = self.authority.attest_takeover_certification(self.signed_certification)
        except Exception:
            certified = None
        if (
            not isinstance(certified, Mapping)
            or type(certified.get("schema_version")) is not int
            or certified["schema_version"] != 2
            or certified.get("status") != "accepted"
            or certified.get("scope") != "live_native"
            or certified.get("epoch") != self.epoch
            or certified.get("harness_sha256") != self.preview.freeze_sha256
            or certified.get("cohort_sha256") != self.preview.cohort_sha256
            or certified.get("campaign_policy_sha256") != self.preview.budget.campaign_policy_sha256
            or certified.get("policy_sha256") != self.preview.budget.model_policy_sha256
            or harness.get("epoch") != self.epoch
            or harness.get("source_commit") != self.preview.source_commit
            or harness.get("campaign_policy_sha256") != self.preview.budget.campaign_policy_sha256
            or harness.get("model_policy_sha256") != self.preview.budget.model_policy_sha256
        ):
            raise RuntimeError("fresh signed takeover certification or source freeze differs")
        try:
            accepted = self.readiness_verifier.verify_subset_readiness(
                signed_freeze=self.signed_freeze,
                signed_certification=self.signed_certification,
                source_commit=self.preview.source_commit,
                epoch=self.epoch,
                campaign_policy_sha256=self.preview.budget.campaign_policy_sha256,
                model_policy_sha256=self.preview.budget.model_policy_sha256,
                cohort_sha256=self.preview.cohort_sha256,
            )
        except Exception:
            accepted = False
        if accepted is not True:
            raise RuntimeError(
                "independent complete two-repetition readiness verification required"
            )

    def creation_event(self) -> dict[str, Any]:
        self._readiness()
        self._resources()
        return {
            "type": "campaign_created",
            "scope": "budgeted_native_subset_dry_run_level1",
            "run_id": self.run_id,
            "epoch": self.epoch,
            "task_ids": list(self.task_ids),
            "previously_exposed_task_ids": list(PREVIOUSLY_EXPOSED_TASK_IDS),
            "task_count": len(self.task_ids),
            "admission_sha256": self.preview.admission_sha256,
            "budget_sha256": self.preview.budget.envelope_sha256,
            "freeze_sha256": self.preview.freeze_sha256,
            "certification_sha256": self.preview.certification_sha256,
            "cohort_sha256": self.preview.cohort_sha256,
            "source_commit": self.preview.source_commit,
            "campaign_policy_sha256": self.preview.budget.campaign_policy_sha256,
            "model_policy_sha256": self.preview.budget.model_policy_sha256,
            "metering_policy_sha256": self.preview.budget.metering_policy_sha256,
        }

    def _completion(
        self,
        event: Mapping[str, Any],
        start: Mapping[str, Any],
        terminal: Mapping[str, Any],
        resources: Mapping[str, Any],
    ) -> None:
        raw = _decode(event, "completion")
        if event != _envelope_event("task_quiescent", start["task_id"], raw):
            raise RuntimeError("task quiescence event differs")
        payload = _attest(self.authority, "subset_driver_quiescence", raw)
        expected = {
            "schema_version": 1,
            "artifact_kind": "subset_driver_quiescence",
            "run_id": self.run_id,
            "epoch": self.epoch,
            "task_id": start["task_id"],
            "attempt_id": start["attempt_id"],
            "request_id": start["request_id"],
            "launch_sha256": start["launch_sha256"],
            "terminal_receipt_sha256": terminal["receipt_sha256"],
            "budget_sha256": self.preview.budget.envelope_sha256,
            "final_accounting_sha256": payload.get("final_accounting_sha256"),
            "owned_cleanup_sha256": payload.get("owned_cleanup_sha256"),
            "owned_cleanup_complete": True,
            "driver_stopped": True,
            "accounting_closed": True,
        }
        if (
            _json_bytes(payload) != _json_bytes(expected)
            or not _digest(payload.get("final_accounting_sha256"))
            or not _digest(payload.get("owned_cleanup_sha256"))
        ):
            raise RuntimeError("signed task quiescence binding or cleanup incomplete")
        closure = resources["closures"].get(start["task_id"])
        if (
            not isinstance(closure, Mapping)
            or closure.get("attempt_id") != start["attempt_id"]
            or closure.get("completion_sha256") != _sha(raw)
            or closure.get("accounting_sha256") != payload["final_accounting_sha256"]
        ):
            raise RuntimeError("signed task quiescence lacks matching sealed accounting")

    def _prepared_completion(
        self,
        event: Mapping[str, Any],
        resources: Mapping[str, Any],
        preparation: Mapping[str, Any],
        prepared: Mapping[str, Any] | None,
    ) -> None:
        raw = _decode(event, "completion")
        task_id = event["task_id"]
        if event != _envelope_event("prepared_quiescent", task_id, raw):
            raise RuntimeError("preparation quiescence event differs")
        payload = _attest(self.authority, "subset_preparation_quiescence", raw)
        expected = {
            "schema_version": 1,
            "artifact_kind": "subset_preparation_quiescence",
            "run_id": self.run_id,
            "epoch": self.epoch,
            "task_id": task_id,
            "budget_sha256": self.preview.budget.envelope_sha256,
            "preparation_id": preparation["preparation_id"],
            "preparation_started_event_sha256": _sha(_json_bytes(preparation)),
            "prepared_event_sha256": None if prepared is None else _sha(_json_bytes(prepared)),
            "owned_cleanup_sha256": payload.get("owned_cleanup_sha256"),
            "owned_cleanup_complete": True,
            "native_send_occurred": False,
        }
        if _json_bytes(payload) != _json_bytes(expected) or not _digest(
            payload.get("owned_cleanup_sha256")
        ):
            raise RuntimeError("signed preparation quiescence binding or cleanup incomplete")
        counts = resources.get("tasks", {}).get(task_id)
        if (
            not isinstance(counts, Mapping)
            or type(counts.get("requests")) is not int
            or counts["requests"] != 0
        ):
            raise RuntimeError("unattempted preparation has unexpected resource reservations")

    def _replay(self, extra: Mapping[str, Any] | None = None):
        expected_root = self.creation_event()
        resources = self._resources()
        try:
            events = self.authority.read_verified_events(self.evidence_root, self.run_id)
        except Exception:
            raise RuntimeError("verified budgeted subset ledger unavailable") from None
        if not isinstance(events, (list, tuple)) or not events or events[0] != expected_root:
            raise RuntimeError("verified budgeted subset ledger creation differs")
        revision = len(events)
        if extra is not None:
            if (
                extra.get("type") in {"preparation_started", "prepared", "started"}
                and resources["stop"] is not None
            ):
                raise RuntimeError("durable resource stop blocks preparation and Send")
            events = [*events, extra]
        cursor, phase, stop, stopped = 0, "unseen", None, False
        start = terminal = None
        preparation = prepared = None
        preparation_ids = set()
        for event in events[1:]:
            if not isinstance(event, Mapping) or stopped:
                raise RuntimeError("invalid budgeted subset ledger transition")
            kind = event.get("type")
            if kind == "run_stop_requested":
                expected = {
                    "type": "run_stop_requested",
                    "budget_sha256": self.preview.budget.envelope_sha256,
                    "stop_evidence_sha256": _sha(_json_bytes(resources["stop"])),
                }
                if stop is not None or resources["stop"] is None or event != expected:
                    raise RuntimeError("run stop differs from durable resource stop")
                stop = event
                continue
            if kind == "run_stopped":
                if (
                    stop is None
                    or phase != "unseen"
                    or event
                    != {
                        "type": "run_stopped",
                        "stop_evidence_sha256": stop["stop_evidence_sha256"],
                        "unattempted_task_ids": list(self.task_ids[cursor:]),
                    }
                ):
                    raise RuntimeError("run stop cannot precede authentic terminal and quiescence")
                stopped = True
                continue
            if cursor >= len(self.task_ids) or event.get("task_id") != self.task_ids[cursor]:
                raise RuntimeError("budgeted subset task order or retry violation")
            if (
                kind == "preparation_started"
                and stop is None
                and phase == "unseen"
                and set(event) == {"type", "task_id", "preparation_id"}
                and _identity(event["preparation_id"])
                and event["preparation_id"] not in preparation_ids
            ):
                preparation_ids.add(event["preparation_id"])
                preparation, phase = event, "preparing"
            elif (
                kind == "prepared"
                and stop is None
                and phase == "preparing"
                and event == {"type": "prepared", "task_id": self.task_ids[cursor]}
            ):
                prepared, phase = event, "prepared"
            elif (
                kind == "started"
                and stop is None
                and phase == "prepared"
                and set(event) == {"type", "task_id", "request_id", "attempt_id", "launch_sha256"}
                and _identity(event["request_id"])
                and _identity(event["attempt_id"])
                and _digest(event["launch_sha256"])
            ):
                start, phase = event, "started"
            elif kind == "terminal" and phase == "started" and _valid_terminal_event(event, self):
                terminal, phase = event, "terminal"
            elif kind == "task_quiescent" and phase == "terminal":
                self._completion(event, start, terminal, resources)
                cursor, phase, start, terminal = cursor + 1, "unseen", None, None
                preparation = prepared = None
            elif (
                kind == "prepared_quiescent"
                and phase in {"preparing", "prepared"}
                and stop is not None
            ):
                self._prepared_completion(event, resources, preparation, prepared)
                phase = "unseen"
                preparation = prepared = None
            else:
                raise RuntimeError("invalid budgeted subset task transition")
        unattempted_from = cursor + (phase in {"started", "terminal"})
        counts_by_task = resources.get("tasks")
        if not isinstance(counts_by_task, Mapping):
            raise RuntimeError("independent task reservation counts unavailable")
        for task_id in self.task_ids[unattempted_from:]:
            counts = counts_by_task.get(task_id)
            if (
                not isinstance(counts, Mapping)
                or type(counts.get("requests")) is not int
                or counts["requests"] != 0
                or task_id in resources["closures"]
            ):
                raise RuntimeError("unattempted task has unexplained reservations or closure")
        if stopped:
            action = CampaignAction("stopped", None)
        elif resources["stop"] is not None and stop is None:
            action = CampaignAction("request_stop", None)
        elif stop is not None and phase == "unseen":
            action = CampaignAction("finalize_stop", None)
        elif stop is not None and phase in {"preparing", "prepared"}:
            action = CampaignAction("cleanup_prepared", self.task_ids[cursor])
        elif cursor == len(self.task_ids):
            action = CampaignAction("complete", None)
        else:
            action = CampaignAction(
                {
                    "unseen": "prepare",
                    "preparing": "observe_preparing",
                    "prepared": "observe_prepared",
                    "started": "observe_started",
                    "terminal": "observe_terminal",
                }[phase],
                self.task_ids[cursor],
            )
        return action, revision, start, terminal, cursor, preparation, prepared

    def next_action(self) -> CampaignAction:
        return self._replay()[0]

    def _append(self, event: Mapping[str, Any], expected: CampaignAction) -> None:
        action, revision, *_ = self._replay()
        if action != expected:
            raise RuntimeError("budgeted subset transition differs from current action")
        # Validate the prospective event, including signatures and accounting,
        # before attempting a durable compare-and-swap append.
        _, current_revision, *_ = self._replay(event)
        if current_revision != revision:
            raise RuntimeError("budgeted subset ledger changed before append")
        try:
            accepted = self.authority.append_event(
                self.evidence_root, self.run_id, event, expected_revision=revision
            )
        except Exception:
            accepted = False
        if accepted is not True:
            raise RuntimeError(
                "budgeted subset append acknowledgement unavailable; replay required"
            )

    def mark_preparation_started(self, task_id: str, *, preparation_id: str) -> None:
        """Commit owned preparation before creating any task files or processes."""
        self._append(
            {"type": "preparation_started", "task_id": task_id, "preparation_id": preparation_id},
            CampaignAction("prepare", task_id),
        )

    def mark_prepared(self, task_id: str) -> None:
        """Record material ready after fresh work or independently verified observation."""
        self._append(
            {"type": "prepared", "task_id": task_id}, CampaignAction("observe_preparing", task_id)
        )

    def preparation_binding(self, task_id: str) -> dict[str, Any]:
        """Return verified owned preparation facts, never permission to restage."""
        _, _, _, _, cursor, preparation, prepared = self._replay()
        if preparation is None or cursor >= len(self.task_ids) or self.task_ids[cursor] != task_id:
            raise RuntimeError("verified current preparation ownership unavailable")
        return {
            "preparation_id": preparation["preparation_id"],
            "preparation_started": dict(preparation),
            "preparation_started_event_sha256": _sha(_json_bytes(preparation)),
            "prepared": None if prepared is None else dict(prepared),
            "prepared_event_sha256": None if prepared is None else _sha(_json_bytes(prepared)),
        }

    def started_binding(self, task_id: str) -> dict[str, Any]:
        """Return the current committed native attempt during observation or cleanup."""
        _, _, start, *_ = self._replay()
        if start is None or start["task_id"] != task_id:
            raise RuntimeError("verified current started attempt unavailable")
        return dict(start)

    def current_terminal_receipt(self, task_id: str) -> bytes:
        """Return the current independently verified terminal while quiescence is pending."""
        _, _, _, terminal, *_ = self._replay()
        if terminal is None or terminal["task_id"] != task_id:
            raise RuntimeError("verified current signed terminal unavailable")
        return _decode(terminal, "receipt")

    def mark_started(
        self, task_id: str, *, request_id: str, attempt_id: str, launch_sha256: str
    ) -> None:
        self._append(
            {
                "type": "started",
                "task_id": task_id,
                "request_id": request_id,
                "attempt_id": attempt_id,
                "launch_sha256": launch_sha256,
            },
            CampaignAction("observe_prepared", task_id),
        )

    def started_event_sha256(self, task_id: str, request_id: str) -> str:
        action, _, start, *_ = self._replay()
        if (
            action != CampaignAction("observe_started", task_id)
            or start["request_id"] != request_id
        ):
            raise RuntimeError("verified budgeted subset started identity unavailable")
        return _sha(_json_bytes(start))

    def mark_terminal(self, task_id: str, signed_receipt: bytes) -> None:
        if not _signed(signed_receipt):
            raise RuntimeError("bounded signed terminal receipt required")
        payload = _attest(self.authority, "terminal_receipt", signed_receipt)
        details = _terminal_receipt(payload, state=self, task_id=task_id)
        self._append(
            {
                "type": "terminal",
                "task_id": task_id,
                "receipt_sha256": _sha(signed_receipt),
                "receipt_envelope_b64": base64.b64encode(signed_receipt).decode("ascii"),
                **details,
            },
            CampaignAction("observe_started", task_id),
        )

    def mark_quiescent(self, task_id: str, signed_completion: bytes) -> None:
        self._append(
            _envelope_event("task_quiescent", task_id, signed_completion),
            CampaignAction("observe_terminal", task_id),
        )

    def request_stop(self) -> None:
        resources = self._resources()
        if resources["stop"] is None:
            raise RuntimeError("durable resource stop required")
        self._append(
            {
                "type": "run_stop_requested",
                "budget_sha256": self.preview.budget.envelope_sha256,
                "stop_evidence_sha256": _sha(_json_bytes(resources["stop"])),
            },
            CampaignAction("request_stop", None),
        )

    def mark_preparation_quiescent(self, task_id: str, signed_completion: bytes) -> None:
        self._append(
            _envelope_event("prepared_quiescent", task_id, signed_completion),
            CampaignAction("cleanup_prepared", task_id),
        )

    def finalize_stop(self) -> None:
        _, _, _, _, cursor, *_ = self._replay()
        self._append(
            {
                "type": "run_stopped",
                "stop_evidence_sha256": _sha(_json_bytes(self._resources()["stop"])),
                "unattempted_task_ids": list(self.task_ids[cursor:]),
            },
            CampaignAction("finalize_stop", None),
        )


def bind_budgeted_subset_state(
    preview: BudgetedSubsetPreview,
    *,
    authority: CampaignAuthority,
    signed_freeze: bytes,
    signed_certification: bytes,
    readiness_verifier: SubsetReadinessVerifier,
    resource_budget: ResourceBudgetView,
) -> BudgetedSubsetState:
    """Bind only after actual fresh readiness and resource stores are verified."""
    if type(preview) is not BudgetedSubsetPreview or authority is None:
        raise RuntimeError("verified budgeted subset preview and authority required")
    state = BudgetedSubsetState(
        preview, authority, signed_freeze, signed_certification, readiness_verifier, resource_budget
    )
    state.creation_event()
    return state
