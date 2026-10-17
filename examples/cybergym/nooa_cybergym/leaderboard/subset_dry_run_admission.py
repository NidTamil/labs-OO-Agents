# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Preview a distinct signed ten-task practice decision without creating a ledger.

The preview is deliberately inert. A later runner must re-attest this decision
and bind a separately frozen worker before it may create durable state or Send.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .campaign import (
    _MAX_TERMINAL_RECEIPT_BYTES,
    CampaignAction,
    CampaignAuthority,
    _attest,
    _json_bytes,
    _terminal_receipt,
    _valid_terminal_event,
)

OFFICIAL_SUBSET_TASK_IDS = (
    "arvo:47101",
    "arvo:3938",
    "arvo:24993",
    "arvo:1065",
    "arvo:10400",
    "arvo:368",
    "oss-fuzz:42535201",
    "oss-fuzz:42535468",
    "oss-fuzz:370689421",
    "oss-fuzz:385167047",
)
PREVIOUSLY_EXPOSED_TASK_IDS = ("arvo:47101", "arvo:3938")
OFFICIAL_SUBSET_REGISTRY_SHA256 = "59d1fa85f6a681fc481f3ac4e14331586b7c9548972fd7ca661787da9995a7ad"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


@dataclass(frozen=True, slots=True)
class SubsetDryRunPreview:
    run_id: str
    epoch: str
    evidence_root: Path
    admission_sha256: str
    payload_sha256: str
    signed_admission: bytes = field(repr=False)
    task_ids: tuple[str, ...] = OFFICIAL_SUBSET_TASK_IDS
    previously_exposed_task_ids: tuple[str, ...] = PREVIOUSLY_EXPOSED_TASK_IDS


def preview_subset_dry_run_admission(
    *,
    signed_admission: bytes,
    authority: CampaignAuthority,
    run_id: str,
    epoch: str,
    evidence_root: Path,
    expected_cohort_sha256: str,
    expected_freeze_sha256: str,
    expected_certification_sha256: str,
    expected_budget_sha256: str,
) -> SubsetDryRunPreview:
    """Require exact official order and exposure disclosure; make no ledger write."""
    if (
        authority is None
        or type(signed_admission) is not bytes
        or not signed_admission
        or type(run_id) is not str
        or _RUN_ID.fullmatch(run_id) is None
        or type(epoch) is not str
        or _RUN_ID.fullmatch(epoch) is None
        or not isinstance(evidence_root, Path)
        or not evidence_root.is_absolute()
        or evidence_root.is_symlink()
        or not evidence_root.is_dir()
        or evidence_root.resolve(strict=True) != evidence_root
        or any(
            type(value) is not str or _DIGEST.fullmatch(value) is None
            for value in (
                expected_cohort_sha256,
                expected_freeze_sha256,
                expected_certification_sha256,
                expected_budget_sha256,
            )
        )
    ):
        raise RuntimeError("trusted subset dry-run admission inputs required")
    payload = _attest(authority, "subset_dry_run_admission", signed_admission)
    expected = {
        "schema_version": 1,
        "artifact_kind": "subset_dry_run_admission",
        "scope": "native_subset_dry_run_level1",
        "run_id": run_id,
        "epoch": epoch,
        "task_ids": list(OFFICIAL_SUBSET_TASK_IDS),
        "previously_exposed_task_ids": list(PREVIOUSLY_EXPOSED_TASK_IDS),
        "max_parallel_tasks": 1,
        "official_registry_sha256": OFFICIAL_SUBSET_REGISTRY_SHA256,
        "cohort_sha256": expected_cohort_sha256,
        "freeze_sha256": expected_freeze_sha256,
        "certification_sha256": expected_certification_sha256,
        "budget_sha256": expected_budget_sha256,
    }
    if type(payload) is not dict or payload != expected:
        raise RuntimeError("signed subset dry-run admission differs from exact scope")
    return SubsetDryRunPreview(
        run_id=run_id,
        epoch=epoch,
        evidence_root=evidence_root,
        admission_sha256=hashlib.sha256(signed_admission).hexdigest(),
        payload_sha256=hashlib.sha256(_json_bytes(expected)).hexdigest(),
        signed_admission=signed_admission,
    )


@dataclass(frozen=True, slots=True)
class SubsetDryRunState:
    """Replay a signed ten-task ledger; never create or launch it implicitly."""

    preview: SubsetDryRunPreview = field(repr=False)
    authority: CampaignAuthority = field(repr=False)

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

    def creation_event(self) -> dict[str, Any]:
        """Return the exact root event after re-attesting the previewed decision."""
        preview = self.preview
        if hashlib.sha256(preview.signed_admission).hexdigest() != preview.admission_sha256:
            raise RuntimeError("subset dry-run admission bytes changed")
        payload = _attest(self.authority, "subset_dry_run_admission", preview.signed_admission)
        if (
            type(payload) is not dict
            or hashlib.sha256(_json_bytes(payload)).hexdigest() != preview.payload_sha256
            or payload.get("scope") != "native_subset_dry_run_level1"
            or payload.get("task_ids") != list(OFFICIAL_SUBSET_TASK_IDS)
            or payload.get("previously_exposed_task_ids") != list(PREVIOUSLY_EXPOSED_TASK_IDS)
        ):
            raise RuntimeError("signed subset dry-run admission changed")
        return {
            "type": "campaign_created",
            "scope": "native_subset_dry_run_level1",
            "run_id": self.run_id,
            "epoch": self.epoch,
            "task_ids": list(OFFICIAL_SUBSET_TASK_IDS),
            "previously_exposed_task_ids": list(PREVIOUSLY_EXPOSED_TASK_IDS),
            "admission_sha256": preview.admission_sha256,
            "official_registry_sha256": OFFICIAL_SUBSET_REGISTRY_SHA256,
            "cohort_sha256": payload["cohort_sha256"],
            "freeze_sha256": payload["freeze_sha256"],
            "certification_sha256": payload["certification_sha256"],
            "budget_sha256": payload["budget_sha256"],
            "task_count": len(OFFICIAL_SUBSET_TASK_IDS),
        }

    def _next_action_and_revision(self) -> tuple[CampaignAction, int]:
        expected_root = self.creation_event()
        try:
            events = self.authority.read_verified_events(self.evidence_root, self.run_id)
        except Exception:
            raise RuntimeError("verified subset dry-run ledger unavailable") from None
        if not isinstance(events, (list, tuple)) or not events or events[0] != expected_root:
            raise RuntimeError("verified subset dry-run ledger creation differs from admission")
        cursor = 0
        phase = "unseen"
        for event in events[1:]:
            if (
                not isinstance(event, dict)
                or cursor >= len(self.task_ids)
                or event.get("task_id") != self.task_ids[cursor]
            ):
                raise RuntimeError("subset dry-run ledger task order or retry violation")
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
            elif kind == "terminal" and phase == "started" and _valid_terminal_event(event, self):
                cursor += 1
                phase = "unseen"
            else:
                raise RuntimeError("subset dry-run ledger has an invalid task transition")
        if cursor == len(self.task_ids):
            return CampaignAction("complete", None), len(events)
        kind = {
            "unseen": "prepare",
            "prepared": "observe_prepared",
            "started": "observe_started",
        }[phase]
        return CampaignAction(kind, self.task_ids[cursor]), len(events)

    def next_action(self) -> CampaignAction:
        return self._next_action_and_revision()[0]

    def started_event_sha256(self, task_id: str, request_id: str) -> str:
        action, revision = self._next_action_and_revision()
        if action != CampaignAction("observe_started", task_id):
            raise RuntimeError("verified subset started event is unavailable")
        events = self.authority.read_verified_events(self.evidence_root, self.run_id)
        expected = {"type": "started", "task_id": task_id, "request_id": request_id}
        if len(events) != revision or events[-1] != expected:
            raise RuntimeError("verified subset started event differs from request")
        return hashlib.sha256(_json_bytes(expected)).hexdigest()

    def _append(self, task_id: str, kind: str, **details: str) -> None:
        action, revision = self._next_action_and_revision()
        expected = {
            "prepared": "prepare",
            "started": "observe_prepared",
            "terminal": "observe_started",
        }[kind]
        if action != CampaignAction(expected, task_id):
            raise RuntimeError("subset dry-run transition differs from signed task order")
        event = {"type": kind, "task_id": task_id, **details}
        try:
            accepted = self.authority.append_event(
                self.evidence_root, self.run_id, event, expected_revision=revision
            )
        except Exception:
            accepted = False
        if accepted is not True:
            raise RuntimeError("subset dry-run ledger append acknowledgement unavailable")

    def mark_prepared(self, task_id: str) -> None:
        self._append(task_id, "prepared")

    def mark_started(self, task_id: str, *, request_id: str) -> None:
        if type(request_id) is not str or not request_id:
            raise ValueError("first model request identity required")
        self._append(task_id, "started", request_id=request_id)

    def mark_terminal(self, task_id: str, signed_receipt: bytes) -> None:
        if (
            type(signed_receipt) is not bytes
            or not 0 < len(signed_receipt) <= _MAX_TERMINAL_RECEIPT_BYTES
        ):
            raise RuntimeError("signed terminal receipt required")
        payload = _attest(self.authority, "terminal_receipt", signed_receipt)
        details = _terminal_receipt(payload, state=self, task_id=task_id)
        self._append(
            task_id,
            "terminal",
            receipt_sha256=hashlib.sha256(signed_receipt).hexdigest(),
            receipt_envelope_b64=base64.b64encode(signed_receipt).decode("ascii"),
            **details,
        )


def bind_subset_dry_run_state(
    preview: SubsetDryRunPreview, *, authority: CampaignAuthority
) -> SubsetDryRunState:
    """Construct only the replay adapter; a later runner owns durable creation."""
    if type(preview) is not SubsetDryRunPreview or authority is None:
        raise RuntimeError("verified subset dry-run preview and authority required")
    state = SubsetDryRunState(preview=preview, authority=authority)
    state.creation_event()
    return state
