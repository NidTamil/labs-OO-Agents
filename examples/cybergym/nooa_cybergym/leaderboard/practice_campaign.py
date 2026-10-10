# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Signed, two-task Level-1 practice admission over the native Xeus ledger.

This is a separate admission path. It cannot construct a scored CampaignState,
and the scored go-live predicate retains its 1,507-task requirement.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .campaign import (
    _MAX_TERMINAL_RECEIPT_BYTES,
    CampaignAction,
    CampaignAuthority,
    _attest,
    _terminal_receipt,
    _valid_terminal_event,
)
from .cohort import FrozenTaskInput

PRACTICE_TASK_IDS = ("arvo:47101", "arvo:3938")
_HOST = "sunchaser-20260905.cinnamon-gamut.ts.net"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_ADMISSION_FIELDS = frozenset(
    {
        "schema_version",
        "artifact_kind",
        "scope",
        "run_id",
        "epoch",
        "task_ids",
        "max_parallel_tasks",
        "freeze_sha256",
        "asset_hashes_sha256",
        "selected_assets_sha256",
        "host_key_sha256",
        "vscode_exe_sha256",
        "vscode_version",
        "claude_extension_version",
        "remote_host",
    }
)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_practice_assets(*, registry, data_dir: Path) -> dict[str, dict[str, str | int]]:
    """Read only the two selected vulnerable inputs against frozen asset metadata."""
    root = Path(data_dir)
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise RuntimeError("trusted practice asset directory required")
    observed = {}
    for task_id in PRACTICE_TASK_IDS:
        entry = registry.inputs_for(task_id)
        if type(entry) is not FrozenTaskInput or entry.task_id != task_id:
            raise RuntimeError("selected practice asset registry differs")
        family, number = task_id.split(":", 1)
        folder = root / family / number
        if folder.is_symlink() or not folder.is_dir():
            raise RuntimeError("selected practice asset directory is missing or linked")
        identity = {"task_id": task_id}
        for name, expected_hash, expected_size, prefix in (
            (
                "description.txt",
                entry.description_sha256,
                entry.description_bytes,
                "description",
            ),
            (
                "repo-vul.tar.gz",
                entry.vulnerable_archive.sha256,
                entry.vulnerable_archive.bytes,
                "vulnerable_archive",
            ),
        ):
            source = folder / name
            if source.is_symlink() or not source.is_file():
                raise RuntimeError("selected practice asset is missing or linked")
            digest = hashlib.sha256()
            size = 0
            with source.open("rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
                    size += len(block)
            if digest.hexdigest() != expected_hash or size != expected_size:
                raise RuntimeError("selected practice asset differs from frozen manifest")
            identity[f"{prefix}_sha256"] = digest.hexdigest()
            identity[f"{prefix}_bytes"] = size
        observed[task_id] = identity
    return observed


def selected_assets_sha256(observed: Mapping[str, Mapping[str, str | int]]) -> str:
    """Bind the four verified practice file identities in one canonical digest."""
    if type(observed) is not dict or set(observed) != set(PRACTICE_TASK_IDS):
        raise ValueError("exactly two selected practice assets required")
    fields = {
        "task_id",
        "description_sha256",
        "description_bytes",
        "vulnerable_archive_sha256",
        "vulnerable_archive_bytes",
    }
    for task_id in PRACTICE_TASK_IDS:
        identity = observed[task_id]
        if (
            type(identity) is not dict
            or set(identity) != fields
            or identity["task_id"] != task_id
            or any(
                type(identity[name]) is not str or _DIGEST.fullmatch(identity[name]) is None
                for name in ("description_sha256", "vulnerable_archive_sha256")
            )
            or any(
                type(identity[name]) is not int or identity[name] <= 0
                for name in ("description_bytes", "vulnerable_archive_bytes")
            )
        ):
            raise ValueError("selected asset identity is invalid")
    return _sha(
        json.dumps(
            {"schema_version": 1, "task_ids": list(PRACTICE_TASK_IDS), "assets": observed},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    )


@dataclass(frozen=True, slots=True)
class PracticeState:
    run_id: str
    epoch: str
    evidence_root: Path
    admission_sha256: str
    signed_admission: bytes = field(repr=False)
    authority: CampaignAuthority = field(repr=False)
    task_ids: tuple[str, str] = PRACTICE_TASK_IDS

    def _root_event(self) -> dict[str, Any]:
        payload = _attest(self.authority, "practice_admission", self.signed_admission)
        if (
            payload.get("run_id") != self.run_id
            or payload.get("epoch") != self.epoch
            or payload.get("task_ids") != list(PRACTICE_TASK_IDS)
            or payload.get("scope") != "native_practice_level1"
            or _sha(self.signed_admission) != self.admission_sha256
        ):
            raise RuntimeError("signed practice admission changed")
        return {
            "type": "campaign_created",
            "scope": "native_practice_level1",
            "run_id": self.run_id,
            "epoch": self.epoch,
            "task_ids": list(PRACTICE_TASK_IDS),
            "admission_sha256": self.admission_sha256,
            "freeze_sha256": payload["freeze_sha256"],
            "asset_hashes_sha256": payload["asset_hashes_sha256"],
            "selected_assets_sha256": payload["selected_assets_sha256"],
            "vscode_exe_sha256": payload["vscode_exe_sha256"],
        }

    def _next_action_and_revision(self) -> tuple[CampaignAction, int]:
        expected_root = self._root_event()
        try:
            events = self.authority.read_verified_events(self.evidence_root, self.run_id)
        except Exception:
            raise RuntimeError("verified practice ledger unavailable") from None
        if not isinstance(events, (list, tuple)) or not events or events[0] != expected_root:
            raise RuntimeError("verified practice ledger creation differs from admission")
        cursor = 0
        phase = "unseen"
        for event in events[1:]:
            if (
                not isinstance(event, Mapping)
                or cursor >= len(self.task_ids)
                or event.get("task_id") != self.task_ids[cursor]
            ):
                raise RuntimeError("practice ledger task order or retry violation")
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
                raise RuntimeError("practice ledger has an invalid task transition")
        if cursor == len(self.task_ids):
            return CampaignAction("complete", None), len(events)
        kind = {
            "unseen": "prepare",
            "prepared": "observe_prepared",
            "started": "observe_started",
        }[phase]
        return CampaignAction(kind, self.task_ids[cursor]), len(events)

    def next_action(self) -> CampaignAction:
        """Replay the verified chain before every controller transition."""
        return self._next_action_and_revision()[0]

    def started_event_sha256(self, task_id: str, request_id: str) -> str:
        """Bind a start intent to the exact last verified practice ledger event."""
        action, revision = self._next_action_and_revision()
        if action != CampaignAction("observe_started", task_id):
            raise RuntimeError("verified practice started event is unavailable")
        events = self.authority.read_verified_events(self.evidence_root, self.run_id)
        expected = {"type": "started", "task_id": task_id, "request_id": request_id}
        if len(events) != revision or events[-1] != expected:
            raise RuntimeError("verified practice started event differs from request")
        return _sha(
            json.dumps(
                expected,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        )

    def _append(self, task_id: str, kind: str, **details: str) -> None:
        action, revision = self._next_action_and_revision()
        expected = {
            "prepared": "prepare",
            "started": "observe_prepared",
            "terminal": "observe_started",
        }[kind]
        if action != CampaignAction(expected, task_id):
            raise RuntimeError("practice transition differs from signed task order")
        event = {"type": kind, "task_id": task_id, **details}
        try:
            accepted = self.authority.append_event(
                self.evidence_root, self.run_id, event, expected_revision=revision
            )
        except Exception:
            accepted = False
        if accepted is not True:
            raise RuntimeError("practice ledger append acknowledgement unavailable")

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
            receipt_sha256=_sha(signed_receipt),
            receipt_envelope_b64=base64.b64encode(signed_receipt).decode("ascii"),
            **details,
        )


def admit_practice(
    *,
    signed_admission: bytes,
    authority: CampaignAuthority,
    run_id: str,
    epoch: str,
    evidence_root: Path,
    expected_freeze_sha256: str,
    expected_asset_hashes_sha256: str,
    expected_selected_assets_sha256: str,
    expected_host_key_sha256: str,
    expected_vscode_exe_sha256: str,
) -> PracticeState:
    """Admit only the authorized pair with exact signed runtime and asset pins."""
    if (
        type(run_id) is not str
        or not run_id
        or type(epoch) is not str
        or not epoch
        or not isinstance(evidence_root, Path)
        or not evidence_root.is_absolute()
        or evidence_root.is_symlink()
        or not evidence_root.is_dir()
        or any(
            type(value) is not str or _DIGEST.fullmatch(value) is None
            for value in (
                expected_freeze_sha256,
                expected_asset_hashes_sha256,
                expected_selected_assets_sha256,
                expected_host_key_sha256,
                expected_vscode_exe_sha256,
            )
        )
    ):
        raise RuntimeError("trusted practice admission inputs required")
    payload = _attest(authority, "practice_admission", signed_admission)
    if set(payload) != _ADMISSION_FIELDS or payload != {
        "schema_version": 1,
        "artifact_kind": "practice_admission",
        "scope": "native_practice_level1",
        "run_id": run_id,
        "epoch": epoch,
        "task_ids": list(PRACTICE_TASK_IDS),
        "max_parallel_tasks": 1,
        "freeze_sha256": expected_freeze_sha256,
        "asset_hashes_sha256": expected_asset_hashes_sha256,
        "selected_assets_sha256": expected_selected_assets_sha256,
        "host_key_sha256": expected_host_key_sha256,
        "vscode_exe_sha256": expected_vscode_exe_sha256,
        "vscode_version": "1.140.0",
        "claude_extension_version": "2.1.289",
        "remote_host": _HOST,
    }:
        raise RuntimeError("signed practice admission differs from authorized pair")
    state = PracticeState(
        run_id=run_id,
        epoch=epoch,
        evidence_root=evidence_root,
        admission_sha256=_sha(signed_admission),
        signed_admission=signed_admission,
        authority=authority,
    )
    created = authority.create_campaign_once(evidence_root, run_id, state._root_event())
    if type(created) is not bool:
        raise RuntimeError("practice ledger creation acknowledgement unavailable")
    state.next_action()
    return state
