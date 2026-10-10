# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Practice-only permit for the frozen native capability inventory.

The v26q report is live native synthetic evidence. A permit changes only the
admission scope of that exact registry for the current signed practice task;
it is never a scored-campaign certification or oracle verdict.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from xeus_cybergym.canonical import canonical_json
from xeus_cybergym.ledger import SignedEnvelope

from .campaign import _attest
from .capabilities import CapabilityRegistry
from .practice_campaign import _ADMISSION_FIELDS, _HOST, PRACTICE_TASK_IDS, PracticeState

_SHA = re.compile(r"[a-f0-9]{64}\Z")


@dataclass(frozen=True, slots=True)
class PracticeCapabilityPermit:
    run_id: str
    task_id: str
    registry_sha256: str
    image_id: str
    admission_sha256: str
    signed_report_sha256: str
    _state: PracticeState = field(repr=False, compare=False)
    _report_path: Path = field(repr=False, compare=False)
    _signed_report_path: Path = field(repr=False, compare=False)
    _verifier: object = field(repr=False, compare=False)

    def verify_current(
        self, *, task_id: str, registry: CapabilityRegistry, observed_image_id: str
    ) -> None:
        """Recheck signed evidence and the live ledger at runtime construction."""
        if observed_image_id != self.image_id:
            raise RuntimeError("observed practice image differs from signed report")
        refreshed = type(self).from_signed_report(
            state=self._state,
            task_id=task_id,
            registry=registry,
            image_id=self.image_id,
            report_path=self._report_path,
            signed_report_path=self._signed_report_path,
            expected_signed_report_sha256=self.signed_report_sha256,
            verifier=self._verifier,
        )
        if refreshed != self:
            raise RuntimeError("signed practice permit fields differ")

    @classmethod
    def from_signed_report(
        cls,
        *,
        state: PracticeState,
        task_id: str,
        registry: CapabilityRegistry,
        image_id: str,
        report_path: Path,
        signed_report_path: Path,
        expected_signed_report_sha256: str,
        verifier,
    ) -> PracticeCapabilityPermit:
        if (
            type(state) is not PracticeState
            or task_id not in PRACTICE_TASK_IDS
            or type(registry) is not CapabilityRegistry
            or type(image_id) is not str
            or re.fullmatch(r"sha256:[a-f0-9]{64}", image_id) is None
            or type(expected_signed_report_sha256) is not str
            or _SHA.fullmatch(expected_signed_report_sha256) is None
            or not callable(getattr(verifier, "verify", None))
        ):
            raise ValueError("signed current practice and frozen inventory required")
        action = state.next_action()
        if action.task_id != task_id or action.kind not in {
            "prepare",
            "observe_prepared",
            "observe_started",
        }:
            raise RuntimeError("current practice task differs from signed ledger")
        admission = _attest(state.authority, "practice_admission", state.signed_admission)
        if (
            set(admission) != _ADMISSION_FIELDS
            or admission.get("artifact_kind") != "practice_admission"
            or admission.get("scope") != "native_practice_level1"
            or admission.get("task_ids") != list(PRACTICE_TASK_IDS)
            or admission.get("run_id") != state.run_id
            or admission.get("epoch") != state.epoch
            or admission.get("max_parallel_tasks") != 1
            or admission.get("vscode_version") != "1.140.0"
            or admission.get("claude_extension_version") != "2.1.289"
            or admission.get("remote_host") != _HOST
            or any(
                type(admission.get(name)) is not str or _SHA.fullmatch(admission[name]) is None
                for name in (
                    "freeze_sha256",
                    "asset_hashes_sha256",
                    "selected_assets_sha256",
                    "host_key_sha256",
                    "vscode_exe_sha256",
                )
            )
        ):
            raise RuntimeError("signed practice admission differs from exact task pins")
        paths = (Path(report_path), Path(signed_report_path))
        if any(
            not path.is_absolute()
            or path.is_symlink()
            or not path.is_file()
            or not 0 < path.stat().st_size <= 1024 * 1024
            for path in paths
        ):
            raise RuntimeError("bounded signed certification files required")
        report_raw, envelope_raw = (path.read_bytes() for path in paths)
        if hashlib.sha256(envelope_raw).hexdigest() != expected_signed_report_sha256:
            raise RuntimeError("signed certification digest differs")
        try:
            envelope = SignedEnvelope.model_validate_json(envelope_raw)
            payload = verifier.verify(envelope)
            report = json.loads(report_raw)
        except Exception:
            raise RuntimeError("signed certification could not be verified") from None
        if (
            canonical_json(envelope.model_dump()) != envelope_raw
            or canonical_json(report) != report_raw
            or payload != report_raw
        ):
            raise RuntimeError("signed certification payload differs")
        capability_ids = sorted(entry.capability_id for entry in registry.entries)
        if (
            report.get("schema_version") != 1
            or report.get("scope") != "live_native"
            or report.get("status") != "accepted"
            or report.get("failures") != []
            or report.get("capability_coverage") != "all_enabled_exercised"
            or report.get("capability_registry_sha256") != registry.digest
            or sorted(report.get("enabled_capability_ids", [])) != capability_ids
            or sorted(report.get("required_approved_capability_ids", [])) != capability_ids
            or report.get("frozen_hashes", {}).get("image_sha256") != image_id[7:]
            or report.get("official_launch_authorised") is not False
        ):
            raise RuntimeError("accepted live-native certification differs from practice pins")
        return cls(
            state.run_id,
            task_id,
            registry.digest,
            image_id,
            state.admission_sha256,
            expected_signed_report_sha256,
            state,
            paths[0],
            paths[1],
            verifier,
        )
