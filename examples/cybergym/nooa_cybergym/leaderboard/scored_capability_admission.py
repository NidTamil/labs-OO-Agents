# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Recheck the separately signed full-cohort capability identity before staging.

This is an admission check, not a source of live capability evidence. The
independent certification signer must have accepted the actual native runs;
the synthetic-only registry used by practice cannot be promoted here.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from .campaign import CampaignState
from .capabilities import CapabilityRegistry, Status
from .capability_runtime import SYNTHETIC_SCOPE

_HASH = re.compile(r"[a-f0-9]{64}\Z")


@dataclass(frozen=True, slots=True)
class ScoredCapabilityAdmission:
    run_id: str
    epoch: str
    cohort_sha256: str
    registry_sha256: str
    image_id: str
    _state: CampaignState = field(repr=False, compare=False)
    _decision: bytes = field(repr=False)
    _certification: bytes = field(repr=False)
    _harness_lock: bytes = field(repr=False)

    def verify_current(
        self, *, task_id: str, registry: CapabilityRegistry, observed_image_id: str
    ) -> None:
        """Recheck the signed bundle and current task on runtime construction."""
        action = self._state.next_action()
        if action.task_id != task_id or action.kind not in {
            "prepare",
            "observe_prepared",
            "observe_started",
        }:
            raise RuntimeError("scored task differs from verified campaign transition")
        if observed_image_id != self.image_id:
            raise RuntimeError("observed scored image differs from signed freeze")
        refreshed = verify_scored_capability_admission(
            state=self._state,
            decision=self._decision,
            certification=self._certification,
            harness_lock=self._harness_lock,
            registry=registry,
            observed_image_id=observed_image_id,
        )
        if refreshed != self:
            raise RuntimeError("scored capability admission changed during task")


def _attest(state: CampaignState, kind: str, envelope: bytes):
    if type(envelope) is not bytes or not envelope:
        raise RuntimeError(f"signed {kind} bytes required")
    payload = state.authority.attest_signed(kind, envelope)
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise RuntimeError(f"signed {kind} verification failed")
    return payload


def verify_scored_capability_admission(
    *,
    state: CampaignState,
    decision: bytes,
    certification: bytes,
    harness_lock: bytes,
    registry: CapabilityRegistry,
    observed_image_id: str,
) -> ScoredCapabilityAdmission:
    """Refuse a practice/synthetic freeze before any scored container is created."""
    if type(state) is not CampaignState or type(registry) is not CapabilityRegistry:
        raise TypeError("signed campaign state and exact capability registry required")
    if (
        type(observed_image_id) is not str
        or not observed_image_id.startswith("sha256:")
        or _HASH.fullmatch(observed_image_id[7:]) is None
    ):
        raise ValueError("observed immutable scored image identity required")
    # Replay the independently verified creation and all subsequent transitions.
    state.next_action()
    approval = _attest(state, "decision", decision)
    certified = _attest(state, "certification", certification)
    harness = _attest(state, "harness_lock", harness_lock)
    cert_sha = hashlib.sha256(certification).hexdigest()
    harness_sha = hashlib.sha256(harness_lock).hexdigest()
    if (
        approval.get("official_launch_authorised") is not True
        or approval.get("run_id") != state.run_id
        or approval.get("epoch") != state.epoch
        or approval.get("certification_sha256") != cert_sha
        or approval.get("harness_sha256") != harness_sha
        or approval.get("cohort_sha256") != state.cohort_sha256
        or approval.get("campaign_policy_sha256") != state.policy_sha256
        or certified.get("status") != "accepted"
        or certified.get("scope") != "live_native"
        or certified.get("epoch") != state.epoch
        or certified.get("harness_sha256") != harness_sha
        or certified.get("cohort_sha256") != state.cohort_sha256
        or certified.get("campaign_policy_sha256") != state.policy_sha256
        or certified.get("capability_coverage") != "all_enabled_exercised"
        or not isinstance(certified.get("frozen_hashes"), dict)
        or certified.get("frozen_hashes", {}).get("image_sha256") != observed_image_id[7:]
        or harness.get("epoch") != state.epoch
        or harness.get("campaign_policy_sha256") != state.policy_sha256
        or harness.get("image_sha256") != observed_image_id[7:]
    ):
        raise RuntimeError("signed full-cohort admission differs from verified campaign")
    digest = registry.digest
    if (
        _HASH.fullmatch(digest) is None
        or harness.get("capability_registry_sha256") != digest
        or certified.get("capability_registry_sha256") != digest
    ):
        raise RuntimeError("capability registry differs from signed full-cohort freeze")
    approved = tuple(entry for entry in registry.entries if entry.status is Status.APPROVED)
    if any(SYNTHETIC_SCOPE in entry.evidence_refs for entry in approved):
        raise RuntimeError("synthetic-only capability cannot enter scored cohort")
    approved_ids = sorted(entry.capability_id for entry in approved)
    if (
        len(approved_ids) != 35
        or certified.get("enabled_capability_ids") != approved_ids
        or certified.get("required_approved_capability_ids") != approved_ids
    ):
        raise RuntimeError("signed live capability coverage differs from scored registry")
    return ScoredCapabilityAdmission(
        state.run_id,
        state.epoch,
        state.cohort_sha256,
        digest,
        observed_image_id,
        state,
        decision,
        certification,
        harness_lock,
    )
