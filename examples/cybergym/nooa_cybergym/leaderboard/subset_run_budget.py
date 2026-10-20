# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Inert verification of a separately signed ten-task budget.

There are no default time or spend limits and no signing or dispatch capability.
Test fixtures are not operator decisions. A verified artifact alone is not run
admission: the later controller must enforce its clock and conservative charges
under the independently pinned metering policy before every provider dispatch.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

from .campaign import CampaignAuthority, _attest, _json_bytes
from .subset_dry_run_admission import OFFICIAL_SUBSET_TASK_IDS

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_MAX_ENVELOPE_BYTES = 65536
_MAX_EXACT_INTEGER = 2**53 - 1
_FIXED = {
    "schema_version": 1,
    "artifact_kind": "subset_run_budget",
    "scope": "native_subset_dry_run_level1",
    "max_model_requests": 15000,
    "max_requests_per_task": 1500,
    "primary_and_memory_requests_per_task": 1410,
    "deepseek_advisory_requests_per_task": 90,
    "spend_unit": "usd_micros",
    "accounting_scope": "all_model_calls_including_memory_and_failed_reservations",
    "elapsed_scope": "first_preparation_through_final_cleanup",
    "exhaustion_action": "stop_run_preserve_task_terminals",
}
_VARIABLE = frozenset(
    {
        "run_id",
        "epoch",
        "task_ids",
        "campaign_policy_sha256",
        "model_policy_sha256",
        "metering_policy_sha256",
        "max_elapsed_seconds",
        "max_spend_units",
    }
)


def _is_digest(value: Any) -> bool:
    return type(value) is str and _DIGEST.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class VerifiedSubsetBudget:
    """Immutable verified bytes, re-attested at binding and recovery boundaries."""

    run_id: str
    epoch: str
    campaign_policy_sha256: str
    model_policy_sha256: str
    metering_policy_sha256: str
    max_elapsed_seconds: int
    max_spend_units: int
    signed_envelope: bytes = field(repr=False)
    envelope_sha256: str
    payload_json: bytes = field(repr=False)
    payload_sha256: str
    task_ids: tuple[str, ...] = OFFICIAL_SUBSET_TASK_IDS
    max_model_requests: int = 15000
    spend_unit: str = "usd_micros"

    def reverify(self, authority: CampaignAuthority) -> None:
        current = verify_subset_run_budget(
            signed_budget=self.signed_envelope,
            authority=authority,
            expected_envelope_sha256=self.envelope_sha256,
            run_id=self.run_id,
            epoch=self.epoch,
            campaign_policy_sha256=self.campaign_policy_sha256,
            model_policy_sha256=self.model_policy_sha256,
            metering_policy_sha256=self.metering_policy_sha256,
        )
        if current != self:
            raise RuntimeError("signed subset budget changed")


def verify_subset_run_budget(
    *,
    signed_budget: bytes,
    authority: CampaignAuthority,
    expected_envelope_sha256: str,
    run_id: str,
    epoch: str,
    campaign_policy_sha256: str,
    model_policy_sha256: str,
    metering_policy_sha256: str,
) -> VerifiedSubsetBudget:
    """Verify actual signed budget bytes and exact scope; create no durable state."""
    if (
        authority is None
        or type(signed_budget) is not bytes
        or not 0 < len(signed_budget) <= _MAX_ENVELOPE_BYTES
        or any(type(value) is not str or _ID.fullmatch(value) is None for value in (run_id, epoch))
        or any(
            not _is_digest(value)
            for value in (
                expected_envelope_sha256,
                campaign_policy_sha256,
                model_policy_sha256,
                metering_policy_sha256,
            )
        )
        or hashlib.sha256(signed_budget).hexdigest() != expected_envelope_sha256
    ):
        raise RuntimeError("actual signed subset budget and frozen identities required")
    payload = dict(_attest(authority, "subset_run_budget", signed_budget))
    if (
        set(payload) != set(_FIXED) | _VARIABLE
        or any(
            type(payload.get(key)) is not type(value) or payload[key] != value
            for key, value in _FIXED.items()
        )
        or payload["run_id"] != run_id
        or payload["epoch"] != epoch
        or type(payload["task_ids"]) is not list
        or any(type(value) is not str for value in payload["task_ids"])
        or tuple(payload["task_ids"]) != OFFICIAL_SUBSET_TASK_IDS
        or payload["campaign_policy_sha256"] != campaign_policy_sha256
        or payload["model_policy_sha256"] != model_policy_sha256
        or payload["metering_policy_sha256"] != metering_policy_sha256
        or any(
            type(payload[key]) is not int or not 0 < payload[key] <= _MAX_EXACT_INTEGER
            for key in ("max_elapsed_seconds", "max_spend_units")
        )
    ):
        raise RuntimeError("signed subset budget scope, limits or metering binding invalid")
    canonical = _json_bytes(payload)
    return VerifiedSubsetBudget(
        run_id=run_id,
        epoch=epoch,
        campaign_policy_sha256=campaign_policy_sha256,
        model_policy_sha256=model_policy_sha256,
        metering_policy_sha256=payload["metering_policy_sha256"],
        max_elapsed_seconds=payload["max_elapsed_seconds"],
        max_spend_units=payload["max_spend_units"],
        signed_envelope=signed_budget,
        envelope_sha256=expected_envelope_sha256,
        payload_json=canonical,
        payload_sha256=hashlib.sha256(canonical).hexdigest(),
    )
