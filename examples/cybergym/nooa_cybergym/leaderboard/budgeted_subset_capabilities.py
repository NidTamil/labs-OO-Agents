# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Bind capability authority to a live, budgeted subset preparation.

This adapter consumes actual signed state and its independent raw readiness
verification. It creates no launch decision, registry approval or evidence.
Historical full-cohort and practice admission retain their existing loaders.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field

from .budgeted_subset_admission import BudgetedSubsetState
from .capabilities import CapabilityRegistry, Status
from .capability_runtime import SYNTHETIC_SCOPE
from .run_resource_budget import RunResourceBudget
from .subset_role_authority import SubsetRoleAuthority

_IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ATTEMPT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_PHASES = frozenset({"observe_preparing", "observe_prepared", "observe_started"})


@dataclass(frozen=True, slots=True)
class BudgetedSubsetCapabilityAdmission:
    run_id: str
    epoch: str
    task_id: str
    preparation_id: str
    cohort_sha256: str
    admission_sha256: str
    budget_sha256: str
    registry_sha256: str
    image_id: str
    _state: BudgetedSubsetState = field(repr=False, compare=False)

    def verify_current(
        self, *, task_id: str, registry: CapabilityRegistry, observed_image_id: str
    ) -> None:
        if task_id != self.task_id or observed_image_id != self.image_id:
            raise RuntimeError("subset capability task or image differs")
        refreshed = verify_budgeted_subset_capability_admission(
            state=self._state,
            task_id=task_id,
            registry=registry,
            observed_image_id=observed_image_id,
        )
        if refreshed != self:
            raise RuntimeError("subset capability admission or preparation changed")

    def verify_runtime_current(
        self,
        *,
        task_id: str,
        attempt_id: str,
        registry: CapabilityRegistry,
        observed_image_id: str,
    ) -> None:
        """Bind a runtime made during preparation to the eventual started attempt."""
        if type(attempt_id) is not str or _ATTEMPT.fullmatch(attempt_id) is None:
            raise RuntimeError("explicit subset runtime attempt required")
        self.verify_current(
            task_id=task_id,
            registry=registry,
            observed_image_id=observed_image_id,
        )
        action = self._state.next_action()
        if action.task_id != task_id or action.kind not in _PHASES:
            raise RuntimeError("subset runtime task is no longer active")
        if action.kind == "observe_started":
            start = self._state.started_binding(task_id)
            if start["attempt_id"] != attempt_id:
                raise RuntimeError("subset runtime attempt differs from signed start")
        self._state.resource_budget.check_active()


def verify_budgeted_subset_capability_admission(
    *,
    state: BudgetedSubsetState,
    task_id: str,
    registry: CapabilityRegistry,
    observed_image_id: str,
) -> BudgetedSubsetCapabilityAdmission:
    """Require the exact approved subset, raw readiness and live aggregate budget."""
    if type(state) is not BudgetedSubsetState or type(registry) is not CapabilityRegistry:
        raise TypeError("exact budgeted subset state and capability registry required")
    if type(state.authority) is not SubsetRoleAuthority:
        raise TypeError("separate pinned subset approval/runtime/evaluator roles required")
    if type(state.resource_budget) is not RunResourceBudget:
        raise TypeError("operational subset resource ledger required")
    if type(observed_image_id) is not str or _IMAGE.fullmatch(observed_image_id) is None:
        raise ValueError("immutable observed subset image required")
    state.resource_budget.check_active()
    # next_action replays signed admission, complete raw readiness and all
    # lifecycle events. An unsigned ready flag or a report summary cannot do so.
    action = state.next_action()
    if action.task_id != task_id or action.kind not in _PHASES:
        raise RuntimeError("subset task differs from its committed preparation")
    preparation = state.preparation_binding(task_id)
    harness = state.authority.attest_signed("harness_lock", state.signed_freeze)
    certified = state.authority.attest_takeover_certification(state.signed_certification)
    if not isinstance(harness, Mapping) or not isinstance(certified, Mapping):
        raise RuntimeError("signed subset capability authority unavailable")
    frozen = certified.get("frozen_hashes")
    if (
        not isinstance(frozen, Mapping)
        or frozen.get("image_sha256") != observed_image_id[7:]
        or harness.get("image_sha256") != observed_image_id[7:]
    ):
        raise RuntimeError("subset image differs from signed freeze and certification")
    digest = registry.digest
    if (
        harness.get("capability_registry_sha256") != digest
        or certified.get("capability_registry_sha256") != digest
    ):
        raise RuntimeError("subset registry differs from signed freeze and certification")
    if any(SYNTHETIC_SCOPE in entry.evidence_refs for entry in registry.entries):
        raise RuntimeError("synthetic-only capability cannot enter budgeted subset")
    approved_ids = sorted(
        entry.capability_id for entry in registry.entries if entry.status is Status.APPROVED
    )
    if (
        len(approved_ids) != 35
        or certified.get("capability_coverage") != "all_enabled_exercised"
        or certified.get("enabled_capability_ids") != approved_ids
        or certified.get("required_approved_capability_ids") != approved_ids
    ):
        raise RuntimeError("signed live capability coverage differs from subset registry")
    # Recheck after evidence reads; a concurrent stop or transition cannot grant
    # fresh permission using the pre-read phase. Tool dispatch checks again.
    state.resource_budget.check_active()
    if state.next_action() != action or state.preparation_binding(task_id) != preparation:
        raise RuntimeError("subset preparation changed while verifying capabilities")
    return BudgetedSubsetCapabilityAdmission(
        state.run_id,
        state.epoch,
        task_id,
        preparation["preparation_id"],
        state.preview.cohort_sha256,
        state.preview.admission_sha256,
        state.preview.budget.envelope_sha256,
        digest,
        observed_image_id,
        state,
    )
