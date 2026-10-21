# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Inert cleanup-time arithmetic for a future budgeted subset phase.

Inputs are caller-supplied claims, not verified calibration, clock, source or
host evidence. A production boundary must independently establish the finished
source, host profile, calibration provenance, boot/clock authority and current
remaining time. This module reads no clock or store and grants no permission to
stage, open UI, Send, dispatch, stop or skip already-owned cleanup.

The phase table names conservative *possible* owned cleanup after each new
effect. In particular preparation may create a native container, so its reap
time is included before preparation. Bounds must be independently calibrated
for the finished source and host profile; no operational duration is set here.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_NS = 2**63 - 1


class CleanupReserveError(ValueError):
    """A claimed reserve input is incomplete, stale, mismatched or unbounded."""


class CleanupObligation(StrEnum):
    """Named possible ownership; a runtime still has to prove actual closure."""

    MANAGER_CGROUP_STOP = "manager_cgroup_stop_and_empty"
    STAGED_MATERIAL_CLEANUP = "staging_processes_cache_and_material_cleanup"
    NATIVE_CONTAINER_REAP = "native_container_network_and_relay_reap"
    WINDOWS_UI_CLEANUP = "windows_ui_job_and_process_cleanup"
    SSH_TUNNEL_CLOSE = "owned_ssh_tunnel_close"
    REMOTE_SESSION_CLOSE = "owned_remote_session_close"
    PROVIDER_WRITER_DRAIN = "provider_and_tool_writer_drain"
    ORACLE_CLEANUP = "official_oracle_container_and_snapshot_cleanup"
    POST_ORACLE_WRITER_DRAIN = "post_oracle_writer_drain"
    STARTED_TERMINAL_PUBLICATION = "authentic_signed_started_terminal_publication"
    ACCOUNTING_QUIESCENCE = "accounting_seal_and_signed_quiescence"


class CleanupPhase(StrEnum):
    """Boundary before a new effect; this enum has no cleanup phase."""

    BEFORE_PREPARATION = "before_preparation"
    BEFORE_UI_OPEN = "before_ui_open"
    BEFORE_SEND = "before_send"


_PREPARATION = (
    CleanupObligation.MANAGER_CGROUP_STOP,
    CleanupObligation.STAGED_MATERIAL_CLEANUP,
    CleanupObligation.NATIVE_CONTAINER_REAP,
    CleanupObligation.ACCOUNTING_QUIESCENCE,
)
_UI_OPEN = (
    _PREPARATION[:-1]
    + (
        CleanupObligation.WINDOWS_UI_CLEANUP,
        CleanupObligation.SSH_TUNNEL_CLOSE,
        CleanupObligation.REMOTE_SESSION_CLOSE,
        CleanupObligation.STARTED_TERMINAL_PUBLICATION,
    )
    + _PREPARATION[-1:]
)
_SEND = (
    _UI_OPEN[:-1]
    + (
        CleanupObligation.PROVIDER_WRITER_DRAIN,
        CleanupObligation.ORACLE_CLEANUP,
        CleanupObligation.POST_ORACLE_WRITER_DRAIN,
    )
    + _UI_OPEN[-1:]
)

PHASE_OBLIGATIONS: Mapping[CleanupPhase, tuple[CleanupObligation, ...]] = MappingProxyType(
    {
        CleanupPhase.BEFORE_PREPARATION: _PREPARATION,
        CleanupPhase.BEFORE_UI_OPEN: _UI_OPEN,
        CleanupPhase.BEFORE_SEND: _SEND,
    }
)


@dataclass(frozen=True, slots=True)
class CleanupBound:
    obligation: CleanupObligation
    upper_ns: int


@dataclass(frozen=True, slots=True)
class CleanupCalibration:
    """Claimed independent upper bounds and margin; provenance is external."""

    source_sha256: str
    host_profile_sha256: str
    calibration_sha256: str
    clock_domain_sha256: str
    valid_from_ns: int
    expires_at_ns: int
    bounds: tuple[CleanupBound, ...]
    margin_ns: int


@dataclass(frozen=True, slots=True)
class RemainingTimeObservation:
    """Caller-supplied, unverified remaining time in a claimed clock domain."""

    source_sha256: str
    host_profile_sha256: str
    clock_domain_sha256: str
    remaining_ns: int
    sampled_at_ns: int
    expires_at_ns: int


@dataclass(frozen=True, slots=True)
class ExpectedReservePins:
    """Independently supplied expected identities; equality is not attestation."""

    source_sha256: str
    host_profile_sha256: str
    calibration_sha256: str
    clock_domain_sha256: str


@dataclass(frozen=True, slots=True)
class CleanupReserveComparison:
    """Arithmetic facts only; no field authorizes an effect or gates cleanup."""

    phase: CleanupPhase
    obligations: tuple[CleanupObligation, ...]
    required_ns: int
    effective_remaining_ns: int
    difference_ns: int


def _ns(value: object, *, positive: bool = False) -> int:
    if type(value) is not int or value < (1 if positive else 0) or value > _MAX_NS:
        raise CleanupReserveError("bounded nonnegative integer nanoseconds required")
    return value


def _pin(value: object) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise CleanupReserveError("exact SHA-256 identity required")
    return value


def _sum_ns(values: tuple[int, ...]) -> int:
    total = 0
    for value in values:
        total += value
        if total > _MAX_NS:
            raise CleanupReserveError("cleanup reserve overflows supported nanoseconds")
    return total


def _calibration_digest(calibration: CleanupCalibration) -> str:
    payload = {
        "domain": "budgeted_subset_cleanup_reserve.calibration.v1",
        "source_sha256": calibration.source_sha256,
        "host_profile_sha256": calibration.host_profile_sha256,
        "clock_domain_sha256": calibration.clock_domain_sha256,
        "valid_from_ns": calibration.valid_from_ns,
        "expires_at_ns": calibration.expires_at_ns,
        "bounds": [
            {"obligation": bound.obligation.value, "upper_ns": bound.upper_ns}
            for bound in calibration.bounds
        ],
        "margin_ns": calibration.margin_ns,
    }
    raw = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def assess_cleanup_reserve(
    phase: CleanupPhase,
    calibration: CleanupCalibration,
    remaining: RemainingTimeObservation,
    *,
    expected: ExpectedReservePins,
    now_ns: int,
) -> CleanupReserveComparison:
    """Compare declared cleanup bounds against an aged remaining-time claim.

    All values, including ``now_ns``, need an independently trusted producer.
    Invoke only before a new phase. Already-owned cleanup continues regardless
    of this arithmetic result or of missing/stale observations.
    """
    if (
        type(phase) is not CleanupPhase
        or type(calibration) is not CleanupCalibration
        or type(remaining) is not RemainingTimeObservation
        or type(expected) is not ExpectedReservePins
    ):
        raise CleanupReserveError("typed phase, calibration, observation and pins required")

    now = _ns(now_ns)
    for name in (
        "source_sha256",
        "host_profile_sha256",
        "calibration_sha256",
        "clock_domain_sha256",
    ):
        _pin(getattr(expected, name))
        if _pin(getattr(calibration, name)) != getattr(expected, name):
            raise CleanupReserveError("calibration identity differs from independent pin")
    for name in ("source_sha256", "host_profile_sha256", "clock_domain_sha256"):
        if _pin(getattr(remaining, name)) != getattr(expected, name):
            raise CleanupReserveError("remaining-time identity differs from independent pin")

    valid_from = _ns(calibration.valid_from_ns)
    calibration_expiry = _ns(calibration.expires_at_ns)
    sampled_at = _ns(remaining.sampled_at_ns)
    observation_expiry = _ns(remaining.expires_at_ns)
    claimed_remaining = _ns(remaining.remaining_ns)
    if not valid_from <= now < calibration_expiry or not sampled_at <= now < observation_expiry:
        raise CleanupReserveError("future or stale cleanup calibration/time observation")

    if type(calibration.bounds) is not tuple or tuple(
        bound.obligation
        if type(bound) is CleanupBound and type(bound.obligation) is CleanupObligation
        else None
        for bound in calibration.bounds
    ) != tuple(CleanupObligation):
        raise CleanupReserveError("exact ordered cleanup-obligation bounds required")
    bound_ns = tuple(_ns(bound.upper_ns, positive=True) for bound in calibration.bounds)
    margin = _ns(calibration.margin_ns, positive=True)
    _sum_ns(bound_ns + (margin,))
    if _calibration_digest(calibration) != calibration.calibration_sha256:
        raise CleanupReserveError("calibration contents differ from independent pin")
    selected = PHASE_OBLIGATIONS[phase]
    by_obligation = dict(zip(CleanupObligation, bound_ns, strict=True))
    required = _sum_ns(tuple(by_obligation[item] for item in selected) + (margin,))
    effective_remaining = max(0, claimed_remaining - (now - sampled_at))
    return CleanupReserveComparison(
        phase=phase,
        obligations=selected,
        required_ns=required,
        effective_remaining_ns=effective_remaining,
        difference_ns=effective_remaining - required,
    )
