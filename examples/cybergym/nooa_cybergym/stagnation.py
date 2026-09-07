# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Deterministic, bounded state for optional CyberGym stagnation escalation."""

from __future__ import annotations

import os
from collections import Counter, deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Protocol

ESCALATION_MODEL_ENV = "NOOA_CYBERGYM_ESCALATION_MODEL"
ESCALATION_TRIGGER_AGE_SEC_ENV = "NOOA_CYBERGYM_ESCALATION_TRIGGER_AGE_SEC"
ESCALATION_QUIET_WINDOW_SEC_ENV = "NOOA_CYBERGYM_ESCALATION_QUIET_WINDOW_SEC"
ESCALATION_MIN_SUBMISSIONS_ENV = "NOOA_CYBERGYM_ESCALATION_MIN_SUBMISSIONS"
ESCALATION_REVIEWER_TIMEOUT_SEC_ENV = "NOOA_CYBERGYM_ESCALATION_REVIEWER_TIMEOUT_SEC"
ESCALATION_REVIEWER_MAX_OUTPUT_TOKENS_ENV = "NOOA_CYBERGYM_ESCALATION_REVIEWER_MAX_OUTPUT_TOKENS"
ESCALATION_RECOVERY_WINDOW_SEC_ENV = "NOOA_CYBERGYM_ESCALATION_RECOVERY_WINDOW_SEC"

DEFAULT_ESCALATION_MODEL = ""
DEFAULT_ESCALATION_TRIGGER_AGE_SEC = 7200
DEFAULT_ESCALATION_QUIET_WINDOW_SEC = 1800
DEFAULT_ESCALATION_MIN_SUBMISSIONS = 20
DEFAULT_ESCALATION_REVIEWER_TIMEOUT_SEC = 900
DEFAULT_ESCALATION_REVIEWER_MAX_OUTPUT_TOKENS = 32768
DEFAULT_ESCALATION_RECOVERY_WINDOW_SEC = 3600

MAX_RECENT_HYPOTHESES = 12
MAX_RECENT_HYPOTHESIS_CHARS = 512
MAX_AGGREGATE_LABEL_CHARS = 128
MAX_AGGREGATE_CATEGORIES = 16
UNSPECIFIED_SOURCE_MODEL = "<unspecified>"
OTHER_AGGREGATE_LABEL = "<other>"


@dataclass(frozen=True, slots=True)
class StagnationConfig:
    """Effective opt-in escalation settings."""

    model: str
    trigger_age_sec: int
    quiet_window_sec: int
    minimum_submissions: int
    reviewer_timeout_sec: int
    reviewer_max_output_tokens: int
    recovery_window_sec: int

    @property
    def enabled(self) -> bool:
        """Escalation is enabled only when an alternate model is configured."""
        return bool(self.model)

    @classmethod
    def from_environment(cls, env: Mapping[str, str] | None = None) -> StagnationConfig:
        """Load deterministic values from an explicit mapping or the process environment."""
        source = os.environ if env is None else env
        return cls(
            model=source.get(ESCALATION_MODEL_ENV, DEFAULT_ESCALATION_MODEL).strip(),
            trigger_age_sec=int(
                source.get(
                    ESCALATION_TRIGGER_AGE_SEC_ENV,
                    str(DEFAULT_ESCALATION_TRIGGER_AGE_SEC),
                )
            ),
            quiet_window_sec=int(
                source.get(
                    ESCALATION_QUIET_WINDOW_SEC_ENV,
                    str(DEFAULT_ESCALATION_QUIET_WINDOW_SEC),
                )
            ),
            minimum_submissions=int(
                source.get(
                    ESCALATION_MIN_SUBMISSIONS_ENV,
                    str(DEFAULT_ESCALATION_MIN_SUBMISSIONS),
                )
            ),
            reviewer_timeout_sec=int(
                source.get(
                    ESCALATION_REVIEWER_TIMEOUT_SEC_ENV,
                    str(DEFAULT_ESCALATION_REVIEWER_TIMEOUT_SEC),
                )
            ),
            reviewer_max_output_tokens=int(
                source.get(
                    ESCALATION_REVIEWER_MAX_OUTPUT_TOKENS_ENV,
                    str(DEFAULT_ESCALATION_REVIEWER_MAX_OUTPUT_TOKENS),
                )
            ),
            recovery_window_sec=int(
                source.get(
                    ESCALATION_RECOVERY_WINDOW_SEC_ENV,
                    str(DEFAULT_ESCALATION_RECOVERY_WINDOW_SEC),
                )
            ),
        )


STAGNATION_CONFIG = StagnationConfig.from_environment()
ESCALATION_MODEL = STAGNATION_CONFIG.model
ESCALATION_TRIGGER_AGE_SEC = STAGNATION_CONFIG.trigger_age_sec
ESCALATION_QUIET_WINDOW_SEC = STAGNATION_CONFIG.quiet_window_sec
ESCALATION_MIN_SUBMISSIONS = STAGNATION_CONFIG.minimum_submissions
ESCALATION_REVIEWER_TIMEOUT_SEC = STAGNATION_CONFIG.reviewer_timeout_sec
ESCALATION_REVIEWER_MAX_OUTPUT_TOKENS = STAGNATION_CONFIG.reviewer_max_output_tokens
ESCALATION_RECOVERY_WINDOW_SEC = STAGNATION_CONFIG.recovery_window_sec


@dataclass(slots=True)
class StagnationState:
    """Monotonic progress state used to decide whether escalation may be claimed."""

    started_at: float
    last_new_family_at: float | None = None
    submission_count: int = 0
    family_count: int = 0
    escalation_attempted: bool = False
    escalation_claimed_at: float | None = None
    family_count_at_escalation: int | None = None

    def __post_init__(self) -> None:
        if self.last_new_family_at is None:
            self.last_new_family_at = self.started_at

    def observe(self, *, now: float, submission_count: int, family_count: int) -> None:
        """Record aggregate progress and reset quiet time only for a new family."""
        assert self.last_new_family_at is not None
        if family_count > self.family_count:
            self.last_new_family_at = max(self.last_new_family_at, now)
        self.submission_count = max(self.submission_count, submission_count)
        self.family_count = max(self.family_count, family_count)

    def elapsed_sec(self, *, now: float) -> float:
        """Return deterministic elapsed monotonic time."""
        return now - self.started_at

    def quiet_sec(self, *, now: float) -> float:
        """Return time since the most recent new verified family."""
        assert self.last_new_family_at is not None
        return now - self.last_new_family_at

    def should_escalate(self, *, now: float, config: StagnationConfig) -> bool:
        """Return whether every inclusive escalation threshold is satisfied."""
        return (
            config.enabled
            and not self.escalation_attempted
            and self.elapsed_sec(now=now) >= config.trigger_age_sec
            and self.quiet_sec(now=now) >= config.quiet_window_sec
            and self.submission_count >= config.minimum_submissions
        )

    def claim_escalation(self, *, now: float, config: StagnationConfig) -> bool:
        """Atomically mark a single eligible attempt before later dispatch."""
        if not self.should_escalate(now=now, config=config):
            return False
        self.escalation_attempted = True
        self.escalation_claimed_at = now
        self.family_count_at_escalation = self.family_count
        return True

    def recovery_expired_without_progress(self, *, now: float, config: StagnationConfig) -> bool:
        """Return whether the claimed recovery window ended without a new family."""
        if self.escalation_claimed_at is None or self.family_count_at_escalation is None:
            return False
        return (
            self.family_count <= self.family_count_at_escalation
            and now >= self.escalation_claimed_at + config.recovery_window_sec
        )

    def next_wakeup_at(self, *, config: StagnationConfig) -> float | None:
        """Return the next monotonic deadline needed by enabled orchestration."""
        if not config.enabled:
            return None
        if self.escalation_claimed_at is not None:
            assert self.family_count_at_escalation is not None
            if self.family_count > self.family_count_at_escalation:
                return None
            return self.escalation_claimed_at + config.recovery_window_sec
        assert self.last_new_family_at is not None
        if self.submission_count < config.minimum_submissions:
            return None
        return max(
            self.started_at + config.trigger_age_sec,
            self.last_new_family_at + config.quiet_window_sec,
        )


class SnapshotSubmission(Protocol):
    """The only submission fields permitted in an escalation snapshot."""

    status: str
    source_model: str | None
    hypothesis: str


@dataclass(frozen=True, slots=True)
class StagnationSnapshot:
    """Bounded, verifier-free aggregate input for a future reviewer."""

    submission_count: int
    family_count: int
    status_counts: dict[str, int]
    source_model_counts: dict[str, int]
    recent_hypotheses: tuple[str, ...]


def _normalize_hypothesis(value: str) -> str:
    return " ".join(value.split())[:MAX_RECENT_HYPOTHESIS_CHARS]


def _normalize_aggregate_label(value: str | None) -> str:
    normalized = " ".join((value or "").split())[:MAX_AGGREGATE_LABEL_CHARS]
    return normalized or UNSPECIFIED_SOURCE_MODEL


def _bounded_counts(counts: Mapping[str, int]) -> dict[str, int]:
    sorted_items = sorted(counts.items())
    if len(sorted_items) <= MAX_AGGREGATE_CATEGORIES:
        return dict(sorted_items)

    first_categories = dict(sorted_items[:MAX_AGGREGATE_CATEGORIES])
    retained_count = (
        MAX_AGGREGATE_CATEGORIES
        if OTHER_AGGREGATE_LABEL in first_categories
        else MAX_AGGREGATE_CATEGORIES - 1
    )
    retained = dict(sorted_items[:retained_count])
    overflow_count = sum(count for _label, count in sorted_items[retained_count:])
    retained[OTHER_AGGREGATE_LABEL] = retained.get(OTHER_AGGREGATE_LABEL, 0) + overflow_count
    return dict(sorted(retained.items()))


def build_stagnation_snapshot(
    submissions: Iterable[SnapshotSubmission], *, family_count: int
) -> StagnationSnapshot:
    """Aggregate allowed fields without reading candidate or verifier details."""
    submission_count = 0
    status_counts: Counter[str] = Counter()
    source_model_counts: Counter[str] = Counter()
    recent_hypotheses: deque[str] = deque(maxlen=MAX_RECENT_HYPOTHESES)

    for submission in submissions:
        submission_count += 1
        status_counts[_normalize_aggregate_label(submission.status)] += 1
        source_model_counts[_normalize_aggregate_label(submission.source_model)] += 1
        recent_hypotheses.append(_normalize_hypothesis(submission.hypothesis))

    return StagnationSnapshot(
        submission_count=submission_count,
        family_count=family_count,
        status_counts=_bounded_counts(status_counts),
        source_model_counts=_bounded_counts(source_model_counts),
        recent_hypotheses=tuple(recent_hypotheses),
    )
