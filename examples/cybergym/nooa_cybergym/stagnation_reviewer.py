# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tool-free alternate-model review for bounded stagnation snapshots."""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator

from nooa import Agent, strategy
from nooa.config.strategy_config import PredictConfig
from nooa.strategies import PredictStrategy

try:
    from .stagnation import (
        MAX_AGGREGATE_CATEGORIES,
        MAX_AGGREGATE_LABEL_CHARS,
        MAX_RECENT_HYPOTHESES,
        MAX_RECENT_HYPOTHESIS_CHARS,
        StagnationSnapshot,
    )
except ImportError:  # pragma: no cover
    from stagnation import (  # type: ignore[no-redef]
        MAX_AGGREGATE_CATEGORIES,
        MAX_AGGREGATE_LABEL_CHARS,
        MAX_RECENT_HYPOTHESES,
        MAX_RECENT_HYPOTHESIS_CHARS,
        StagnationSnapshot,
    )

MAX_ADVICE_CHARS = 4096
MAX_TASK_DESCRIPTION_CHARS = 8192

BoundedLabel = Annotated[str, Field(min_length=1, max_length=MAX_AGGREGATE_LABEL_CHARS)]
BoundedCount = Annotated[int, Field(ge=0)]
BoundedCountPairs = Annotated[
    tuple[tuple[BoundedLabel, BoundedCount], ...],
    Field(max_length=MAX_AGGREGATE_CATEGORIES),
]
BoundedHypothesis = Annotated[str, Field(max_length=MAX_RECENT_HYPOTHESIS_CHARS)]
BoundedHypotheses = Annotated[
    tuple[BoundedHypothesis, ...],
    Field(max_length=MAX_RECENT_HYPOTHESES),
]


class StagnationReviewInput(BaseModel):
    """Structurally bounded immutable data exposed to the reviewer."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    submission_count: int = Field(ge=0)
    family_count: int = Field(ge=0)
    status_counts: BoundedCountPairs
    source_model_counts: BoundedCountPairs
    recent_hypotheses: BoundedHypotheses
    task_description: str = Field(max_length=MAX_TASK_DESCRIPTION_CHARS)


def build_stagnation_review_input(
    *, snapshot: StagnationSnapshot, task_description: str
) -> StagnationReviewInput:
    """Convert the safe snapshot and description into the validating contract."""
    bounded_description = " ".join(task_description.split())[:MAX_TASK_DESCRIPTION_CHARS]
    return StagnationReviewInput(
        submission_count=snapshot.submission_count,
        family_count=snapshot.family_count,
        status_counts=tuple(snapshot.status_counts.items()),
        source_model_counts=tuple(snapshot.source_model_counts.items()),
        recent_hypotheses=snapshot.recent_hypotheses,
        task_description=bounded_description,
    )


class StagnationAdvice(BaseModel):
    """Bounded alternate-model guidance for continued exploration."""

    model_config = ConfigDict(extra="forbid")
    guidance: str = Field(min_length=1, max_length=MAX_ADVICE_CHARS)
    reasoning: str = Field(min_length=1, max_length=MAX_ADVICE_CHARS)

    @field_validator("guidance", "reasoning")
    @classmethod
    def strip_and_require_content(cls, value: str) -> str:
        """Normalize reviewer prose and reject responses without content."""
        stripped = value.strip()
        if not stripped:
            raise ValueError("reviewer advice must contain non-whitespace content")
        return stripped


class StagnationReviewer(Agent, context={"state": None}):
    """Single-purpose reviewer with no worker capabilities."""

    @strategy(PredictStrategy(config=PredictConfig(max_retries=1)))
    async def review(self, review_input: StagnationReviewInput) -> StagnationAdvice:
        """Recommend one concrete next direction from the bounded review input.

        A vulnerable-build crash is candidate evidence; hidden fixed-build evidence
        is unavailable during the run. Never claim that the task is solved, that a
        crash is patch-specific, or that one family is the only reachable bug.
        Use the task description to rank hypotheses by patch-specific alignment,
        identify repetitive generic sanitizer crashes, and direct the worker toward
        plausible code paths or input structures that can produce a distinct family.
        Return concise guidance and reasoning grounded only in the provided input.
        """
        ...
