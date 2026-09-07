# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Inert unit tests for SunChaser v2 stagnation detection."""

from dataclasses import asdict
from types import SimpleNamespace

from examples.cybergym.nooa_cybergym.stagnation import (
    MAX_AGGREGATE_CATEGORIES,
    MAX_AGGREGATE_LABEL_CHARS,
    MAX_RECENT_HYPOTHESES,
    MAX_RECENT_HYPOTHESIS_CHARS,
    OTHER_AGGREGATE_LABEL,
    ReviewEvent,
    ReviewSnapshot,
    StagnationConfig,
    StagnationState,
    build_stagnation_snapshot,
)


def _config(**overrides) -> StagnationConfig:
    values = {
        "model": "alternate-reviewer",
        "trigger_age_sec": 100,
        "quiet_window_sec": 20,
        "minimum_submissions": 3,
        "reviewer_timeout_sec": 900,
        "reviewer_max_output_tokens": 32768,
        "recovery_window_sec": 3600,
    }
    values.update(overrides)
    return StagnationConfig(**values)


def test_stagnation_config_defaults_are_disabled_and_behavior_preserving():
    config = StagnationConfig.from_environment({})

    assert config == StagnationConfig(
        model="",
        trigger_age_sec=7200,
        quiet_window_sec=1800,
        minimum_submissions=20,
        reviewer_timeout_sec=900,
        reviewer_max_output_tokens=32768,
        recovery_window_sec=3600,
        consecutive_no_growth_reviews=3,
    )
    assert config.enabled is False


def test_stagnation_config_reads_all_opt_in_environment_values():
    config = StagnationConfig.from_environment(
        {
            "NOOA_CYBERGYM_ESCALATION_MODEL": "  reviewer-model  ",
            "NOOA_CYBERGYM_ESCALATION_TRIGGER_AGE_SEC": "101",
            "NOOA_CYBERGYM_ESCALATION_QUIET_WINDOW_SEC": "21",
            "NOOA_CYBERGYM_ESCALATION_MIN_SUBMISSIONS": "4",
            "NOOA_CYBERGYM_ESCALATION_REVIEWER_TIMEOUT_SEC": "901",
            "NOOA_CYBERGYM_ESCALATION_REVIEWER_MAX_OUTPUT_TOKENS": "32769",
            "NOOA_CYBERGYM_ESCALATION_RECOVERY_WINDOW_SEC": "3601",
        }
    )

    assert config == StagnationConfig(
        model="reviewer-model",
        trigger_age_sec=101,
        quiet_window_sec=21,
        minimum_submissions=4,
        reviewer_timeout_sec=901,
        reviewer_max_output_tokens=32769,
        recovery_window_sec=3601,
        consecutive_no_growth_reviews=3,
    )
    assert config.enabled is True


def test_stagnation_thresholds_are_inclusive_at_the_exact_boundaries():
    state = StagnationState(started_at=10)
    state.observe(now=89, submission_count=3, family_count=0)

    assert state.should_escalate(now=109, config=_config()) is False
    assert state.should_escalate(now=110, config=_config(minimum_submissions=4)) is False
    assert state.should_escalate(now=110, config=_config()) is True
    assert state.elapsed_sec(now=110) == 100
    assert state.quiet_sec(now=110) == 100


def test_new_family_progress_resets_only_the_quiet_window():
    state = StagnationState(started_at=0)
    state.observe(now=7100, submission_count=20, family_count=1)

    assert state.started_at == 0
    assert state.last_new_family_at == 7100
    assert state.submission_count == 20
    assert state.family_count == 1
    assert (
        state.should_escalate(
            now=7200,
            config=StagnationConfig.from_environment(
                {
                    "NOOA_CYBERGYM_ESCALATION_MODEL": "reviewer",
                }
            ),
        )
        is False
    )
    assert (
        state.should_escalate(
            now=8900,
            config=StagnationConfig.from_environment(
                {
                    "NOOA_CYBERGYM_ESCALATION_MODEL": "reviewer",
                }
            ),
        )
        is True
    )

    state.observe(now=9000, submission_count=21, family_count=1)
    assert state.last_new_family_at == 7100


def test_stale_lower_counts_cannot_create_false_progress_when_counts_reappear():
    state = StagnationState(started_at=0)
    state.observe(now=100, submission_count=20, family_count=2)

    state.observe(now=200, submission_count=5, family_count=1)
    state.observe(now=210, submission_count=20, family_count=2)

    assert state.submission_count == 20
    assert state.family_count == 2
    assert state.last_new_family_at == 100


def test_duplicate_and_out_of_order_observations_preserve_monotonic_state():
    state = StagnationState(started_at=0)
    state.observe(now=100, submission_count=20, family_count=2)

    state.observe(now=100, submission_count=20, family_count=2)
    state.observe(now=90, submission_count=25, family_count=3)
    state.observe(now=80, submission_count=24, family_count=2)

    assert state.submission_count == 25
    assert state.family_count == 3
    assert state.last_new_family_at == 100


def test_claim_escalation_marks_one_shot_before_dispatch():
    state = StagnationState(started_at=0)
    state.observe(now=100, submission_count=3, family_count=0)

    assert state.claim_escalation(now=99, config=_config()) is False
    assert state.escalation_attempted is False
    assert state.claim_escalation(now=100, config=_config()) is True
    assert state.escalation_attempted is True
    assert state.escalation_claimed_at == 100
    assert state.family_count_at_escalation == 0
    assert state.claim_escalation(now=200, config=_config()) is False


def test_next_wakeup_deadline_reaches_trigger_then_recovery_without_wall_clock_sleep():
    state = StagnationState(started_at=10)
    config = _config(trigger_age_sec=100, quiet_window_sec=20, recovery_window_sec=40)
    state.observe(now=50, submission_count=3, family_count=1)

    assert state.next_wakeup_at(config=config) == 110
    assert state.claim_escalation(now=110, config=config) is True
    assert state.next_wakeup_at(config=config) == 150


def test_recovery_expires_at_exact_deadline_without_a_new_family():
    state = StagnationState(started_at=0)
    config = _config(recovery_window_sec=40)
    state.observe(now=0, submission_count=3, family_count=1)
    assert state.claim_escalation(now=100, config=config) is True

    assert state.recovery_expired_without_progress(now=139.999, config=config) is False
    assert state.recovery_expired_without_progress(now=140, config=config) is True


def test_new_verified_family_cancels_recovery_termination():
    state = StagnationState(started_at=0)
    config = _config(recovery_window_sec=40)
    state.observe(now=0, submission_count=3, family_count=1)
    assert state.claim_escalation(now=100, config=config) is True

    state.observe(now=120, submission_count=4, family_count=2)

    assert state.recovery_expired_without_progress(now=1_000, config=config) is False
    assert state.next_wakeup_at(config=config) is None


def test_disabled_configuration_never_claims_escalation():
    state = StagnationState(started_at=0)
    state.observe(now=10_000, submission_count=100, family_count=5)

    assert state.claim_escalation(now=20_000, config=StagnationConfig.from_environment({})) is False
    assert state.escalation_attempted is False


def test_first_valid_review_establishes_a_zero_count_baseline():
    state = StagnationState(started_at=0)
    state.observe(now=10, submission_count=2, family_count=1)

    snapshot = state.begin_review()

    assert snapshot == ReviewSnapshot(review_id=1, submission_count=2, family_count=1)
    assert state.complete_review(snapshot, parsed=True) == ReviewEvent(
        snapshot=snapshot,
        outcome="completed",
        consecutive_no_growth_reviews=0,
    )
    assert state.consecutive_no_growth_reviews == 0


def test_valid_unchanged_family_reviews_count_at_the_exact_plateau_threshold():
    state = StagnationState(started_at=0)
    config = _config(minimum_submissions=4, consecutive_no_growth_reviews=2)
    state.observe(now=10, submission_count=3, family_count=1)
    state.complete_review(state.begin_review(), parsed=True)

    state.observe(now=20, submission_count=4, family_count=1)
    first_no_growth = state.complete_review(state.begin_review(), parsed=True)
    assert first_no_growth.consecutive_no_growth_reviews == 1
    assert state.plateau_eligible(config=config) is False

    second_no_growth = state.complete_review(state.begin_review(), parsed=True)
    assert second_no_growth.consecutive_no_growth_reviews == 2
    assert state.plateau_eligible(config=config) is True


def test_family_growth_resets_no_growth_reviews_even_when_observed_between_reviews():
    state = StagnationState(started_at=0)
    state.observe(now=10, submission_count=2, family_count=1)
    state.complete_review(state.begin_review(), parsed=True)
    state.complete_review(state.begin_review(), parsed=True)
    assert state.consecutive_no_growth_reviews == 1

    state.observe(now=20, submission_count=3, family_count=2)
    assert state.consecutive_no_growth_reviews == 0

    event = state.complete_review(state.begin_review(), parsed=True)
    assert event.consecutive_no_growth_reviews == 0


def test_duplicate_stale_failed_and_cancelled_reviews_never_count():
    state = StagnationState(started_at=0)
    state.observe(now=10, submission_count=3, family_count=1)
    baseline = state.begin_review()
    state.complete_review(baseline, parsed=True)

    duplicate = state.complete_review(baseline, parsed=True)
    assert duplicate.outcome == "duplicate"

    failed = state.begin_review()
    assert state.complete_review(failed, parsed=False).outcome == "failed"

    cancelled = state.begin_review()
    assert state.complete_review(cancelled, parsed=True, cancelled=True).outcome == "cancelled"

    stale = state.begin_review()
    state.observe(now=20, submission_count=4, family_count=2)
    assert state.complete_review(stale, parsed=True).outcome == "stale"
    assert state.consecutive_no_growth_reviews == 0


def test_only_the_latest_review_can_complete_and_its_snapshot_is_immutable():
    state = StagnationState(started_at=0)
    state.observe(now=10, submission_count=3, family_count=1)

    first = state.begin_review()
    state.observe(now=11, submission_count=4, family_count=1)
    latest = state.begin_review()

    assert first == ReviewSnapshot(review_id=1, submission_count=3, family_count=1)
    assert latest == ReviewSnapshot(review_id=2, submission_count=4, family_count=1)
    assert state.complete_review(first, parsed=True).outcome == "stale"
    assert state.complete_review(latest, parsed=True).outcome == "completed"


def test_plateau_requires_one_family_and_minimum_submissions_but_not_age_or_quiet():
    state = StagnationState(started_at=0)
    config = _config(
        trigger_age_sec=10_000,
        quiet_window_sec=10_000,
        minimum_submissions=4,
        consecutive_no_growth_reviews=1,
    )
    state.observe(now=10, submission_count=3, family_count=1)
    state.complete_review(state.begin_review(), parsed=True)
    state.complete_review(state.begin_review(), parsed=True)

    assert state.plateau_eligible(config=config) is False
    assert state.should_escalate(now=20, config=config) is False

    state.observe(now=20, submission_count=4, family_count=1)
    assert state.plateau_eligible(config=config) is True
    assert state.escalation_reason(now=20, config=config) == "plateau"
    assert state.should_escalate(now=20, config=config) is True


def test_escalation_reason_reports_combined_plateau_and_age_predicates():
    state = StagnationState(started_at=0)
    config = _config(
        trigger_age_sec=100,
        quiet_window_sec=20,
        minimum_submissions=3,
        consecutive_no_growth_reviews=1,
    )
    state.observe(now=0, submission_count=3, family_count=1)
    state.complete_review(state.begin_review(), parsed=True)
    state.complete_review(state.begin_review(), parsed=True)

    assert state.escalation_reason(now=99, config=config) == "plateau"
    assert state.escalation_reason(now=100, config=config) == "plateau_and_age"
    assert state.claim_escalation(now=100, config=config) is True
    assert state.escalation_reason(now=100, config=config) is None
    assert state.plateau_eligible(config=config) is False


def test_snapshot_contains_only_aggregates_and_bounded_recent_hypotheses():
    submissions = []
    for index in range(15):
        submissions.append(
            SimpleNamespace(
                status="crashed" if index % 3 == 0 else "no_crash",
                source_model="model-b" if index % 2 else "model-a",
                hypothesis=f"  candidate\n {index}  " + ("x" * 700),
                original_path=f"/secret/candidate-{index}",
                submitted_path=f"/workspace/submissions/{index}",
                output_excerpt="private verifier output",
                candidate_bytes=b"private candidate bytes",
                fixed_image="private fixed image",
            )
        )

    snapshot = build_stagnation_snapshot(submissions, family_count=2)
    payload = asdict(snapshot)

    assert payload.keys() == {
        "submission_count",
        "family_count",
        "status_counts",
        "source_model_counts",
        "recent_hypotheses",
    }
    assert snapshot.submission_count == 15
    assert snapshot.family_count == 2
    assert snapshot.status_counts == {"crashed": 5, "no_crash": 10}
    assert snapshot.source_model_counts == {"model-a": 8, "model-b": 7}
    assert len(snapshot.recent_hypotheses) == MAX_RECENT_HYPOTHESES
    assert snapshot.recent_hypotheses[0].startswith("candidate 3 ")
    assert snapshot.recent_hypotheses[-1].startswith("candidate 14 ")
    assert all("\n" not in item for item in snapshot.recent_hypotheses)
    assert all(len(item) <= MAX_RECENT_HYPOTHESIS_CHARS for item in snapshot.recent_hypotheses)

    serialized = repr(payload)
    assert "/secret/" not in serialized
    assert "private verifier output" not in serialized
    assert "private candidate bytes" not in serialized
    assert "private fixed image" not in serialized


def test_snapshot_normalizes_missing_source_model_without_mutating_input():
    submission = SimpleNamespace(
        status="timeout",
        source_model=None,
        hypothesis="  one\t brief   hypothesis  ",
    )

    snapshot = build_stagnation_snapshot([submission], family_count=0)

    assert snapshot.source_model_counts == {"<unspecified>": 1}
    assert snapshot.recent_hypotheses == ("one brief hypothesis",)
    assert submission.hypothesis == "  one\t brief   hypothesis  "


def test_snapshot_bounds_attacker_controlled_aggregate_labels_and_categories():
    submissions = []
    for index in range(40):
        for duplicate in range(index % 3 + 1):
            submissions.append(
                SimpleNamespace(
                    status=f"  status-{index:02d}\n" + ("s" * 200),
                    source_model=f"  model-{39 - index:02d}\t" + ("m" * 200),
                    hypothesis=f"candidate {index}-{duplicate}",
                )
            )

    snapshot = build_stagnation_snapshot(submissions, family_count=7)

    for counts in (snapshot.status_counts, snapshot.source_model_counts):
        assert len(counts) <= MAX_AGGREGATE_CATEGORIES
        assert list(counts) == sorted(counts)
        assert OTHER_AGGREGATE_LABEL in counts
        assert all(len(label) <= MAX_AGGREGATE_LABEL_CHARS for label in counts)
        assert all("\n" not in label and "\t" not in label for label in counts)
        assert sum(counts.values()) == len(submissions)
