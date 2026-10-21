"""Synthetic arithmetic checks for the inert cleanup reserve contract."""

from dataclasses import replace

import pytest
from nooa_cybergym.leaderboard.budgeted_subset_cleanup_reserve import (
    PHASE_OBLIGATIONS,
    CleanupBound,
    CleanupCalibration,
    CleanupObligation,
    CleanupPhase,
    CleanupReserveError,
    ExpectedReservePins,
    RemainingTimeObservation,
    assess_cleanup_reserve,
)

_SOURCE = "a" * 64
_HOST = "b" * 64
_CALIBRATION = "9045015fdc3996e7ffdbcd5635390a57c37cb4d9e2cc5d00103a640d2f492cd3"
_BOOT = "d" * 64


def _inputs():
    values = (11, 13, 17, 19, 23, 29, 31, 37, 41, 47, 43)
    bounds = tuple(
        CleanupBound(obligation, upper_ns)
        for obligation, upper_ns in zip(CleanupObligation, values, strict=True)
    )
    return {
        "calibration": CleanupCalibration(
            source_sha256=_SOURCE,
            host_profile_sha256=_HOST,
            calibration_sha256=_CALIBRATION,
            clock_domain_sha256=_BOOT,
            valid_from_ns=50,
            expires_at_ns=200,
            bounds=bounds,
            margin_ns=7,
        ),
        "remaining": RemainingTimeObservation(
            source_sha256=_SOURCE,
            host_profile_sha256=_HOST,
            clock_domain_sha256=_BOOT,
            remaining_ns=300,
            sampled_at_ns=100,
            expires_at_ns=120,
        ),
        "expected": ExpectedReservePins(
            source_sha256=_SOURCE,
            host_profile_sha256=_HOST,
            calibration_sha256=_CALIBRATION,
            clock_domain_sha256=_BOOT,
        ),
        "now_ns": 110,
    }


@pytest.mark.parametrize(
    "phase,required_ns",
    [
        (CleanupPhase.BEFORE_PREPARATION, 91),
        (CleanupPhase.BEFORE_UI_OPEN, 209),
        (CleanupPhase.BEFORE_SEND, 318),
    ],
)
def test_phase_reserve_sums_each_named_obligation_and_margin(phase, required_ns):
    comparison = assess_cleanup_reserve(phase, **_inputs())
    assert comparison.phase is phase
    assert comparison.required_ns == required_ns
    assert comparison.effective_remaining_ns == 290
    assert comparison.difference_ns == 290 - required_ns
    assert not hasattr(comparison, "permitted")
    assert not hasattr(comparison, "allowed")


def test_remaining_observation_age_consumes_reserve_before_comparison():
    inputs = _inputs()
    inputs["remaining"] = replace(inputs["remaining"], remaining_ns=270)
    comparison = assess_cleanup_reserve(CleanupPhase.BEFORE_SEND, **inputs)
    assert comparison.effective_remaining_ns == 260
    assert comparison.difference_ns == -58


def test_elapsed_observation_can_exhaust_known_remaining_without_negative_time():
    inputs = _inputs()
    inputs["remaining"] = replace(inputs["remaining"], remaining_ns=5)
    comparison = assess_cleanup_reserve(CleanupPhase.BEFORE_SEND, **inputs)
    assert comparison.effective_remaining_ns == 0
    assert comparison.difference_ns == -318


def test_send_reserve_includes_authentic_started_terminal_publication_separately():
    comparison = assess_cleanup_reserve(CleanupPhase.BEFORE_SEND, **_inputs())
    assert CleanupObligation.STARTED_TERMINAL_PUBLICATION in comparison.obligations
    assert comparison.required_ns == 318


def test_ui_open_reserve_covers_started_commitment_before_send():
    comparison = assess_cleanup_reserve(CleanupPhase.BEFORE_UI_OPEN, **_inputs())
    assert CleanupObligation.STARTED_TERMINAL_PUBLICATION in comparison.obligations
    assert comparison.required_ns == 209


@pytest.mark.parametrize(
    "field", ["source_sha256", "host_profile_sha256", "calibration_sha256", "clock_domain_sha256"]
)
def test_independent_pin_mismatch_is_rejected(field):
    inputs = _inputs()
    inputs["expected"] = replace(inputs["expected"], **{field: "e" * 64})
    with pytest.raises(CleanupReserveError):
        assess_cleanup_reserve(CleanupPhase.BEFORE_SEND, **inputs)


def test_calibration_pin_rejects_changed_positive_margin_or_upper_bound():
    inputs = _inputs()
    for changed in (
        replace(inputs["calibration"], margin_ns=8),
        replace(
            inputs["calibration"],
            bounds=(replace(inputs["calibration"].bounds[0], upper_ns=12),)
            + inputs["calibration"].bounds[1:],
        ),
    ):
        with pytest.raises(CleanupReserveError):
            assess_cleanup_reserve(
                CleanupPhase.BEFORE_SEND,
                **(inputs | {"calibration": changed}),
            )


@pytest.mark.parametrize("field", ["source_sha256", "host_profile_sha256", "clock_domain_sha256"])
def test_remaining_observation_must_match_finished_source_host_and_boot(field):
    inputs = _inputs()
    inputs["remaining"] = replace(inputs["remaining"], **{field: "e" * 64})
    with pytest.raises(CleanupReserveError):
        assess_cleanup_reserve(CleanupPhase.BEFORE_SEND, **inputs)


@pytest.mark.parametrize("now_ns", [49, 120, 200])
def test_future_or_expired_calibration_and_remaining_observation_are_rejected(now_ns):
    with pytest.raises(CleanupReserveError):
        assess_cleanup_reserve(CleanupPhase.BEFORE_SEND, **(_inputs() | {"now_ns": now_ns}))


@pytest.mark.parametrize("remaining_ns", [None, -1, True, 1.0, 2**63])
def test_unknown_negative_noninteger_or_overflow_remaining_is_rejected(remaining_ns):
    inputs = _inputs()
    inputs["remaining"] = replace(inputs["remaining"], remaining_ns=remaining_ns)
    with pytest.raises(CleanupReserveError):
        assess_cleanup_reserve(CleanupPhase.BEFORE_SEND, **inputs)


@pytest.mark.parametrize("margin_ns", [None, -1, 0, True, 1.0, 2**63])
def test_missing_nonpositive_noninteger_or_overflow_margin_is_rejected(margin_ns):
    inputs = _inputs()
    inputs["calibration"] = replace(inputs["calibration"], margin_ns=margin_ns)
    with pytest.raises(CleanupReserveError):
        assess_cleanup_reserve(CleanupPhase.BEFORE_SEND, **inputs)


def test_missing_duplicate_unknown_or_reordered_bounds_are_rejected():
    inputs = _inputs()
    bounds = inputs["calibration"].bounds
    for changed in (
        bounds[:-1],
        bounds[:-1] + (bounds[0],),
        bounds[1:] + bounds[:1],
        bounds[:-1] + (CleanupBound("unknown", 43),),
    ):
        with pytest.raises(CleanupReserveError):
            assess_cleanup_reserve(
                CleanupPhase.BEFORE_SEND,
                **(inputs | {"calibration": replace(inputs["calibration"], bounds=changed)}),
            )


def test_plain_string_obligation_is_rejected_with_contract_error():
    inputs = _inputs()
    bounds = inputs["calibration"].bounds
    changed = (CleanupBound(CleanupObligation.MANAGER_CGROUP_STOP.value, 11),) + bounds[1:]
    with pytest.raises(CleanupReserveError):
        assess_cleanup_reserve(
            CleanupPhase.BEFORE_SEND,
            **(inputs | {"calibration": replace(inputs["calibration"], bounds=changed)}),
        )


def test_required_sum_overflow_is_rejected_without_python_bigint_escape():
    inputs = _inputs()
    bounds = list(inputs["calibration"].bounds)
    bounds[0] = replace(bounds[0], upper_ns=2**63 - 1)
    with pytest.raises(CleanupReserveError):
        assess_cleanup_reserve(
            CleanupPhase.BEFORE_PREPARATION,
            **(inputs | {"calibration": replace(inputs["calibration"], bounds=tuple(bounds))}),
        )


@pytest.mark.parametrize("phase", [None, "before_send", True])
def test_untyped_or_unknown_phase_is_rejected(phase):
    with pytest.raises(CleanupReserveError):
        assess_cleanup_reserve(phase, **_inputs())


def test_phase_requirements_cannot_be_mutated_between_assessments():
    with pytest.raises(TypeError):
        PHASE_OBLIGATIONS[CleanupPhase.BEFORE_SEND] = ()
    assert assess_cleanup_reserve(CleanupPhase.BEFORE_SEND, **_inputs()).required_ns == 318
