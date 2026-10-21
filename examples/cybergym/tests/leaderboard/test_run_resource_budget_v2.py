# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Source-only v2 clock checks. Synthetic samples are not boot authority."""

import importlib.util
import json
import sqlite3
from pathlib import Path

import pytest
from nooa_cybergym.leaderboard.subset_dry_run_admission import OFFICIAL_SUBSET_TASK_IDS

_HELPERS_SPEC = importlib.util.spec_from_file_location(
    "_resource_budget_v1_test_helpers", Path(__file__).with_name("test_run_resource_budget.py")
)
assert _HELPERS_SPEC is not None and _HELPERS_SPEC.loader is not None
_HELPERS = importlib.util.module_from_spec(_HELPERS_SPEC)
_HELPERS_SPEC.loader.exec_module(_HELPERS)
inputs, reserve = _HELPERS.inputs, _HELPERS.reserve


@pytest.fixture
def setup(tmp_path):
    from nooa_cybergym.leaderboard import pinned_metering, run_resource_budget

    module = run_resource_budget
    args = inputs((module, pinned_metering), elapsed=120)
    path = tmp_path / "resources-v2.sqlite"
    clock = {"domain": "a" * 64, "uptime_ns": 5_000_000_000, "fail": False}

    def sample():
        if clock["fail"]:
            raise OSError("synthetic clock source unavailable")
        return module.BootUptimeSample(clock["domain"], clock["uptime_ns"])

    return module, args, path, clock, sample


def test_v2_elapsed_uses_injected_uptime_not_utc(setup, monkeypatch):
    module, args, path, clock, sample = setup
    utc = [1_800_000_000_000_000_000]
    monkeypatch.setattr(module, "_now_ns", lambda: utc[0])
    ledger = module.RunResourceBudget.create_v2(path, clock_source=sample, **args)
    started = ledger.snapshot()
    assert started["schema_version"] == 2
    assert started["clock_basis"] == "suspend_aware_uptime_ns"
    assert started["boot_domain_sha256"] == "a" * 64
    assert started["started_at_ns"] == 5_000_000_000
    assert started["deadline_ns"] == 125_000_000_000
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (2,)
    utc[0] -= 50_000_000_000
    clock["uptime_ns"] += 30_000_000_000
    assert ledger.remaining_seconds() == 90
    with pytest.raises(module.ResourceBudgetError, match="schema"):
        module.RunResourceBudget.open(path, **args)


def test_v2_reopen_retains_atomic_elapsed_highwater_and_reservation_debits(setup):
    module, args, path, clock, sample = setup
    ledger = module.RunResourceBudget.create_v2(path, clock_source=sample, **args)
    reserve(ledger, "failed-provider")
    clock["uptime_ns"] += 2_000_000_000
    reopened = module.RunResourceBudget.open_v2(path, clock_source=sample, **args)
    reserve(reopened, "replacement-provider")
    snapshot = reopened.snapshot()
    assert (snapshot["requests"], snapshot["spend_units"]) == (2, 22)
    assert snapshot["last_observed_ns"] == clock["uptime_ns"]
    assert reopened.remaining_seconds() == 118
    inventory = json.loads(
        reopened.read_attempt_debits(task_id=OFFICIAL_SUBSET_TASK_IDS[0], attempt_id="attempt-0")
    )
    assert [row["request_id"] for row in inventory["reservations"]] == [
        "failed-provider",
        "replacement-provider",
    ]


def test_v2_boot_change_durably_stops_at_last_trusted_tick_and_preserves_reads(setup):
    module, args, path, clock, sample = setup
    ledger = module.RunResourceBudget.create_v2(path, clock_source=sample, **args)
    reserve(ledger, "before-reboot")
    trusted = ledger.snapshot()["last_observed_ns"]
    clock["domain"] = "b" * 64
    clock["uptime_ns"] = 1_000_000_000
    with pytest.raises(module.ResourceBudgetStopped, match="clock_untrusted"):
        reserve(ledger, "after-reboot")
    reopened = module.RunResourceBudget.open_v2(path, clock_source=sample, **args)
    snapshot = reopened.snapshot()
    assert snapshot["stop"]["reason"] == "clock_untrusted"
    assert snapshot["stop"]["observed_ns"] == trusted
    assert (snapshot["requests"], snapshot["spend_units"]) == (1, 11)
    assert [
        row["request_id"]
        for row in json.loads(
            reopened.read_attempt_debits(
                task_id=OFFICIAL_SUBSET_TASK_IDS[0], attempt_id="attempt-0"
            )
        )["reservations"]
    ] == ["before-reboot"]
    with pytest.raises(module.ResourceBudgetStopped):
        reopened.check_active()


@pytest.mark.parametrize("fault", ["regression", "unavailable", "malformed"])
def test_v2_untrusted_sample_stops_without_refunding_or_resetting_clock(setup, fault):
    module, args, path, clock, sample = setup
    ledger = module.RunResourceBudget.create_v2(path, clock_source=sample, **args)
    reserve(ledger)
    clock["uptime_ns"] += 3_000_000_000
    ledger.check_active()
    trusted = ledger.snapshot()["last_observed_ns"]
    if fault == "regression":
        clock["uptime_ns"] -= 1
        bad_source = sample
    elif fault == "unavailable":
        clock["fail"] = True
        bad_source = sample
    else:
        def bad_source():
            return module.BootUptimeSample("not-a-digest", 9_000_000_000)
    reopened = module.RunResourceBudget.open_v2(path, clock_source=bad_source, **args)
    with pytest.raises(module.ResourceBudgetStopped, match="clock_untrusted"):
        reopened.check_active()
    snapshot = reopened.snapshot()
    assert snapshot["stop"]["observed_ns"] == trusted
    assert snapshot["last_observed_ns"] == trusted
    assert (snapshot["requests"], snapshot["spend_units"]) == (1, 11)


def test_v2_deadline_stops_before_another_reservation(setup):
    module, args, path, clock, sample = setup
    module.RunResourceBudget.create_v2(path, clock_source=sample, **args)
    clock["uptime_ns"] += 120_000_000_000
    reopened = module.RunResourceBudget.open_v2(path, clock_source=sample, **args)
    with pytest.raises(module.ResourceBudgetStopped, match="elapsed_limit"):
        reopened.check_active()
    assert reopened.snapshot()["stop"]["reason"] == "elapsed_limit"
    with pytest.raises(module.ResourceBudgetStopped):
        reserve(reopened)


def test_v2_untrusted_clock_does_not_acknowledge_operator_stop_or_task_close(setup):
    module, args, path, clock, sample = setup
    ledger = module.RunResourceBudget.create_v2(path, clock_source=sample, **args)
    reserve(ledger)
    digest = ledger.snapshot()["accounting_sha256"]
    clock["fail"] = True
    with pytest.raises(module.ResourceBudgetStopped, match="clock_untrusted"):
        ledger.stop(reason="operator_stop")
    assert ledger.snapshot()["stop"]["reason"] == "clock_untrusted"
    with pytest.raises(module.ResourceBudgetStopped, match="clock_untrusted"):
        ledger.close_task(
            task_id=OFFICIAL_SUBSET_TASK_IDS[0],
            attempt_id="attempt-0",
            completion_sha256="e" * 64,
            expected_accounting_sha256=digest,
        )
    assert ledger.snapshot()["closures"] == {}


def test_v2_existing_stop_reason_survives_later_clock_failure(setup):
    module, args, path, clock, sample = setup
    ledger = module.RunResourceBudget.create_v2(path, clock_source=sample, **args)
    ledger.stop(reason="operator_stop")
    clock["fail"] = True
    with pytest.raises(module.ResourceBudgetStopped, match="operator_stop"):
        ledger.check_active()
    assert ledger.snapshot()["stop"]["reason"] == "operator_stop"


def test_v2_open_rejects_v1_without_migration(setup):
    module, args, path, _, sample = setup
    module.RunResourceBudget.create(path, **args)
    with pytest.raises(module.ResourceBudgetError, match="schema"):
        module.RunResourceBudget.open_v2(path, clock_source=sample, **args)
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (1,)
