# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Synthetic charges only: no test number is an approved operational price."""

import copy
import hashlib
import json
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
from threading import Barrier

import pytest
from nooa_cybergym.leaderboard.subset_dry_run_admission import OFFICIAL_SUBSET_TASK_IDS
from nooa_cybergym.leaderboard.subset_run_budget import verify_subset_run_budget


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class Authority:
    def __init__(self, payload):
        self.payload = payload

    def attest_signed(self, kind, envelope):
        assert kind == "subset_run_budget"
        assert envelope == b"synthetic-signed-budget"
        return copy.deepcopy(self.payload)


@pytest.fixture
def modules():
    from nooa_cybergym.leaderboard import pinned_metering, run_resource_budget

    return run_resource_budget, pinned_metering


def inputs(modules, *, spend=100, elapsed=432000):
    _, metering_module = modules
    bounds = (
        metering_module.DispatchBound("primary", "zai-coding-plan", "glm-5.3", 1000, 100),
        metering_module.DispatchBound(
            "primary", "deepseek-official-api", "deepseek-flash", 1000, 100
        ),
        metering_module.DispatchBound("count_tokens", "zai-coding-plan", "glm-5.3", 1000, 0),
        metering_module.DispatchBound(
            "advisory_recon", "deepseek-official-api", "deepseek-flash", 1000, 100
        ),
        metering_module.DispatchBound(
            "advisory_debug", "deepseek-official-api", "deepseek-flash", 1000, 100
        ),
        metering_module.DispatchBound(
            "advisory_critic", "deepseek-official-api", "deepseek-flash", 1000, 100
        ),
        metering_module.DispatchBound("memory", "memory-provider", "memory-model", 1000, 100),
        metering_module.DispatchBound(
            "post_oracle_memory", "memory-provider", "memory-model", 1000, 100
        ),
    )
    document = {
        "schema_version": 1,
        "artifact_kind": "conservative_dispatch_metering",
        "model_policy_sha256": "b" * 64,
        "spend_unit": "usd_micros",
        "accounting": "reserve_all_attempts_no_refunds",
        "dispatch_bounds": [
            asdict(bound)
            | {
                "max_charge_units": 7 if bound.lane.startswith("advisory_") else 11,
                "bound_evidence_sha256": "d" * 64,
            }
            for bound in bounds
        ],
    }
    raw = canonical(document)
    metering = metering_module.verify_metering_policy(
        policy_json=raw,
        expected_sha256=hashlib.sha256(raw).hexdigest(),
        model_policy_sha256="b" * 64,
        required_dispatch_bounds=bounds,
    )
    payload = {
        "schema_version": 1,
        "artifact_kind": "subset_run_budget",
        "scope": "native_subset_dry_run_level1",
        "run_id": "test-run",
        "epoch": "test-epoch",
        "task_ids": list(OFFICIAL_SUBSET_TASK_IDS),
        "campaign_policy_sha256": "a" * 64,
        "model_policy_sha256": "b" * 64,
        "metering_policy_sha256": metering.sha256,
        "max_model_requests": 15000,
        "max_requests_per_task": 1500,
        "primary_and_memory_requests_per_task": 1410,
        "deepseek_advisory_requests_per_task": 90,
        "max_elapsed_seconds": elapsed,
        "max_spend_units": spend,
        "spend_unit": "usd_micros",
        "accounting_scope": "all_model_calls_including_memory_and_failed_reservations",
        "elapsed_scope": "first_preparation_through_final_cleanup",
        "exhaustion_action": "stop_run_preserve_task_terminals",
    }
    authority = Authority(payload)
    budget = verify_subset_run_budget(
        signed_budget=b"synthetic-signed-budget",
        authority=authority,
        expected_envelope_sha256=hashlib.sha256(b"synthetic-signed-budget").hexdigest(),
        run_id="test-run",
        epoch="test-epoch",
        campaign_policy_sha256="a" * 64,
        model_policy_sha256="b" * 64,
        metering_policy_sha256=metering.sha256,
    )
    return {"budget": budget, "authority": authority, "metering": metering}


@pytest.fixture
def store(tmp_path, modules, monkeypatch):
    module, _ = modules
    now = [1_800_000_000_000_000_000]
    monkeypatch.setattr(module, "_now_ns", lambda: now[0])
    args = inputs(modules)
    path = tmp_path / "resources.sqlite"
    return module.RunResourceBudget.create(path, **args), path, args, now


def reserve(ledger, request="request-1", *, task=0, allocation="primary_and_memory"):
    return ledger.reserve(
        task_id=OFFICIAL_SUBSET_TASK_IDS[task],
        attempt_id=f"attempt-{task}",
        request_id=request,
        allocation=allocation,
    )


def test_atomic_debit_persists_request_spend_and_clock_across_reopen(store, modules):
    ledger, path, args, now = store
    first = reserve(ledger)
    assert (first.run_ordinal, first.task_ordinal) == (1, 1)
    now[0] += 30_000_000_000
    reopened = modules[0].RunResourceBudget.open(path, **args)
    second = reserve(reopened, "failed-provider", allocation="deepseek_advisory")
    assert (second.run_ordinal, second.allocation_ordinal) == (2, 1)
    snapshot = reopened.snapshot()
    assert snapshot["requests"] == 2
    assert snapshot["spend_units"] == 18
    assert snapshot["tasks"][OFFICIAL_SUBSET_TASK_IDS[0]]["requests"] == 2
    assert reopened.remaining_seconds() == 432000 - 30
    snapshot["spend_units"] = 0
    assert ledger.snapshot()["spend_units"] == 18


def test_clock_expiry_before_first_preparation_stops_and_survives_reopen(store, modules):
    ledger, path, args, now = store
    now[0] += 432000 * 1_000_000_000
    with pytest.raises(modules[0].ResourceBudgetStopped, match="elapsed"):
        ledger.check_active()
    reopened = modules[0].RunResourceBudget.open(path, **args)
    assert reopened.snapshot()["stop"]["reason"] == "elapsed_limit"
    with pytest.raises(modules[0].ResourceBudgetStopped):
        reserve(reopened)
    assert reopened.snapshot()["requests"] == 0


def test_spend_upper_bound_is_never_caller_selected_or_refunded(tmp_path, modules):
    module, _ = modules
    args = inputs(modules, spend=11)
    ledger = module.RunResourceBudget.create(tmp_path / "resources.sqlite", **args)
    reserve(ledger)
    with pytest.raises(module.ResourceBudgetStopped, match="spend"):
        reserve(ledger, "replacement")
    snapshot = ledger.snapshot()
    assert (snapshot["requests"], snapshot["spend_units"]) == (1, 11)
    assert snapshot["stop"]["reason"] == "spend_limit"
    with pytest.raises(TypeError):
        ledger.reserve(
            task_id=OFFICIAL_SUBSET_TASK_IDS[0],
            attempt_id="attempt-0",
            request_id="caller-free",
            allocation="primary_and_memory",
            max_charge_units=0,
        )


def test_concurrent_last_spend_slot_admits_exactly_once(tmp_path, modules):
    module, _ = modules
    args = inputs(modules, spend=11)
    path = tmp_path / "resources.sqlite"
    module.RunResourceBudget.create(path, **args)
    barrier = Barrier(2)

    def attempt(number):
        ledger = module.RunResourceBudget.open(path, **args)
        barrier.wait()
        try:
            reserve(ledger, f"request-{number}")
            return True
        except module.ResourceBudgetStopped:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(attempt, [1, 2])) == [False, True]
    snapshot = module.RunResourceBudget.open(path, **args).snapshot()
    assert (snapshot["requests"], snapshot["spend_units"]) == (1, 11)


def test_closure_compares_accounting_atomically_then_blocks_new_debits(store, modules):
    ledger, path, args, now = store
    reserve(ledger)
    old = ledger.snapshot()["accounting_sha256"]
    now[0] += 1000000
    ledger.check_active()
    assert ledger.snapshot()["accounting_sha256"] == old
    reserve(ledger, "post-oracle")
    with pytest.raises(modules[0].ResourceBudgetError, match="accounting"):
        ledger.close_task(
            task_id=OFFICIAL_SUBSET_TASK_IDS[0],
            attempt_id="attempt-0",
            completion_sha256="e" * 64,
            expected_accounting_sha256=old,
        )
    current = ledger.snapshot()["accounting_sha256"]
    ledger.close_task(
        task_id=OFFICIAL_SUBSET_TASK_IDS[0],
        attempt_id="attempt-0",
        completion_sha256="e" * 64,
        expected_accounting_sha256=current,
    )
    reopened = modules[0].RunResourceBudget.open(path, **args)
    with pytest.raises(modules[0].ResourceBudgetError, match="closed"):
        reserve(reopened, "late-post-oracle")
    assert reopened.snapshot()["requests"] == 2
    reserve(reopened, "next-task", task=1)


def test_stopped_run_still_allows_verified_task_closure(store, modules):
    ledger, _, _, _ = store
    reserve(ledger)
    ledger.stop(reason="operator_stop")
    ledger.close_task(
        task_id=OFFICIAL_SUBSET_TASK_IDS[0],
        attempt_id="attempt-0",
        completion_sha256="e" * 64,
        expected_accounting_sha256=ledger.snapshot()["accounting_sha256"],
    )
    assert ledger.snapshot()["closures"][OFFICIAL_SUBSET_TASK_IDS[0]]["attempt_id"] == "attempt-0"
    with pytest.raises(modules[0].ResourceBudgetStopped):
        ledger.check_active()


def test_clock_regression_is_a_persistent_stop(store, modules):
    ledger, path, args, now = store
    reserve(ledger)
    now[0] -= 1
    with pytest.raises(modules[0].ResourceBudgetStopped, match="clock"):
        ledger.remaining_seconds()
    now[0] += 100
    assert (
        modules[0].RunResourceBudget.open(path, **args).snapshot()["stop"]["reason"]
        == "clock_regression"
    )


def test_one_thousand_clock_polls_do_not_grow_immutable_history(store):
    ledger, path, _, now = store
    reserve(ledger)
    ledger.remaining_seconds()
    with sqlite3.connect(path) as connection:
        initial_events = connection.execute("SELECT count(*) FROM events").fetchone()[0]
    for _ in range(1000):
        now[0] += 1000000
        ledger.remaining_seconds()
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT count(*) FROM events").fetchone()[0] == initial_events
        assert connection.execute("SELECT count(*) FROM clock").fetchone()[0] == 1
        assert connection.execute("SELECT observed_ns FROM clock").fetchone()[0] == now[0]


def test_polling_observes_other_handle_debit_and_preserves_reopened_clock(store, modules):
    ledger, path, args, now = store
    ledger.remaining_seconds()
    other = modules[0].RunResourceBudget.open(path, **args)
    reserve(other)
    now[0] += 123000000000
    assert ledger.remaining_seconds() == 432000 - 123
    reopened = modules[0].RunResourceBudget.open(path, **args)
    assert reopened.snapshot()["last_observed_ns"] == now[0]
    assert reopened.snapshot()["requests"] == 1


def test_clock_high_watermark_cannot_be_reduced_or_deleted(store, modules):
    ledger, path, _, now = store
    now[0] += 1000000000
    ledger.remaining_seconds()
    with sqlite3.connect(path) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("UPDATE clock SET observed_ns=observed_ns-1")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM clock")
    assert ledger.snapshot()["last_observed_ns"] == now[0]


@pytest.mark.parametrize("table", ["clock", "identity"])
def test_resource_clock_and_identity_cannot_be_reset_by_replacement(store, modules, table):
    ledger, path, _, now = store
    initial = now[0]
    now[0] += 100_000_000_000
    ledger.check_active()
    with sqlite3.connect(path) as connection:
        row = list(connection.execute(f"SELECT * FROM {table}").fetchone())
        if table == "clock":
            row[1] = initial
        else:
            row[2] += 100_000_000_000
            row[3] += 100_000_000_000
        placeholders = ",".join("?" for _ in row)
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(f"INSERT OR REPLACE INTO {table} VALUES({placeholders})", row)
    now[0] = initial + 1_000_000_000
    with pytest.raises(modules[0].ResourceBudgetStopped, match="clock_regression"):
        ledger.check_active()


def test_polling_detects_schema_bypass_and_changed_history(store, modules):
    ledger, path, _, _ = store
    reserve(ledger)
    ledger.remaining_seconds()
    with sqlite3.connect(path) as connection:
        trigger = connection.execute(
            "SELECT sql FROM sqlite_schema WHERE name='events_no_update'"
        ).fetchone()[0]
        connection.execute("DROP TRIGGER events_no_update")
        body = json.loads(
            connection.execute("SELECT body FROM events WHERE ordinal=1").fetchone()[0]
        )
        body["charge_units"] = 1
        connection.execute("UPDATE events SET body=? WHERE ordinal=1", (canonical(body).decode(),))
        connection.execute(trigger)
    with pytest.raises(modules[0].ResourceBudgetError, match="history"):
        ledger.remaining_seconds()


def test_polling_observes_other_handle_stop(store, modules):
    ledger, path, args, _ = store
    ledger.remaining_seconds()
    other = modules[0].RunResourceBudget.open(path, **args)
    other.stop(reason="operator_stop")
    with pytest.raises(modules[0].ResourceBudgetStopped, match="operator_stop"):
        ledger.remaining_seconds()


def test_cleanup_clock_observation_is_retained_after_existing_stop(store, modules):
    ledger, _, _, now = store
    ledger.stop(reason="operator_stop")
    before = ledger.snapshot()
    now[0] = before["deadline_ns"] + 1_000_000_000
    with pytest.raises(modules[0].ResourceBudgetStopped, match="operator_stop"):
        ledger.check_active()
    after = ledger.snapshot()
    assert after["stop"] == before["stop"]
    assert after["event_ordinal"] == before["event_ordinal"]
    assert after["last_observed_ns"] == now[0]
    assert after["last_observed_ns"] > after["deadline_ns"]


def test_resource_event_cannot_be_replaced_at_same_ordinal(store):
    ledger, path, _, _ = store
    reserve(ledger)
    ledger.check_active()
    with sqlite3.connect(path) as connection:
        row = list(connection.execute("SELECT * FROM events WHERE ordinal=1").fetchone())
        body = json.loads(row[3])
        body["charge_units"] = 99
        row[3] = canonical(body).decode()
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("INSERT OR REPLACE INTO events VALUES(?,?,?,?)", row)


def test_permission_poll_rejects_same_size_raw_history_corruption(store, modules):
    ledger, path, _, _ = store
    reserve(ledger)
    ledger.check_active()
    raw = path.read_bytes()
    original, corrupt = b'"charge_units":11', b'"charge_units":99'
    assert raw.count(original) == 1
    with path.open("r+b") as output:
        output.write(raw.replace(original, corrupt))
        output.flush()
        os.fsync(output.fileno())
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
    with pytest.raises(modules[0].ResourceBudgetError, match="history"):
        ledger.check_active()


def test_closed_history_and_schema_tampering_fail_closed(store, modules):
    ledger, path, _, _ = store
    reserve(ledger)
    with sqlite3.connect(path) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM events")
        connection.execute("CREATE TABLE extra (id INTEGER)")
    with pytest.raises(modules[0].ResourceBudgetError, match="schema"):
        ledger.snapshot()


def test_rebinding_signed_budget_or_metering_is_rejected_before_store_creation(tmp_path, modules):
    module, _ = modules
    args = inputs(modules)
    forged = replace(args["budget"], max_spend_units=999999)
    with pytest.raises(RuntimeError):
        module.RunResourceBudget.create(tmp_path / "forged.sqlite", **(args | {"budget": forged}))
    assert not (tmp_path / "forged.sqlite").exists()


def test_advisory_allocation_exhaustion_does_not_stop_remaining_primary(tmp_path, modules):
    module, _ = modules
    args = inputs(modules, spend=100000)
    ledger = module.RunResourceBudget.create(tmp_path / "resources.sqlite", **args)
    for number in range(90):
        reserve(ledger, f"advisory-{number}", allocation="deepseek_advisory")
    with pytest.raises(module.RequestBudgetExceeded, match="allocation"):
        reserve(ledger, "advisory-91", allocation="deepseek_advisory")
    assert ledger.snapshot()["stop"] is None
    assert reserve(ledger, "primary-after-advisory").task_ordinal == 91


def test_duplicate_attempt_change_and_cross_task_attempt_never_consume_budget(store, modules):
    ledger, _, _, _ = store
    reserve(ledger)
    before = ledger.snapshot()["accounting_sha256"]
    with pytest.raises(modules[0].DuplicateRequestReservation):
        reserve(ledger)
    for task, attempt in [
        (OFFICIAL_SUBSET_TASK_IDS[0], "new-attempt"),
        (OFFICIAL_SUBSET_TASK_IDS[1], "attempt-0"),
    ]:
        with pytest.raises(modules[0].ResourceBudgetError, match="attempt"):
            ledger.reserve(
                task_id=task,
                attempt_id=attempt,
                request_id="new-request",
                allocation="primary_and_memory",
            )
    assert ledger.snapshot()["accounting_sha256"] == before


def test_concurrent_closure_and_debit_never_accept_a_stale_snapshot(store, modules):
    ledger, path, args, _ = store
    reserve(ledger)
    expected = ledger.snapshot()["accounting_sha256"]
    barrier = Barrier(2)

    def action(kind):
        opened = modules[0].RunResourceBudget.open(path, **args)
        barrier.wait()
        try:
            if kind == "close":
                opened.close_task(
                    task_id=OFFICIAL_SUBSET_TASK_IDS[0],
                    attempt_id="attempt-0",
                    completion_sha256="e" * 64,
                    expected_accounting_sha256=expected,
                )
            else:
                reserve(opened, "concurrent-post-oracle")
            return kind + "-accepted"
        except modules[0].ResourceBudgetError:
            return kind + "-rejected"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = set(pool.map(action, ["close", "debit"]))
    assert results in [{"close-accepted", "debit-rejected"}, {"close-rejected", "debit-accepted"}]


def test_closure_detects_cleanup_elapsed_overrun_without_forbidding_cleanup(store, modules):
    ledger, path, args, now = store
    reserve(ledger)
    digest = ledger.snapshot()["accounting_sha256"]
    now[0] += 432001 * 1_000_000_000
    ledger.close_task(
        task_id=OFFICIAL_SUBSET_TASK_IDS[0],
        attempt_id="attempt-0",
        completion_sha256="e" * 64,
        expected_accounting_sha256=digest,
    )
    snapshot = modules[0].RunResourceBudget.open(path, **args).snapshot()
    assert snapshot["stop"]["reason"] == "elapsed_limit"
    assert snapshot["closures"][OFFICIAL_SUBSET_TASK_IDS[0]]["accounting_sha256"] == digest


@pytest.mark.parametrize("operation", ["snapshot", "reserve", "check_active", "close_task"])
def test_deleted_store_is_never_recreated(store, modules, operation):
    ledger, path, _, _ = store
    digest = ledger.snapshot()["accounting_sha256"]
    path.unlink()
    with pytest.raises(modules[0].ResourceBudgetError):
        if operation == "reserve":
            reserve(ledger)
        elif operation == "close_task":
            ledger.close_task(
                task_id=OFFICIAL_SUBSET_TASK_IDS[0],
                attempt_id="attempt-0",
                completion_sha256="e" * 64,
                expected_accounting_sha256=digest,
            )
        else:
            getattr(ledger, operation)()
    assert not path.exists()


def test_replaced_store_inode_is_rejected_even_if_bytes_match(store, modules):
    ledger, path, _, _ = store
    old = path.with_suffix(".old")
    path.rename(old)
    path.write_bytes(old.read_bytes())
    with pytest.raises(modules[0].ResourceBudgetError, match="identity"):
        reserve(ledger)


@pytest.mark.parametrize(
    "mutation", ["false_charge", "duplicate_request", "changed_ordinal", "boolean_closure"]
)
def test_semantically_corrupt_history_is_rejected_even_with_valid_sqlite_indexes(
    store, modules, mutation
):
    ledger, path, _, _ = store
    reserve(ledger)
    if mutation != "boolean_closure":
        reserve(ledger, "request-2")
    ledger.close_task(
        task_id=OFFICIAL_SUBSET_TASK_IDS[0],
        attempt_id="attempt-0",
        completion_sha256="e" * 64,
        expected_accounting_sha256=ledger.snapshot()["accounting_sha256"],
    )
    with sqlite3.connect(path) as connection:
        trigger = connection.execute(
            "SELECT sql FROM sqlite_schema WHERE name='events_no_update'"
        ).fetchone()[0]
        connection.execute("DROP TRIGGER events_no_update")
        ordinal = 2
        body = json.loads(
            connection.execute("SELECT body FROM events WHERE ordinal=?", (ordinal,)).fetchone()[0]
        )
        if mutation == "false_charge":
            body["charge_units"] = 1
        elif mutation == "duplicate_request":
            body["request_id"] = "request-1"
        elif mutation == "changed_ordinal":
            body["run_ordinal"] = 1
        else:
            # A bool must not be accepted as a numeric count, even when 0/1 match.
            body["task_ordinal"] = True
            body["run_ordinal"] = True
        connection.execute(
            "UPDATE events SET body=? WHERE ordinal=?", (canonical(body).decode(), ordinal)
        )
        connection.execute(trigger)
    with pytest.raises(modules[0].ResourceBudgetError, match="history"):
        ledger.snapshot()


def test_commit_acknowledgement_loss_retains_charge_and_poisons_handle(store, modules, monkeypatch):
    ledger, path, args, _ = store
    module, _ = modules
    real_connect = sqlite3.connect

    class AmbiguousConnection:
        def __init__(self, connection):
            self.connection = connection

        def __getattr__(self, name):
            return getattr(self.connection, name)

        def commit(self):
            self.connection.commit()
            raise sqlite3.OperationalError("acknowledgement lost")

    monkeypatch.setattr(
        module.sqlite3, "connect", lambda *a, **kw: AmbiguousConnection(real_connect(*a, **kw))
    )
    with pytest.raises(module.ResourceBudgetError):
        reserve(ledger)
    monkeypatch.setattr(module.sqlite3, "connect", real_connect)
    with pytest.raises(module.ResourceBudgetError, match="prior write failure"):
        reserve(ledger, "retry")
    reopened = module.RunResourceBudget.open(path, **args)
    assert (reopened.snapshot()["requests"], reopened.snapshot()["spend_units"]) == (1, 11)
    with pytest.raises(module.DuplicateRequestReservation):
        reserve(reopened)


def test_aggregate_request_stop_is_persisted_even_when_last_task_pool_is_full(tmp_path, modules):
    module, _ = modules
    args = inputs(modules, spend=1000000)
    path = tmp_path / "resources.sqlite"
    ledger = module.RunResourceBudget.create(path, **args)
    observed = ledger.snapshot()["started_at_ns"]
    rows = []
    for index, task_id in enumerate(OFFICIAL_SUBSET_TASK_IDS):
        task_ordinal = 0
        for allocation, limit in (("primary_and_memory", 1410), ("deepseek_advisory", 90)):
            for allocation_ordinal in range(1, limit + 1):
                task_ordinal += 1
                body = {
                    "run_id": "test-run",
                    "task_id": task_id,
                    "attempt_id": f"attempt-{index}",
                    "request_id": f"seed-{index}-{task_ordinal}",
                    "allocation": allocation,
                    "run_ordinal": len(rows) + 1,
                    "task_ordinal": task_ordinal,
                    "allocation_ordinal": allocation_ordinal,
                    "charge_units": args["metering"].charge(allocation),
                }
                rows.append((len(rows) + 1, "reserve", observed, canonical(body).decode()))
    with sqlite3.connect(path) as connection:
        connection.executemany("INSERT INTO events VALUES(?,?,?,?)", rows)
    with pytest.raises(module.ResourceBudgetStopped, match="request_limit"):
        reserve(ledger, "over-aggregate", task=9)
    assert ledger.snapshot()["stop"]["reason"] == "request_limit"
    assert ledger.snapshot()["requests"] == 15000


@pytest.mark.parametrize(
    "mutation", ["missing_lane", "lower_cap", "zero_charge", "wrong_pin", "noncanonical", "extra"]
)
def test_metering_requires_exact_frozen_coverage_and_positive_conservative_bounds(
    modules, mutation
):
    _, module = modules
    metering = inputs(modules)["metering"]
    document = json.loads(metering.policy_json)
    if mutation == "missing_lane":
        document["dispatch_bounds"].pop()
    elif mutation == "lower_cap":
        document["dispatch_bounds"][0]["input_token_limit"] -= 1
    elif mutation == "zero_charge":
        document["dispatch_bounds"][0]["max_charge_units"] = 0
    elif mutation == "extra":
        document["free_retries"] = True
    raw = canonical(document)
    if mutation == "noncanonical":
        raw += b"\n"
    pin = "f" * 64 if mutation == "wrong_pin" else hashlib.sha256(raw).hexdigest()
    with pytest.raises(ValueError):
        module.verify_metering_policy(
            policy_json=raw,
            expected_sha256=pin,
            model_policy_sha256="b" * 64,
            required_dispatch_bounds=metering.required_dispatch_bounds,
        )
