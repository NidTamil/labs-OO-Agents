# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""A controller-private request ledger never releases an admitted dispatch."""

from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from threading import Barrier

import pytest

TASKS = tuple(f"task-{i}" for i in range(10))
IDENTITY = {
    "run_id": "ten-task-run",
    "epoch": "freeze-20261021",
    "policy_sha256": "a" * 64,
    "ordered_task_ids": TASKS,
}


@pytest.fixture
def budget_module():
    from nooa_cybergym.leaderboard import run_request_budget

    return run_request_budget


@pytest.fixture
def store(tmp_path, budget_module):
    path = tmp_path / "request-budget.sqlite"
    return path, budget_module.RunRequestBudget.create(path, **IDENTITY)


def reserve(budget, number=1, *, task=0, allocation="primary_and_memory"):
    return budget.reserve(
        task_id=TASKS[task],
        attempt_id=f"attempt-{task}",
        request_id=f"request-{task}-{number}",
        allocation=allocation,
    )


def seed_history(path, counts):
    """Write a realistic committed history in one transaction, avoiding 15,000 fsyncs."""
    rows = []
    for task, (primary, advisory) in enumerate(counts):
        ordinal = 0
        for allocation, count in (
            ("primary_and_memory", primary),
            ("deepseek_advisory", advisory),
        ):
            for allocation_ordinal in range(1, count + 1):
                ordinal += 1
                rows.append(
                    (
                        len(rows) + 1,
                        TASKS[task],
                        f"attempt-{task}",
                        f"history-{task}-{ordinal}",
                        allocation,
                        ordinal,
                        allocation_ordinal,
                    )
                )
    with sqlite3.connect(path) as connection:
        connection.executemany("INSERT INTO reservations VALUES(?,?,?,?,?,?,?)", rows)


def test_committed_debits_and_ordinals_survive_reopening(store, budget_module):
    path, budget = store
    first = reserve(budget)
    second = reserve(budget, 2, allocation="deepseek_advisory")
    third = reserve(budget, task=1)
    assert (first.run_ordinal, first.task_ordinal, first.allocation_ordinal) == (1, 1, 1)
    assert (second.run_ordinal, second.task_ordinal, second.allocation_ordinal) == (2, 2, 1)
    assert (third.run_ordinal, third.task_ordinal, third.allocation_ordinal) == (3, 1, 1)
    assert (
        first.run_id,
        first.task_id,
        first.attempt_id,
        first.request_id,
        first.allocation,
    ) == ("ten-task-run", "task-0", "attempt-0", "request-0-1", "primary_and_memory")
    with pytest.raises(FrozenInstanceError):
        first.run_ordinal = 99
    reopened = budget_module.RunRequestBudget.open(path, **IDENTITY)
    snapshot = reopened.snapshot()
    assert snapshot["requests"] == 3
    assert snapshot["tasks"]["task-0"] == {
        "requests": 2,
        "primary_and_memory": 1,
        "deepseek_advisory": 1,
    }
    assert snapshot["tasks"]["task-9"]["requests"] == 0
    assert reserve(reopened, 3).allocation_ordinal == 2
    snapshot["tasks"]["task-0"]["requests"] = 0
    assert budget.snapshot()["requests"] == 4


@pytest.mark.parametrize(
    "change",
    [
        {"run_id": "another-run"},
        {"epoch": "another-epoch"},
        {"policy_sha256": "b" * 64},
        {"ordered_task_ids": TASKS[::-1]},
        {"ordered_task_ids": (*TASKS[:-1], "another-task")},
    ],
)
def test_open_requires_exact_bound_identity(store, budget_module, change):
    path, budget = store
    reserve(budget)
    with pytest.raises(budget_module.RunRequestBudgetError, match="identity"):
        budget_module.RunRequestBudget.open(path, **(IDENTITY | change))
    assert budget.snapshot()["requests"] == 1


@pytest.mark.parametrize(
    "change",
    [
        {"run_id": ""},
        {"epoch": None},
        {"policy_sha256": "a" * 63},
        {"policy_sha256": "A" * 64},
        {"ordered_task_ids": TASKS[:-1]},
        {"ordered_task_ids": (*TASKS, "eleventh")},
        {"ordered_task_ids": (*TASKS[:-1], TASKS[0])},
        {"ordered_task_ids": (*TASKS[:-1], "")},
        {"ordered_task_ids": set(TASKS)},
    ],
)
def test_invalid_identity_cannot_create_a_store(tmp_path, budget_module, change):
    path = tmp_path / "invalid.sqlite"
    with pytest.raises(ValueError):
        budget_module.RunRequestBudget.create(path, **(IDENTITY | change))
    assert not path.exists()


def test_create_refuses_existing_store_without_resetting_it(store, budget_module):
    path, budget = store
    reserve(budget)
    with pytest.raises(budget_module.RunRequestBudgetError):
        budget_module.RunRequestBudget.create(path, **IDENTITY)
    assert budget.snapshot()["requests"] == 1


@pytest.mark.parametrize("content", [None, b"", b"not a SQLite database"])
def test_open_missing_or_corrupt_store_fails_closed(tmp_path, budget_module, content):
    path = tmp_path / "missing.sqlite"
    if content is not None:
        path.write_bytes(content)
    with pytest.raises(budget_module.RunRequestBudgetError):
        budget_module.RunRequestBudget.open(path, **IDENTITY)
    if content is None:
        assert not path.exists()


@pytest.mark.parametrize("operation", ["snapshot", "reserve"])
def test_a_missing_store_is_not_recreated_by_an_existing_handle(store, budget_module, operation):
    path, budget = store
    path.unlink()
    with pytest.raises(budget_module.RunRequestBudgetError):
        budget.snapshot() if operation == "snapshot" else reserve(budget)
    assert not path.exists()


@pytest.mark.parametrize("task", [0, 1])
def test_duplicate_request_ids_fail_even_with_changed_task_or_attempt(store, budget_module, task):
    _, budget = store
    first = reserve(budget)
    with pytest.raises(budget_module.DuplicateRequestReservation):
        budget.reserve(
            task_id=TASKS[task],
            attempt_id="another-attempt",
            request_id=first.request_id,
            allocation="deepseek_advisory",
        )
    assert budget.snapshot()["requests"] == 1


@pytest.mark.parametrize(
    "change",
    [
        {"task_id": "outside-run"},
        {"attempt_id": ""},
        {"request_id": ""},
        {"allocation": "deepseek_primary"},
        {"allocation": "primary_and_memory "},
    ],
)
def test_invalid_reservation_is_rejected_before_debit(store, budget_module, change):
    _, budget = store
    kwargs = {
        "task_id": TASKS[0],
        "attempt_id": "attempt-0",
        "request_id": "request-1",
        "allocation": "primary_and_memory",
    }
    with pytest.raises(ValueError):
        budget.reserve(**(kwargs | change))
    assert budget.snapshot()["requests"] == 0


def test_attempt_identity_cannot_move_between_tasks(store, budget_module):
    _, budget = store
    reserve(budget)
    with pytest.raises(budget_module.RunRequestBudgetError, match="attempt"):
        budget.reserve(
            task_id=TASKS[1],
            attempt_id="attempt-0",
            request_id="different-request",
            allocation="primary_and_memory",
        )
    assert budget.snapshot()["requests"] == 1


@pytest.mark.parametrize(
    ("counts", "allocation"),
    [([(1409, 0)], "primary_and_memory"), ([(0, 89)], "deepseek_advisory")],
)
def test_exact_allocation_limit_has_no_borrowing(store, budget_module, counts, allocation):
    path, budget = store
    seed_history(path, counts)
    final = reserve(budget, allocation=allocation)
    assert final.allocation_ordinal == (1410 if allocation == "primary_and_memory" else 90)
    with pytest.raises(budget_module.RequestBudgetExceeded, match="allocation"):
        reserve(budget, 2, allocation=allocation)
    other = "deepseek_advisory" if allocation == "primary_and_memory" else "primary_and_memory"
    assert reserve(budget, 3, allocation=other).allocation_ordinal == 1


def test_exact_task_limit_preserves_other_tasks_capacity(store, budget_module):
    path, budget = store
    seed_history(path, [(1410, 89)])
    final = reserve(budget, allocation="deepseek_advisory")
    assert final.task_ordinal == 1500
    with pytest.raises(budget_module.RequestBudgetExceeded, match="task"):
        reserve(budget, 2)
    assert reserve(budget, task=1).run_ordinal == 1501
    assert budget.snapshot()["tasks"]["task-0"]["requests"] == 1500


def test_concurrent_final_run_slot_is_charged_exactly_once(store, budget_module):
    path, budget = store
    seed_history(path, [(1410, 90)] * 9 + [(1410, 89)])
    barrier = Barrier(8)

    def compete(number):
        independent = budget_module.RunRequestBudget.open(path, **IDENTITY)
        barrier.wait(timeout=30)
        try:
            return reserve(independent, number, task=9, allocation="deepseek_advisory")
        except budget_module.RequestBudgetExceeded:
            return None

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(compete, range(8)))
    winners = [result for result in results if result is not None]
    assert len(winners) == 1
    assert winners[0].run_ordinal == 15000
    assert winners[0].task_ordinal == 1500
    assert winners[0].allocation_ordinal == 90
    assert budget.snapshot()["requests"] == 15000
    with pytest.raises(budget_module.RequestBudgetExceeded, match="run"):
        reserve(budget, 100, task=9)


def test_concurrent_duplicate_dispatch_id_has_one_debit(store, budget_module):
    path, budget = store
    barrier = Barrier(4)

    def compete(_):
        independent = budget_module.RunRequestBudget.open(path, **IDENTITY)
        barrier.wait(timeout=30)
        try:
            return reserve(independent)
        except budget_module.DuplicateRequestReservation:
            return None

    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(compete, range(4)))
    assert sum(result is not None for result in results) == 1
    assert budget.snapshot()["requests"] == 1


@pytest.mark.parametrize(
    "mutation",
    [
        "PRAGMA user_version = 99",
        "CREATE TABLE unexpected(extra TEXT)",
        "ALTER TABLE reservations ADD COLUMN extra TEXT",
        "DROP TABLE reservations",
    ],
)
def test_schema_drift_is_rejected_by_existing_and_new_handles(store, budget_module, mutation):
    path, budget = store
    with sqlite3.connect(path) as connection:
        connection.execute(mutation)
    with pytest.raises(budget_module.RunRequestBudgetError, match="schema"):
        budget.snapshot()
    with pytest.raises(budget_module.RunRequestBudgetError, match="schema"):
        budget_module.RunRequestBudget.open(path, **IDENTITY)
    with pytest.raises(budget_module.RunRequestBudgetError, match="schema"):
        reserve(budget)


def test_noncontiguous_history_fails_closed(store, budget_module):
    path, budget = store
    with sqlite3.connect(path) as connection:
        connection.execute(
            "INSERT INTO reservations VALUES(2,?,?,?,?,?,?)",
            (TASKS[0], "attempt-0", "gap", "primary_and_memory", 1, 1),
        )
    with pytest.raises(budget_module.RunRequestBudgetError, match="history"):
        budget.snapshot()
    with pytest.raises(budget_module.RunRequestBudgetError, match="history"):
        reserve(budget)


@pytest.mark.parametrize("operation", ["open", "snapshot", "reserve"])
def test_stale_request_index_fails_closed_before_duplicate_lookup(store, budget_module, operation):
    path, budget = store
    reserve(budget)
    with sqlite3.connect(path) as connection:
        page_size = connection.execute("PRAGMA page_size").fetchone()[0]
        root_page = connection.execute(
            "SELECT rootpage FROM sqlite_schema WHERE name='reservations'"
        ).fetchone()[0]
    # Corrupt the table's request ID while leaving its unique index untouched.
    # Keep the record length and file identity unchanged, so only cross-index
    # verification can detect this otherwise well-formed SQLite store.
    with path.open("r+b") as database:
        page_start = (root_page - 1) * page_size
        database.seek(page_start)
        page = database.read(page_size)
        assert page.count(b"request-0-1") == 1
        database.seek(page_start)
        database.write(page.replace(b"request-0-1", b"request-0-9"))
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA quick_check").fetchall() == [("ok",)]
        assert connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]
        assert connection.execute("SELECT request_id FROM reservations NOT INDEXED").fetchall() == [
            ("request-0-9",)
        ]
    with pytest.raises(budget_module.RunRequestBudgetError, match="corrupt"):
        if operation == "open":
            budget_module.RunRequestBudget.open(path, **IDENTITY)
        elif operation == "snapshot":
            budget.snapshot()
        else:
            reserve(budget, 9)
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT request_id FROM reservations NOT INDEXED").fetchall() == [
            ("request-0-9",)
        ]


def test_committed_rows_cannot_be_refunded_or_relabelled(store):
    path, budget = store
    reserve(budget)
    with sqlite3.connect(path) as connection:
        with pytest.raises(sqlite3.DatabaseError):
            connection.execute("DELETE FROM reservations")
        with pytest.raises(sqlite3.DatabaseError):
            connection.execute("UPDATE reservations SET allocation='deepseek_advisory'")
    assert budget.snapshot()["requests"] == 1


def test_ambiguous_commit_is_charged_on_reopen(store, budget_module, monkeypatch):
    path, budget = store
    real_connect = sqlite3.connect

    class LostCommitAcknowledgement(sqlite3.Connection):
        def commit(self):
            super().commit()
            raise sqlite3.OperationalError("lost acknowledgement after commit")

    with monkeypatch.context() as patch:
        patch.setattr(
            budget_module.sqlite3,
            "connect",
            lambda *args, **kwargs: real_connect(
                *args, **kwargs, factory=LostCommitAcknowledgement
            ),
        )
        with pytest.raises(budget_module.RunRequestBudgetError):
            reserve(budget)
    reopened = budget_module.RunRequestBudget.open(path, **IDENTITY)
    assert reopened.snapshot()["requests"] == 1
    with pytest.raises(budget_module.DuplicateRequestReservation):
        reserve(reopened)
    assert budget.snapshot()["requests"] == 1
    with pytest.raises(budget_module.RunRequestBudgetError, match="write failure"):
        reserve(budget, 2)


@pytest.mark.parametrize(
    ("counts", "allocation"),
    [([(1409, 0)], "primary_and_memory"), ([(0, 89)], "deepseek_advisory")],
)
def test_concurrent_final_allocation_slot_cannot_overshoot(
    store, budget_module, counts, allocation
):
    path, budget = store
    seed_history(path, counts)
    barrier = Barrier(4)

    def compete(number):
        independent = budget_module.RunRequestBudget.open(path, **IDENTITY)
        barrier.wait(timeout=30)
        try:
            return reserve(independent, number, allocation=allocation)
        except budget_module.RequestBudgetExceeded:
            return None

    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(compete, range(4)))
    assert sum(result is not None for result in results) == 1
    assert budget.snapshot()["tasks"]["task-0"][allocation] == (
        1410 if allocation == "primary_and_memory" else 90
    )
