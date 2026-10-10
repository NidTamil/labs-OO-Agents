# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""The full-cohort worker is serial and refuses ambiguous relaunch."""

from types import SimpleNamespace

import pytest
from nooa_cybergym.leaderboard.cohort_native_worker import CohortNativeWorker


class State:
    run_id = "scored-run"
    task_ids = ("arvo:47101", "oss-fuzz:42535201")

    def __init__(self):
        self.task_id = self.task_ids[0]
        self.kind = "prepare"

    def next_action(self):
        return SimpleNamespace(task_id=self.task_id, kind=self.kind)


def test_cohort_worker_runs_each_family_once_in_order():
    state = State()
    calls = []

    def driver(task_id, *, on_prepared, stop):
        calls.append(task_id)
        on_prepared(SimpleNamespace(task_id=task_id))
        assert not stop.is_set()
        return b"signed-terminal"

    worker = CohortNativeWorker(state=state, driver=driver, ready_timeout_seconds=2)
    assert worker.ensure_prepared("arvo:47101").task_id == "arvo:47101"
    assert worker.ensure_prepared("arvo:47101").task_id == "arvo:47101"
    assert worker.await_terminal("arvo:47101") == b"signed-terminal"
    state.task_id = "oss-fuzz:42535201"
    assert worker.ensure_prepared("oss-fuzz:42535201").task_id == "oss-fuzz:42535201"
    assert worker.await_terminal("oss-fuzz:42535201") == b"signed-terminal"
    assert calls == ["arvo:47101", "oss-fuzz:42535201"]


def test_cohort_worker_rejects_task_swap_and_parallel_driver():
    state = State()
    launch = SimpleNamespace(task_id="arvo:47101")

    def driver(task_id, *, on_prepared, stop):
        on_prepared(launch)
        stop.wait(2)
        return b"signed-terminal"

    worker = CohortNativeWorker(state=state, driver=driver, ready_timeout_seconds=2)
    with pytest.raises(ValueError, match="current signed cohort"):
        worker.ensure_prepared("oss-fuzz:42535201")
    assert worker.ensure_prepared("arvo:47101") is launch
    state.task_id = "oss-fuzz:42535201"
    with pytest.raises(RuntimeError, match="prior cohort task"):
        worker.ensure_prepared("oss-fuzz:42535201")
    worker.abort()


def test_cohort_worker_fails_closed_after_driver_error_and_process_restart():
    state = State()
    calls = []

    def driver(task_id, *, on_prepared, stop):
        calls.append(task_id)
        raise RuntimeError("prepare failed")

    worker = CohortNativeWorker(state=state, driver=driver, ready_timeout_seconds=2)
    with pytest.raises(RuntimeError, match="prepare failed"):
        worker.ensure_prepared("arvo:47101")
    with pytest.raises(RuntimeError, match="prepare failed"):
        worker.ensure_prepared("arvo:47101")
    assert calls == ["arvo:47101"]
    state.kind = "observe_started"
    replacement = CohortNativeWorker(state=state, driver=driver, ready_timeout_seconds=2)
    with pytest.raises(RuntimeError, match="refuse duplicate container"):
        replacement.ensure_prepared("arvo:47101")
    assert calls == ["arvo:47101"]
