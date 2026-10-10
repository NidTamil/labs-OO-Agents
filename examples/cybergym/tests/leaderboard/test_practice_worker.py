# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""The practice worker starts one driver and never retries a failed launch."""

from types import SimpleNamespace

import pytest
from nooa_cybergym.leaderboard.practice_worker import PracticeNativeWorker


class State:
    run_id = "practice-run"

    def __init__(self):
        self.task_id = "arvo:47101"
        self.kind = "prepare"

    def next_action(self):
        return SimpleNamespace(task_id=self.task_id, kind=self.kind)


def test_worker_prepares_once_then_returns_one_terminal_receipt():
    state = State()
    calls = []
    launch = SimpleNamespace(task_id="arvo:47101")

    def driver(task_id, *, on_prepared, stop):
        calls.append(task_id)
        on_prepared(launch)
        assert not stop.is_set()
        return b"signed-terminal"

    worker = PracticeNativeWorker(state=state, driver=driver, ready_timeout_seconds=2)
    assert worker.ensure_prepared("arvo:47101") is launch
    assert worker.ensure_prepared("arvo:47101") is launch
    assert worker.await_terminal("arvo:47101") == b"signed-terminal"
    assert calls == ["arvo:47101"]


def test_worker_fails_closed_when_driver_fails_before_prepared():
    state = State()
    calls = []

    def driver(task_id, *, on_prepared, stop):
        calls.append(task_id)
        raise RuntimeError("preparation failed")

    worker = PracticeNativeWorker(state=state, driver=driver, ready_timeout_seconds=2)
    with pytest.raises(RuntimeError, match="preparation failed"):
        worker.ensure_prepared("arvo:47101")
    with pytest.raises(RuntimeError, match="preparation failed"):
        worker.ensure_prepared("arvo:47101")
    assert calls == ["arvo:47101"]


def test_worker_rejects_next_task_until_current_driver_is_terminal():
    state = State()
    launch = SimpleNamespace(task_id="arvo:47101")

    def driver(task_id, *, on_prepared, stop):
        on_prepared(launch)
        stop.wait(2)
        return b"signed-terminal"

    worker = PracticeNativeWorker(state=state, driver=driver, ready_timeout_seconds=2)
    assert worker.ensure_prepared("arvo:47101") is launch
    state.task_id = "arvo:3938"
    with pytest.raises(RuntimeError, match="prior practice task"):
        worker.ensure_prepared("arvo:3938")
    worker.abort()


def test_worker_refuses_to_reprepare_started_task_after_process_restart():
    state = State()
    state.kind = "observe_started"
    called = []
    worker = PracticeNativeWorker(
        state=state,
        driver=lambda *args, **kwargs: called.append(args),
    )
    with pytest.raises(RuntimeError, match="refuse duplicate container"):
        worker.ensure_prepared("arvo:47101")
    assert called == []
