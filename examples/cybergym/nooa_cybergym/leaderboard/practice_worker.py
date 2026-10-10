# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""One controller-owned live native driver at a time for the practice pair."""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, field

from .practice_campaign import PRACTICE_TASK_IDS


@dataclass(slots=True)
class _Task:
    task_id: str
    ready: threading.Event = field(default_factory=threading.Event)
    done: threading.Event = field(default_factory=threading.Event)
    stop: threading.Event = field(default_factory=threading.Event)
    thread: threading.Thread | None = None
    launch: object | None = None
    receipt: bytes | None = None
    error: BaseException | None = None


class PracticeNativeWorker:
    """Prepare once, await one signed receipt, and fail closed on ambiguity."""

    def __init__(
        self,
        *,
        state,
        driver: Callable,
        ready_timeout_seconds: float = 180,
        terminal_timeout_seconds: float = 43200,
    ) -> None:
        if (
            type(getattr(state, "run_id", None)) is not str
            or not callable(getattr(state, "next_action", None))
            or not callable(driver)
            or type(ready_timeout_seconds) not in {int, float}
            or not 0 < ready_timeout_seconds <= 600
            or type(terminal_timeout_seconds) not in {int, float}
            or not 60 <= terminal_timeout_seconds <= 43200
        ):
            raise ValueError("bounded signed practice worker inputs required")
        self.state = state
        self.driver = driver
        self.ready_timeout = ready_timeout_seconds
        self.terminal_timeout = terminal_timeout_seconds
        self._lock = threading.Lock()
        self._tasks: dict[str, _Task] = {}

    def _run(self, task: _Task) -> None:
        def prepared(launch) -> None:
            if task.launch is not None or getattr(launch, "task_id", None) != task.task_id:
                raise RuntimeError("native practice launch was duplicated or task-swapped")
            task.launch = launch
            task.ready.set()

        try:
            receipt = self.driver(task.task_id, on_prepared=prepared, stop=task.stop)
            if task.launch is None or type(receipt) is not bytes or not receipt:
                raise RuntimeError("native practice driver lacked a launch or signed receipt")
            task.receipt = receipt
        except BaseException as error:
            task.error = error
        finally:
            task.ready.set()
            task.done.set()

    def ensure_prepared(self, task_id: str):
        if task_id not in PRACTICE_TASK_IDS or self.state.next_action().task_id != task_id:
            raise ValueError("only current signed practice task can be prepared")
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                if self.state.next_action().kind != "prepare":
                    raise RuntimeError(
                        "prepared native task lost controller custody; refuse duplicate container"
                    )
                if any(not prior.done.is_set() for prior in self._tasks.values()):
                    raise RuntimeError("prior practice task is not terminal")
                task = _Task(task_id)
                self._tasks[task_id] = task
                task.thread = threading.Thread(
                    target=self._run, args=(task,), name=f"practice-{task_id}", daemon=True
                )
                task.thread.start()
        if not task.ready.wait(self.ready_timeout):
            task.stop.set()
            raise TimeoutError("native practice preparation did not become observable")
        if task.error is not None:
            raise task.error
        if task.launch is None:
            raise RuntimeError("native practice prepared launch is absent")
        return task.launch

    def await_terminal(self, task_id: str) -> bytes:
        task = self._tasks.get(task_id)
        if task is None or task.launch is None:
            raise RuntimeError("current native practice task was not prepared")
        if not task.done.wait(self.terminal_timeout):
            task.stop.set()
            raise TimeoutError("native practice terminal receipt did not arrive")
        if task.error is not None:
            raise task.error
        if type(task.receipt) is not bytes or not task.receipt:
            raise RuntimeError("signed native practice terminal receipt is absent")
        return task.receipt

    def abort(self) -> None:
        """Signal the active driver and wait for Docker context cleanup."""
        for task in self._tasks.values():
            task.stop.set()
        for task in self._tasks.values():
            if task.thread is not None and task.thread.is_alive():
                task.thread.join(timeout=30)
                if task.thread.is_alive():
                    raise RuntimeError("native practice driver did not stop after abort")
