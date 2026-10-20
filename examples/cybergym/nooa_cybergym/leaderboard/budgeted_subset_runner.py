# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Explicit serial runner for an already admitted, resource-bound subset.

This module neither admits nor signs a run and has no live CLI entrypoint. The
trusted executor must independently verify prepared launch material, recover
existing artifacts without restaging, and produce genuine signed quiescence
only after owned worker and Windows UI cleanup. Concrete pinned worker, launch,
failure-evidence and completion writers are separate integration work.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal, Protocol
from uuid import uuid4

from .budgeted_subset_admission import BudgetedSubsetState
from .campaign_runner import NativeUiController, UiTarget
from .run_resource_budget import ResourceBudgetStopped, RunResourceBudget

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")


class SubsetRecoveryBlocked(RuntimeError):
    """Existing evidence is incomplete; no new attempt or Send is permitted."""


@dataclass(frozen=True, slots=True)
class PreparedSubsetLaunch:
    """One executor-verified launch, never assembled from separate selectors.

    The controller executor verifies actual signed launch bytes, ownership and
    pinned material before returning this value. Merely constructing this value
    is not launch authority and does not establish readiness.
    """

    task_id: str
    preparation_id: str
    request_id: str
    attempt_id: str
    launch_sha256: str
    ui_target: UiTarget


class BudgetedSubsetExecutor(Protocol):
    """Trusted effects bound to the exact admitted state and resource store.

    All waiting/stop methods operate on existing owned processes only. They must
    honor the persisted aggregate deadline and produce authentic failure evidence
    if a committed start has no Send. None may start a second native attempt.
    Quiescence methods independently verify durable Windows cleanup acknowledgments
    and atomic resource closure; a caller's cleanup boolean is insufficient.
    """

    state: BudgetedSubsetState
    resource_budget: RunResourceBudget

    def prepare(self, task_id: str, preparation_id: str) -> PreparedSubsetLaunch: ...

    def recover_prepared(
        self, task_id: str, preparation_id: str
    ) -> PreparedSubsetLaunch | None: ...

    def start(self, launch: PreparedSubsetLaunch) -> None: ...

    def await_terminal(self, task_id: str, request_id: str) -> bytes | None: ...

    def recover_terminal(self, task_id: str, request_id: str) -> bytes | None: ...

    def await_driver_stopped(self, task_id: str, request_id: str) -> bool: ...

    def request_owned_stop(
        self, task_id: str, preparation_id: str, request_id: str | None
    ) -> None: ...

    def await_quiescence(
        self, task_id: str, request_id: str, terminal_receipt: bytes
    ) -> bytes | None: ...

    def await_preparation_quiescence(self, task_id: str, preparation_id: str) -> bytes | None: ...


def _launch(value, *, task_id: str, preparation_id: str) -> PreparedSubsetLaunch:
    if value is None:
        raise SubsetRecoveryBlocked(
            "verified prepared launch is not available; restaging forbidden"
        )
    if (
        type(value) is not PreparedSubsetLaunch
        or value.task_id != task_id
        or value.preparation_id != preparation_id
        or any(
            type(item) is not str or _ID.fullmatch(item) is None
            for item in (value.preparation_id, value.request_id, value.attempt_id)
        )
        or type(value.launch_sha256) is not str
        or _HASH.fullmatch(value.launch_sha256) is None
        or type(value.ui_target) is not UiTarget
        or type(value.ui_target.remote_host) is not str
        or re.fullmatch(r"[a-z][a-z0-9-]{1,63}", value.ui_target.remote_host) is None
        or type(value.ui_target.ssh_port) is not int
        or not 1024 <= value.ui_target.ssh_port <= 65535
    ):
        raise RuntimeError("verified prepared launch identity or UI target differs")
    return value


def _evidence(raw, label: str) -> bytes:
    if raw is None:
        raise SubsetRecoveryBlocked(f"existing signed {label} unavailable; recovery is blocked")
    if type(raw) is not bytes or not raw:
        raise RuntimeError(f"signed {label} bytes required")
    return raw


def _allow(resources: RunResourceBudget) -> bool:
    try:
        resources.check_active()
    except ResourceBudgetStopped:
        return False
    return True


def _record_stop(state: BudgetedSubsetState) -> None:
    if state.next_action().kind == "request_stop":
        state.request_stop()


def run_budgeted_subset(
    state: BudgetedSubsetState,
    resources: RunResourceBudget,
    executor: BudgetedSubsetExecutor,
    ui: NativeUiController,
) -> Literal["complete", "stopped"]:
    """Advance authentic lifecycle evidence; recovery never sends a started task.

    The resource clock must have been created before preparation. No legacy
    state, substitute store, automatic admission or terminal-only completion is
    accepted. A start receives Send only in the invocation that acknowledged its
    durable started event; ambiguous appends and process restarts recover evidence.
    """
    if type(state) is not BudgetedSubsetState or type(resources) is not RunResourceBudget:
        raise TypeError("explicit budgeted subset state and resource store required")
    if (
        state.resource_budget is not resources
        or getattr(executor, "state", None) is not state
        or getattr(executor, "resource_budget", None) is not resources
    ):
        raise ValueError("exact executor/state/resource binding required")
    if not all(
        callable(getattr(executor, name, None))
        for name in (
            "prepare",
            "recover_prepared",
            "start",
            "await_terminal",
            "recover_terminal",
            "await_driver_stopped",
            "request_owned_stop",
            "await_quiescence",
            "await_preparation_quiescence",
        )
    ) or not all(callable(getattr(ui, name, None)) for name in ("open", "close", "reap")):
        raise TypeError("complete controller executor and owned UI interfaces required")
    # Fail before effects if admission, raw readiness or existing state is invalid.
    state.next_action()
    current_task = None
    launch = None
    open_task = None
    pending_send = None
    invocation_started: set[tuple[str, str]] = set()
    stop_requested: set[tuple[str, str | None]] = set()

    def stop_owned(task_id: str, request_id: str | None) -> None:
        identity = (task_id, request_id)
        if identity not in stop_requested:
            preparation_id = state.preparation_binding(task_id)["preparation_id"]
            executor.request_owned_stop(task_id, preparation_id, request_id)
            stop_requested.add(identity)

    try:
        while True:
            _record_stop(state)
            action = state.next_action()
            current_task = action.task_id
            if action.kind in {"complete", "finalize_stop"}:
                ui.reap(state.run_id)
                allowed = _allow(resources)  # Final cleanup is part of aggregate elapsed time.
                if action.kind == "complete":
                    if not allowed:
                        continue
                    return "complete"
                state.finalize_stop()
                return "stopped"
            if action.kind == "stopped":
                return "stopped"
            if current_task is None:
                raise RuntimeError("budgeted subset action lacks current task")
            task_id = current_task

            if action.kind == "prepare":
                if not _allow(resources):
                    continue
                preparation_id = uuid4().hex
                state.mark_preparation_started(task_id, preparation_id=preparation_id)
                if not _allow(resources):
                    continue
                launch = _launch(
                    executor.prepare(task_id, preparation_id),
                    task_id=task_id,
                    preparation_id=preparation_id,
                )
                if not _allow(resources):
                    continue
                state.mark_prepared(task_id)

            elif action.kind == "observe_preparing":
                if not _allow(resources):
                    continue
                preparation_id = state.preparation_binding(task_id)["preparation_id"]
                launch = _launch(
                    executor.recover_prepared(task_id, preparation_id),
                    task_id=task_id,
                    preparation_id=preparation_id,
                )
                if not _allow(resources):
                    continue
                state.mark_prepared(task_id)

            elif action.kind == "observe_prepared":
                preparation_id = state.preparation_binding(task_id)["preparation_id"]
                if launch is None or launch.task_id != task_id:
                    launch = _launch(
                        executor.recover_prepared(task_id, preparation_id),
                        task_id=task_id,
                        preparation_id=preparation_id,
                    )
                launch = _launch(launch, task_id=task_id, preparation_id=preparation_id)
                if not _allow(resources):
                    continue
                ui.open(
                    state.run_id, task_id, launch.ui_target.remote_host, launch.ui_target.ssh_port
                )
                open_task = launch
                if not _allow(resources):
                    continue
                state.mark_started(
                    task_id,
                    request_id=launch.request_id,
                    attempt_id=launch.attempt_id,
                    launch_sha256=launch.launch_sha256,
                )
                invocation_started.add((task_id, launch.request_id))
                pending_send = launch

            elif action.kind == "observe_started":
                start = state.started_binding(task_id)
                request_id = start["request_id"]
                if pending_send is not None and pending_send.task_id == task_id:
                    sending = pending_send
                    pending_send = None  # Never replay an ambiguous submit call.
                    if _allow(resources):
                        executor.start(sending)
                    else:
                        _record_stop(state)
                        stop_owned(task_id, request_id)
                if resources.snapshot()["stop"] is not None:
                    stop_owned(task_id, request_id)
                if (task_id, request_id) in invocation_started:
                    raw = executor.await_terminal(task_id, request_id)
                else:
                    raw = executor.recover_terminal(task_id, request_id)
                receipt = _evidence(raw, "terminal receipt")
                _record_stop(state)
                state.mark_terminal(task_id, receipt)

            elif action.kind == "observe_terminal":
                start = state.started_binding(task_id)
                request_id = start["request_id"]
                receipt = state.current_terminal_receipt(task_id)
                if executor.await_driver_stopped(task_id, request_id) is not True:
                    raise SubsetRecoveryBlocked("driver/accounting writers are not yet stopped")
                if open_task is not None and open_task.task_id == task_id:
                    ui.close(state.run_id, task_id, open_task.ui_target.remote_host)
                else:
                    ui.reap(state.run_id)
                open_task = None
                _allow(resources)  # Observe cleanup time; permission never gates cleanup.
                _record_stop(state)
                completion = _evidence(
                    executor.await_quiescence(task_id, request_id, receipt), "driver quiescence"
                )
                _record_stop(state)
                state.mark_quiescent(task_id, completion)
                launch = None

            elif action.kind == "cleanup_prepared":
                preparation_id = state.preparation_binding(task_id)["preparation_id"]
                stop_owned(task_id, None)
                ui.reap(state.run_id)
                open_task = None
                _allow(resources)
                completion = _evidence(
                    executor.await_preparation_quiescence(task_id, preparation_id),
                    "preparation quiescence",
                )
                state.mark_preparation_quiescent(task_id, completion)
                launch = None
            else:
                raise RuntimeError(f"unsupported budgeted subset action: {action.kind!r}")
    except BaseException as error:
        # Preserve the primary failure. Best-effort cleanup never manufactures a
        # terminal/quiescence event or gives another invocation Send permission.
        primary_error = error

        def cleanup(label, effect):
            try:
                effect()
            except BaseException as secondary:
                primary_error.add_note(f"{label} failed: {type(secondary).__name__}: {secondary}")

        cleanup("durable run stop", lambda: resources.stop(reason="controller_failure"))
        cleanup("run stop evidence", lambda: _record_stop(state))
        if current_task is not None:

            def stop_current():
                binding = state.preparation_binding(current_task)
                try:
                    request_id = state.started_binding(current_task)["request_id"]
                except RuntimeError:
                    request_id = None
                executor.request_owned_stop(current_task, binding["preparation_id"], request_id)

            cleanup("owned task stop", stop_current)
        cleanup("owned Windows UI cleanup", lambda: ui.reap(state.run_id))
        cleanup("cleanup elapsed observation", lambda: _allow(resources))
        raise
