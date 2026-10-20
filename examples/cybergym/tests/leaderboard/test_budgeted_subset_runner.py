# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Offline runner controls: synthetic Ed25519 artifacts, real state and resource store."""

from __future__ import annotations

from dataclasses import replace

import pytest
from nooa_cybergym.leaderboard import pinned_metering, run_resource_budget
from nooa_cybergym.leaderboard.budgeted_subset_admission import (
    bind_budgeted_subset_state,
    preview_budgeted_subset_admission,
)
from nooa_cybergym.leaderboard.campaign import _json_bytes
from nooa_cybergym.leaderboard.campaign_runner import UiTarget

from .test_budgeted_subset_admission import RealSignatureAuthority, setup, sha
from .test_run_resource_budget import inputs


@pytest.fixture
def runner_module():
    from nooa_cybergym.leaderboard import budgeted_subset_runner

    return budgeted_subset_runner


class Ui:
    def __init__(self, events):
        self.events = events
        self.on_open = self.on_close = self.on_reap = None

    def open(self, run_id, task_id, remote_host, ssh_port):
        self.events.append(("ui_open", task_id))
        if self.on_open:
            self.on_open()

    def close(self, run_id, task_id, remote_host):
        self.events.append(("ui_close", task_id))
        if self.on_close:
            self.on_close()

    def reap(self, run_id):
        self.events.append(("ui_reap", None))
        if self.on_reap:
            self.on_reap()


class Executor:
    """Fake controller effects; proof signatures and atomic closure are real."""

    def __init__(self, module, state, resources, authority, events):
        self.module = module
        self.state, self.resource_budget = state, resources
        self.authority, self.events = authority, events
        self.launches, self.terminals = {}, {}
        self.on_prepare = self.on_start = self.on_quiescence = None
        self.driver_stopped = True
        self.seal_accounting = True
        self.cleanup_error = None

    def prepare(self, task_id, preparation_id):
        self.events.append(("prepare", task_id))
        number = self.state.task_ids.index(task_id)
        launch = self.module.PreparedSubsetLaunch(
            task_id=task_id,
            preparation_id=preparation_id,
            request_id=f"request-{number}",
            attempt_id=f"attempt-{number}",
            launch_sha256=sha(f"signed-launch-{number}".encode()),
            ui_target=UiTarget("sunchaser", 2200 + number),
        )
        self.launches[task_id] = launch
        if self.on_prepare:
            self.on_prepare(task_id)
        return launch

    def recover_prepared(self, task_id, preparation_id):
        self.events.append(("recover_prepared", task_id))
        return self.launches.get(task_id)

    def start(self, launch):
        self.events.append(("send", launch.task_id))
        self.resource_budget.reserve(
            task_id=launch.task_id,
            attempt_id=launch.attempt_id,
            request_id=f"provider-{launch.request_id}",
            allocation="primary_and_memory",
        )
        if self.on_start:
            self.on_start(launch.task_id)

    def _terminal(self, task_id):
        if task_id not in self.terminals:
            self.terminals[task_id] = self.authority.put(
                "terminal_receipt",
                {
                    "schema_version": 1,
                    "artifact_kind": "terminal_receipt",
                    "run_id": self.state.run_id,
                    "epoch": self.state.epoch,
                    "task_id": task_id,
                    "status": "timeout",
                    "evidence_sha256": "2" * 64,
                },
            )
        return self.terminals[task_id]

    def await_terminal(self, task_id, request_id):
        self.events.append(("await_terminal", task_id))
        return self._terminal(task_id)

    def recover_terminal(self, task_id, request_id):
        self.events.append(("recover_terminal", task_id))
        return self.terminals.get(task_id)

    def await_driver_stopped(self, task_id, request_id):
        self.events.append(("driver_stopped", task_id))
        return self.driver_stopped

    def request_owned_stop(self, task_id, preparation_id, request_id):
        self.events.append(("owned_stop", task_id))
        if self.cleanup_error:
            raise self.cleanup_error

    def await_quiescence(self, task_id, request_id, terminal_receipt):
        self.events.append(("quiescence", task_id))
        assert self.events[-2][0] in {"ui_close", "ui_reap"}
        start = self.state.started_binding(task_id)
        snapshot = self.resource_budget.snapshot()
        raw = self.authority.put(
            "subset_driver_quiescence",
            {
                "schema_version": 1,
                "artifact_kind": "subset_driver_quiescence",
                "run_id": self.state.run_id,
                "epoch": self.state.epoch,
                "task_id": task_id,
                "attempt_id": start["attempt_id"],
                "request_id": start["request_id"],
                "launch_sha256": start["launch_sha256"],
                "terminal_receipt_sha256": sha(terminal_receipt),
                "budget_sha256": self.state.preview.budget.envelope_sha256,
                "final_accounting_sha256": snapshot["accounting_sha256"],
                "owned_cleanup_sha256": "3" * 64,
                "owned_cleanup_complete": True,
                "driver_stopped": True,
                "accounting_closed": True,
            },
        )
        if self.seal_accounting:
            self.resource_budget.close_task(
                task_id=task_id,
                attempt_id=start["attempt_id"],
                completion_sha256=sha(raw),
                expected_accounting_sha256=snapshot["accounting_sha256"],
            )
        if self.on_quiescence:
            self.on_quiescence(task_id)
        return raw

    def await_preparation_quiescence(self, task_id, preparation_id):
        self.events.append(("preparation_quiescence", task_id))
        assert self.events[-2][0] == "ui_reap"
        events = self.authority.read_verified_events(self.state.evidence_root, self.state.run_id)
        started = next(
            e for e in events if e.get("type") == "preparation_started" and e["task_id"] == task_id
        )
        prepared = next(
            (e for e in events if e.get("type") == "prepared" and e["task_id"] == task_id), None
        )
        return self.authority.put(
            "subset_preparation_quiescence",
            {
                "schema_version": 1,
                "artifact_kind": "subset_preparation_quiescence",
                "run_id": self.state.run_id,
                "epoch": self.state.epoch,
                "task_id": task_id,
                "budget_sha256": self.state.preview.budget.envelope_sha256,
                "preparation_id": preparation_id,
                "preparation_started_event_sha256": sha(_json_bytes(started)),
                "prepared_event_sha256": None if prepared is None else sha(_json_bytes(prepared)),
                "owned_cleanup_sha256": "3" * 64,
                "owned_cleanup_complete": True,
                "native_send_occurred": False,
            },
        )


@pytest.fixture
def bound(tmp_path, monkeypatch, runner_module):
    now = [1_800_000_000_000_000_000]
    monkeypatch.setattr(run_resource_budget, "_now_ns", lambda: now[0])
    metering = inputs((run_resource_budget, pinned_metering), spend=500000000)["metering"]
    authority, args, bindings = setup(tmp_path, RealSignatureAuthority())
    budget = dict(authority.artifacts[("subset_run_budget", args["signed_budget"])])
    budget["metering_policy_sha256"] = metering.sha256
    raw_budget = authority.put("subset_run_budget", budget)
    admission = dict(authority.artifacts[("budgeted_subset_admission", args["signed_admission"])])
    admission.update(budget_sha256=sha(raw_budget), metering_policy_sha256=metering.sha256)
    raw_admission = authority.put("budgeted_subset_admission", admission)
    args.update(
        signed_budget=raw_budget,
        expected_budget_sha256=sha(raw_budget),
        signed_admission=raw_admission,
        expected_admission_sha256=sha(raw_admission),
        metering_policy_sha256=metering.sha256,
    )
    preview = preview_budgeted_subset_admission(**args)
    resources = run_resource_budget.RunResourceBudget.create(
        tmp_path / "resources.sqlite",
        budget=preview.budget,
        authority=authority,
        metering=metering,
    )
    bindings["resource_budget"] = resources
    state = bind_budgeted_subset_state(preview, **bindings)
    authority.events.append(state.creation_event())
    events = []
    executor = Executor(runner_module, state, resources, authority, events)
    ui = Ui(events)
    return state, resources, executor, ui, authority, events, now


def run(module, bound):
    state, resources, executor, ui, *_ = bound
    return module.run_budgeted_subset(state, resources, executor, ui)


def test_all_ten_require_worker_stop_ui_cleanup_signed_quiescence_and_sealed_accounting(
    runner_module, bound
):
    state, resources, executor, ui, authority, events, now = bound
    executor.on_prepare = lambda _: now.__setitem__(0, now[0] + 1_000_000_000)
    assert run(runner_module, bound) == "complete"
    assert state.next_action().kind == "complete"
    assert len(resources.snapshot()["closures"]) == 10
    assert [task for kind, task in events if kind == "send"] == list(state.task_ids)
    for task in state.task_ids:
        task_events = [kind for kind, event_task in events if event_task == task]
        assert (
            task_events.index("driver_stopped")
            < task_events.index("ui_close")
            < task_events.index("quiescence")
        )
    assert resources.remaining_seconds() == 432000 - 10
    assert resources.snapshot()["requests"] == 10
    assert resources.snapshot()["spend_units"] == 110


def test_stop_before_preparation_has_no_attempt_or_send(runner_module, bound):
    state, resources, _, _, authority, events, now = bound
    now[0] += 432000 * 1_000_000_000
    assert run(runner_module, bound) == "stopped"
    assert state.next_action().kind == "stopped"
    assert not any(kind in {"prepare", "send"} for kind, _ in events)
    assert authority.events[-1]["unattempted_task_ids"] == list(state.task_ids)
    assert resources.snapshot()["requests"] == 0


@pytest.mark.parametrize("where", ["during_preparation", "after_ui_open"])
def test_stop_before_started_requires_signed_preparation_cleanup(runner_module, bound, where):
    state, resources, executor, ui, authority, events, _ = bound
    if where == "during_preparation":
        executor.on_prepare = lambda _: resources.stop(reason="operator_stop")
    else:
        ui.on_open = lambda: resources.stop(reason="operator_stop")
    assert run(runner_module, bound) == "stopped"
    assert not any(kind == "send" for kind, _ in events)
    assert any(event["type"] == "prepared_quiescent" for event in authority.events)
    assert not any(event["type"] == "started" for event in authority.events)
    assert authority.events[-1]["unattempted_task_ids"] == list(state.task_ids)


def test_limit_after_started_commit_before_send_requires_authentic_terminal(runner_module, bound):
    state, resources, executor, ui, authority, events, now = bound
    original = authority.append_event

    def append(root, run_id, event, expected_revision):
        accepted = original(root, run_id, event, expected_revision)
        if event["type"] == "started":
            now[0] += 432000 * 1_000_000_000
        return accepted

    authority.append_event = append
    assert run(runner_module, bound) == "stopped"
    assert not any(kind == "send" for kind, _ in events)
    assert any(event["type"] == "terminal" for event in authority.events)
    assert len(resources.snapshot()["closures"]) == 1
    assert authority.events[-1]["unattempted_task_ids"] == list(state.task_ids[1:])


def test_started_append_acknowledgement_failure_never_sends_on_recovery(runner_module, bound):
    state, resources, executor, ui, authority, events, _ = bound
    original = authority.append_event

    def append(root, run_id, event, expected_revision):
        result = original(root, run_id, event, expected_revision)
        return False if event["type"] == "started" else result

    authority.append_event = append
    with pytest.raises(RuntimeError, match="acknowledgement"):
        run(runner_module, bound)
    authority.append_event = original
    before = len(events)
    with pytest.raises(runner_module.SubsetRecoveryBlocked):
        run(runner_module, bound)
    assert not any(kind in {"prepare", "ui_open", "send"} for kind, _ in events[before:])
    assert not any(kind == "send" for kind, _ in events)
    assert len([event for event in authority.events if event["type"] == "started"]) == 1


def test_terminal_before_driver_stop_does_not_advance_or_sign_quiescence(runner_module, bound):
    state, resources, executor, ui, authority, events, _ = bound
    executor.driver_stopped = False
    with pytest.raises(runner_module.SubsetRecoveryBlocked):
        run(runner_module, bound)
    assert sum(event["type"] == "terminal" for event in authority.events) == 1
    assert not any(event["type"] == "task_quiescent" for event in authority.events)
    assert not resources.snapshot()["closures"]
    assert not any(kind == "quiescence" for kind, _ in events)
    assert [task for kind, task in events if kind == "prepare"] == [state.task_ids[0]]


def test_signed_quiescence_without_atomic_closure_cannot_advance(runner_module, bound):
    state, resources, executor, ui, authority, events, _ = bound
    executor.seal_accounting = False
    with pytest.raises(RuntimeError, match="sealed accounting"):
        run(runner_module, bound)
    assert not any(event["type"] == "task_quiescent" for event in authority.events)
    assert [task for kind, task in events if kind == "prepare"] == [state.task_ids[0]]


def test_cleanup_failure_preserves_error_and_blocks_quiescence(runner_module, bound):
    state, resources, executor, ui, authority, events, _ = bound
    failure = OSError("Windows cleanup failed")

    def fail():
        raise failure

    ui.on_close = fail
    with pytest.raises(OSError) as raised:
        run(runner_module, bound)
    assert raised.value is failure
    assert not resources.snapshot()["closures"]
    assert not any(kind == "quiescence" for kind, _ in events)


def test_secondary_cleanup_failure_does_not_replace_primary_error(runner_module, bound):
    state, resources, executor, ui, authority, events, _ = bound
    primary = RuntimeError("original preparation failure")

    def fail(_):
        raise primary

    executor.on_prepare = fail
    executor.cleanup_error = OSError("secondary owned cleanup failure")
    with pytest.raises(RuntimeError) as raised:
        run(runner_module, bound)
    assert raised.value is primary
    assert any("secondary owned cleanup failure" in note for note in raised.value.__notes__)
    assert not any(event["type"] == "prepared_quiescent" for event in authority.events)


def test_final_cleanup_overrun_is_recorded_as_run_stop(runner_module, bound):
    state, resources, executor, ui, authority, events, now = bound

    def finish():
        if len(resources.snapshot()["closures"]) == 10:
            now[0] += 432000 * 1_000_000_000

    ui.on_reap = finish
    assert run(runner_module, bound) == "stopped"
    assert resources.snapshot()["stop"]["reason"] == "elapsed_limit"
    assert state.next_action().kind == "stopped"
    assert authority.events[-1]["unattempted_task_ids"] == []


def test_runner_rejects_different_or_legacy_state_and_resource_handles(runner_module, bound):
    state, resources, executor, ui, *_ = bound
    with pytest.raises(TypeError):
        runner_module.run_budgeted_subset(object(), resources, executor, ui)
    with pytest.raises(TypeError):
        runner_module.run_budgeted_subset(state, object(), executor, ui)
    with pytest.raises(ValueError, match="binding"):
        runner_module.run_budgeted_subset(replace(state), resources, executor, ui)


def test_started_recovery_uses_existing_terminal_without_preparation_open_or_send(
    runner_module, bound
):
    state, resources, executor, ui, authority, events, _ = bound
    task_id = state.task_ids[0]
    state.mark_preparation_started(task_id, preparation_id="previous-controller")
    launch = executor.prepare(task_id, "previous-controller")
    state.mark_prepared(task_id)
    state.mark_started(
        task_id,
        request_id=launch.request_id,
        attempt_id=launch.attempt_id,
        launch_sha256=launch.launch_sha256,
    )
    executor._terminal(task_id)
    executor.on_quiescence = lambda _: resources.stop(reason="operator_stop")
    events.clear()
    assert run(runner_module, bound) == "stopped"
    assert not any(kind in {"prepare", "ui_open", "send"} for kind, _ in events)
    assert ("recover_terminal", task_id) in events
    assert len(resources.snapshot()["closures"]) == 1


@pytest.mark.parametrize("prepared_exists", [True, False])
def test_preparing_recovery_never_repeats_preparation(runner_module, bound, prepared_exists):
    state, resources, executor, ui, authority, events, _ = bound
    task_id = state.task_ids[0]
    state.mark_preparation_started(task_id, preparation_id="previous-controller")
    if prepared_exists:
        executor.prepare(task_id, "previous-controller")
        executor.on_quiescence = lambda _: resources.stop(reason="operator_stop")
    events.clear()
    if prepared_exists:
        assert run(runner_module, bound) == "stopped"
        assert [task for kind, task in events if kind == "send"] == [task_id]
    else:
        with pytest.raises(runner_module.SubsetRecoveryBlocked, match="restaging"):
            run(runner_module, bound)
        assert not any(kind == "send" for kind, _ in events)
    assert not any(kind == "prepare" for kind, _ in events)
    assert ("recover_prepared", task_id) in events


def test_terminal_without_signed_quiescence_remains_blocked(runner_module, bound):
    state, resources, executor, ui, authority, events, _ = bound
    executor.await_quiescence = lambda *_: None
    with pytest.raises(runner_module.SubsetRecoveryBlocked, match="quiescence"):
        run(runner_module, bound)
    assert not resources.snapshot()["closures"]
    assert not any(event["type"] == "task_quiescent" for event in authority.events)
    assert sum(event["type"] == "terminal" for event in authority.events) == 1


@pytest.mark.parametrize(
    "field,value",
    [("task_id", "arvo:wrong"), ("preparation_id", "other-owner"), ("launch_sha256", "unsigned")],
)
def test_substituted_prepared_launch_never_starts(runner_module, bound, field, value):
    state, resources, executor, ui, authority, events, _ = bound
    prepare = executor.prepare

    def wrong_launch(task_id, preparation_id):
        return replace(prepare(task_id, preparation_id), **{field: value})

    executor.prepare = wrong_launch
    with pytest.raises(RuntimeError, match="launch identity"):
        run(runner_module, bound)
    assert not any(kind in {"ui_open", "send"} for kind, _ in events)
    assert not any(event["type"] == "started" for event in authority.events)


def test_independent_readiness_failure_blocks_all_effects(runner_module, bound):
    state, resources, _, _, _, events, _ = bound
    state.readiness_verifier.accepted = False
    with pytest.raises(RuntimeError, match="readiness"):
        run(runner_module, bound)
    assert events == []
    assert resources.snapshot()["stop"] is None
