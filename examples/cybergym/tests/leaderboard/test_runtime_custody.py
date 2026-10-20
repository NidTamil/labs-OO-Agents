# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
import base64
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor

import pytest
from nooa_cybergym.leaderboard.runtime_custody import AttemptStart, RuntimeAudit


def test_shared_start_is_concurrent_idempotent_but_restart_is_rejected(tmp_path):
    tmp_path.chmod(0o700)
    path = tmp_path / "attempt.sqlite"
    start = AttemptStart(path, task_id="synthetic:length-header", attempt_id="first")
    assert not start.started
    assert not start.mark_started("other", "first")
    with ThreadPoolExecutor(max_workers=8) as executor:
        assert all(executor.map(lambda _: start.mark_started(start.task_id, "first"), range(16)))
    assert start.started
    with pytest.raises(RuntimeError, match="budget reset"):
        AttemptStart(path, task_id=start.task_id, attempt_id="first")


def test_audit_marks_actual_memory_admission_and_redacts_encoded_secrets(tmp_path):
    tmp_path.chmod(0o700)
    start = AttemptStart(
        tmp_path / "attempt.sqlite", task_id="synthetic:chunk-table", attempt_id="first"
    )
    path = tmp_path / "events.jsonl"
    secret = "synthetic-controller-secret"
    with RuntimeAudit(path, secrets=(secret,), start=start) as audit:
        audit.record({"event": "memory_scope_inspection"})
        assert not start.started
        audit.record(
            {
                "event": "memory_model_admitted",
                "payload": [secret, base64.b64encode(secret.encode()).decode()],
            }
        )
        assert start.started
        audit.record({"event": "after"})
    content = path.read_text()
    assert secret not in content and base64.b64encode(secret.encode()).decode() not in content
    previous = "0" * 64
    for index, line in enumerate(content.splitlines(), 1):
        row = json.loads(line)
        digest = row.pop("sha256")
        assert row["sequence"] == index and row["previous_sha256"] == previous
        assert (
            hashlib.sha256(
                json.dumps(row, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
            ).hexdigest()
            == digest
        )
        previous = digest


def test_audit_failure_permanently_denies_following_effects(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    start = AttemptStart(
        tmp_path / "attempt.sqlite", task_id="synthetic:length-header", attempt_id="first"
    )
    with RuntimeAudit(tmp_path / "events.jsonl", secrets=("synthetic-key",), start=start) as audit:
        monkeypatch.setattr(
            "nooa_cybergym.leaderboard.runtime_custody.os.fsync",
            lambda _: (_ for _ in ()).throw(OSError("disk")),
        )
        with pytest.raises(OSError):
            audit.record({"event": "first"})
        with pytest.raises(RuntimeError, match="unavailable"):
            audit.record({"event": "second"})


def test_task_context_owns_one_budget_and_audit_and_cannot_restart(tmp_path):
    from nooa_cybergym.leaderboard.runtime_custody import TaskRuntimeContext

    with TaskRuntimeContext(
        tmp_path, task_id="synthetic:length-header", attempt_id="first", secrets=("synthetic-key",)
    ) as context:
        assert context.audit.start is context.start
        assert context.budget.reserve_request() == 1
        assert context.budget.reserve_deepseek_request() == 2
        assert context.budget.snapshot()["requests"] == 2
        context.halt()
        with pytest.raises(Exception, match="budget|halted|exhausted"):
            context.budget.reserve_request()
        assert context.audit.record({"event": "terminal-after-halt"}) is True
    with pytest.raises(RuntimeError, match="budget reset"):
        TaskRuntimeContext(
            tmp_path,
            task_id="synthetic:length-header",
            attempt_id="first",
            secrets=("synthetic-key",),
        )


def test_invalid_event_permanently_halts_audit(tmp_path):
    start = AttemptStart(
        tmp_path / "attempt.sqlite", task_id="synthetic:length-header", attempt_id="first"
    )
    with RuntimeAudit(tmp_path / "events.jsonl", secrets=("synthetic-key",), start=start) as audit:
        with pytest.raises((TypeError, ValueError)):
            audit.record(None)
        with pytest.raises(RuntimeError, match="unavailable"):
            audit.record({"event": "after-invalid"})


def test_removed_audit_destination_prevents_acknowledged_invisible_writes(tmp_path):
    import os

    if os.name != "posix":
        pytest.skip("POSIX permits unlinking an open audit descriptor")
    start = AttemptStart(
        tmp_path / "attempt.sqlite", task_id="synthetic:length-header", attempt_id="first"
    )
    path = tmp_path / "events.jsonl"
    with RuntimeAudit(path, secrets=("synthetic-key",), start=start) as audit:
        path.unlink()
        with pytest.raises(RuntimeError, match="audit"):
            audit.record({"event": "must-not-ack"})


def _run_budget(tmp_path):
    from nooa_cybergym.leaderboard.run_request_budget import RunRequestBudget

    tmp_path.chmod(0o700)
    return RunRequestBudget.create(
        tmp_path / "run-requests.sqlite",
        run_id="ten-task-run",
        epoch="takeover-v1",
        policy_sha256="a" * 64,
        ordered_task_ids=tuple(f"arvo:{i}" for i in range(10)),
    )


def test_task_context_all_model_lanes_share_durable_run_debits(tmp_path):
    from nooa_cybergym.leaderboard.runtime_custody import TaskRuntimeContext

    ledger = _run_budget(tmp_path)
    evidence = tmp_path / "task"
    evidence.mkdir(mode=0o700)
    with TaskRuntimeContext(
        evidence,
        task_id="arvo:0",
        attempt_id="attempt-0",
        secrets=("synthetic-key",),
        run_request_budget=ledger,
    ) as context:
        # Native GLM, primary takeover and memory use the same primary method.
        assert [context.budget.reserve_request() for _ in range(3)] == [1, 2, 3]
        assert context.budget.reserve_deepseek_request() == 4
        assert context.budget.snapshot()["requests"] == 4
        assert ledger.snapshot()["tasks"]["arvo:0"] == {
            "requests": 4,
            "primary_and_memory": 3,
            "deepseek_advisory": 1,
        }
        rows = [json.loads(line)["event"] for line in context.audit.path.read_text().splitlines()]
        assert [row["task_ordinal"] for row in rows] == [1, 2, 3, 4]
        assert [row["run_ordinal"] for row in rows] == [1, 2, 3, 4]
        assert all(row["event"] == "run_request_reserved" for row in rows)
        assert len({row["request_id"] for row in rows}) == 4
        context.halt()
        with pytest.raises(Exception, match="exhausted|halted"):
            context.budget.reserve_request()
        assert ledger.snapshot()["requests"] == 4


def test_run_debit_survives_failed_lane_audit_and_blocks_dispatch(tmp_path, monkeypatch):
    from nooa_cybergym.leaderboard.runtime_custody import TaskRuntimeContext

    ledger = _run_budget(tmp_path)
    evidence = tmp_path / "task"
    evidence.mkdir(mode=0o700)
    with TaskRuntimeContext(
        evidence,
        task_id="arvo:0",
        attempt_id="attempt-0",
        secrets=("synthetic-key",),
        run_request_budget=ledger,
    ) as context:
        monkeypatch.setattr(context.audit, "record", lambda _: False)
        with pytest.raises(Exception, match="audit"):
            context.budget.reserve_request()
        assert ledger.snapshot()["requests"] == 1
        assert context.budget.snapshot()["requests"] == 1
        with pytest.raises(Exception, match="exhausted|halted"):
            context.budget.reserve_deepseek_request()
        assert ledger.snapshot()["requests"] == 1


def test_new_context_cannot_reset_previously_reserved_run_task(tmp_path):
    from nooa_cybergym.leaderboard.runtime_custody import TaskRuntimeContext

    ledger = _run_budget(tmp_path)
    ledger.reserve(
        task_id="arvo:0",
        attempt_id="attempt-0",
        request_id="already-reserved",
        allocation="primary_and_memory",
    )
    evidence = tmp_path / "new-location"
    evidence.mkdir(mode=0o700)
    with pytest.raises(Exception, match="reserved|reset|resume"):
        TaskRuntimeContext(
            evidence,
            task_id="arvo:0",
            attempt_id="attempt-0",
            secrets=("synthetic-key",),
            run_request_budget=ledger,
        )
    assert ledger.snapshot()["requests"] == 1


def test_unknown_task_cannot_bind_run_budget(tmp_path):
    from nooa_cybergym.leaderboard.runtime_custody import TaskRuntimeContext

    ledger = _run_budget(tmp_path)
    evidence = tmp_path / "task"
    evidence.mkdir(mode=0o700)
    with pytest.raises(ValueError, match="task"):
        TaskRuntimeContext(
            evidence,
            task_id="arvo:999",
            attempt_id="attempt-0",
            secrets=("synthetic-key",),
            run_request_budget=ledger,
        )
    assert ledger.snapshot()["requests"] == 0


def test_advisory_exhaustion_does_not_halt_remaining_primary_pool(tmp_path):
    from nooa_cybergym.leaderboard.deepseek import BudgetExceeded
    from nooa_cybergym.leaderboard.runtime_custody import TaskRuntimeContext

    ledger = _run_budget(tmp_path)
    evidence = tmp_path / "task"
    evidence.mkdir(mode=0o700)
    with TaskRuntimeContext(
        evidence,
        task_id="arvo:0",
        attempt_id="attempt-0",
        secrets=("synthetic-key",),
        run_request_budget=ledger,
    ) as context:
        for _ in range(90):
            context.budget.reserve_deepseek_request()
        with pytest.raises(BudgetExceeded, match="allocation"):
            context.budget.reserve_deepseek_request()
        assert context.budget.reserve_request() == 91
        assert ledger.snapshot()["requests"] == 91


def test_fixture_reservations_are_durable_before_lane_permission(tmp_path):
    from nooa_cybergym.leaderboard.runtime_custody import TaskRuntimeContext

    with TaskRuntimeContext(
        tmp_path,
        task_id="synthetic:length-header",
        attempt_id="fixture-new-policy",
        secrets=("synthetic-key",),
        record_request_reservations=True,
    ) as context:
        assert context.budget.reserve_request() == 1
        assert context.budget.reserve_deepseek_request() == 2
        assert context.budget.reserve_request() == 3
        rows = [json.loads(line)["event"] for line in context.audit.path.read_text().splitlines()]
        assert [row["event"] for row in rows] == ["task_request_reserved"] * 3
        assert [row["task_ordinal"] for row in rows] == [1, 2, 3]
        assert [row["allocation_ordinal"] for row in rows] == [1, 1, 2]
        assert [row["allocation"] for row in rows] == [
            "primary_and_memory",
            "deepseek_advisory",
            "primary_and_memory",
        ]
        assert len({row["request_id"] for row in rows}) == 3
        assert all("run_id" not in row for row in rows)


def test_failed_fixture_reservation_audit_retains_debit_and_denies_permission(
    tmp_path, monkeypatch
):
    from nooa_cybergym.leaderboard.runtime_custody import TaskRuntimeContext

    with TaskRuntimeContext(
        tmp_path,
        task_id="synthetic:length-header",
        attempt_id="fixture-new-policy",
        secrets=("synthetic-key",),
        record_request_reservations=True,
    ) as context:
        monkeypatch.setattr(context.audit, "record", lambda _: False)
        with pytest.raises(RuntimeError, match="audit"):
            context.budget.reserve_request()
        assert context.budget.snapshot()["requests"] == 1
        with pytest.raises(Exception, match="exhausted"):
            context.budget.reserve_deepseek_request()
        assert context.budget.snapshot()["requests"] == 1


def test_legacy_fixture_reservation_audit_stays_unchanged(tmp_path):
    from nooa_cybergym.leaderboard.runtime_custody import TaskRuntimeContext

    with TaskRuntimeContext(
        tmp_path,
        task_id="synthetic:length-header",
        attempt_id="legacy",
        secrets=("synthetic-key",),
    ) as context:
        assert context.budget.reserve_request() == 1
        assert context.audit.path.read_bytes() == b""
