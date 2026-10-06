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
