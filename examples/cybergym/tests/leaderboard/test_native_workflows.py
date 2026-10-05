from __future__ import annotations

import hashlib

import pytest
from nooa_cybergym.leaderboard.child_capacity import ChildCapacity
from nooa_cybergym.leaderboard.native_workflows import frozen_workflows, reserve_workflow


def test_workflow_source_pins_capacity_and_rejects_override_or_unproven_debug(tmp_path):
    definitions = frozen_workflows()
    assert [item.child_types for item in definitions] == [
        ("cybergym-recon", "cybergym-recon"),
        ("cybergym-debug",),
        ("cybergym-review",),
    ]
    assert all(
        hashlib.sha256(item.source.read_bytes()).hexdigest() == item.sha256 for item in definitions
    )
    capacity = ChildCapacity(
        tmp_path / "capacity.db",
        run_id="run",
        task_id="task",
        attempt_id="attempt",
        launch_id="launch",
    )
    recon, debug, _ = definitions
    arguments = {"scriptPath": recon.script_path, "args": {"question": "Inspect source"}}
    with pytest.raises(ValueError, match="scriptPath"):
        reserve_workflow(
            capacity,
            "tool1",
            arguments | {"script": "fake"},
            definitions,
            observed_sha256=recon.sha256,
        )
    with pytest.raises(ValueError, match="identity"):
        reserve_workflow(capacity, "tool1", arguments, definitions, observed_sha256="0" * 64)
    reserve_workflow(capacity, "tool1", arguments, definitions, observed_sha256=recon.sha256)
    assert capacity.snapshot()["pending_native"] == 2
    debug_args = {"scriptPath": debug.script_path, "args": {"question": "Inspect failure"}}
    with pytest.raises(ValueError, match="failure"):
        reserve_workflow(capacity, "tool2", debug_args, definitions, observed_sha256=debug.sha256)
    reserve_workflow(
        capacity,
        "tool2",
        debug_args,
        definitions,
        observed_sha256=debug.sha256,
        vulnerable_failure_observed=True,
    )
    assert capacity.snapshot()["occupied"] == 3
