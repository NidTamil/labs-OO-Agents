"""Native capacity is fungible; it does not invent tool-to-child identity proof."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest


@pytest.fixture
def create(tmp_path):
    from nooa_cybergym.leaderboard.child_capacity import ChildCapacity

    return lambda: ChildCapacity(
        tmp_path / "children.sqlite",
        run_id="run-1",
        task_id="task-1",
        attempt_id="attempt-1",
        launch_id="launch-1",
    )


def test_native_pending_and_advisory_share_three_durable_slots(create):
    ledger = create()
    with ledger.advisory_slot("independent_recon"):
        ledger.reserve_native("tool-1", "cybergym-recon")
        ledger.reserve_native("tool-2", "cybergym-recon")
        assert create().snapshot() == {
            "pending_native": 2,
            "active_native": 0,
            "active_advisory": 1,
            "occupied": 3,
        }
        with pytest.raises(RuntimeError, match="capacity"):
            create().reserve_native("tool-3", "cybergym-review")
        ledger.bind_native("agent-2", "cybergym-recon")
        ledger.bind_native("agent-1", "cybergym-recon")
        assert ledger.is_native_active("agent-1")
        assert ledger.snapshot()["occupied"] == 3
        ledger.release_native("agent-2")
        ledger.reserve_native("tool-3", "cybergym-review")
    assert create().snapshot()["occupied"] == 2


def test_reservation_is_idempotent_but_cannot_change_type_or_reopen_child(create):
    ledger = create()
    ledger.reserve_native("tool-1", "cybergym-recon")
    ledger.reserve_native("tool-1", "cybergym-recon")
    assert ledger.snapshot()["occupied"] == 1
    with pytest.raises(ValueError, match="type"):
        ledger.reserve_native("tool-1", "cybergym-review")
    with pytest.raises(ValueError, match="pending"):
        ledger.bind_native("unknown", "cybergym-debug")
    ledger.bind_native("agent-1", "cybergym-recon")
    ledger.bind_native("agent-1", "cybergym-recon")
    ledger.release_native("agent-1")
    ledger.release_native("agent-1")
    assert not ledger.is_native_active("agent-1")
    with pytest.raises(ValueError, match="terminal"):
        ledger.bind_native("agent-1", "cybergym-recon")


def test_concurrent_reservations_cannot_cross_durable_capacity(create):
    ledger = create()

    def reserve(index):
        try:
            create().reserve_native(f"tool-{index}", "cybergym-recon")
            return True
        except RuntimeError:
            return False

    with ThreadPoolExecutor(max_workers=8) as workers:
        results = list(workers.map(reserve, range(12)))
    assert sum(results) == 3
    assert ledger.snapshot()["occupied"] == 3


def test_advisory_failure_releases_known_synchronous_slot_but_prevents_role_replay(create):
    ledger = create()
    with pytest.raises(ValueError):
        with ledger.advisory_slot("independent_recon"):
            raise ValueError("synthetic failure")
    assert ledger.snapshot()["occupied"] == 0
    with pytest.raises(ValueError, match="reserved"):
        with create().advisory_slot("independent_recon"):
            pass


def test_workflow_reserves_actual_declared_native_children_without_fake_agent_calls(create):
    ledger = create()
    with ledger.advisory_slot("independent_recon"):
        ledger.reserve_workflow("workflow-tool-1", "a" * 64, ("cybergym-recon", "cybergym-recon"))
        ledger.reserve_workflow("workflow-tool-1", "a" * 64, ("cybergym-recon", "cybergym-recon"))
        assert create().snapshot()["occupied"] == 3
        with pytest.raises(RuntimeError, match="capacity"):
            ledger.reserve_native("tool-1", "cybergym-review")
        ledger.bind_native("native-1", "cybergym-recon")
        ledger.bind_native("native-2", "cybergym-recon")
        assert ledger.snapshot()["active_native"] == 2
        with pytest.raises(ValueError, match="changed"):
            ledger.reserve_workflow("workflow-tool-1", "b" * 64, ("cybergym-recon",))
    ledger.release_native("native-1")
    ledger.release_native("native-2")
    assert ledger.snapshot()["occupied"] == 0
    # A retried native provider call cannot create a second batch after completion.
    ledger.reserve_workflow("workflow-tool-1", "a" * 64, ("cybergym-recon", "cybergym-recon"))
    assert ledger.snapshot()["occupied"] == 0


def test_workflow_reservation_is_atomic_and_cannot_alias_agent_tool_id(create):
    ledger = create()
    ledger.reserve_native("tool-1", "cybergym-recon")
    with pytest.raises(ValueError, match="already"):
        ledger.reserve_workflow("tool-1", "a" * 64, ("cybergym-recon",))
    with pytest.raises(RuntimeError, match="capacity"):
        ledger.reserve_workflow("workflow-tool-1", "a" * 64, ("cybergym-recon",) * 3)
    assert ledger.snapshot()["occupied"] == 1
    ledger.reserve_workflow("workflow-tool-1", "a" * 64, ("cybergym-recon",))
    with pytest.raises(ValueError, match="already"):
        ledger.reserve_native("workflow-tool-1", "cybergym-recon")
