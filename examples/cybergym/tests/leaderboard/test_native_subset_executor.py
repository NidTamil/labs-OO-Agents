"""The ten-task dry run has its own exact native executor scope."""

from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

import pytest
from nooa_cybergym.leaderboard.campaign import CampaignAction
from nooa_cybergym.leaderboard.native_campaign_executor import (
    NativeCampaignTaskExecutor,
    NativeSubsetTaskExecutor,
)
from nooa_cybergym.leaderboard.subset_dry_run_admission import (
    OFFICIAL_SUBSET_REGISTRY_SHA256,
    OFFICIAL_SUBSET_TASK_IDS,
    PREVIOUSLY_EXPOSED_TASK_IDS,
    bind_subset_dry_run_state,
    preview_subset_dry_run_admission,
)


class _Authority:
    def __init__(self):
        self.payload = {
            "schema_version": 1,
            "artifact_kind": "subset_dry_run_admission",
            "scope": "native_subset_dry_run_level1",
            "run_id": "subset-1",
            "epoch": "scored-freeze-1",
            "task_ids": list(OFFICIAL_SUBSET_TASK_IDS),
            "previously_exposed_task_ids": list(PREVIOUSLY_EXPOSED_TASK_IDS),
            "max_parallel_tasks": 1,
            "official_registry_sha256": OFFICIAL_SUBSET_REGISTRY_SHA256,
            "cohort_sha256": "a" * 64,
            "freeze_sha256": "b" * 64,
            "certification_sha256": "c" * 64,
            "budget_sha256": "d" * 64,
        }
        self.events = []

    def attest_signed(self, kind, envelope):
        if kind == "subset_dry_run_admission" and envelope == b"signed-subset":
            return deepcopy(self.payload)
        return None

    def read_verified_events(self, _root, _run_id):
        return tuple(deepcopy(self.events))


def _state(tmp_path):
    authority = _Authority()
    preview = preview_subset_dry_run_admission(
        signed_admission=b"signed-subset",
        authority=authority,
        run_id="subset-1",
        epoch="scored-freeze-1",
        evidence_root=tmp_path,
        expected_cohort_sha256="a" * 64,
        expected_freeze_sha256="b" * 64,
        expected_certification_sha256="c" * 64,
        expected_budget_sha256="d" * 64,
    )
    state = bind_subset_dry_run_state(preview, authority=authority)
    authority.events.extend(
        (
            state.creation_event(),
            {"type": "prepared", "task_id": OFFICIAL_SUBSET_TASK_IDS[0]},
            {
                "type": "started",
                "task_id": OFFICIAL_SUBSET_TASK_IDS[0],
                "request_id": "launch-1",
            },
        )
    )
    return state, authority


def _executor_kwargs(state, tmp_path, events):
    task_id = OFFICIAL_SUBSET_TASK_IDS[0]
    launch = SimpleNamespace(
        task_id=task_id,
        launch_id="launch-1",
        attempt_id="attempt-1",
        remote_alias="cybergym-scored",
        ssh_port=22511,
        evidence=tmp_path,
        launch_authority=SimpleNamespace(
            manifest={"run_id": state.run_id, "task_id": task_id, "launch_id": "launch-1"},
            _check_receipt=lambda _receipt: None,
        ),
        witness=SimpleNamespace(observed=lambda _request: False),
    )

    class Worker:
        def ensure_prepared(self, candidate):
            assert candidate == task_id
            events.append("prepared")
            return launch

        def await_terminal(self, candidate):
            assert candidate == task_id
            events.append("terminal")
            return b"signed-terminal"

    def publish(_evidence, **kwargs):
        assert kwargs["started_event_sha256"] == state.started_event_sha256(task_id, "launch-1")
        events.append("intent")
        return b"signed-intent"

    def submitter(**kwargs):
        assert kwargs["started_intent"]("launch-1") is True

        def submit_once(_request):
            events.append("send")
            return True

        return SimpleNamespace(submit_once=submit_once)

    return {
        "state": state,
        "worker": Worker(),
        "mailbox": SimpleNamespace(run_id=state.run_id),
        "signer": object(),
        "verifier": object(),
        "remote_alias": "cybergym-scored",
        "publish_intent": publish,
        "submitter_factory": submitter,
    }


def test_distinct_subset_executor_preserves_full_cohort_guard_and_start_order(tmp_path):
    state, _ = _state(tmp_path)
    events = []
    kwargs = _executor_kwargs(state, tmp_path, events)
    with pytest.raises(ValueError, match="full cohort"):
        NativeCampaignTaskExecutor(**kwargs)
    executor = NativeSubsetTaskExecutor(**kwargs)
    task_id = OFFICIAL_SUBSET_TASK_IDS[0]
    assert state.next_action() == CampaignAction("observe_started", task_id)
    assert executor.first_request_id(task_id) == "launch-1"
    executor.start(task_id, "launch-1")
    assert executor.await_terminal(task_id) == b"signed-terminal"
    assert events.index("intent") < events.index("send") < events.index("terminal")


def test_subset_executor_rejects_full_cohort_state_before_worker(tmp_path):
    state, _ = _state(tmp_path)
    kwargs = _executor_kwargs(state, tmp_path, [])
    kwargs["state"] = SimpleNamespace(run_id=state.run_id, task_ids=OFFICIAL_SUBSET_TASK_IDS)
    with pytest.raises(ValueError, match="subset dry-run"):
        NativeSubsetTaskExecutor(**kwargs)
