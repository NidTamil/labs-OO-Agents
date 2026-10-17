"""A ten-task practice decision cannot inherit either existing launch scope."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest
from nooa_cybergym.leaderboard.campaign import CampaignAction
from nooa_cybergym.leaderboard.subset_dry_run_admission import (
    OFFICIAL_SUBSET_TASK_IDS,
    PREVIOUSLY_EXPOSED_TASK_IDS,
    bind_subset_dry_run_state,
    preview_subset_dry_run_admission,
)


class _Authority:
    def __init__(self, payload: dict) -> None:
        self.payload = payload
        self.kinds: list[str] = []
        self.create_calls = 0

    def attest_signed(self, kind: str, envelope: bytes):
        self.kinds.append(kind)
        return deepcopy(self.payload) if envelope == b"signed-subset-admission" else None

    def create_campaign_once(self, *_args, **_kwargs):
        self.create_calls += 1
        raise AssertionError("preview must not create a ledger")


class _LedgerAuthority(_Authority):
    def __init__(self, payload: dict) -> None:
        super().__init__(payload)
        self.events: list[dict] = []
        self.receipts: dict[bytes, dict] = {}

    def attest_signed(self, kind: str, envelope: bytes):
        if kind == "terminal_receipt":
            return deepcopy(self.receipts.get(envelope))
        return super().attest_signed(kind, envelope)

    def read_verified_events(self, _root, _run_id):
        return tuple(deepcopy(self.events))

    def append_event(self, _root, _run_id, event, expected_revision):
        if expected_revision != len(self.events):
            return False
        self.events.append(dict(event))
        return True


def _payload() -> dict:
    return {
        "schema_version": 1,
        "artifact_kind": "subset_dry_run_admission",
        "scope": "native_subset_dry_run_level1",
        "run_id": "subset-20261017",
        "epoch": "scored-freeze-20261017",
        "task_ids": list(OFFICIAL_SUBSET_TASK_IDS),
        "previously_exposed_task_ids": list(PREVIOUSLY_EXPOSED_TASK_IDS),
        "max_parallel_tasks": 1,
        "official_registry_sha256": "59d1fa85f6a681fc481f3ac4e14331586b7c9548972fd7ca661787da9995a7ad",
        "cohort_sha256": "a" * 64,
        "freeze_sha256": "b" * 64,
        "certification_sha256": "c" * 64,
        "budget_sha256": "d" * 64,
    }


def _preview(authority: _Authority, evidence_root: Path):
    return preview_subset_dry_run_admission(
        signed_admission=b"signed-subset-admission",
        authority=authority,
        run_id="subset-20261017",
        epoch="scored-freeze-20261017",
        evidence_root=evidence_root,
        expected_cohort_sha256="a" * 64,
        expected_freeze_sha256="b" * 64,
        expected_certification_sha256="c" * 64,
        expected_budget_sha256="d" * 64,
    )


def test_preview_binds_exact_official_ten_and_prior_exposure_without_creating_ledger(tmp_path):
    authority = _Authority(_payload())
    preview = _preview(authority, tmp_path)
    assert preview.task_ids == OFFICIAL_SUBSET_TASK_IDS
    assert preview.previously_exposed_task_ids == PREVIOUSLY_EXPOSED_TASK_IDS
    assert authority.kinds == ["subset_dry_run_admission"]
    assert authority.create_calls == 0


@pytest.mark.parametrize(
    "field,value",
    [
        ("scope", "native_practice_level1"),
        ("task_ids", list(OFFICIAL_SUBSET_TASK_IDS[:-1])),
        ("task_ids", list(reversed(OFFICIAL_SUBSET_TASK_IDS))),
        ("previously_exposed_task_ids", []),
        ("previously_exposed_task_ids", ["arvo:47101"]),
        ("max_parallel_tasks", 2),
        ("freeze_sha256", "e" * 64),
        ("budget_sha256", "e" * 64),
    ],
)
def test_preview_rejects_changed_scope_order_disclosure_or_signed_pin(tmp_path, field, value):
    payload = _payload()
    payload[field] = value
    authority = _Authority(payload)
    with pytest.raises(RuntimeError, match="subset dry-run admission"):
        _preview(authority, tmp_path)
    assert authority.create_calls == 0


def test_subset_state_replays_exact_ten_signed_terminals_without_creating_ledger(tmp_path):
    authority = _LedgerAuthority(_payload())
    preview = _preview(authority, tmp_path)
    state = bind_subset_dry_run_state(preview, authority=authority)
    assert authority.events == []
    with pytest.raises(RuntimeError, match="creation"):
        state.next_action()
    authority.events.append(state.creation_event())
    for number, task_id in enumerate(OFFICIAL_SUBSET_TASK_IDS, start=1):
        assert state.next_action() == CampaignAction("prepare", task_id)
        state.mark_prepared(task_id)
        request_id = f"request-{number}"
        state.mark_started(task_id, request_id=request_id)
        assert len(state.started_event_sha256(task_id, request_id)) == 64
        receipt = f"signed-terminal-{number}".encode()
        authority.receipts[receipt] = {
            "schema_version": 1,
            "artifact_kind": "terminal_receipt",
            "run_id": state.run_id,
            "epoch": state.epoch,
            "task_id": task_id,
            "status": "timeout",
            "evidence_sha256": "e" * 64,
        }
        state.mark_terminal(task_id, receipt)
    assert state.next_action() == CampaignAction("complete", None)
    assert authority.create_calls == 0


def test_subset_state_rejects_changed_admission_and_out_of_order_transition(tmp_path):
    authority = _LedgerAuthority(_payload())
    state = bind_subset_dry_run_state(_preview(authority, tmp_path), authority=authority)
    authority.events.append(state.creation_event())
    with pytest.raises(RuntimeError, match="task order"):
        state.mark_prepared(OFFICIAL_SUBSET_TASK_IDS[1])
    authority.payload["task_ids"] = list(reversed(OFFICIAL_SUBSET_TASK_IDS))
    with pytest.raises(RuntimeError, match="admission"):
        state.next_action()


def test_subset_state_rejects_receipt_for_another_task(tmp_path):
    authority = _LedgerAuthority(_payload())
    state = bind_subset_dry_run_state(_preview(authority, tmp_path), authority=authority)
    authority.events.append(state.creation_event())
    task_id = OFFICIAL_SUBSET_TASK_IDS[0]
    state.mark_prepared(task_id)
    state.mark_started(task_id, request_id="request-1")
    authority.receipts[b"other-task-receipt"] = {
        "schema_version": 1,
        "artifact_kind": "terminal_receipt",
        "run_id": state.run_id,
        "epoch": state.epoch,
        "task_id": OFFICIAL_SUBSET_TASK_IDS[1],
        "status": "timeout",
        "evidence_sha256": "e" * 64,
    }
    with pytest.raises(RuntimeError, match="identity"):
        state.mark_terminal(task_id, b"other-task-receipt")
    assert state.next_action() == CampaignAction("observe_started", task_id)
