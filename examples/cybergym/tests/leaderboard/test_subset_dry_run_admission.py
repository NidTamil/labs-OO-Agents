"""A ten-task practice decision cannot inherit either existing launch scope."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest
from nooa_cybergym.leaderboard.subset_dry_run_admission import (
    OFFICIAL_SUBSET_TASK_IDS,
    PREVIOUSLY_EXPOSED_TASK_IDS,
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
