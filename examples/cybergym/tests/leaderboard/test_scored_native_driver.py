# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""The scored driver accepts only the current signed cohort task."""

from __future__ import annotations

from pathlib import Path

import pytest
from nooa_cybergym.leaderboard.campaign import CampaignAction, CampaignState
from nooa_cybergym.leaderboard.scored_native_driver import (
    validate_request,
    verify_live_scored_terminal,
)


def _state(tmp_path: Path) -> CampaignState:
    return CampaignState(
        run_id="scored-1",
        epoch="epoch-1",
        evidence_root=tmp_path / "ledger",
        task_ids=("oss-fuzz:42535201", "arvo:47101"),
        policy_sha256="b" * 64,
        cohort_sha256="c" * 64,
        asset_hashes_sha256="d" * 64,
        benchmark_commit="1" * 40,
        dataset_commit="2" * 40,
        mask_map_sha256="e" * 64,
        cohort_envelope=b"signed:cohort",
        authority=object(),
    )


def test_scored_driver_accepts_current_oss_fuzz_and_rejects_swapped_task(
    tmp_path: Path, monkeypatch
):
    state = _state(tmp_path)
    observed = []
    donor = type("Donor", (), {"verify_unchanged": lambda self: observed.append("verified")})()
    monkeypatch.setattr(
        CampaignState,
        "next_action",
        lambda self: CampaignAction("prepare", "oss-fuzz:42535201"),
    )
    assert validate_request(donor, state=state, task_id="oss-fuzz:42535201") == "oss-fuzz:42535201"
    assert observed == ["verified"]
    with pytest.raises(ValueError, match="current signed scored"):
        validate_request(donor, state=state, task_id="arvo:47101")
    assert observed == ["verified"]


def test_scored_run_rejects_task_swap_before_docker_or_asset_staging(tmp_path: Path, monkeypatch):
    import nooa_cybergym.leaderboard.scored_native_driver as driver

    state = _state(tmp_path)
    monkeypatch.setattr(
        CampaignState,
        "next_action",
        lambda self: CampaignAction("prepare", "oss-fuzz:42535201"),
    )
    observed = []
    donor = type("Donor", (), {"verify_unchanged": lambda self: observed.append("verified")})()
    monkeypatch.setattr(driver, "load_runtime_config", lambda path: donor)
    monkeypatch.setattr(driver.docker, "from_env", lambda: pytest.fail("Docker touched"))
    monkeypatch.setattr(
        driver,
        "prepare_current_scored_inputs",
        lambda **kw: pytest.fail("official assets touched"),
    )
    with pytest.raises(ValueError, match="current signed scored"):
        driver.run(
            config_path=tmp_path / "donor.json",
            bindings_path=tmp_path / "bindings.json",
            public_ssh_key=tmp_path / "id.pub",
            state=state,
            task_id="arvo:47101",
            ssh_port=23456,
            timeout=60,
            controller_paths=object(),
            asset_manifest=tmp_path / "assets.json",
            image_manifest=tmp_path / "images.json",
            scored_registry=object(),
            admission=object(),
            official_verifier_source=tmp_path / "verifier.py",
            official_verifier_sha256="f" * 64,
            evaluator_signer=object(),
            evaluator_verifier=object(),
            remote_alias="cybergym-cal-v26q",
            on_prepared=lambda _: None,
            stop=object(),
        )
    assert observed == []


def test_live_driver_requires_recovery_grade_receipt_verification(monkeypatch):
    import nooa_cybergym.leaderboard.scored_native_driver as driver

    observed = []
    source = b"actual-signed-terminal"
    identities = {
        "state": object(),
        "task_id": "oss-fuzz:42535201",
        "launch_authority": object(),
        "attempt_id": "attempt-1",
        "witness": object(),
        "evidence_dir": Path("D:/controller/evidence/run-1-oss-fuzz-42535201"),
        "controller_verifier": object(),
        "evaluator_verifier": object(),
    }
    monkeypatch.setattr(
        driver,
        "recover_scored_terminal",
        lambda **kw: observed.append(kw) or source,
    )
    assert verify_live_scored_terminal(terminal=source, **identities) == source
    assert observed == [identities]
    monkeypatch.setattr(driver, "recover_scored_terminal", lambda **kw: b"changed")
    with pytest.raises(RuntimeError, match="verified scored terminal"):
        verify_live_scored_terminal(terminal=source, **identities)
