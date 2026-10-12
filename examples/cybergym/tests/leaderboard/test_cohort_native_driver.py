# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Scored staging composes the existing signed gates before touching task files."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from nooa_cybergym.leaderboard.campaign import CampaignAction, CampaignState
from nooa_cybergym.leaderboard.capabilities import CapabilityRegistry
from nooa_cybergym.leaderboard.cohort_native_driver import stage_current_cohort_task
from nooa_cybergym.leaderboard.scored_capability_admission import ScoredCapabilityAdmission
from nooa_cybergym.leaderboard.workspace import ControllerPaths

TASK = "oss-fuzz:42535201"
IMAGE = "sha256:" + "a" * 64


def test_current_scored_task_stages_only_after_admission_and_signed_path_check(
    tmp_path: Path, monkeypatch
):
    import nooa_cybergym.leaderboard.cohort_native_driver as driver

    state = CampaignState(
        run_id="scored-1",
        epoch="epoch-1",
        evidence_root=tmp_path / "ledger",
        task_ids=(TASK, "arvo:47101"),
        policy_sha256="b" * 64,
        cohort_sha256="c" * 64,
        asset_hashes_sha256="d" * 64,
        benchmark_commit="1" * 40,
        dataset_commit="2" * 40,
        mask_map_sha256="e" * 64,
        cohort_envelope=b"signed:cohort",
        authority=object(),
    )
    permit = ScoredCapabilityAdmission(
        state.run_id,
        state.epoch,
        state.cohort_sha256,
        "f" * 64,
        IMAGE,
        state,
        b"decision",
        b"certification",
        b"harness-lock",
    )
    paths = ControllerPaths(
        data_dir=tmp_path / "data",
        mask_map_path=tmp_path / "mask.json",
        server="http://controller.invalid",
        staging_root=tmp_path / "controller" / "stage",
        evidence_root=tmp_path / "controller" / "evidence",
        harness_dir=tmp_path / "harness",
        harness_manifest_path=tmp_path / "harness.json",
        harness_manifest_sha256="1" * 64,
        mask_map_sha256="e" * 64,
        generator_source=tmp_path / "generator.py",
        generator_sha256="2" * 64,
    )
    registry = CapabilityRegistry(())
    manifest = tmp_path / "asset-hashes.json"
    calls = []
    monkeypatch.setattr(CampaignState, "next_action", lambda self: CampaignAction("prepare", TASK))
    monkeypatch.setattr(
        ScoredCapabilityAdmission,
        "verify_current",
        lambda self, **kw: calls.append(("admission", kw["task_id"])),
    )
    monkeypatch.setattr(
        CampaignState,
        "verified_staging_paths",
        lambda self, task_id, controller_paths, asset_manifest: (
            calls.append(("paths", task_id)) or controller_paths
        ),
    )

    def prepare(**kw):
        calls.append(("prepare", kw["task_id"]))
        assert kw["task_root"] == tmp_path / "controller" / "scored-1-oss-fuzz-42535201"
        return SimpleNamespace(task_id=TASK)

    def overlay(prepared, **kw):
        calls.append(("overlay", prepared.task_id))
        assert kw["evidence"] == paths.evidence_root / "scored-1-oss-fuzz-42535201"
        assert kw["cohort_sha256"] == state.cohort_sha256
        return "staged"

    monkeypatch.setattr(driver, "prepare_workspace", prepare)
    monkeypatch.setattr(driver, "overlay_cohort_template", overlay)
    assert (
        stage_current_cohort_task(
            state=state,
            task_id=TASK,
            controller_paths=paths,
            asset_manifest=manifest,
            template_files={"CLAUDE.md": (tmp_path / "CLAUDE.md", "3" * 64)},
            admission=permit,
            registry=registry,
            observed_image_id=IMAGE,
        )
        == "staged"
    )
    assert calls == [
        ("admission", TASK),
        ("paths", TASK),
        ("prepare", TASK),
        ("overlay", TASK),
    ]
    with pytest.raises(RuntimeError, match="current"):
        stage_current_cohort_task(
            state=state,
            task_id="arvo:47101",
            controller_paths=paths,
            asset_manifest=manifest,
            template_files={"CLAUDE.md": (tmp_path / "CLAUDE.md", "3" * 64)},
            admission=permit,
            registry=registry,
            observed_image_id=IMAGE,
        )
    assert len(calls) == 4
    bad_state = replace(state, run_id="../escaped")
    bad_permit = replace(permit, run_id=bad_state.run_id, _state=bad_state)
    with pytest.raises(RuntimeError, match="run|current"):
        stage_current_cohort_task(
            state=bad_state,
            task_id=TASK,
            controller_paths=paths,
            asset_manifest=manifest,
            template_files={"CLAUDE.md": (tmp_path / "CLAUDE.md", "3" * 64)},
            admission=bad_permit,
            registry=registry,
            observed_image_id=IMAGE,
        )
    assert len(calls) == 4
