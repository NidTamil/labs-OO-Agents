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
from nooa_cybergym.leaderboard.cohort_native_driver import (
    announce_prepared_scored_launch,
    prepare_current_scored_inputs,
    stage_current_cohort_task,
)
from nooa_cybergym.leaderboard.cohort_native_workspace import CohortNativeWorkspace
from nooa_cybergym.leaderboard.scored_capability_admission import ScoredCapabilityAdmission
from nooa_cybergym.leaderboard.scored_image_registry import ScoredImages
from nooa_cybergym.leaderboard.workspace import ControllerPaths

TASK = "oss-fuzz:42535201"
IMAGE = "sha256:" + "a" * 64


def test_scored_launch_reservation_precedes_native_prepared_callback(tmp_path: Path, monkeypatch):
    import nooa_cybergym.leaderboard.cohort_native_driver as driver

    task = "arvo:47101"
    events = []
    root = tmp_path / "workspace"
    (root / ".sunchaser").mkdir(parents=True)
    evidence = tmp_path / "evidence" / "run-1-arvo-47101"
    evidence.mkdir(parents=True)
    workspace = CohortNativeWorkspace(task, "run-1", root, evidence, {}, b"manifest")
    state = SimpleNamespace(run_id="run-1", task_ids=(task,))
    launch = SimpleNamespace(manifest={"launch_id": "launch-1"})
    monkeypatch.setattr(
        driver,
        "persist_scored_launch",
        lambda **kw: events.append("persist") or launch,
    )
    monkeypatch.setattr(
        driver,
        "write_new",
        lambda path, raw, mode: events.append("write-agent-launch"),
    )
    monkeypatch.setattr(
        driver,
        "NativeFirstRequestWitness",
        lambda **kw: events.append("witness") or "verified-witness",
    )
    prepared = announce_prepared_scored_launch(
        state=state,
        task_id=task,
        workspace=workspace,
        signed_envelope=b"signed-native-launch",
        public_keys={"controller": object()},
        attempt_id="attempt-1",
        remote_alias="cybergym-cal-v26q",
        ssh_port=23456,
        policy_sha256="f" * 64,
        on_prepared=lambda item: events.append(("callback", item.launch_id)),
    )
    assert events == ["persist", "write-agent-launch", "witness", ("callback", "launch-1")]
    assert prepared.launch_authority is launch
    assert prepared.witness == "verified-witness"
    assert prepared.task_id == task

    events.clear()

    def denied_write(path, raw, mode):
        events.append("write-agent-launch")
        raise FileExistsError

    monkeypatch.setattr(driver, "write_new", denied_write)
    with pytest.raises(FileExistsError):
        announce_prepared_scored_launch(
            state=state,
            task_id=task,
            workspace=workspace,
            signed_envelope=b"signed-native-launch",
            public_keys={"controller": object()},
            attempt_id="attempt-1",
            remote_alias="cybergym-cal-v26q",
            ssh_port=23456,
            policy_sha256="f" * 64,
            on_prepared=lambda item: events.append(("callback", item.launch_id)),
        )
    assert events == ["persist", "write-agent-launch"]


def test_scored_prelaunch_observes_all_images_before_workspace_staging(monkeypatch):
    import nooa_cybergym.leaderboard.cohort_native_driver as driver

    task = "oss-fuzz:42535201"
    vulnerable, fixed = "sha256:" + "b" * 64, "sha256:" + "c" * 64
    images = ScoredImages(vulnerable, fixed)
    calls = []
    observed = {IMAGE: IMAGE, vulnerable: vulnerable, fixed: fixed}

    class ImageAccess:
        def get(self, image_id):
            calls.append(("observe", image_id))
            return SimpleNamespace(id=observed[image_id])

    client = SimpleNamespace(images=ImageAccess())
    donor = SimpleNamespace(image_id=IMAGE)
    binding = SimpleNamespace(images=SimpleNamespace(images_for=lambda task_id: images))
    monkeypatch.setattr(
        driver,
        "bind_scored_runtime",
        lambda **kw: calls.append(("bind", kw["observed_image_id"])) or binding,
    )
    monkeypatch.setattr(
        driver,
        "stage_current_cohort_task",
        lambda **kw: calls.append(("stage", kw["task_id"])) or "workspace",
    )
    inputs = {
        "docker_client": client,
        "donor": donor,
        "state": object(),
        "task_id": task,
        "controller_paths": object(),
        "asset_manifest": Path("asset-hashes.json"),
        "template_files": {},
        "admission": object(),
        "registry": CapabilityRegistry(()),
        "bindings_path": Path("bindings.json"),
        "image_manifest": Path("images.json"),
    }
    result = prepare_current_scored_inputs(**inputs)
    assert (result.workspace, result.runtime, result.images) == ("workspace", binding, images)
    assert calls == [
        ("observe", IMAGE),
        ("bind", IMAGE),
        ("observe", vulnerable),
        ("observe", fixed),
        ("stage", task),
    ]
    observed[fixed] = "sha256:" + "d" * 64
    calls.clear()
    with pytest.raises(RuntimeError, match="private image"):
        prepare_current_scored_inputs(**inputs)
    assert ("stage", task) not in calls
    observed[IMAGE] = "sha256:" + "e" * 64
    calls.clear()
    with pytest.raises(RuntimeError, match="native image"):
        prepare_current_scored_inputs(**inputs)
    assert calls == [("observe", IMAGE)]


def test_scored_native_runtime_probe_follows_signed_binding_and_precedes_staging(monkeypatch):
    import nooa_cybergym.leaderboard.cohort_native_driver as driver

    task = "oss-fuzz:42535201"
    vulnerable, fixed = "sha256:" + "b" * 64, "sha256:" + "c" * 64
    images = ScoredImages(vulnerable, fixed)
    calls = []

    class ImageAccess:
        def get(self, image_id):
            calls.append(("observe", image_id))
            return SimpleNamespace(id=image_id)

    monkeypatch.setattr(
        driver,
        "bind_scored_runtime",
        lambda **kw: (
            calls.append(("bind", kw["task_id"]))
            or SimpleNamespace(images=SimpleNamespace(images_for=lambda task_id: images))
        ),
    )
    monkeypatch.setattr(
        driver,
        "stage_current_cohort_task",
        lambda **kw: calls.append(("stage", kw["task_id"])) or "workspace",
    )
    inputs = {
        "docker_client": SimpleNamespace(images=ImageAccess()),
        "donor": SimpleNamespace(image_id=IMAGE),
        "state": object(),
        "task_id": task,
        "controller_paths": object(),
        "asset_manifest": Path("assets.json"),
        "template_files": {},
        "admission": object(),
        "registry": CapabilityRegistry(()),
        "bindings_path": Path("bindings.json"),
        "image_manifest": Path("images.json"),
    }
    driver.prepare_current_scored_inputs(
        **inputs, probe_native_runtime=lambda: calls.append(("probe", IMAGE))
    )
    assert calls == [
        ("observe", IMAGE),
        ("bind", task),
        ("probe", IMAGE),
        ("observe", vulnerable),
        ("observe", fixed),
        ("stage", task),
    ]

    calls.clear()

    def changed_runtime():
        calls.append(("probe", IMAGE))
        raise RuntimeError("native runtime changed")

    with pytest.raises(RuntimeError, match="native runtime changed"):
        driver.prepare_current_scored_inputs(**inputs, probe_native_runtime=changed_runtime)
    assert calls == [("observe", IMAGE), ("bind", task), ("probe", IMAGE)]


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
