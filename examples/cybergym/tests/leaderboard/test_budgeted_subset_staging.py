# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Temporary signed metadata; no official generator, images or provider calls."""

from __future__ import annotations

import hashlib
import importlib
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest
from nooa_cybergym.leaderboard import budgeted_subset_runtime, run_resource_budget
from nooa_cybergym.leaderboard.campaign import CampaignAction, _json_bytes
from nooa_cybergym.leaderboard.runtime_config import RuntimeConfigError
from nooa_cybergym.leaderboard.workspace import PreparedWorkspace

from . import test_budgeted_subset_runtime as runtime_tests


@pytest.fixture
def module():
    return importlib.import_module("nooa_cybergym.leaderboard.budgeted_subset_staging")


@pytest.fixture
def bound(tmp_path, monkeypatch):
    data = runtime_tests.factory.__wrapped__(tmp_path, monkeypatch)()
    runtime = runtime_tests.bind(budgeted_subset_runtime, data)
    paths = runtime.material.paths
    slug = f"{runtime.state.run_id}-{runtime.task_id.replace(':', '-')}"
    return SimpleNamespace(
        data=data,
        runtime=runtime,
        paths=paths,
        root=paths.staging_root.parent / slug,
        evidence=paths.evidence_root / slug,
        stage=paths.staging_root / runtime.preparation_id,
        raw=paths.evidence_root / f"workspace-{runtime.preparation_id}",
        marker=paths.evidence_root / "subset-preparations" / f"{runtime.preparation_id}.json",
    )


def fake_workspace(bound, calls):
    def prepare(**kwargs):
        marker = json.loads(bound.marker.read_bytes())
        assert marker["preparation_id"] == bound.runtime.preparation_id
        assert kwargs["preparation_id"] == bound.runtime.preparation_id
        registry = kwargs["controller_paths"].official_registry
        assert registry.task_ids == bound.runtime.material.cohort.task_ids
        assert registry.inputs_for(
            bound.runtime.task_id
        ) == bound.runtime.material.assets.inputs_for(bound.runtime.task_id)
        calls.append(kwargs)
        root = kwargs["task_root"]
        root.mkdir()
        hashes = {}
        for name in ("description.txt", "README.md", "repo-vul.tar.gz", "submit.sh"):
            content = b"synthetic " + name.encode()
            (root / name).write_bytes(content)
            hashes[name] = hashlib.sha256(content).hexdigest()
        (root / "output").mkdir()
        (root / "src").mkdir()
        bound.raw.mkdir()
        manifest = bound.raw / "task-manifest.json"
        manifest.write_bytes(
            _json_bytes(
                {
                    "schema_version": 1,
                    "task_id": kwargs["task_id"],
                    "difficulty": "level1",
                    "file_hashes": hashes,
                }
            )
        )
        return PreparedWorkspace(kwargs["task_id"], root, manifest, hashes)

    return prepare


def test_stage_records_exact_ownership_before_effects_and_retains_full_cohort(
    module, bound, monkeypatch
):
    calls, overlay_calls, durable = [], [], []
    monkeypatch.setattr(module, "prepare_workspace", fake_workspace(bound, calls))
    actual_overlay = module.overlay_cohort_template
    actual_sync = module._fsync_directory

    def sync(path):
        durable.append(path)
        return actual_sync(path)

    def overlay(*args, **kwargs):
        assert bound.marker.parent in durable
        overlay_calls.append(kwargs)
        return actual_overlay(*args, **kwargs)

    monkeypatch.setattr(module, "_fsync_directory", sync)
    monkeypatch.setattr(module, "overlay_cohort_template", overlay)
    result = module.stage_current_budgeted_subset_task(bound.runtime)
    marker_raw = bound.marker.read_bytes()
    marker = json.loads(marker_raw)
    state = bound.runtime.state
    preparation = state.preparation_binding(bound.runtime.task_id)
    assert marker_raw == _json_bytes(marker)
    assert marker == {
        "schema_version": 1,
        "artifact_kind": "subset_preparation_ownership",
        "run_id": state.run_id,
        "epoch": state.epoch,
        "task_id": bound.runtime.task_id,
        "preparation_id": bound.runtime.preparation_id,
        "preparation_started_event_sha256": preparation["preparation_started_event_sha256"],
        "attempt_id": bound.runtime.attempt_id,
        "budget_sha256": state.preview.budget.envelope_sha256,
        "admission_sha256": state.preview.admission_sha256,
        "freeze_sha256": state.preview.freeze_sha256,
        "cohort_sha256": state.preview.cohort_sha256,
        "source_commit": bound.runtime.source_commit,
        "donor_configuration_sha256": bound.runtime.donor_configuration_sha256,
        "bindings_sha256": bound.runtime.bindings_sha256,
        "capability_registry_sha256": bound.runtime.registry.digest,
        "paths": {
            "task_root": str(bound.root),
            "overlay_evidence": str(bound.evidence),
            "controller_stage": str(bound.stage),
            "raw_manifest_directory": str(bound.raw),
            "raw_manifest": str(bound.raw / "task-manifest.json"),
        },
    }
    assert result.preparation_marker == bound.marker
    assert result.preparation_marker_sha256 == hashlib.sha256(marker_raw).hexdigest()
    assert result.runtime is bound.runtime
    assert result.workspace.root == bound.root
    assert result.workspace.evidence == bound.evidence
    assert overlay_calls[0]["cohort_task_ids"] == bound.runtime.material.cohort.task_ids
    assert len(overlay_calls[0]["cohort_task_ids"]) == 1507
    assert dict(overlay_calls[0]["template_files"]) == dict(bound.runtime.template_files)
    assert len(calls) == 1
    assert state.next_action() == CampaignAction("observe_preparing", bound.runtime.task_id)
    assert state.resource_budget.snapshot()["requests"] == 0


@pytest.mark.parametrize("occupied", ["marker", "root", "evidence", "stage", "raw"])
def test_existing_owned_path_blocks_before_generator_and_preserves_old_bytes(
    module, bound, monkeypatch, occupied
):
    target = getattr(bound, occupied)
    if occupied == "marker":
        target.parent.mkdir()
        target.write_bytes(b"earlier ownership")
        sentinel = target
    else:
        target.mkdir(parents=True)
        sentinel = target / "unchanged"
        sentinel.write_bytes(b"earlier ownership")
    calls = []
    monkeypatch.setattr(module, "prepare_workspace", lambda **kwargs: calls.append(kwargs))
    with pytest.raises((RuntimeError, FileExistsError)):
        module.stage_current_budgeted_subset_task(bound.runtime)
    assert calls == []
    assert sentinel.read_bytes() == b"earlier ownership"


def test_generator_failure_keeps_marker_and_refuses_second_preparation(module, bound, monkeypatch):
    calls = []

    def fail(**kwargs):
        calls.append(kwargs)
        assert bound.marker.is_file()
        bound.stage.mkdir()
        (bound.stage / "partial").write_bytes(b"crash evidence")
        raise RuntimeError("synthetic generator failure")

    monkeypatch.setattr(module, "prepare_workspace", fail)
    with pytest.raises(RuntimeError, match="synthetic generator failure"):
        module.stage_current_budgeted_subset_task(bound.runtime)
    assert (bound.stage / "partial").read_bytes() == b"crash evidence"
    assert bound.marker.is_file()
    with pytest.raises((RuntimeError, FileExistsError)):
        module.stage_current_budgeted_subset_task(bound.runtime)
    assert len(calls) == 1


@pytest.mark.parametrize("transition", ["stop", "elapsed", "prepared", "template"])
def test_drift_after_workspace_blocks_overlay_and_preserves_owned_files(
    module, bound, monkeypatch, transition
):
    calls, overlays = [], []
    prepare = fake_workspace(bound, calls)

    def change(**kwargs):
        result = prepare(**kwargs)
        if transition == "stop":
            bound.data.resources.stop(reason="operator_stop")
        elif transition == "elapsed":
            deadline = bound.data.resources.snapshot()["deadline_ns"]
            monkeypatch.setattr(run_resource_budget, "_now_ns", lambda: deadline)
        elif transition == "prepared":
            bound.runtime.state.mark_prepared(bound.runtime.task_id)
        else:
            (bound.data.template / "CLAUDE.md").write_bytes(b"changed template")
        return result

    monkeypatch.setattr(module, "prepare_workspace", change)
    monkeypatch.setattr(
        module, "overlay_cohort_template", lambda *args, **kwargs: overlays.append(kwargs)
    )
    with pytest.raises((RuntimeError, RuntimeConfigError)):
        module.stage_current_budgeted_subset_task(bound.runtime)
    assert bound.marker.is_file() and bound.root.is_dir() and bound.raw.is_dir()
    assert overlays == []
    assert not bound.evidence.exists()
    if transition == "elapsed":
        assert bound.data.resources.snapshot()["stop"]["reason"] == "elapsed_limit"


def test_stop_after_overlay_never_returns_staged_permission(module, bound, monkeypatch):
    monkeypatch.setattr(module, "prepare_workspace", fake_workspace(bound, []))
    overlay = module.overlay_cohort_template

    def stop(*args, **kwargs):
        result = overlay(*args, **kwargs)
        bound.data.resources.stop(reason="operator_stop")
        return result

    monkeypatch.setattr(module, "overlay_cohort_template", stop)
    with pytest.raises(RuntimeError):
        module.stage_current_budgeted_subset_task(bound.runtime)
    assert bound.marker.is_file() and bound.evidence.is_dir() and bound.root.is_dir()


def test_marker_sync_failure_prevents_staging_and_keeps_uncertain_marker(
    module, bound, monkeypatch
):
    calls = []
    monkeypatch.setattr(module, "prepare_workspace", lambda **kwargs: calls.append(kwargs))

    def fail(path):
        if path == bound.marker.parent:
            raise OSError("synthetic directory fsync failure")

    monkeypatch.setattr(module, "_fsync_directory", fail)
    with pytest.raises(OSError, match="fsync"):
        module.stage_current_budgeted_subset_task(bound.runtime)
    assert bound.marker.is_file()
    assert calls == []


def test_stager_requires_exact_runtime_and_matching_committed_preparation(
    module, bound, monkeypatch
):
    calls = []
    monkeypatch.setattr(module, "prepare_workspace", lambda **kwargs: calls.append(kwargs))
    for invalid in (object(), replace(bound.runtime, preparation_id="uncommitted")):
        with pytest.raises((TypeError, RuntimeError)):
            module.stage_current_budgeted_subset_task(invalid)
    assert calls == []
    assert not bound.marker.exists()


def test_stop_immediately_after_marker_prevents_generator(module, bound, monkeypatch):
    calls = []
    monkeypatch.setattr(module, "prepare_workspace", lambda **kwargs: calls.append(kwargs))
    actual_sync = module._fsync_directory

    def stop(path):
        actual_sync(path)
        if path == bound.marker.parent:
            bound.data.resources.stop(reason="operator_stop")

    monkeypatch.setattr(module, "_fsync_directory", stop)
    with pytest.raises(RuntimeError):
        module.stage_current_budgeted_subset_task(bound.runtime)
    assert bound.marker.is_file()
    assert calls == []


def test_marker_substitution_after_workspace_blocks_overlay(module, bound, monkeypatch):
    calls, overlays = [], []
    prepare = fake_workspace(bound, calls)

    def change(**kwargs):
        result = prepare(**kwargs)
        bound.marker.write_bytes(b"substituted ownership")
        return result

    monkeypatch.setattr(module, "prepare_workspace", change)
    monkeypatch.setattr(
        module, "overlay_cohort_template", lambda *args, **kwargs: overlays.append(kwargs)
    )
    with pytest.raises(RuntimeError, match="marker changed"):
        module.stage_current_budgeted_subset_task(bound.runtime)
    assert overlays == []
    assert bound.root.is_dir() and bound.raw.is_dir()
    assert bound.marker.read_bytes() == b"substituted ownership"


def test_linked_marker_directory_is_not_followed(module, bound, monkeypatch, tmp_path):
    elsewhere = tmp_path / "unrelated"
    elsewhere.mkdir()
    bound.marker.parent.symlink_to(elsewhere, target_is_directory=True)
    calls = []
    monkeypatch.setattr(module, "prepare_workspace", lambda **kwargs: calls.append(kwargs))
    with pytest.raises(RuntimeError, match="canonical"):
        module.stage_current_budgeted_subset_task(bound.runtime)
    assert list(elsewhere.iterdir()) == []
    assert calls == []


def test_marker_directory_cannot_overlap_controller_data(module, bound, monkeypatch):
    bound.marker.parent.mkdir()
    controller = replace(
        bound.runtime.material.paths, data_dir=bound.marker.parent, official_registry=None
    )
    material = replace(bound.runtime.material, _controller_paths=controller)
    runtime = replace(bound.runtime, material=material)
    calls = []
    monkeypatch.setattr(module, "prepare_workspace", lambda **kwargs: calls.append(kwargs))
    with pytest.raises(RuntimeError, match="overlap protected"):
        module.stage_current_budgeted_subset_task(runtime)
    assert calls == []
    assert list(bound.marker.parent.iterdir()) == []
