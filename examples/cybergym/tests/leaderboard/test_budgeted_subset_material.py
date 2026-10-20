# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Synthetic signed metadata only: no task assets, Docker, keys or provider calls."""

from __future__ import annotations

import copy
import json
from dataclasses import FrozenInstanceError, replace
from types import SimpleNamespace

import pytest
from nooa_cybergym.leaderboard import pinned_metering, run_resource_budget
from nooa_cybergym.leaderboard.budgeted_subset_admission import (
    bind_budgeted_subset_state,
    preview_budgeted_subset_admission,
)
from nooa_cybergym.leaderboard.campaign import _json_bytes
from nooa_cybergym.leaderboard.cohort import freeze_harness_manifest
from nooa_cybergym.leaderboard.subset_dry_run_admission import (
    OFFICIAL_SUBSET_TASK_IDS,
    PREVIOUSLY_EXPOSED_TASK_IDS,
)
from nooa_cybergym.leaderboard.workspace import ControllerPaths

from .test_budgeted_subset_admission import RealSignatureAuthority, setup, sha
from .test_run_resource_budget import inputs


@pytest.fixture
def module():
    from nooa_cybergym.leaderboard import budgeted_subset_material

    return budgeted_subset_material


@pytest.fixture
def factory(tmp_path, monkeypatch):
    now = [1_800_000_000_000_000_000]
    monkeypatch.setattr(run_resource_budget, "_now_ns", lambda: now[0])
    roots = {name: tmp_path / name for name in ("data", "staging", "evidence", "harness")}
    for root in roots.values():
        root.mkdir()
    (roots["harness"] / "README.md").write_text("Generic synthetic harness.\n")
    mask, generator, harness_manifest = (
        tmp_path / "mask.json",
        tmp_path / "generator.py",
        tmp_path / "harness.json",
    )
    mask.write_bytes(b"{}")
    generator.write_bytes(b"# synthetic generator identity only\n")
    harness_manifest.write_bytes(freeze_harness_manifest(roots["harness"]))
    full_ids = OFFICIAL_SUBSET_TASK_IDS + tuple(f"arvo:{100000 + n}" for n in range(1497))
    tasks = _json_bytes([{"task_id": task} for task in full_ids])
    assets = {
        "schema_version": 1,
        "benchmark_commit": "1" * 40,
        "dataset_commit": "2" * 40,
        "assets": [
            {
                "task_id": task,
                "description_sha256": "a" * 64,
                "description_bytes": 12,
                "description_lfs_pointer": True,
                "vulnerable_archive_sha256": "b" * 64,
                "vulnerable_archive_bytes": 14,
                "vulnerable_archive_lfs_pointer": True,
            }
            for task in full_ids
        ],
    }
    images = {
        "schema_version": 1,
        "scope": "scored_official_images",
        "images": [
            {"task_id": task, "vulnerable": "sha256:" + "c" * 64, "fixed": "sha256:" + "d" * 64}
            for task in full_ids
        ],
    }
    asset_path, image_path = tmp_path / "assets.json", tmp_path / "images.json"
    paths = ControllerPaths(
        data_dir=roots["data"],
        mask_map_path=mask,
        server="http://registered-tool-gateway",
        staging_root=roots["staging"],
        evidence_root=roots["evidence"],
        harness_dir=roots["harness"],
        harness_manifest_path=harness_manifest,
        harness_manifest_sha256=sha(harness_manifest.read_bytes()),
        mask_map_sha256=sha(mask.read_bytes()),
        generator_source=generator,
        generator_sha256=sha(generator.read_bytes()),
    )

    def make(
        *,
        change_cohort=None,
        change_assets=None,
        change_images=None,
        change_freeze=None,
        change_tasks=None,
    ):
        task_rows = json.loads(tasks)
        if change_tasks:
            change_tasks(task_rows)
        actual_tasks = _json_bytes(task_rows)
        asset_payload, image_payload = copy.deepcopy(assets), copy.deepcopy(images)
        if change_assets:
            change_assets(asset_payload)
        if change_images:
            change_images(image_payload)
        asset_path.write_bytes(_json_bytes(asset_payload))
        image_path.write_bytes(_json_bytes(image_payload))
        cohort_payload = {
            "schema_version": 1,
            "task_ids": [row["task_id"] for row in task_rows],
            "tasks_json_sha256": sha(actual_tasks),
            "asset_hashes_sha256": sha(asset_path.read_bytes()),
            "benchmark_commit": "1" * 40,
            "dataset_commit": "2" * 40,
            "mask_map_sha256": paths.mask_map_sha256,
            "generator_sha256": paths.generator_sha256,
            "harness_manifest_sha256": paths.harness_manifest_sha256,
        }
        if change_cohort:
            change_cohort(cohort_payload)
        authority, args, bindings = setup(roots["evidence"], RealSignatureAuthority())
        cohort_raw = authority.put("cohort", cohort_payload)
        freeze = dict(authority.artifacts[("harness_lock", bindings["signed_freeze"])])
        freeze.update(
            cohort_sha256=sha(cohort_raw), scored_images_sha256=sha(image_path.read_bytes())
        )
        if change_freeze:
            change_freeze(freeze)
        freeze_raw = authority.put("harness_lock", freeze)
        certification = dict(
            authority.artifacts[("certification", bindings["signed_certification"])]
        )
        certification.update(cohort_sha256=sha(cohort_raw), harness_sha256=sha(freeze_raw))
        certificate_raw = authority.put("certification", certification)
        metering = inputs((run_resource_budget, pinned_metering), spend=500000000)["metering"]
        budget = dict(authority.artifacts[("subset_run_budget", args["signed_budget"])])
        budget["metering_policy_sha256"] = metering.sha256
        budget_raw = authority.put("subset_run_budget", budget)
        admission = dict(
            authority.artifacts[("budgeted_subset_admission", args["signed_admission"])]
        )
        admission.update(
            cohort_sha256=sha(cohort_raw),
            freeze_sha256=sha(freeze_raw),
            certification_sha256=sha(certificate_raw),
            budget_sha256=sha(budget_raw),
            metering_policy_sha256=metering.sha256,
        )
        admission_raw = authority.put("budgeted_subset_admission", admission)
        args.update(
            signed_admission=admission_raw,
            signed_budget=budget_raw,
            expected_admission_sha256=sha(admission_raw),
            expected_budget_sha256=sha(budget_raw),
            expected_cohort_sha256=sha(cohort_raw),
            expected_freeze_sha256=sha(freeze_raw),
            expected_certification_sha256=sha(certificate_raw),
            metering_policy_sha256=metering.sha256,
        )
        preview = preview_budgeted_subset_admission(**args)
        resources = run_resource_budget.RunResourceBudget.create(
            tmp_path / "resources.sqlite",
            budget=preview.budget,
            authority=authority,
            metering=metering,
        )
        bindings.update(
            resource_budget=resources,
            signed_freeze=freeze_raw,
            signed_certification=certificate_raw,
        )
        state = bind_budgeted_subset_state(preview, **bindings)
        authority.events.append(state.creation_event())
        return SimpleNamespace(
            state=state,
            resources=resources,
            authority=authority,
            paths=paths,
            cohort_raw=cohort_raw,
            tasks=actual_tasks,
            full_ids=full_ids,
            asset_path=asset_path,
            image_path=image_path,
            readiness=bindings["readiness_verifier"],
            now=now,
        )

    return make


def load(module, data, *, paths=None):
    cohort = module.verify_subset_cohort(
        data.state, signed_cohort=data.cohort_raw, tasks_json=data.tasks
    )
    return module.load_budgeted_subset_material(
        data.state,
        cohort=cohort,
        paths=paths or data.paths,
        asset_manifest_path=data.asset_path,
        image_manifest_path=data.image_path,
    )


def prepare(data):
    task = data.state.task_ids[0]
    data.state.mark_preparation_started(task, preparation_id="synthetic-preparation")
    return task


def test_full_metadata_stays_full_but_only_committed_subset_task_can_stage(module, factory):
    data = factory()
    material = load(module, data)
    assert material.state is data.state
    assert material.resource_budget is data.resources
    assert material.cohort.task_ids == data.full_ids
    assert material.allowed_task_ids == OFFICIAL_SUBSET_TASK_IDS
    assert material.previously_exposed_task_ids == PREVIOUSLY_EXPOSED_TASK_IDS
    assert material.assets.task_ids == data.full_ids
    assert material.images.task_ids == data.full_ids
    assert len(material.assets.task_ids) == 1507
    before = list(data.authority.events)
    with pytest.raises(RuntimeError, match="committed preparation"):
        material.verify_current(data.state.task_ids[0])
    assert data.authority.events == before
    task = prepare(data)
    verified_paths = material.verify_current(task)
    assert verified_paths.official_registry.task_ids == data.full_ids
    assert data.resources.snapshot()["requests"] == 0
    assert tuple(data.paths.data_dir.iterdir()) == ()
    assert tuple(data.paths.staging_root.iterdir()) == ()


@pytest.mark.parametrize(
    "field",
    [
        "tasks_json_sha256",
        "asset_hashes_sha256",
        "mask_map_sha256",
        "generator_sha256",
        "harness_manifest_sha256",
    ],
)
def test_signed_cohort_pins_are_enforced(module, factory, field):
    data = factory(change_cohort=lambda payload: payload.update({field: "f" * 64}))
    with pytest.raises((RuntimeError, ValueError)):
        load(module, data)


@pytest.mark.parametrize("field", ["benchmark_commit", "dataset_commit"])
def test_asset_revision_cannot_be_substituted(module, factory, field):
    data = factory(change_assets=lambda payload: payload.update({field: "3" * 40}))
    with pytest.raises(RuntimeError, match="disagrees with signed cohort"):
        load(module, data)


@pytest.mark.parametrize("which", ["cohort", "assets", "images"])
def test_full_order_cannot_be_replaced_with_ten_or_reordered(module, factory, which):
    changes = {
        "cohort": {"change_cohort": lambda payload: payload["task_ids"].reverse()},
        "assets": {"change_assets": lambda payload: payload["assets"].reverse()},
        "images": {"change_images": lambda payload: payload.update(images=payload["images"][:10])},
    }
    data = factory(**changes[which])
    with pytest.raises((RuntimeError, ValueError)):
        load(module, data)


@pytest.mark.parametrize("field", ["cohort_sha256", "scored_images_sha256"])
def test_signed_freeze_binds_actual_cohort_and_full_image_registry(module, factory, field):
    data = factory(change_freeze=lambda payload: payload.update({field: "f" * 64}))
    with pytest.raises((RuntimeError, ValueError)):
        load(module, data)


def test_actual_signed_cohort_and_tasks_bytes_are_required(module, factory):
    data = factory()
    for signed, tasks in ((data.cohort_raw + b" ", data.tasks), (data.cohort_raw, b"[]")):
        with pytest.raises(RuntimeError):
            module.verify_subset_cohort(data.state, signed_cohort=signed, tasks_json=tasks)


@pytest.mark.parametrize("which", ["missing_approved", "ten_only", "duplicate", "unsupported"])
def test_signed_matching_tasks_still_require_full_supported_cohort_and_approved_membership(
    module, factory, which
):
    def change(rows):
        if which == "missing_approved":
            rows[0] = {"task_id": "arvo:999999"}
        elif which == "ten_only":
            del rows[10:]
        elif which == "duplicate":
            rows[-1] = rows[0]
        else:
            rows[-1] = {"task_id": "other:999999"}

    data = factory(change_tasks=change)
    with pytest.raises(RuntimeError):
        module.verify_subset_cohort(
            data.state, signed_cohort=data.cohort_raw, tasks_json=data.tasks
        )


@pytest.mark.parametrize("which", ["mask", "generator", "harness", "assets", "images"])
def test_material_rechecks_disk_content_at_staging_boundary(module, factory, which):
    data = factory()
    material = load(module, data)
    task = prepare(data)
    target = {
        "mask": data.paths.mask_map_path,
        "generator": data.paths.generator_source,
        "harness": data.paths.harness_dir / "README.md",
        "assets": data.asset_path,
        "images": data.image_path,
    }[which]
    target.write_bytes(target.read_bytes() + b"changed")
    with pytest.raises((RuntimeError, ValueError)):
        material.verify_current(task)


def test_material_rechecks_independent_readiness_and_freeze(module, factory):
    data = factory()
    material = load(module, data)
    task = prepare(data)
    data.readiness.accepted = False
    with pytest.raises(RuntimeError, match="readiness"):
        material.verify_current(task)
    data.readiness.accepted = True
    changed_state = replace(data.state, signed_freeze=data.state.signed_freeze + b" ")
    with pytest.raises(RuntimeError, match="signed readiness bytes"):
        replace(material, state=changed_state).verify_current(task)


@pytest.mark.parametrize(
    "which", ["different_task", "outside_subset", "prepared", "stopped", "expired"]
)
def test_staging_access_is_bound_to_current_preparation_only(module, factory, which):
    data = factory()
    material = load(module, data)
    task = prepare(data)
    if which == "different_task":
        task = data.state.task_ids[1]
    elif which == "outside_subset":
        task = data.full_ids[-1]
    elif which == "prepared":
        data.state.mark_prepared(task)
    elif which == "stopped":
        data.resources.stop(reason="operator_stop")
    else:
        data.now[0] += 432000 * 1_000_000_000
    with pytest.raises(RuntimeError):
        material.verify_current(task)


def test_returned_mutable_registries_cannot_change_material(module, factory):
    data = factory()
    material = load(module, data)
    task = prepare(data)
    material.assets._entries.clear()
    material.images._images.clear()
    material.paths.official_registry._entries.clear()
    assert material.assets.inputs_for(task).task_id == task
    assert material.images.images_for(task).vulnerable == "sha256:" + "c" * 64
    assert material.verify_current(task).official_registry.inputs_for(task).task_id == task
    with pytest.raises(FrozenInstanceError):
        material.cohort = None
    with pytest.raises(FrozenInstanceError):
        material.cohort.task_ids = OFFICIAL_SUBSET_TASK_IDS


@pytest.mark.parametrize("which", ["evidence", "relative", "overlap", "route"])
def test_controller_paths_are_bound_and_separated(module, factory, which):
    data = factory()
    paths = data.paths
    paths = {
        "evidence": replace(paths, evidence_root=paths.data_dir),
        "relative": replace(
            paths,
            generator_source=paths.generator_source.relative_to(paths.generator_source.parent),
        ),
        "overlap": replace(paths, staging_root=paths.harness_dir),
        "route": replace(paths, server="http://unbound.example"),
    }[which]
    with pytest.raises(RuntimeError):
        load(module, data, paths=paths)


@pytest.mark.parametrize("which", ["prepared", "expired"])
def test_preparation_identity_and_resource_allowance_rechecked_after_file_verification(
    module, factory, monkeypatch, which
):
    data = factory()
    material = load(module, data)
    task = prepare(data)
    original = module.verify_harness_tree

    def changing_boundary(*args):
        result = original(*args)
        if which == "prepared":
            data.state.mark_prepared(task)
        else:
            data.now[0] += 432000 * 1_000_000_000
        return result

    monkeypatch.setattr(module, "verify_harness_tree", changing_boundary)
    with pytest.raises(RuntimeError):
        material.verify_current(task)
    assert data.resources.snapshot()["requests"] == 0


def test_harness_extra_file_rejected_without_reading_task_assets(module, factory):
    data = factory()
    material = load(module, data)
    task = prepare(data)
    (data.paths.harness_dir / "unexpected.txt").write_text("unfrozen generic content")
    with pytest.raises(RuntimeError):
        material.verify_current(task)
    assert not tuple(data.paths.data_dir.iterdir())


def test_verification_rejects_changed_trust_registry(module, factory):
    data = factory()
    material = load(module, data)
    task = prepare(data)
    data.authority.verifier = RealSignatureAuthority().verifier
    with pytest.raises(RuntimeError):
        material.verify_current(task)


def test_material_rejects_forged_cached_cohort_or_registry_rows(module, factory):
    data = factory()
    material = load(module, data)
    task = prepare(data)
    changed = replace(material.cohort, task_ids=tuple(reversed(material.cohort.task_ids)))
    with pytest.raises(RuntimeError, match="full-cohort identity"):
        replace(material, cohort=changed).verify_current(task)
    with pytest.raises(RuntimeError, match="metadata changed"):
        replace(material, _image_rows=material._image_rows[:10]).verify_current(task)
