# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Scored native binding never inherits the donor's synthetic capability digest."""

from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from nooa_cybergym.leaderboard.capabilities import CapabilityRegistry
from nooa_cybergym.leaderboard.model_gateway import PRIMARY_MODEL
from nooa_cybergym.leaderboard.scored_capability_admission import ScoredCapabilityAdmission
from nooa_cybergym.leaderboard.scored_runtime_binding import bind_scored_runtime


def test_scored_runtime_binds_live_registry_and_signed_image_manifest(tmp_path: Path, monkeypatch):
    import nooa_cybergym.leaderboard.scored_runtime_binding as module

    component = CapabilityRegistry(())
    scored = CapabilityRegistry(())
    monkeypatch.setattr(
        CapabilityRegistry,
        "digest",
        property(lambda self: "1" * 64 if self is component else "2" * 64),
    )
    image_id = "sha256:" + "a" * 64
    calls = []
    donor = SimpleNamespace(
        image_id=image_id,
        registry=component,
        freeze_sha256="c" * 64,
        alternate_policy=SimpleNamespace(),
        verify_unchanged=lambda: calls.append("donor"),
    )
    image_pin = ["b" * 64]
    bindings_path = tmp_path / "bindings.json"
    bindings_path.write_bytes(b"frozen-binding")
    authority = SimpleNamespace(
        attest_signed=lambda kind, raw: (
            {
                "scored_images_sha256": image_pin[0],
                "donor_configuration_sha256": "c" * 64,
                "capability_bindings_sha256": hashlib.sha256(b"frozen-binding").hexdigest(),
                "model_policy_sha256": "e" * 64,
                "epoch": "epoch-1",
            }
            if kind == "harness_lock" and raw == b"signed-lock"
            else None
        )
    )
    task_ids = ("arvo:47101", "oss-fuzz:42535201")
    state = SimpleNamespace(run_id="run-1", epoch="epoch-1", task_ids=task_ids, authority=authority)
    admission = ScoredCapabilityAdmission(
        "run-1",
        "epoch-1",
        "3" * 64,
        scored.digest,
        image_id,
        state,
        b"decision",
        b"certification",
        b"signed-lock",
    )
    monkeypatch.setattr(
        ScoredCapabilityAdmission,
        "verify_current",
        lambda self, **kw: calls.append(("admission", kw)),
    )
    manifest = tmp_path / "images.json"
    images = object()

    monkeypatch.setattr(
        module.ScoredImageRegistry,
        "load",
        lambda path, **kw: calls.append(("images", path, kw)) or images,
    )
    monkeypatch.setattr(
        module,
        "load_scored_binding_provenance",
        lambda path, **kw: calls.append(("bindings", path, kw)) or ("bound",),
    )
    monkeypatch.setattr(
        module,
        "load_captured_native_schemas",
        lambda path, registry: {"Read": "c" * 64},
    )
    monkeypatch.setattr(
        module,
        "ModelPolicy",
        lambda primary, alternate, digest, url: SimpleNamespace(
            primary=primary, capability_policy_sha256=digest, digest="e" * 64
        ),
    )
    result = bind_scored_runtime(
        donor=donor,
        state=state,
        task_id=task_ids[1],
        admission=admission,
        registry=scored,
        bindings_path=bindings_path,
        image_manifest=manifest,
        observed_image_id=image_id,
    )
    assert result.images is images
    assert result.bindings == ("bound",)
    assert result.captured_schemas == {"Read": "c" * 64}
    assert result.model_policy.primary == PRIMARY_MODEL
    assert result.model_policy.capability_policy_sha256 == scored.digest
    assert calls[0] == "donor"
    assert calls[1] == (
        "admission",
        {"task_id": task_ids[1], "registry": scored, "observed_image_id": image_id},
    )
    assert calls[2] == (
        "images",
        manifest,
        {"expected_sha256": "b" * 64, "task_ids": task_ids},
    )
    assert calls[3][0] == "bindings"
    assert calls[3][2] == {"component_registry": component, "scored_registry": scored}
    assert result.model_policy.capability_policy_sha256 != component.digest

    with pytest.raises(RuntimeError, match="image"):
        bind_scored_runtime(
            donor=donor,
            state=state,
            task_id=task_ids[1],
            admission=admission,
            registry=scored,
            bindings_path=bindings_path,
            image_manifest=manifest,
            observed_image_id="sha256:" + "d" * 64,
        )
    assert len(calls) == 4
    image_pin[0] = None
    with pytest.raises(RuntimeError, match="manifest pin"):
        bind_scored_runtime(
            donor=donor,
            state=state,
            task_id=task_ids[1],
            admission=admission,
            registry=scored,
            bindings_path=bindings_path,
            image_manifest=manifest,
            observed_image_id=image_id,
        )
    assert [item for item in calls if isinstance(item, tuple) and item[0] == "images"] == [calls[2]]
    image_pin[0] = "b" * 64
    bindings_path.write_bytes(b"changed-binding")
    with pytest.raises(RuntimeError, match="binding"):
        bind_scored_runtime(
            donor=donor,
            state=state,
            task_id=task_ids[1],
            admission=admission,
            registry=scored,
            bindings_path=bindings_path,
            image_manifest=manifest,
            observed_image_id=image_id,
        )
