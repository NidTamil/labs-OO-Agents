# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""A scored worker cannot be admitted before its frozen native image and UI client."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from nooa_cybergym.leaderboard.capabilities import CapabilityRegistry
from nooa_cybergym.leaderboard.scored_campaign_inputs import (
    ScoredLaunchPreview,
    SignedCampaignInputs,
)
from nooa_cybergym.leaderboard.scored_launch_config import (
    ScoredControllerMaterial,
    ScoredSignerPreflight,
)
from nooa_cybergym.leaderboard.scored_ui_preflight import ScoredUiPreflight
from nooa_cybergym.leaderboard.scored_worker_preflight import prepare_previewed_scored_worker


def test_scored_worker_preflight_requires_observed_image_then_fresh_ui_ack(
    tmp_path: Path, monkeypatch
):
    import nooa_cybergym.leaderboard.scored_worker_preflight as module

    config = {
        "run_id": "run-1",
        "epoch": "epoch-1",
        "timeout_seconds": 3600,
        "remote_alias": "cybergym-task-1",
        "ssh_port": 25000,
        "paths": {"evidence_root": str(tmp_path)},
    }
    native_image = "sha256:" + "a" * 64
    donor = SimpleNamespace(
        image_id=native_image,
        budgets=SimpleNamespace(task_wall_timeout_sec=3600),
        verify_unchanged=lambda: None,
    )
    signers = ScoredSignerPreflight(config, donor, object(), object(), object(), object())
    material = ScoredControllerMaterial(config, object(), object(), object())
    registry = CapabilityRegistry(())
    ui = ScoredUiPreflight(object(), object())
    authority = object()
    state = SimpleNamespace(
        run_id="run-1", epoch="epoch-1", evidence_root=tmp_path, authority=authority
    )
    preview = ScoredLaunchPreview(
        SignedCampaignInputs(b"decision", b"cert", b"lock", b"cohort", b"[]", {}),
        authority,
        state,
        {},
    )
    observed = []
    monkeypatch.setattr(module, "load_previewed_scored_signers", lambda *_: signers)
    monkeypatch.setattr(module, "load_previewed_scored_controller_material", lambda *_: material)
    monkeypatch.setattr(module, "load_previewed_scored_capabilities", lambda *_: registry)
    monkeypatch.setattr(module, "prepare_previewed_scored_ui", lambda *_: ui)
    monkeypatch.setattr(
        module, "require_previewed_scored_ui_client", lambda *_: observed.append("ui")
    )
    image = SimpleNamespace(id="sha256:" + "b" * 64)
    monkeypatch.setattr(
        module.docker,
        "from_env",
        lambda: SimpleNamespace(images=SimpleNamespace(get=lambda *_: image)),
    )

    with pytest.raises(RuntimeError, match="native image"):
        prepare_previewed_scored_worker(preview, tmp_path / "scored-launch.json")
    assert observed == []

    image.id = native_image
    plan = prepare_previewed_scored_worker(preview, tmp_path / "scored-launch.json")
    assert plan.observed_image_id == native_image
    assert plan.registry is registry
    assert plan.ui is ui
    assert observed == ["ui"]
