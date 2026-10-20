# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""A scored worker cannot be admitted before its frozen native image and UI client."""

from __future__ import annotations

import threading
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from nooa_cybergym.leaderboard.campaign import CampaignAction, CampaignState
from nooa_cybergym.leaderboard.capabilities import CapabilityRegistry
from nooa_cybergym.leaderboard.deepseek import AlternateModelPolicy
from nooa_cybergym.leaderboard.model_gateway import ModelPolicy
from nooa_cybergym.leaderboard.primary_takeover import PrimaryTakeoverPolicy
from nooa_cybergym.leaderboard.scored_campaign_inputs import (
    ScoredLaunchPreview,
    SignedCampaignInputs,
)
from nooa_cybergym.leaderboard.scored_launch_config import (
    ScoredControllerMaterial,
    ScoredSignerPreflight,
)
from nooa_cybergym.leaderboard.scored_ui_preflight import ScoredUiPreflight
from nooa_cybergym.leaderboard.scored_worker_preflight import (
    ScoredWorkerPlan,
    bind_admitted_scored_worker,
    prepare_previewed_scored_worker,
)


@pytest.mark.parametrize("takeover_enabled", [False, True])
def test_scored_worker_preflight_requires_observed_image_then_fresh_ui_ack(
    tmp_path: Path, monkeypatch, takeover_enabled
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
    takeover = PrimaryTakeoverPolicy() if takeover_enabled else None
    donor = SimpleNamespace(
        image_id=native_image,
        alternate_policy=alternate_policy(),
        primary_takeover_policy=takeover,
        budgets=SimpleNamespace(task_wall_timeout_sec=3600),
        verify_unchanged=lambda: None,
    )
    signers = ScoredSignerPreflight(config, donor, object(), object(), object(), object())
    material = ScoredControllerMaterial(config, object(), object(), object())
    registry = CapabilityRegistry(())
    ui = ScoredUiPreflight(object(), object())
    model_policy = ModelPolicy(
        "glm-5.3[1m]",
        donor.alternate_policy,
        registry.digest,
        "https://api.z.ai/api/anthropic",
        primary_takeover=takeover,
    )
    harness = {"model_policy_sha256": model_policy.digest}

    class Authority:
        def attest_signed(self, kind, envelope):
            assert (kind, envelope) == ("harness_lock", b"lock")
            return harness

    authority = Authority()
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
    assert plan.model_policy_sha256 == model_policy.digest
    assert plan.registry is registry
    assert plan.ui is ui
    assert observed == ["ui"]

    harness["model_policy_sha256"] = "d" * 64
    with pytest.raises(RuntimeError, match="model policy"):
        prepare_previewed_scored_worker(preview, tmp_path / "scored-launch.json")
    assert observed == ["ui"]


def alternate_policy():
    path = Path(__file__).resolve().parents[2] / "leaderboard/config/alternate-model.json"
    return AlternateModelPolicy.model_validate_json(path.read_bytes())


@pytest.mark.parametrize("takeover_enabled", [False, True])
def test_admitted_worker_binds_exact_preview_to_driver_executor_and_recovery(
    tmp_path: Path, monkeypatch, takeover_enabled
):
    import nooa_cybergym.leaderboard.scored_worker_preflight as module

    harness = {}

    class Authority:
        def attest_signed(self, kind, envelope):
            assert (kind, envelope) == ("harness_lock", b"lock")
            return harness

    authority = Authority()
    task_ids = tuple(f"arvo:{index}" for index in range(1507))
    preview_state = CampaignState(
        "run-1",
        "epoch-1",
        tmp_path,
        task_ids,
        "a" * 64,
        "b" * 64,
        "c" * 64,
        "1" * 40,
        "2" * 40,
        "d" * 64,
        b"signed-cohort",
        authority,
    )
    admitted = replace(preview_state)
    preview = ScoredLaunchPreview(
        SignedCampaignInputs(b"decision", b"cert", b"lock", b"cohort", b"[]", {}),
        authority,
        preview_state,
        {},
    )
    config = {
        "run_id": "run-1",
        "epoch": "epoch-1",
        "timeout_seconds": 3600,
        "remote_alias": "cybergym-task-1",
        "ssh_port": 25000,
        "paths": {"evidence_root": str(tmp_path), "mailbox_root": str(tmp_path)},
        "files": {
            name: {"path": str(tmp_path / name), "sha256": "e" * 64}
            for name in (
                "donor_config",
                "bindings",
                "public_ssh_key",
                "asset_manifest",
                "image_manifest",
                "official_verifier",
            )
        },
    }
    native_image = "sha256:" + "f" * 64
    takeover = PrimaryTakeoverPolicy() if takeover_enabled else None
    donor = SimpleNamespace(
        image_id=native_image,
        alternate_policy=alternate_policy(),
        primary_takeover_policy=takeover,
        budgets=SimpleNamespace(task_wall_timeout_sec=3600),
        verify_unchanged=lambda: None,
    )
    signers = ScoredSignerPreflight(config, donor, object(), object(), object(), object())
    material = ScoredControllerMaterial(
        config, SimpleNamespace(name="controller-paths"), object(), object()
    )
    registry = CapabilityRegistry(())
    model_policy = ModelPolicy(
        "glm-5.3[1m]",
        donor.alternate_policy,
        registry.digest,
        "https://api.z.ai/api/anthropic",
        primary_takeover=takeover,
    )
    harness["model_policy_sha256"] = model_policy.digest
    mailbox = SimpleNamespace(run_id="run-1", root=tmp_path)
    ui = ScoredUiPreflight(mailbox, SimpleNamespace(mailbox=mailbox))
    plan = ScoredWorkerPlan(
        preview,
        tmp_path / "launch.json",
        signers,
        material,
        registry,
        ui,
        native_image,
        model_policy.digest,
    )
    observed = {}
    monkeypatch.setattr(
        CampaignState, "next_action", lambda self: CampaignAction("prepare", task_ids[0])
    )
    monkeypatch.setattr(
        module, "load_previewed_scored_launch_config", lambda *_: config, raising=False
    )
    monkeypatch.setattr(
        module.docker,
        "from_env",
        lambda: SimpleNamespace(
            images=SimpleNamespace(get=lambda *_: SimpleNamespace(id=native_image))
        ),
    )

    def admission_spy(**kwargs):
        observed["admission"] = kwargs
        return object()

    def recovery_spy(**kwargs):
        observed["recovery"] = kwargs
        return object()

    def worker_spy(**kwargs):
        observed["worker_args"] = kwargs
        return SimpleNamespace(driver=kwargs["driver"])

    def executor_spy(**kwargs):
        observed["executor_args"] = kwargs
        return object()

    def driver_spy(**kwargs):
        observed["driver_args"] = kwargs
        return b"terminal"

    monkeypatch.setattr(module, "verify_scored_capability_admission", admission_spy)
    monkeypatch.setattr(module, "CohortTerminalRecovery", recovery_spy)
    monkeypatch.setattr(module, "CohortNativeWorker", worker_spy)
    monkeypatch.setattr(module, "NativeCampaignTaskExecutor", executor_spy)
    monkeypatch.setattr(module, "run_scored_native", driver_spy)

    with pytest.raises(RuntimeError, match="admitted state"):
        bind_admitted_scored_worker(plan, replace(admitted, epoch="other"))
    assert observed == {}

    harness["model_policy_sha256"] = "8" * 64
    with pytest.raises(RuntimeError, match="model policy"):
        bind_admitted_scored_worker(plan, admitted)
    assert observed == {}
    harness["model_policy_sha256"] = model_policy.digest

    bound = bind_admitted_scored_worker(plan, admitted)
    assert bound.state is admitted
    assert bound.ui is ui.ui
    assert observed["admission"]["state"] is admitted
    assert observed["executor_args"]["state"] is admitted
    assert observed["recovery"]["expected_model"] == "glm-5.3"
    assert observed["recovery"]["expected_policy_sha256"] == model_policy.digest
    worker_driver = observed["worker_args"]["driver"]
    worker_driver(task_ids[0], on_prepared=lambda _: None, stop=threading.Event())
    assert observed["driver_args"]["state"] is admitted
    assert observed["driver_args"]["task_id"] == task_ids[0]
    assert observed["driver_args"]["remote_alias"] == "cybergym-task-1"
