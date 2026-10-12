# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""The scored CLI must preview and bind before it can run a signed cohort."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from nooa_cybergym.leaderboard import campaign_runner


def test_scored_cli_refuses_missing_signed_inputs_before_launch(monkeypatch):
    dispatched = []
    monkeypatch.setattr(
        campaign_runner,
        "launch_signed_scored_campaign",
        lambda **kwargs: dispatched.append(kwargs),
        raising=False,
    )
    with pytest.raises(SystemExit) as failure:
        campaign_runner.main([])
    assert failure.value.code == 2
    assert dispatched == []


def test_signed_scored_launch_previews_then_preflights_then_admits_then_runs(
    tmp_path: Path, monkeypatch
):
    import nooa_cybergym.leaderboard.scored_campaign_inputs as inputs
    import nooa_cybergym.leaderboard.scored_worker_preflight as worker

    calls = []
    preview = SimpleNamespace(inputs=object(), authority=object())
    plan = object()
    admitted = object()
    binding = SimpleNamespace(state=admitted, executor=object(), ui=object())

    def preview_spy(**kwargs):
        calls.append("preview")
        return preview

    def preflight_spy(value, path):
        assert value is preview
        calls.append("preflight")
        return plan

    def admit_spy(value, **kwargs):
        assert value is preview.inputs
        assert kwargs["authority"] is preview.authority
        calls.append("admit")
        return admitted

    def bind_spy(value, state):
        assert value is plan and state is admitted
        calls.append("bind")
        return binding

    def run_spy(state, executor, ui):
        assert (state, executor, ui) == (admitted, binding.executor, binding.ui)
        calls.append("run")

    monkeypatch.setattr(inputs, "preview_signed_campaign", preview_spy)
    monkeypatch.setattr(inputs, "admit_signed_campaign", admit_spy)
    monkeypatch.setattr(worker, "prepare_previewed_scored_worker", preflight_spy)
    monkeypatch.setattr(worker, "bind_admitted_scored_worker", bind_spy)
    monkeypatch.setattr(campaign_runner, "run_campaign", run_spy)

    campaign_runner.launch_signed_scored_campaign(
        input_root=tmp_path,
        trust_registry=tmp_path / "trust.json",
        trust_sha256="a" * 64,
        run_id="run-1",
        evidence_root=tmp_path,
        launch_config=tmp_path / "launch.json",
    )
    assert calls == ["preview", "preflight", "admit", "bind", "run"]


def test_scored_cli_resumes_only_when_explicitly_requested(tmp_path: Path, monkeypatch):
    calls = []
    monkeypatch.setattr(
        campaign_runner,
        "launch_signed_scored_campaign",
        lambda **kwargs: calls.append(kwargs),
        raising=False,
    )
    code = campaign_runner.main(
        [
            "--input-root",
            str(tmp_path),
            "--trust-registry",
            str(tmp_path / "trust.json"),
            "--trust-sha256",
            "a" * 64,
            "--run-id",
            "run-1",
            "--evidence-root",
            str(tmp_path),
            "--launch-config",
            str(tmp_path / "launch.json"),
            "--resume",
        ]
    )
    assert code == 0
    assert calls[0]["resume"] is True


def test_scored_cli_refuses_empty_signed_directory_without_creating_ledger(tmp_path: Path):
    with pytest.raises(RuntimeError, match="bounded regular scored input required"):
        campaign_runner.main(
            [
                "--input-root",
                str(tmp_path),
                "--trust-registry",
                str(tmp_path / "trust.json"),
                "--trust-sha256",
                "a" * 64,
                "--run-id",
                "run-1",
                "--evidence-root",
                str(tmp_path),
                "--launch-config",
                str(tmp_path / "launch.json"),
            ]
        )
    assert list(tmp_path.iterdir()) == []
