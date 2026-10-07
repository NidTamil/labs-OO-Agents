# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""The toy-task stager must keep fixed-side bytes out of the solver mount."""

import hashlib
import io
import json
import shutil
import tarfile
from pathlib import Path

import pytest
from nooa_cybergym.leaderboard.runtime_config import load_runtime_config
from nooa_cybergym.leaderboard.synthetic_workspace import stage_synthetic

pytest_plugins = ("examples.cybergym.tests.leaderboard.test_runtime_config",)


def test_both_runs_stage_only_verified_vulnerable_fixture_and_frozen_contract(prepared):
    raw, save, _ = prepared
    repo = Path(raw["repo_root"])
    source = Path(__file__).resolve().parents[2] / "leaderboard/agent-template"
    target = repo / "examples/cybergym/leaderboard/agent-template"
    shutil.copytree(source, target)
    manifest_path = Path(raw["artifacts"]["harness_manifest"]["path"])
    manifest = json.loads(manifest_path.read_bytes())
    for path in target.rglob("*"):
        if path.is_file():
            manifest["file_hashes"][path.relative_to(repo).as_posix()] = hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")))
    raw["artifacts"]["harness_manifest"]["sha256"] = hashlib.sha256(
        manifest_path.read_bytes()
    ).hexdigest()
    config = load_runtime_config(save())
    stages = []
    for run in config.run_ids:
        for fixture in config.fixtures:
            stage = stage_synthetic(config, run_id=run, task_id=fixture.task_id)
            stages.append(stage)
            assert (stage.root / "description.txt").read_bytes() == fixture.description.read_bytes()
            assert (stage.root / "README.md").is_file()
            assert (stage.root / "submit.sh").read_bytes().startswith(b"#!/bin/sh\n")
            assert not ((stage.root / "submit.sh").stat().st_mode & 0o111)
            assert "submit.sh" in stage.file_hashes
            assert (stage.root / "CLAUDE.md").read_bytes() == (target / "CLAUDE.md").read_bytes()
            assert fixture.fixed.read_bytes() not in b"".join(
                path.read_bytes() for path in stage.root.rglob("*") if path.is_file()
            )
            with tarfile.open(
                fileobj=io.BytesIO((stage.root / "repo-vul.tar.gz").read_bytes()), mode="r:gz"
            ) as archive:
                members = archive.getmembers()
                assert [member.name for member in members] == ["parser.c"]
                assert archive.extractfile(members[0]).read() == fixture.vulnerable.read_bytes()
            assert stage.evidence != stage.root and not stage.evidence.is_relative_to(stage.root)
            assert (
                stage.file_hashes["CLAUDE.md"]
                == hashlib.sha256((target / "CLAUDE.md").read_bytes()).hexdigest()
            )
            for workflow in ("recon", "debug", "review"):
                relative = f".claude/workflows/{workflow}.js"
                staged = stage.root / relative
                canonical = (
                    Path(__file__).resolve().parents[2]
                    / "leaderboard/native-launcher/workflows"
                    / f"{workflow}.js"
                )
                assert staged.read_bytes() == canonical.read_bytes()
                assert (
                    stage.file_hashes[relative]
                    == hashlib.sha256(canonical.read_bytes()).hexdigest()
                )
    assert len({stage.root for stage in stages}) == 4
    with pytest.raises(FileExistsError):
        stage_synthetic(config, run_id=config.run_ids[0], task_id=config.fixtures[0].task_id)


def test_stager_refuses_unfrozen_generic_contract(prepared):
    _, save, _ = prepared
    config = load_runtime_config(save())
    with pytest.raises(ValueError, match="task contract absent"):
        stage_synthetic(config, run_id=config.run_ids[0], task_id=config.fixtures[0].task_id)
