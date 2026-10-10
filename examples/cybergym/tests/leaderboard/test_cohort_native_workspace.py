# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Any signed-cohort Level-1 task can receive the pinned native template."""

from __future__ import annotations

import hashlib
import json

import pytest
from nooa_cybergym.leaderboard.cohort_native_workspace import overlay_cohort_template
from nooa_cybergym.leaderboard.workspace import PreparedWorkspace


def _prepared(tmp_path, task_id="oss-fuzz:42535201"):
    root = tmp_path / "task"
    root.mkdir()
    (root / "output").mkdir()
    (root / "src").mkdir()
    (root / "harness").mkdir()
    files = {
        "description.txt": b"official description",
        "repo-vul.tar.gz": b"vulnerable archive bytes",
        "README.md": b"official readme",
        "submit.sh": b"official submit",
        "harness/generic.py": b"generic harness",
    }
    hashes = {}
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        hashes[name] = hashlib.sha256(content).hexdigest()
    manifest = tmp_path / "official-task-manifest.json"
    manifest.write_text(
        json.dumps({"schema_version": 1, "task_id": task_id, "file_hashes": hashes})
    )
    return PreparedWorkspace(task_id, root, manifest, hashes)


def test_cohort_overlay_accepts_oss_fuzz_and_binds_scored_freeze(tmp_path):
    prepared = _prepared(tmp_path)
    template = tmp_path / "CLAUDE.md"
    template.write_bytes(b"pinned native contract")
    stage = overlay_cohort_template(
        prepared,
        cohort_task_ids=("arvo:47101", "oss-fuzz:42535201"),
        template_files={"CLAUDE.md": (template, hashlib.sha256(template.read_bytes()).hexdigest())},
        evidence=tmp_path / "evidence",
        run_id="scored-run",
        freeze_sha256="a" * 64,
        cohort_sha256="b" * 64,
    )
    assert (stage.root / "README.md").read_bytes() == b"official readme"
    assert (stage.root / "CLAUDE.md").read_bytes() == b"pinned native contract"
    manifest = json.loads(stage.manifest_bytes)
    assert manifest["scope"] == "scored_native"
    assert manifest["task_id"] == "oss-fuzz:42535201"
    assert manifest["freeze_sha256"] == "a" * 64
    assert manifest["cohort_sha256"] == "b" * 64
    assert manifest["file_hashes"] == stage.file_hashes
    assert (stage.evidence / "task-manifest.json").read_bytes() == stage.manifest_bytes


def test_cohort_overlay_rejects_task_outside_signed_cohort(tmp_path):
    prepared = _prepared(tmp_path)
    template = tmp_path / "CLAUDE.md"
    template.write_bytes(b"pinned native contract")
    with pytest.raises(ValueError, match="signed cohort"):
        overlay_cohort_template(
            prepared,
            cohort_task_ids=("arvo:47101",),
            template_files={
                "CLAUDE.md": (template, hashlib.sha256(template.read_bytes()).hexdigest())
            },
            evidence=tmp_path / "evidence",
            run_id="scored-run",
            freeze_sha256="a" * 64,
            cohort_sha256="b" * 64,
        )
    assert not (tmp_path / "evidence").exists()


def test_cohort_overlay_rejects_template_collision_with_official_input(tmp_path):
    prepared = _prepared(tmp_path)
    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"attacker description")
    with pytest.raises(RuntimeError, match="collides"):
        overlay_cohort_template(
            prepared,
            cohort_task_ids=("oss-fuzz:42535201",),
            template_files={
                "description.txt": (
                    replacement,
                    hashlib.sha256(replacement.read_bytes()).hexdigest(),
                )
            },
            evidence=tmp_path / "evidence",
            run_id="scored-run",
            freeze_sha256="a" * 64,
            cohort_sha256="b" * 64,
        )
    assert (prepared.root / "description.txt").read_bytes() == b"official description"
