# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Official Level-1 workspace receives only pinned native template files."""

from __future__ import annotations

import hashlib
import json

import pytest
from nooa_cybergym.leaderboard.practice_native_workspace import overlay_native_template
from nooa_cybergym.leaderboard.workspace import PreparedWorkspace


def _prepared(tmp_path):
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
        json.dumps({"schema_version": 1, "task_id": "arvo:47101", "file_hashes": hashes})
    )
    return PreparedWorkspace("arvo:47101", root, manifest, hashes)


def test_practice_overlay_preserves_official_files_and_freezes_native_template(tmp_path):
    prepared = _prepared(tmp_path)
    template = tmp_path / "template"
    (template / ".claude" / "agents").mkdir(parents=True)
    (template / "CLAUDE.md").write_bytes(b"pinned native contract")
    (template / ".claude" / "agents" / "cybergym-recon.md").write_bytes(b"pinned recon")
    frozen = {
        "CLAUDE.md": (
            template / "CLAUDE.md",
            hashlib.sha256(b"pinned native contract").hexdigest(),
        ),
        ".claude/agents/cybergym-recon.md": (
            template / ".claude" / "agents" / "cybergym-recon.md",
            hashlib.sha256(b"pinned recon").hexdigest(),
        ),
    }
    stage = overlay_native_template(
        prepared,
        template_files=frozen,
        evidence=tmp_path / "evidence",
        run_id="practice-run",
        practice_freeze_sha256="a" * 64,
    )
    assert (stage.root / "README.md").read_bytes() == b"official readme"
    assert (stage.root / "CLAUDE.md").read_bytes() == b"pinned native contract"
    assert (
        stage.file_hashes[".claude/agents/cybergym-recon.md"]
        == hashlib.sha256(b"pinned recon").hexdigest()
    )
    manifest = json.loads(stage.manifest_bytes)
    assert manifest["scope"] == "practice_native"
    assert manifest["file_hashes"] == stage.file_hashes
    assert (stage.evidence / "task-manifest.json").read_bytes() == stage.manifest_bytes


def test_practice_overlay_rejects_template_collision_with_official_input(tmp_path):
    prepared = _prepared(tmp_path)
    source = tmp_path / "replacement"
    source.write_bytes(b"attacker description")
    with pytest.raises(RuntimeError, match="collides"):
        overlay_native_template(
            prepared,
            template_files={
                "description.txt": (source, hashlib.sha256(source.read_bytes()).hexdigest())
            },
            evidence=tmp_path / "evidence",
            run_id="practice-run",
            practice_freeze_sha256="a" * 64,
        )
    assert (prepared.root / "description.txt").read_bytes() == b"official description"
