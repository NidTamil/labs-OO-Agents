# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""The scored CLI may bind only files named by its signed launch configuration."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from nooa_cybergym.leaderboard.scored_launch_config import load_scored_launch_config

FILES = (
    "donor_config",
    "bindings",
    "public_ssh_key",
    "asset_manifest",
    "image_manifest",
    "capability_registry",
    "official_verifier",
    "mask_map",
    "harness_manifest",
    "generator_source",
)
ROOTS = ("data_dir", "staging_root", "evidence_root", "harness_dir", "mailbox_root")


def _bundle(tmp_path: Path):
    files = {}
    for name in FILES:
        path = tmp_path / f"{name}.json"
        path.write_bytes(name.encode())
        files[name] = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    paths = {}
    for name in ROOTS:
        path = tmp_path / name
        path.mkdir()
        paths[name] = str(path)
    config = {
        "schema_version": 1,
        "scope": "scored_native_level1",
        "run_id": "run-1",
        "epoch": "scored-epoch-1",
        "max_parallel_tasks": 1,
        "remote_alias": "cybergym-cal-v26q",
        "ssh_port": 28473,
        "timeout_seconds": 3600,
        "server": "http://registered-tool-gateway",
        "files": files,
        "paths": paths,
        "evaluator": {
            "key_id": "evaluator-1",
            "public_key_sha256": "a" * 64,
            "private_key_path": str(tmp_path / "evaluator.pem"),
        },
    }
    source = tmp_path / "scored-launch-config.json"
    source.write_text(json.dumps(config, sort_keys=True), encoding="utf-8")
    harness = {
        "epoch": "scored-epoch-1",
        "scored_launch_config_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
    }
    return source, harness, config


def test_scored_launch_config_requires_signed_pin_and_all_file_hashes(tmp_path: Path):
    source, harness, config = _bundle(tmp_path)
    loaded = load_scored_launch_config(source, harness=harness, run_id="run-1")
    assert loaded["files"]["donor_config"] == config["files"]["donor_config"]

    donor = Path(config["files"]["donor_config"]["path"])
    donor.write_bytes(b"changed")
    with pytest.raises(RuntimeError, match="donor_config"):
        load_scored_launch_config(source, harness=harness, run_id="run-1")


def test_scored_launch_config_rejects_unsigned_or_parallel_drift(tmp_path: Path):
    source, harness, config = _bundle(tmp_path)
    with pytest.raises(RuntimeError, match="signed scored launch config"):
        load_scored_launch_config(source, harness={"epoch": "scored-epoch-1"}, run_id="run-1")
    config["max_parallel_tasks"] = 2
    source.write_text(json.dumps(config, sort_keys=True), encoding="utf-8")
    harness["scored_launch_config_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
    with pytest.raises(RuntimeError, match="serial"):
        load_scored_launch_config(source, harness=harness, run_id="run-1")
