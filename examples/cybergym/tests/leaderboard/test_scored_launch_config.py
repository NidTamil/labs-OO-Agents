# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""The scored CLI may bind only files named by its signed launch configuration."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nooa_cybergym.leaderboard.scored_campaign_inputs import (
    ScoredLaunchPreview,
    SignedCampaignInputs,
)
from nooa_cybergym.leaderboard.scored_launch_config import (
    load_previewed_scored_launch_config,
    load_scored_evaluator_signer,
    load_scored_launch_config,
)

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


def test_previewed_scored_config_binds_attested_harness_and_evidence_root(tmp_path: Path):
    source, harness, config = _bundle(tmp_path)
    evidence = Path(config["paths"]["evidence_root"])
    signed_harness = b"signed scored harness lock"
    inputs = SignedCampaignInputs(b"decision", b"cert", signed_harness, b"cohort", b"[]", {})

    class Authority:
        def attest_signed(self, kind, envelope):
            assert (kind, envelope) == ("harness_lock", signed_harness)
            return harness

    class State:
        run_id = "run-1"
        epoch = "scored-epoch-1"
        evidence_root = evidence

    authority = Authority()
    state = State()
    state.authority = authority
    preview = ScoredLaunchPreview(inputs, authority, state)
    assert load_previewed_scored_launch_config(preview, source)["run_id"] == "run-1"

    other = tmp_path / "other-ledger"
    other.mkdir()
    state.evidence_root = other
    with pytest.raises(RuntimeError, match="evidence root"):
        load_previewed_scored_launch_config(preview, source)

    state.evidence_root = evidence
    harness["epoch"] = "different"
    with pytest.raises(RuntimeError, match="identity"):
        load_previewed_scored_launch_config(preview, source)


def test_scored_evaluator_key_must_match_signed_public_identity(tmp_path: Path):
    _, _, config = _bundle(tmp_path)
    private = Ed25519PrivateKey.generate()
    path = Path(config["evaluator"]["private_key_path"])
    path.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    config["evaluator"]["public_key_sha256"] = hashlib.sha256(public_pem).hexdigest()
    controller = Ed25519PrivateKey.generate().public_key()
    signer, verifier = load_scored_evaluator_signer(
        config, controller_key_id="controller-1", controller_public_key=controller
    )
    assert signer.sign(b"synthetic-evaluator-probe").key_id == "evaluator-1"
    assert verifier is not None

    config["evaluator"]["public_key_sha256"] = "0" * 64
    with pytest.raises(RuntimeError, match="public key"):
        load_scored_evaluator_signer(
            config, controller_key_id="controller-1", controller_public_key=controller
        )

    config["evaluator"]["public_key_sha256"] = hashlib.sha256(public_pem).hexdigest()
    with pytest.raises(RuntimeError, match="separate"):
        load_scored_evaluator_signer(
            config, controller_key_id="controller-1", controller_public_key=private.public_key()
        )
    with pytest.raises(RuntimeError, match="separate"):
        load_scored_evaluator_signer(
            config | {"evaluator": config["evaluator"] | {"key_id": "controller-1"}},
            controller_key_id="controller-1",
            controller_public_key=controller,
        )
