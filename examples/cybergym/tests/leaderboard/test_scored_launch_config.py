# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""The scored CLI may bind only files named by its signed launch configuration."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nooa_cybergym.leaderboard.capabilities import (
    Capability,
    CapabilityRegistry,
    ControlLabel,
    Effect,
    Role,
    Status,
    ToolIdentity,
)
from nooa_cybergym.leaderboard.capability_runtime import SYNTHETIC_SCOPE
from nooa_cybergym.leaderboard.cohort import freeze_harness_manifest
from nooa_cybergym.leaderboard.scored_campaign_inputs import (
    ScoredLaunchPreview,
    SignedCampaignInputs,
)
from nooa_cybergym.leaderboard.scored_launch_config import (
    load_previewed_scored_capabilities,
    load_previewed_scored_controller_material,
    load_previewed_scored_launch_config,
    load_previewed_scored_signers,
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
    preview = ScoredLaunchPreview(inputs, authority, state, {})
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


def test_previewed_scored_signers_require_trusted_controller_and_separate_evaluator(
    tmp_path: Path, monkeypatch
):
    import nooa_cybergym.leaderboard.scored_launch_config as module

    source, harness, config = _bundle(tmp_path)
    controller = Ed25519PrivateKey.generate()
    evaluator = Ed25519PrivateKey.generate()
    Path(config["evaluator"]["private_key_path"]).write_bytes(
        evaluator.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    config["evaluator"]["public_key_sha256"] = hashlib.sha256(
        evaluator.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).hexdigest()
    source.write_text(json.dumps(config, sort_keys=True), encoding="utf-8")
    harness["scored_launch_config_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()

    class Signing:
        key_id = "controller-1"

        @staticmethod
        def load_private_key():
            return controller

    class Donor:
        signing = Signing()
        verified = False

        def verify_unchanged(self):
            self.verified = True

    donor = Donor()
    monkeypatch.setattr(module, "load_runtime_config", lambda path: donor)
    inputs = SignedCampaignInputs(b"decision", b"cert", b"signed-lock", b"cohort", b"[]", {})

    class Authority:
        def attest_signed(self, kind, envelope):
            assert (kind, envelope) == ("harness_lock", b"signed-lock")
            return harness

    class State:
        run_id = "run-1"
        epoch = "scored-epoch-1"
        evidence_root = Path(config["paths"]["evidence_root"])

    authority = Authority()
    state = State()
    state.authority = authority
    preview = ScoredLaunchPreview(
        inputs, authority, state, {"controller-1": controller.public_key()}
    )
    prepared = load_previewed_scored_signers(preview, source)
    assert donor.verified
    assert prepared.controller_signer.sign(b"synthetic-probe").key_id == "controller-1"
    assert prepared.evaluator_signer.sign(b"synthetic-probe").key_id == "evaluator-1"

    untrusted = ScoredLaunchPreview(
        inputs, authority, state, {"controller-1": Ed25519PrivateKey.generate().public_key()}
    )
    with pytest.raises(RuntimeError, match="trusted controller"):
        load_previewed_scored_signers(untrusted, source)


def test_scored_controller_material_checks_full_cohort_and_harness_before_creation(
    tmp_path: Path,
):
    source, harness, config = _bundle(tmp_path)
    task_ids = tuple(f"arvo:{index}" for index in range(1507))
    assets = {
        "schema_version": 1,
        "benchmark_commit": "1" * 40,
        "dataset_commit": "2" * 40,
        "assets": [
            {
                "task_id": task_id,
                "description_sha256": "a" * 64,
                "description_bytes": 12,
                "description_lfs_pointer": True,
                "vulnerable_archive_sha256": "b" * 64,
                "vulnerable_archive_bytes": 14,
                "vulnerable_archive_lfs_pointer": True,
            }
            for task_id in task_ids
        ],
    }
    images = {
        "schema_version": 1,
        "scope": "scored_official_images",
        "images": [
            {"task_id": task_id, "vulnerable": "sha256:" + "c" * 64, "fixed": "sha256:" + "d" * 64}
            for task_id in task_ids
        ],
    }

    def replace(name: str, raw: bytes):
        path = Path(config["files"][name]["path"])
        path.write_bytes(raw)
        config["files"][name]["sha256"] = hashlib.sha256(raw).hexdigest()

    replace("asset_manifest", json.dumps(assets).encode())
    replace("image_manifest", json.dumps(images, sort_keys=True, separators=(",", ":")).encode())
    replace("mask_map", b"{}")
    harness_dir = Path(config["paths"]["harness_dir"])
    (harness_dir / "prompt.md").write_bytes(b"synthetic harness\n")
    replace("harness_manifest", freeze_harness_manifest(harness_dir))
    harness["scored_images_sha256"] = config["files"]["image_manifest"]["sha256"]
    source.write_text(json.dumps(config, sort_keys=True), encoding="utf-8")
    harness["scored_launch_config_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
    cohort = {
        "generator_sha256": config["files"]["generator_source"]["sha256"],
        "harness_manifest_sha256": config["files"]["harness_manifest"]["sha256"],
        "mask_map_sha256": config["files"]["mask_map"]["sha256"],
    }
    inputs = SignedCampaignInputs(b"decision", b"cert", b"signed-lock", b"cohort", b"[]", {})

    class Authority:
        def attest_signed(self, kind, envelope):
            if (kind, envelope) == ("harness_lock", b"signed-lock"):
                return harness
            if (kind, envelope) == ("cohort", b"cohort"):
                return cohort
            raise AssertionError("unexpected attestation")

    class State:
        run_id = "run-1"
        epoch = "scored-epoch-1"
        evidence_root = Path(config["paths"]["evidence_root"])
        asset_hashes_sha256 = config["files"]["asset_manifest"]["sha256"]
        benchmark_commit = "1" * 40
        dataset_commit = "2" * 40
        mask_map_sha256 = config["files"]["mask_map"]["sha256"]

    authority = Authority()
    state = State()
    state.task_ids = task_ids
    state.authority = authority
    preview = ScoredLaunchPreview(inputs, authority, state, {})
    material = load_previewed_scored_controller_material(preview, source)
    assert material.paths.official_registry is material.assets
    assert material.assets.task_ids == task_ids
    assert material.images.task_ids == task_ids

    harness["scored_images_sha256"] = "0" * 64
    with pytest.raises(RuntimeError, match="image manifest"):
        load_previewed_scored_controller_material(preview, source)
    harness["scored_images_sha256"] = config["files"]["image_manifest"]["sha256"]
    (harness_dir / "prompt.md").write_bytes(b"changed harness\n")
    with pytest.raises(RuntimeError, match="generic harness hash mismatch"):
        load_previewed_scored_controller_material(preview, source)
    (harness_dir / "prompt.md").write_bytes(b"synthetic harness\n")
    cohort["generator_sha256"] = "0" * 64
    with pytest.raises(RuntimeError, match="generator"):
        load_previewed_scored_controller_material(preview, source)


def test_scored_capability_preflight_requires_35_live_signed_uses(tmp_path: Path):
    source, harness, config = _bundle(tmp_path)
    identity = ToolIdentity(
        "service", "1", "a" * 64, "tool", "1", "b" * 64, "adapter", "1", "c" * 64
    )
    registry = CapabilityRegistry(
        tuple(
            Capability(
                capability_id=f"cap-{index:02d}",
                identity=identity,
                operation="read",
                status=Status.APPROVED,
                control_label=ControlLabel.OPTIONAL,
                purpose="synthetic preflight test",
                roles=(Role.PARENT,),
                effects=(Effect.READ,),
                data_scopes=("task",),
                path_scopes=(),
                routes=(),
                provider_ids=(),
                model_ids=(),
                credential_refs=(),
                accounting="counted",
                log_schema="audit-v1",
                evidence_refs=("live-fixture-attestation",),
                certification_digest="d" * 64,
            )
            for index in range(35)
        )
    )
    registry_path = Path(config["files"]["capability_registry"]["path"])
    registry_path.write_text(registry.manifest_json, encoding="utf-8")
    config["files"]["capability_registry"]["sha256"] = registry.digest
    source.write_text(json.dumps(config, sort_keys=True), encoding="utf-8")
    harness["scored_launch_config_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
    harness["capability_registry_sha256"] = registry.digest
    approved_ids = sorted(entry.capability_id for entry in registry.entries)
    certified = {
        "status": "accepted",
        "scope": "live_native",
        "capability_registry_sha256": registry.digest,
        "capability_coverage": "all_enabled_exercised",
        "enabled_capability_ids": approved_ids,
        "required_approved_capability_ids": approved_ids,
    }
    inputs = SignedCampaignInputs(b"decision", b"cert", b"signed-lock", b"cohort", b"[]", {})

    class Authority:
        def attest_signed(self, kind, envelope):
            if (kind, envelope) == ("harness_lock", b"signed-lock"):
                return harness
            if (kind, envelope) == ("certification", b"cert"):
                return certified
            raise AssertionError("unexpected attestation")

    class State:
        run_id = "run-1"
        epoch = "scored-epoch-1"
        evidence_root = Path(config["paths"]["evidence_root"])

    authority = Authority()
    state = State()
    state.authority = authority
    preview = ScoredLaunchPreview(inputs, authority, state, {})
    assert load_previewed_scored_capabilities(preview, source).digest == registry.digest

    certified["enabled_capability_ids"] = approved_ids[:-1]
    with pytest.raises(RuntimeError, match="coverage"):
        load_previewed_scored_capabilities(preview, source)
    certified["enabled_capability_ids"] = approved_ids
    tainted = CapabilityRegistry(
        (replace(registry.entries[0], evidence_refs=(SYNTHETIC_SCOPE,)), *registry.entries[1:])
    )
    registry_path.write_text(tainted.manifest_json, encoding="utf-8")
    config["files"]["capability_registry"]["sha256"] = tainted.digest
    source.write_text(json.dumps(config, sort_keys=True), encoding="utf-8")
    harness["scored_launch_config_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
    harness["capability_registry_sha256"] = tainted.digest
    certified["capability_registry_sha256"] = tainted.digest
    with pytest.raises(RuntimeError, match="synthetic-only"):
        load_previewed_scored_capabilities(preview, source)


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
