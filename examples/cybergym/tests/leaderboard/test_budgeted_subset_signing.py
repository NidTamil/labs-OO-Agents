# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Synthetic keys only; real signed config and guarded private acquisition."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nooa_cybergym.leaderboard.campaign import _json_bytes
from nooa_cybergym.leaderboard.runtime_config import load_runtime_config

from . import test_runtime_config as donor_tests
from .test_budgeted_subset_launch_config import Fixture


def write_private(path, key):
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)


@pytest.fixture
def setup(tmp_path):
    config_root, donor_root, secret_root = (tmp_path / name for name in ("config", "donor", "keys"))
    for root in (config_root, donor_root, secret_root):
        root.mkdir(mode=0o700)
    fixture = Fixture(config_root)
    prepared = donor_tests.prepared.__wrapped__(donor_root)
    donor_tests.enable_takeover(prepared)
    raw = prepared[0]
    raw["signing"] = dict(fixture.donor["signing"])
    raw["signing"]["private_key_path"] = str(secret_root / "runtime.pem")
    write_private(Path(raw["signing"]["private_key_path"]), fixture.keys["runtime"])
    fixture.config["evaluator"]["private_key_path"] = str(secret_root / "evaluator.pem")
    write_private(secret_root / "evaluator.pem", fixture.keys["evaluator"])
    fixture.donor = raw
    fixture.write_donor()
    donor = load_runtime_config(Path(fixture.config["files"]["donor_config"]["path"]))
    fixture.freeze["donor_configuration_sha256"] = donor.freeze_sha256
    return fixture


def test_acquires_only_role_pinned_runtime_and_evaluator_after_public_validation(setup):
    from nooa_cybergym.leaderboard.budgeted_subset_signing import load_budgeted_subset_signers

    state = setup.state()
    result = load_budgeted_subset_signers(state, setup.path)
    assert result.donor.schema_version == 2
    assert result.donor.signing.key_id == "synthetic-runtime"
    assert result.preflight.runtime_verifier is not result.preflight.evaluator_verifier
    assert result.preflight.config == setup.config
    assert result.donor.freeze_sha256 == setup.freeze["donor_configuration_sha256"]
    result.verify_current()


@pytest.mark.parametrize(
    "mutation",
    [
        "approval_runtime",
        "approval_evaluator",
        "bad_public_pin",
        "same_key_path",
        "credential_key_alias",
        "published_private_path",
        "old_schema",
    ],
)
def test_rejects_role_and_path_errors_before_eager_donor_or_any_private_read(
    setup, monkeypatch, mutation
):
    from nooa_cybergym.leaderboard import budgeted_subset_signing as module
    from nooa_cybergym.leaderboard import runtime_config

    if mutation == "approval_runtime":
        setup.donor["signing"]["key_id"] = "synthetic-approval"
    elif mutation == "approval_evaluator":
        setup.config["evaluator"]["key_id"] = "synthetic-approval"
    elif mutation == "bad_public_pin":
        setup.donor["signing"]["public_key_sha256"] = "f" * 64
    elif mutation == "same_key_path":
        setup.config["evaluator"]["private_key_path"] = setup.donor["signing"]["private_key_path"]
    elif mutation == "credential_key_alias":
        setup.donor["credentials"]["zai"]["path"] = setup.donor["signing"]["private_key_path"]
    elif mutation == "published_private_path":
        setup.donor["signing"]["private_key_path"] = str(setup.path.parent / "runtime.pem")
    else:
        setup.donor["schema_version"] = 1
    setup.write_donor()
    state = setup.state()
    calls = []

    def forbidden(*args, **kwargs):
        calls.append("secret")
        raise AssertionError("private acquisition preceded public role/path validation")

    monkeypatch.setattr(module, "load_runtime_config", forbidden)
    monkeypatch.setattr(runtime_config.SecretFileRef, "read_bytes", forbidden)
    with pytest.raises((RuntimeError, ValueError)):
        module.load_budgeted_subset_signers(state, setup.path)
    assert calls == []


@pytest.mark.parametrize("role", ["runtime", "evaluator"])
def test_wrong_private_material_is_rejected_without_returning_signers(setup, role):
    from nooa_cybergym.leaderboard.budgeted_subset_signing import load_budgeted_subset_signers

    metadata = setup.donor["signing"] if role == "runtime" else setup.config["evaluator"]
    write_private(Path(metadata["private_key_path"]), Ed25519PrivateKey.generate())
    with pytest.raises((RuntimeError, ValueError)):
        load_budgeted_subset_signers(setup.state(), setup.path)


def test_donor_public_freeze_mismatch_fails_before_signer_bundle_return(setup):
    from nooa_cybergym.leaderboard.budgeted_subset_signing import load_budgeted_subset_signers

    setup.freeze["donor_configuration_sha256"] = "f" * 64
    with pytest.raises(RuntimeError, match="donor"):
        load_budgeted_subset_signers(setup.state(), setup.path)


def test_config_change_during_private_acquisition_is_rejected(setup, monkeypatch):
    from nooa_cybergym.leaderboard import budgeted_subset_signing as module

    state = setup.state()
    original = module.load_runtime_config

    def change(path, **kwargs):
        donor = original(path, **kwargs)
        value = json.loads(setup.path.read_bytes())
        value["ssh_port"] += 1
        setup.path.write_bytes(_json_bytes(value))
        return donor

    monkeypatch.setattr(module, "load_runtime_config", change)
    with pytest.raises(RuntimeError, match="config"):
        module.load_budgeted_subset_signers(state, setup.path)


def test_donor_replacement_after_public_preflight_is_rejected_before_any_secret_read(
    setup, monkeypatch
):
    from nooa_cybergym.leaderboard import budgeted_subset_signing as module
    from nooa_cybergym.leaderboard import runtime_config

    state = setup.state()
    original_load, original_observe = module.load_runtime_config, runtime_config._observe
    private_reads = []

    def observe(path, **kwargs):
        if kwargs.get("private"):
            private_reads.append(path)
        return original_observe(path, **kwargs)

    def replace_before_load(path, **kwargs):
        value = json.loads(path.read_bytes())
        value["signing"]["key_id"] = "synthetic-approval"
        path.write_bytes(_json_bytes(value))
        return original_load(path, **kwargs)

    monkeypatch.setattr(runtime_config, "_observe", observe)
    monkeypatch.setattr(module, "load_runtime_config", replace_before_load)
    with pytest.raises((RuntimeError, ValueError)):
        module.load_budgeted_subset_signers(state, setup.path)
    assert private_reads == []


def test_revalidation_never_reopens_private_material_but_detects_public_drift(setup, monkeypatch):
    from nooa_cybergym.leaderboard.budgeted_subset_signing import load_budgeted_subset_signers
    from nooa_cybergym.leaderboard.runtime_config import SecretFileRef

    result = load_budgeted_subset_signers(setup.state(), setup.path)

    def forbidden(*args):
        raise AssertionError("public revalidation read private bytes")

    monkeypatch.setattr(SecretFileRef, "read_bytes", forbidden)
    result.verify_current()
    setup.path.write_bytes(setup.path.read_bytes() + b" ")
    with pytest.raises(RuntimeError):
        result.verify_current()
