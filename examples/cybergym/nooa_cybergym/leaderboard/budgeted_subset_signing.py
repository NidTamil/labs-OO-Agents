# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Acquire runtime/evaluator keys only after frozen public role/path checks.

The dedicated approval authority is never acquired here. This is controller
key acquisition, not admission, a readiness signature, or permission to run a
provider request. Callers must still bind material, metering and owned workers.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from xeus_cybergym.ledger import Ed25519Signer

from .budgeted_subset_admission import BudgetedSubsetState
from .budgeted_subset_launch_config import (
    BudgetedSubsetSignerPreflight,
    _absolute,
    _json,
    _ref,
    _signing_metadata,
    load_budgeted_subset_launch_config,
    preflight_budgeted_subset_signers,
)
from .campaign import _json_bytes
from .runtime_config import NativeRuntimeConfig, _observe, load_runtime_config
from .scored_campaign_inputs import load_scored_public_keys


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _public_inputs(state: BudgetedSubsetState, path: Path) -> tuple[dict, dict]:
    config = load_budgeted_subset_launch_config(state, path)
    _, raw = _ref(config["files"]["donor_config"], "donor config", capture=True)
    donor = _json(raw, "donor config")
    if type(donor.get("schema_version")) is not int or donor["schema_version"] != 2:
        raise RuntimeError("subset signer acquisition requires schema-two donor")
    runtime = donor.get("signing")
    _signing_metadata(runtime, "runtime")
    # Verify BOTH roles before the eager donor loader can read any secret.
    for role, metadata in (("runtime", runtime), ("evaluator", config["evaluator"])):
        ref = config["trust"][role]
        keys = load_scored_public_keys(Path(ref["path"]), expected_sha256=ref["sha256"])
        key = keys.get(metadata["key_id"])
        if key is None:
            raise RuntimeError(f"subset {role} signing key is outside its independent role")
        encoding, form = (
            (serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            if role == "runtime"
            else (serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        )
        if _sha(key.public_bytes(encoding, form)) != metadata["public_key_sha256"]:
            raise RuntimeError(f"subset {role} public signing identity differs")
    credentials = donor.get("credentials")
    if type(credentials) is not dict or set(credentials) != {
        "zai",
        "deepseek",
        "gbrain_read",
        "gbrain_write",
    }:
        raise RuntimeError("subset donor credential references differ")
    private_paths = [
        _absolute(runtime["private_key_path"]),
        _absolute(config["evaluator"]["private_key_path"]),
    ]
    for ref in credentials.values():
        if type(ref) is not dict or set(ref) != {"path"}:
            raise RuntimeError("subset credential path reference differs")
        private_paths.append(_absolute(ref["path"]))
    public_roots = [
        *(_absolute(value) for value in config["paths"].values()),
        *(_absolute(donor.get(name)) for name in ("repo_root", "staging_root", "evidence_root")),
    ]
    public_files = {
        _absolute(str(path)),
        *(_absolute(ref["path"]) for ref in config["files"].values()),
        *(_absolute(ref["path"]) for ref in config["trust"].values()),
        _absolute(config["budget"]["path"]),
        _absolute(config["metering"]["path"]),
    }
    if len(set(private_paths)) != len(private_paths) or any(
        candidate in public_files or any(candidate.is_relative_to(root) for root in public_roots)
        for candidate in private_paths
    ):
        raise RuntimeError("subset private signing/credential paths overlap public or other roles")
    return config, donor


@dataclass(frozen=True, slots=True, repr=False)
class AcquiredSubsetSigners:
    """Private controller capabilities; never serialize or pass to the task."""

    donor: NativeRuntimeConfig
    preflight: BudgetedSubsetSignerPreflight
    _state: BudgetedSubsetState = field(compare=False)
    _config_path: Path
    _config_bytes: bytes
    _donor_bytes: bytes

    def verify_current(self) -> None:
        config, donor = _public_inputs(self._state, self._config_path)
        if _json_bytes(config) != self._config_bytes or _json_bytes(donor) != self._donor_bytes:
            raise RuntimeError("subset signing configuration changed")
        self.donor.verify_public_unchanged()
        harness = self._state.authority.attest_signed("harness_lock", self._state.signed_freeze)
        if harness.get("donor_configuration_sha256") != self.donor.freeze_sha256:
            raise RuntimeError("subset acquired donor differs from signed public freeze")
        # Recheck the acquired keys by role without reopening their private files.
        preflight_budgeted_subset_signers(
            self._state,
            self._config_path,
            runtime_signer=self.preflight.runtime_signer,
            evaluator_signer=self.preflight.evaluator_signer,
        )


def load_budgeted_subset_signers(state: BudgetedSubsetState, path: Path) -> AcquiredSubsetSigners:
    """Validate actual public bytes and independent roles before private loading."""
    config, donor_metadata = _public_inputs(state, path)
    donor = load_runtime_config(
        Path(config["files"]["donor_config"]["path"]),
        expected_sha256=config["files"]["donor_config"]["sha256"],
    )
    harness = state.authority.attest_signed("harness_lock", state.signed_freeze)
    if harness.get("donor_configuration_sha256") != donor.freeze_sha256:
        raise RuntimeError("subset acquired donor differs from signed public freeze")
    runtime = donor.signing
    if (
        runtime.key_id != donor_metadata["signing"]["key_id"]
        or str(runtime.private_key.path) != donor_metadata["signing"]["private_key_path"]
        or runtime.public_key_sha256 != donor_metadata["signing"]["public_key_sha256"]
    ):
        raise RuntimeError("subset acquired runtime signer differs from public preflight")
    private = runtime.load_private_key()
    runtime_signer = Ed25519Signer(private_key=private, key_id=runtime.key_id)
    # Repeat all public role/path checks after eager loading and before acquiring
    # the evaluator key. No mixed-version bundle can escape either boundary.
    checked_config, checked_donor = _public_inputs(state, path)
    if checked_config != config or checked_donor != donor_metadata:
        raise RuntimeError("subset signing configuration changed during acquisition")
    evaluator = config["evaluator"]
    try:
        _, _, raw = _observe(
            Path(evaluator["private_key_path"]), private=True, maximum=8192, capture=True
        )
        key = serialization.load_pem_private_key(raw, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError
        public = key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        if _sha(public) != evaluator["public_key_sha256"]:
            raise ValueError
    except (OSError, ValueError, TypeError):
        raise RuntimeError("subset evaluator key differs from independently pinned role") from None
    evaluator_signer = Ed25519Signer(private_key=key, key_id=evaluator["key_id"])
    preflight = preflight_budgeted_subset_signers(
        state, path, runtime_signer=runtime_signer, evaluator_signer=evaluator_signer
    )
    result = AcquiredSubsetSigners(
        donor, preflight, state, Path(path), _json_bytes(config), _json_bytes(donor_metadata)
    )
    result.verify_current()
    return result
