# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Read-only, role-bound inputs for the explicit budgeted subset path.

This verifies actual admission/readiness custody and config/file bindings. Full
1,507-task material verification and semantic metering/dispatch-cap enforcement
are separate required consumers. No ledger, worker or provider request is
created here. Signer preflight verifies already acquired signers; it never loads
credentials or any private key, including the approval private key.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from xeus_cybergym.ledger import Ed25519Signer

from .budgeted_subset_admission import BudgetedSubsetState
from .campaign import _json_bytes
from .runtime_config import _observe
from .scored_campaign_inputs import load_scored_public_keys
from .subset_role_authority import SubsetRoleAuthority

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_ALIAS = re.compile(r"cybergym-[a-z0-9-]{1,56}\Z")
_FILES = frozenset(
    {
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
    }
)
_ROOTS = frozenset({"data_dir", "staging_root", "evidence_root", "harness_dir", "mailbox_root"})
_FIELDS = frozenset(
    {
        "schema_version",
        "scope",
        "run_id",
        "epoch",
        "max_parallel_tasks",
        "remote_alias",
        "ssh_port",
        "timeout_seconds",
        "server",
        "files",
        "paths",
        "evaluator",
        "budget",
        "metering",
        "trust",
    }
)
_ROLES = ("approval", "runtime", "evaluator")
_MAX_CONFIG = 65536
_MAX_REFERENCE = 64 * 1024 * 1024


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digest(value: Any) -> bool:
    return type(value) is str and _SHA.fullmatch(value) is not None


def _absolute(value: Any) -> Path:
    if (
        type(value) is not str
        or not value
        or len(value) > 4096
        or any(ord(c) < 32 for c in value)
        or any(part in {".", ".."} for part in value.replace("\\", "/").split("/"))
    ):
        raise RuntimeError("absolute unaliased subset controller path required")
    path = Path(value)
    if not path.is_absolute() or path.is_symlink() or path.resolve() != path:
        raise RuntimeError("absolute unaliased subset controller path required")
    return path


def _read(
    path: Path, *, maximum: int, label: str, capture: bool = True
) -> tuple[str, bytes | None]:
    try:
        digest, _, raw = _observe(path, maximum=maximum, capture=capture)
        return digest, raw
    except (OSError, ValueError, RuntimeError):
        raise RuntimeError(f"bounded regular subset {label} unavailable") from None


def _ref(ref: Any, label: str, *, maximum: int = _MAX_REFERENCE, capture: bool = False):
    if type(ref) is not dict or set(ref) != {"path", "sha256"} or not _digest(ref["sha256"]):
        raise RuntimeError(f"subset {label} reference differs")
    path = _absolute(ref["path"])
    digest, raw = _read(path, maximum=maximum, label=label, capture=capture)
    if digest != ref["sha256"]:
        raise RuntimeError(f"subset {label} digest differs")
    return path, raw


def _unique_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate subset config key")
        value[key] = item
    return value


def _json(raw: bytes, label: str) -> dict:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
    except (UnicodeError, ValueError, RecursionError):
        raise RuntimeError(f"subset {label} JSON is invalid") from None
    if type(value) is not dict:
        raise RuntimeError(f"subset {label} JSON object required")
    return value


def _signing_metadata(value: Any, label: str) -> None:
    if (
        type(value) is not dict
        or set(value) != {"key_id", "public_key_sha256", "private_key_path"}
        or type(value["key_id"]) is not str
        or _ID.fullmatch(value["key_id"]) is None
        or not _digest(value["public_key_sha256"])
    ):
        raise RuntimeError(f"subset {label} signer identity differs")
    # Syntax only: this module never opens or loads this private path.
    _absolute(value["private_key_path"])


def load_budgeted_subset_launch_config(state: BudgetedSubsetState, path: Path) -> dict:
    """Verify public inputs against the actual role-scoped, signed subset state.

    The config contains budget/metering and public trust pins, never freeze or
    certificate hashes. The signed freeze pins this config, and certification
    pins that freeze, so artifact construction has no hash cycle. Successful
    loading is not worker readiness or authorization to send a request.
    """
    if type(state) is not BudgetedSubsetState or type(state.authority) is not SubsetRoleAuthority:
        raise RuntimeError("actual budgeted subset state and exact role authority required")
    state.creation_event()  # Reverify signed admission, readiness and resource identity; no writes.
    harness = state.authority.attest_signed("harness_lock", state.signed_freeze)
    pin = harness.get("budgeted_subset_launch_config_sha256") if type(harness) is dict else None
    if not _digest(pin):
        raise RuntimeError("signed budgeted subset launch config pin required")
    source = _absolute(str(path))
    digest, raw = _read(source, maximum=_MAX_CONFIG, label="launch config")
    if digest != pin:
        raise RuntimeError("signed subset launch config digest differs")
    value = _json(raw, "launch config")
    if set(value) != _FIELDS:
        raise RuntimeError("subset launch config fields differ")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["scope"] != "budgeted_subset_native_level1"
        or value["run_id"] != state.run_id
        or value["epoch"] != state.epoch
    ):
        raise RuntimeError("subset launch config identity differs")
    if type(value["max_parallel_tasks"]) is not int or value["max_parallel_tasks"] != 1:
        raise RuntimeError("subset launch config requires serial execution")
    if (
        type(value["remote_alias"]) is not str
        or _ALIAS.fullmatch(value["remote_alias"]) is None
        or type(value["ssh_port"]) is not int
        or not 1024 <= value["ssh_port"] <= 65535
        or type(value["timeout_seconds"]) is not int
        or not 60 <= value["timeout_seconds"] <= 43200
        or value["server"] != "http://registered-tool-gateway"
    ):
        raise RuntimeError("subset launch config route or timeout differs")
    roots = value["paths"]
    if type(roots) is not dict or set(roots) != _ROOTS:
        raise RuntimeError("subset controller roots differ")
    for name, raw_path in roots.items():
        if not _absolute(raw_path).is_dir():
            raise RuntimeError(f"subset {name} is unavailable")
    if Path(roots["evidence_root"]) != state.evidence_root:
        raise RuntimeError("subset launch evidence root differs from signed state")
    files = value["files"]
    if type(files) is not dict or set(files) != _FILES:
        raise RuntimeError("subset file references differ")
    for name, ref in files.items():
        _ref(ref, name)
    _, budget_bytes = _ref(value["budget"], "budget", maximum=65536, capture=True)
    budget = state.preview.budget
    if (
        budget_bytes != budget.signed_envelope
        or value["budget"]["sha256"] != budget.envelope_sha256
        or budget.max_model_requests != 15000
        or budget.max_elapsed_seconds != 432000
        or budget.max_spend_units != 500000000
        or budget.spend_unit != "usd_micros"
    ):
        raise RuntimeError("subset actual signed approved budget differs")
    _ref(value["metering"], "metering", maximum=262144)
    if value["metering"]["sha256"] != budget.metering_policy_sha256:
        raise RuntimeError("subset metering differs from independently pinned budget")
    trust = value["trust"]
    if type(trust) is not dict or set(trust) != set(_ROLES):
        raise RuntimeError("subset independent trust roles differ")
    args = {}
    for role, ref in trust.items():
        public_path, _ = _ref(ref, f"{role} trust", maximum=65536)
        args[f"{role}_registry"] = public_path
        args[f"{role}_sha256"] = ref["sha256"]
    if SubsetRoleAuthority(**args) != state.authority:
        raise RuntimeError("subset trust differs from independently pinned state authority")
    _signing_metadata(value["evaluator"], "evaluator")
    return value


@dataclass(frozen=True, slots=True)
class BudgetedSubsetSignerPreflight:
    """Verified already acquired signers; no donor/private-key loading is implied."""

    config: dict = field(repr=False)
    runtime_signer: Ed25519Signer = field(repr=False)
    runtime_verifier: Any = field(repr=False)
    evaluator_signer: Ed25519Signer = field(repr=False)
    evaluator_verifier: Any = field(repr=False)


def preflight_budgeted_subset_signers(
    state: BudgetedSubsetState,
    path: Path,
    *,
    runtime_signer: Ed25519Signer,
    evaluator_signer: Ed25519Signer,
) -> BudgetedSubsetSignerPreflight:
    """Check frozen public metadata and real role proofs for supplied signers.

    A later worker must independently constrain runtime/evaluator private paths
    before acquiring these signers. In particular, the eager donor loader must
    not be called before that boundary; this function does not call it at all.
    Challenge signatures are only ephemeral possession checks, not artifacts.
    """
    config = load_budgeted_subset_launch_config(state, path)
    _, donor_raw = _ref(config["files"]["donor_config"], "donor config", capture=True)
    donor = _json(donor_raw, "donor config")
    if type(donor.get("schema_version")) is not int or donor["schema_version"] != 2:
        raise RuntimeError("subset runtime signer requires explicit schema-two donor")
    runtime = donor.get("signing")
    _signing_metadata(runtime, "runtime")
    for role, metadata, signer in (
        ("runtime", runtime, runtime_signer),
        ("evaluator", config["evaluator"], evaluator_signer),
    ):
        ref = config["trust"][role]
        keys = load_scored_public_keys(Path(ref["path"]), expected_sha256=ref["sha256"])
        key = keys.get(metadata["key_id"])
        if key is None:
            raise RuntimeError(f"subset {role} signer is outside its trusted role")
        encoding, form = (
            (serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            if role == "runtime"
            else (serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        )
        if _sha(key.public_bytes(encoding, form)) != metadata["public_key_sha256"]:
            raise RuntimeError(f"subset {role} signer public identity differs")
        challenge = _json_bytes(
            {
                "domain": "budgeted_subset_signer_preflight_v1",
                "role": role,
                "run_id": state.run_id,
                "epoch": state.epoch,
                "admission_sha256": state.preview.admission_sha256,
                "budget_sha256": state.preview.budget.envelope_sha256,
            }
        )
        try:
            if type(signer) is not Ed25519Signer:
                raise ValueError("signer identity mismatch")
            envelope = signer.sign(challenge)
            if (
                envelope.key_id != metadata["key_id"]
                or getattr(state.authority, f"{role}_verifier").verify(envelope) != challenge
            ):
                raise ValueError("signer proof mismatch")
        except Exception:
            raise RuntimeError(f"subset {role} signer possession proof failed") from None
    return BudgetedSubsetSignerPreflight(
        config,
        runtime_signer,
        state.authority.runtime_verifier,
        evaluator_signer,
        state.authority.evaluator_verifier,
    )
