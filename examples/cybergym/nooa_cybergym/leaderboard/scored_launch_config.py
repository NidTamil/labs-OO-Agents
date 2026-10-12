# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Validate the controller-only scored launch configuration pinned by harness lock."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from xeus_cybergym.ledger import Ed25519Signer, Ed25519Verifier

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
    }
)
_MAX_CONFIG_BYTES = 64 * 1024
_MAX_REFERENCED_BYTES = 64 * 1024 * 1024


def _absolute(value: object) -> Path:
    if type(value) is not str or "\x00" in value:
        raise RuntimeError("absolute scored controller path required")
    path = Path(value)
    if not path.is_absolute() or path.is_symlink() or path.resolve() != path:
        raise RuntimeError("absolute unaliased scored controller path required")
    return path


def _hash_file(path: Path, label: str) -> str:
    if (
        path.is_symlink()
        or not path.is_file()
        or not 0 < path.stat().st_size <= _MAX_REFERENCED_BYTES
    ):
        raise RuntimeError(f"scored {label} is not a bounded regular file")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate scored launch config key")
        value[key] = item
    return value


def load_scored_launch_config(path: Path, *, harness: dict, run_id: str) -> dict:
    """Recheck every local file the scored worker may consume before admission.

    The caller must independently attest ``harness`` as the signed harness-lock
    payload; a bare caller-supplied digest is not a scored authority.
    """
    if type(harness) is not dict or type(run_id) is not str or _ID.fullmatch(run_id) is None:
        raise RuntimeError("signed scored launch config and run identity required")
    pin = harness.get("scored_launch_config_sha256")
    if type(pin) is not str or _SHA.fullmatch(pin) is None:
        raise RuntimeError("signed scored launch config pin required")
    source = _absolute(str(path))
    if not source.is_file() or not 0 < source.stat().st_size <= _MAX_CONFIG_BYTES:
        raise RuntimeError("bounded scored launch config required")
    raw = source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != pin:
        raise RuntimeError("signed scored launch config digest differs")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
    except (UnicodeDecodeError, ValueError):
        raise RuntimeError("scored launch config JSON is invalid") from None
    if type(value) is not dict or set(value) != _FIELDS:
        raise RuntimeError("scored launch config fields differ")
    if (
        value["schema_version"] != 1
        or value["scope"] != "scored_native_level1"
        or value["run_id"] != run_id
        or value["epoch"] != harness.get("epoch")
        or type(value["epoch"]) is not str
        or _ID.fullmatch(value["epoch"]) is None
    ):
        raise RuntimeError("scored launch config identity differs")
    if type(value["max_parallel_tasks"]) is not int or value["max_parallel_tasks"] != 1:
        raise RuntimeError("scored launch config requires serial execution")
    if (
        type(value["remote_alias"]) is not str
        or _ALIAS.fullmatch(value["remote_alias"]) is None
        or type(value["ssh_port"]) is not int
        or not 1024 <= value["ssh_port"] <= 65535
        or type(value["timeout_seconds"]) is not int
        or not 60 <= value["timeout_seconds"] <= 43200
        or value["server"] != "http://registered-tool-gateway"
    ):
        raise RuntimeError("scored launch config route or budget differs")
    roots = value["paths"]
    if type(roots) is not dict or set(roots) != _ROOTS:
        raise RuntimeError("scored controller roots differ")
    for name, raw_path in roots.items():
        root = _absolute(raw_path)
        if not root.is_dir():
            raise RuntimeError(f"scored {name} is unavailable")
    files = value["files"]
    if type(files) is not dict or set(files) != _FILES:
        raise RuntimeError("scored file references differ")
    for name, ref in files.items():
        if (
            type(ref) is not dict
            or set(ref) != {"path", "sha256"}
            or type(ref["sha256"]) is not str
            or _SHA.fullmatch(ref["sha256"]) is None
        ):
            raise RuntimeError(f"scored {name} reference differs")
        artifact = _absolute(ref["path"])
        if _hash_file(artifact, name) != ref["sha256"]:
            raise RuntimeError(f"scored {name} digest differs")
    evaluator = value["evaluator"]
    if (
        type(evaluator) is not dict
        or set(evaluator) != {"key_id", "public_key_sha256", "private_key_path"}
        or type(evaluator["key_id"]) is not str
        or _ID.fullmatch(evaluator["key_id"]) is None
        or type(evaluator["public_key_sha256"]) is not str
        or _SHA.fullmatch(evaluator["public_key_sha256"]) is None
    ):
        raise RuntimeError("scored evaluator identity differs")
    _absolute(evaluator["private_key_path"])
    return value


def load_scored_evaluator_signer(
    config: dict, *, controller_key_id: str, controller_public_key: Ed25519PublicKey
) -> tuple[Ed25519Signer, Ed25519Verifier]:
    """Preflight the separate controller-held oracle signer before campaign creation."""
    if (
        type(config) is not dict
        or type(config.get("evaluator")) is not dict
        or type(controller_key_id) is not str
        or _ID.fullmatch(controller_key_id) is None
        or not isinstance(controller_public_key, Ed25519PublicKey)
    ):
        raise RuntimeError("signed scored evaluator configuration required")
    identity = config["evaluator"]
    if (
        set(identity) != {"key_id", "public_key_sha256", "private_key_path"}
        or type(identity["key_id"]) is not str
        or _ID.fullmatch(identity["key_id"]) is None
        or type(identity["public_key_sha256"]) is not str
        or _SHA.fullmatch(identity["public_key_sha256"]) is None
    ):
        raise RuntimeError("signed scored evaluator identity differs")
    path = _absolute(identity["private_key_path"])
    if not path.is_file() or not 0 < path.stat().st_size <= 8192:
        raise RuntimeError("controller-only scored evaluator key is unavailable")
    try:
        private = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (TypeError, ValueError):
        raise RuntimeError("separate Ed25519 scored evaluator key required") from None
    if not isinstance(private, Ed25519PrivateKey):
        raise RuntimeError("separate Ed25519 scored evaluator key required")
    public = private.public_key()
    pem = public.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if hashlib.sha256(pem).hexdigest() != identity["public_key_sha256"]:
        raise RuntimeError("scored evaluator public key differs from signed config")
    if identity["key_id"] == controller_key_id or public.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ) == controller_public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ):
        raise RuntimeError("separate scored evaluator and controller keys required")
    key_id = identity["key_id"]
    return Ed25519Signer(private_key=private, key_id=key_id), Ed25519Verifier({key_id: public})
