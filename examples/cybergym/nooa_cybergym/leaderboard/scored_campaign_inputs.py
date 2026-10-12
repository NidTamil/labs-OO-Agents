# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Read externally signed scored inputs without manufacturing a go-live decision.

This is the file-custody seam for the cohort CLI. `check_go_live` remains the
authority for signatures, frozen policy, task order and durable creation.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .campaign import CampaignState, check_go_live, preview_go_live, resume_campaign
from .xeus_authority import XeusCampaignAuthority

_MAX_SIGNED = 1024 * 1024
_MAX_POLICY = 64 * 1024
_RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")


@dataclass(frozen=True, slots=True)
class SignedCampaignInputs:
    decision: bytes
    certification: bytes
    harness_lock: bytes
    cohort: bytes
    tasks_json: bytes
    campaign_policy: dict[str, Any]


@dataclass(frozen=True, slots=True)
class ScoredLaunchPreview:
    inputs: SignedCampaignInputs
    authority: XeusCampaignAuthority
    state: CampaignState


def _regular_bytes(root: Path, name: str, limit: int) -> bytes:
    source = root / name
    try:
        if source.is_symlink() or not source.is_file() or source.parent != root:
            raise RuntimeError()
        size = source.stat().st_size
        if not 0 < size <= limit:
            raise RuntimeError()
        data = source.read_bytes()
        if len(data) != size:
            raise RuntimeError()
        return data
    except (OSError, RuntimeError):
        raise RuntimeError(f"bounded regular scored input required: {name}") from None


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate campaign policy key")
        result[key] = value
    return result


def _unique_trust_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate scored trust key")
        result[key] = value
    return result


def load_scored_public_keys(path: Path, *, expected_sha256: str) -> dict[str, Ed25519PublicKey]:
    """Load only externally pinned public verification keys; never choose a fallback."""
    path = Path(path)
    if (
        not path.is_absolute()
        or path.is_symlink()
        or not path.is_file()
        or path.resolve() != path
        or type(expected_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None
        or not 0 < path.stat().st_size <= _MAX_POLICY
    ):
        raise RuntimeError("absolute pinned scored public-key registry required")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise RuntimeError("scored public-key registry digest differs")
    try:
        entries = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_trust_pairs)
    except (UnicodeDecodeError, ValueError) as error:
        raise RuntimeError(f"invalid scored public-key registry: {error}") from None
    if type(entries) is not dict or not entries or len(entries) > 16:
        raise RuntimeError("bounded scored public-key registry required")
    keys = {}
    for key_id, pem in entries.items():
        if (
            type(key_id) is not str
            or _KEY_ID.fullmatch(key_id) is None
            or type(pem) is not str
            or len(pem) > 4096
        ):
            raise RuntimeError("invalid scored public-key entry")
        try:
            public = serialization.load_pem_public_key(pem.encode("ascii"))
        except (UnicodeEncodeError, ValueError, TypeError):
            raise RuntimeError("invalid scored Ed25519 public key") from None
        if not isinstance(public, Ed25519PublicKey):
            raise RuntimeError("scored trust requires Ed25519 public keys")
        keys[key_id] = public
    return keys


def read_signed_campaign_inputs(root: Path) -> SignedCampaignInputs:
    """Read exact named inputs; retain signed envelope bytes for Xeus checks."""
    root = Path(root)
    if not root.is_absolute() or root.is_symlink() or not root.is_dir() or root.resolve() != root:
        raise RuntimeError("absolute unaliased scored input directory required")
    decision = _regular_bytes(root, "decision.signed.json", _MAX_SIGNED)
    certification = _regular_bytes(root, "certification.signed.json", _MAX_SIGNED)
    harness_lock = _regular_bytes(root, "harness_lock.signed.json", _MAX_SIGNED)
    cohort = _regular_bytes(root, "cohort.signed.json", _MAX_SIGNED)
    tasks_json = _regular_bytes(root, "tasks.json", _MAX_SIGNED)
    policy_raw = _regular_bytes(root, "campaign-policy.json", _MAX_POLICY)
    try:
        policy = json.loads(
            policy_raw.decode("utf-8"),
            object_pairs_hook=_unique_pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
        )
    except (UnicodeDecodeError, ValueError):
        raise RuntimeError("campaign-policy.json is invalid") from None
    if type(policy) is not dict:
        raise RuntimeError("campaign-policy.json must be an object")
    return SignedCampaignInputs(decision, certification, harness_lock, cohort, tasks_json, policy)


def preview_signed_campaign(
    *,
    input_root: Path,
    trust_registry: Path,
    trust_sha256: str,
    run_id: str,
    evidence_root: Path,
) -> ScoredLaunchPreview:
    """Verify pinned trust and every signed input before durable admission."""
    if (
        type(run_id) is not str
        or _RUN_ID.fullmatch(run_id) is None
        or not isinstance(evidence_root, Path)
        or not evidence_root.is_absolute()
        or evidence_root.is_symlink()
        or not evidence_root.is_dir()
        or evidence_root.resolve() != evidence_root
    ):
        raise RuntimeError("verified scored campaign identity and evidence root required")
    inputs = read_signed_campaign_inputs(input_root)
    public_keys = load_scored_public_keys(trust_registry, expected_sha256=trust_sha256)
    authority = XeusCampaignAuthority(public_keys)
    state = preview_go_live(
        decision=inputs.decision,
        certification=inputs.certification,
        harness_lock=inputs.harness_lock,
        cohort=inputs.cohort,
        campaign_policy=inputs.campaign_policy,
        tasks_json=inputs.tasks_json,
        authority=authority,
        run_id=run_id,
        evidence_root=evidence_root,
    )
    return ScoredLaunchPreview(inputs, authority, state)


def admit_signed_campaign(
    inputs: SignedCampaignInputs,
    *,
    authority,
    run_id: str,
    evidence_root: Path,
    resume: bool = False,
):
    """Apply frozen Xeus admission; never sign or fabricate any input here."""
    if (
        type(inputs) is not SignedCampaignInputs
        or type(run_id) is not str
        or _RUN_ID.fullmatch(run_id) is None
        or type(resume) is not bool
        or not isinstance(evidence_root, Path)
        or not evidence_root.is_absolute()
        or evidence_root.is_symlink()
        or not evidence_root.is_dir()
        or evidence_root.resolve() != evidence_root
    ):
        raise RuntimeError("verified scored campaign identity and evidence root required")
    admission = resume_campaign if resume else check_go_live
    return admission(
        decision=inputs.decision,
        certification=inputs.certification,
        harness_lock=inputs.harness_lock,
        cohort=inputs.cohort,
        campaign_policy=inputs.campaign_policy,
        tasks_json=inputs.tasks_json,
        authority=authority,
        run_id=run_id,
        evidence_root=evidence_root,
    )
