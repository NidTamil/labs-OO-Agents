# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Independently join two native fixture observations without certifying them.

The custody manifest is checked before each raw attestor reads the fixture.
No gate, signature, scored-freeze, or launch decision is derived here.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .capabilities import CapabilityRegistry, Status
from .raw_fixture_attestor import (
    SignatureVerifier,
    verify_completed_capability_uses,
    verify_deepseek_model_usage,
    verify_live_synthetic_fixture,
    verify_primary_model_usage,
)
from .raw_pair_manifest import verify_raw_pair_manifest

_FIXTURES = ("synthetic:length-header", "synthetic:chunk-table")
_ADVISORY_ROLES = frozenset(
    {"independent_recon", "conditional_debug_recovery", "final_adversarial_critic"}
)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_MANIFEST_BYTES = 1024 * 1024


@dataclass(frozen=True, slots=True)
class RawFixtureIdentity:
    run_id: str
    freeze_sha256: str
    image_id: str
    registry_sha256: str
    bindings_sha256: str
    alternate_policy_sha256: str


@dataclass(frozen=True, slots=True)
class PairedRawFacts:
    """Observed coverage and request counts; never a certification verdict."""

    manifest_sha256: str
    run_ids: tuple[str, str]
    completed_capability_ids: frozenset[str]
    missing_capability_ids: frozenset[str]
    primary_completed_requests: int
    primary_incomplete_requests: int
    primary_input_tokens: int
    primary_output_tokens: int
    primary_cache_tokens: int


def approved_capability_ids(registry: CapabilityRegistry) -> frozenset[str]:
    return frozenset(
        entry.capability_id for entry in registry.entries if entry.status is Status.APPROVED
    )


def _identity_values(
    identities: Mapping[str, RawFixtureIdentity], registry: CapabilityRegistry
) -> tuple[str, str]:
    if not isinstance(identities, Mapping) or set(identities) != set(_FIXTURES):
        raise ValueError("exact fixture identities required")
    runs = []
    image_ids = set()
    for fixture in _FIXTURES:
        item = identities[fixture]
        if type(item) is not RawFixtureIdentity or not item.run_id:
            raise ValueError("frozen fixture identity required")
        for value in (
            item.freeze_sha256,
            item.registry_sha256,
            item.bindings_sha256,
            item.alternate_policy_sha256,
        ):
            if type(value) is not str or _SHA256.fullmatch(value) is None:
                raise ValueError("frozen fixture digest required")
        if (
            item.registry_sha256 != registry.digest
            or type(item.image_id) is not str
            or not item.image_id.startswith("sha256:")
            or _SHA256.fullmatch(item.image_id[7:]) is None
        ):
            raise ValueError("registry or image identity changed")
        runs.append(item.run_id)
        image_ids.add(item.image_id)
    if len(set(runs)) != 2 or len(image_ids) != 1:
        raise ValueError("distinct attempts with one pinned image required")
    return runs[0], runs[1]


def verify_raw_pair_coverage(
    manifest_bytes: bytes,
    *,
    roots: Mapping[str, Path],
    identities: Mapping[str, RawFixtureIdentity],
    registry: CapabilityRegistry,
    verifier: SignatureVerifier,
) -> PairedRawFacts:
    """Re-attest both fixture roots and report only directly observed facts."""
    if type(manifest_bytes) is not bytes or not 0 < len(manifest_bytes) <= _MAX_MANIFEST_BYTES:
        raise ValueError("bounded raw pair manifest required")
    try:
        manifest = json.loads(manifest_bytes)
    except (ValueError, UnicodeError) as error:
        raise ValueError("raw pair manifest malformed") from error
    canonical = json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    if canonical != manifest_bytes:
        raise ValueError("raw pair manifest is not canonical")
    verify_raw_pair_manifest(manifest, roots)
    runs = _identity_values(identities, registry)
    approved = approved_capability_ids(registry)
    if not approved:
        raise ValueError("approved capability baseline absent")

    observed: set[str] = set()
    provider_ids: set[str] = set()
    completed = incomplete = input_tokens = output_tokens = cache_tokens = 0
    for fixture in _FIXTURES:
        root = roots[fixture]
        identity = identities[fixture]
        attested = verify_live_synthetic_fixture(
            root,
            verifier=verifier,
            run_id=identity.run_id,
            task_id=fixture,
            freeze_sha256=identity.freeze_sha256,
            image_id=identity.image_id,
            registry_sha256=identity.registry_sha256,
            bindings_sha256=identity.bindings_sha256,
        )
        if attested.run_id != identity.run_id or attested.task_id != fixture:
            raise ValueError("raw fixture attestation identity mismatch")
        primary = verify_primary_model_usage(root, task_id=fixture, attempt_id=attested.attempt_id)
        deepseek = verify_deepseek_model_usage(
            root,
            task_id=fixture,
            attempt_id=attested.attempt_id,
            registry_sha256=identity.registry_sha256,
            policy_sha256=identity.alternate_policy_sha256,
        )
        counts = verify_completed_capability_uses(
            root,
            registry=registry,
            task_id=fixture,
            attempt_id=attested.attempt_id,
        )
        if (
            set(deepseek) != _ADVISORY_ROLES
            or primary.completed_requests < 1
            or any(role.requests < 1 or role.incomplete_requests for role in deepseek.values())
            or any(type(count) is not int or count < 1 for count in counts.values())
            or not set(counts) <= approved
        ):
            raise ValueError("paired live activity invalid")
        ids = [*primary.provider_request_ids]
        for role in sorted(deepseek):
            ids.extend(deepseek[role].provider_request_ids)
        if len(ids) != len(set(ids)) or provider_ids.intersection(ids):
            raise ValueError("provider request identity reused across fixtures")
        provider_ids.update(ids)
        observed.update(counts)
        completed += primary.completed_requests
        incomplete += primary.incomplete_requests
        input_tokens += primary.input_tokens
        output_tokens += primary.output_tokens
        cache_tokens += primary.cache_tokens
    return PairedRawFacts(
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        run_ids=runs,
        completed_capability_ids=frozenset(observed),
        missing_capability_ids=approved - observed,
        primary_completed_requests=completed,
        primary_incomplete_requests=incomplete,
        primary_input_tokens=input_tokens,
        primary_output_tokens=output_tokens,
        primary_cache_tokens=cache_tokens,
    )
