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
from typing import Any

from .capabilities import CapabilityRegistry, Status
from .primary_takeover import PrimaryTakeoverPolicy
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


@dataclass(frozen=True, slots=True)
class PairedRawAccountingFacts:
    """Schema-two observed all-lane facts, including unreconciled exposure."""

    schema_version: int
    manifest_sha256: str
    run_ids: tuple[str, str]
    completed_capability_ids: frozenset[str]
    missing_capability_ids: frozenset[str]
    request_accounting: dict[str, Any]
    primary_final_selections: dict[str, Any]
    allocations: dict[str, int]
    reconciled: bool
    model_requests: int
    observed_requests: int
    unknown_usage_requests: int
    unmatched_reservations: int
    unbounded_unknown_usage_requests: int
    input_tokens: int
    output_tokens: int
    cache_tokens: int
    counted_tokens: int
    conservative_tokens: int


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
    takeover_policy: PrimaryTakeoverPolicy | None = None,
    memory_model_bindings: Mapping[str, Mapping[str, str]] | None = None,
    budget_run_id: str | None = None,
) -> PairedRawFacts | PairedRawAccountingFacts:
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
    if takeover_policy is not None:
        return _verify_accounted_pair(
            manifest_bytes,
            roots=roots,
            identities=identities,
            registry=registry,
            verifier=verifier,
            takeover_policy=takeover_policy,
            memory_model_bindings=memory_model_bindings,
            budget_run_id=budget_run_id,
            runs=runs,
            approved=approved,
        )
    if memory_model_bindings is not None or budget_run_id is not None:
        raise ValueError("new accounting inputs require explicit takeover policy")

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
        if getattr(attested, "request_accounting", None) is not None:
            raise ValueError("new accounting cannot use legacy pair verification")
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


def _verify_accounted_pair(
    manifest_bytes,
    *,
    roots,
    identities,
    registry,
    verifier,
    takeover_policy,
    memory_model_bindings,
    budget_run_id,
    runs,
    approved,
) -> PairedRawAccountingFacts:
    from .finalize import _validate_declaration
    from .raw_request_accounting import validate_memory_model_bindings

    if type(takeover_policy) is not PrimaryTakeoverPolicy:
        raise ValueError("explicit primary takeover policy required")
    bindings = validate_memory_model_bindings(memory_model_bindings)
    bindings_digest = hashlib.sha256(
        json.dumps(
            bindings, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode()
    ).hexdigest()
    accounting, observed, provider_ids, attempts = {}, set(), set(), set()
    primary_final_selections = {}
    allocations = {"primary_and_memory": 0, "deepseek_advisory": 0}
    totals = dict.fromkeys(
        (
            "model_requests",
            "observed_requests",
            "unknown_usage_requests",
            "unmatched_reservations",
            "unbounded_unknown_usage_requests",
            "input_tokens",
            "output_tokens",
            "cache_tokens",
            "counted_tokens",
            "conservative_tokens",
        ),
        0,
    )
    reconciled = True
    for fixture in _FIXTURES:
        identity, root = identities[fixture], roots[fixture]
        attested = verify_live_synthetic_fixture(
            root,
            verifier=verifier,
            run_id=identity.run_id,
            task_id=fixture,
            freeze_sha256=identity.freeze_sha256,
            image_id=identity.image_id,
            registry_sha256=identity.registry_sha256,
            bindings_sha256=identity.bindings_sha256,
            takeover_policy=takeover_policy,
            alternate_policy_sha256=identity.alternate_policy_sha256,
            memory_model_bindings=bindings,
            budget_run_id=budget_run_id,
        )
        verified = getattr(attested, "request_accounting", None)
        if (
            verified is None
            or attested.run_id != identity.run_id
            or attested.task_id != fixture
            or attested.attempt_id in attempts
        ):
            raise ValueError("independent schema-two fixture accounting absent")
        attempts.add(attested.attempt_id)
        final_raw = getattr(attested, "primary_final_selection", None)
        if type(final_raw) is not bytes or not final_raw:
            raise ValueError("independent primary final declaration absent")
        try:
            declaration = _validate_declaration(final_raw, fixture, takeover_policy=takeover_policy)
            canonical_final = json.dumps(
                declaration,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode()
            if final_raw != canonical_final or declaration["attempt_id"] != attested.attempt_id:
                raise ValueError("primary final declaration identity or canonical bytes changed")
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("independent primary final declaration invalid") from error
        primary_final_selections[fixture] = {
            "declaration": declaration,
            "sha256": hashlib.sha256(final_raw).hexdigest(),
        }
        manifest, digest = verified.manifest, verified.digest
        encoded = json.dumps(
            manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode()
        if (
            type(manifest) is not dict
            or hashlib.sha256(encoded).hexdigest() != digest
            or type(manifest.get("schema_version")) is not int
            or manifest["schema_version"] != 2
            or manifest.get("task_id") != fixture
            or manifest.get("attempt_id") != attested.attempt_id
            or manifest.get("takeover_policy_sha256") != takeover_policy.digest
            or manifest.get("registry_sha256") != registry.digest
            or manifest.get("alternate_policy_sha256") != identity.alternate_policy_sha256
            or manifest.get("memory_model_bindings_sha256") != bindings_digest
            or type(manifest.get("reconciled")) is not bool
            or type(manifest.get("totals")) is not dict
            or set(manifest["totals"]) != set(totals)
            or type(manifest.get("allocations")) is not dict
            or set(manifest["allocations"]) != set(allocations)
        ):
            raise ValueError("raw accounting identity or shape mismatch")
        for target, source in (
            (totals, manifest["totals"]),
            (allocations, manifest["allocations"]),
        ):
            for key in target:
                if type(source[key]) is not int or source[key] < 0:
                    raise ValueError("raw accounting count malformed")
                target[key] += source[key]
        for row in manifest["requests"]:
            provider_id = row.get("provider_request_id")
            if provider_id is not None:
                if type(provider_id) is not str or not provider_id or provider_id in provider_ids:
                    raise ValueError("provider request identity reused across fixtures")
                provider_ids.add(provider_id)
        counts = verify_completed_capability_uses(
            root,
            registry=registry,
            task_id=fixture,
            attempt_id=attested.attempt_id,
        )
        if (
            any(type(count) is not int or count < 1 for count in counts.values())
            or not set(counts) <= approved
        ):
            raise ValueError("paired live capability activity invalid")
        observed.update(counts)
        reconciled = reconciled and manifest["reconciled"]
        accounting[fixture] = {"manifest": json.loads(encoded), "sha256": digest}
    return PairedRawAccountingFacts(
        schema_version=2,
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        run_ids=runs,
        completed_capability_ids=frozenset(observed),
        missing_capability_ids=approved - observed,
        request_accounting=accounting,
        primary_final_selections=primary_final_selections,
        allocations=allocations,
        reconciled=reconciled,
        **totals,
    )
