# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""A paired raw check must preserve observed gaps, never mint gate passes."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from nooa_cybergym.leaderboard.raw_pair_coverage import (
    RawFixtureIdentity,
    verify_raw_pair_coverage,
)
from nooa_cybergym.leaderboard.raw_pair_manifest import build_raw_pair_manifest


def _inputs(tmp_path):
    roots = {}
    for fixture, name in (("synthetic:length-header", "a"), ("synthetic:chunk-table", "b")):
        root = tmp_path / name
        root.mkdir()
        (root / "result.json").write_text(json.dumps({"run_id": name}))
        roots[fixture] = root
    manifest = build_raw_pair_manifest("repeat-one", roots)
    raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    identities = {
        fixture: RawFixtureIdentity(
            run_id=name,
            freeze_sha256="1" * 64,
            image_id="sha256:" + "2" * 64,
            registry_sha256="3" * 64,
            bindings_sha256="4" * 64,
            alternate_policy_sha256="5" * 64,
        )
        for fixture, name in (("synthetic:length-header", "a"), ("synthetic:chunk-table", "b"))
    }
    registry = SimpleNamespace(digest="3" * 64, entries=[])
    return raw, roots, identities, registry


def test_pair_coverage_preserves_incomplete_request_and_missing_capability(tmp_path, monkeypatch):
    raw, roots, identities, registry = _inputs(tmp_path)
    import nooa_cybergym.leaderboard.raw_pair_coverage as module

    def fixture(root, *, run_id, task_id, **_kwargs):
        return SimpleNamespace(run_id=run_id, task_id=task_id, attempt_id=run_id)

    monkeypatch.setattr(module, "verify_live_synthetic_fixture", fixture)
    monkeypatch.setattr(
        module,
        "verify_primary_model_usage",
        lambda root, **_kwargs: SimpleNamespace(
            completed_requests=4,
            incomplete_requests=1 if root == roots["synthetic:chunk-table"] else 0,
            input_tokens=10,
            output_tokens=5,
            cache_tokens=1,
            provider_request_ids=(str(root) + "-primary",),
        ),
    )
    monkeypatch.setattr(
        module,
        "verify_deepseek_model_usage",
        lambda root, **_kwargs: {
            role: SimpleNamespace(
                requests=1, incomplete_requests=0, provider_request_ids=(str(root) + "-" + role,)
            )
            for role in (
                "independent_recon",
                "conditional_debug_recovery",
                "final_adversarial_critic",
            )
        },
    )
    monkeypatch.setattr(
        module,
        "verify_completed_capability_uses",
        lambda root, **_kwargs: (
            {"cap-a": 2} if root == roots["synthetic:length-header"] else {"cap-b": 1}
        ),
    )
    monkeypatch.setattr(
        module, "approved_capability_ids", lambda _registry: frozenset({"cap-a", "cap-b", "cap-c"})
    )

    facts = verify_raw_pair_coverage(
        raw, roots=roots, identities=identities, registry=registry, verifier=object()
    )

    assert facts.completed_capability_ids == frozenset({"cap-a", "cap-b"})
    assert facts.missing_capability_ids == frozenset({"cap-c"})
    assert facts.primary_incomplete_requests == 1
    assert facts.primary_completed_requests == 8
    assert not hasattr(facts, "gates")
    assert not hasattr(facts, "certified")

    (roots["synthetic:length-header"] / "result.json").write_text("changed")
    with pytest.raises(ValueError, match="changed"):
        verify_raw_pair_coverage(
            raw, roots=roots, identities=identities, registry=registry, verifier=object()
        )


def test_pair_coverage_rejects_reused_attempt_identity(tmp_path):
    raw, roots, identities, registry = _inputs(tmp_path)
    identities["synthetic:chunk-table"] = identities["synthetic:length-header"]
    with pytest.raises(ValueError, match="distinct"):
        verify_raw_pair_coverage(
            raw, roots=roots, identities=identities, registry=registry, verifier=object()
        )


def test_pair_coverage_rejects_uncanonical_manifest_before_attestation(tmp_path, monkeypatch):
    raw, roots, identities, registry = _inputs(tmp_path)
    import nooa_cybergym.leaderboard.raw_pair_coverage as module

    monkeypatch.setattr(
        module,
        "verify_live_synthetic_fixture",
        lambda *_args, **_kwargs: pytest.fail("raw attestor called before custody check"),
    )
    with pytest.raises(ValueError, match="canonical"):
        verify_raw_pair_coverage(
            raw + b" ", roots=roots, identities=identities, registry=registry, verifier=object()
        )
    (roots["synthetic:chunk-table"] / "result.json").write_text("changed")
    with pytest.raises(ValueError, match="changed"):
        verify_raw_pair_coverage(
            raw, roots=roots, identities=identities, registry=registry, verifier=object()
        )


@pytest.mark.parametrize("unreconciled", [False, True])
@pytest.mark.parametrize("selection_change", [None, "missing", "uncanonical", "task", "attempt"])
def test_pair_v2_preserves_all_lane_accounting_and_gaps(
    tmp_path, monkeypatch, unreconciled, selection_change
):
    import hashlib

    import nooa_cybergym.leaderboard.raw_pair_coverage as module
    from nooa_cybergym.leaderboard.primary_takeover import PrimaryTakeoverPolicy

    raw, roots, identities, registry = _inputs(tmp_path)
    policy = PrimaryTakeoverPolicy()
    bindings = {"memory-model": {"provider": "memory-provider", "kind": "completion"}}
    manifests = {}
    declarations = {}
    for fixture, identity in identities.items():
        declarations[fixture] = {
            "schema_version": 2,
            "task_id": fixture,
            "attempt_id": identity.run_id,
            "candidate_path": "/workspace/output/final-poc",
            "sha256": "a" * 64,
            "byte_length": 4,
            "selected_at": "2026-10-21T00:00:00+00:00",
            "selection_reason": "Synthetic final",
            "final_declaration": True,
            "selected_by": "primary_parent",
            "provider": policy.initial.provider,
            "configured_model": policy.initial.model,
            "provider_model": policy.initial.wire_model,
            "provider_attempt_id": identity.run_id + "-provider-attempt",
            "request_id": identity.run_id + "-request",
            "session_id": identity.run_id + "-session",
            "tool_id": identity.run_id + "-tool",
            "takeover_policy_sha256": policy.digest,
        }
        manifests[fixture] = {
            "schema_version": 2,
            "task_id": fixture,
            "attempt_id": identity.run_id,
            "takeover_policy_sha256": policy.digest,
            "registry_sha256": registry.digest,
            "alternate_policy_sha256": identity.alternate_policy_sha256,
            "memory_model_bindings_sha256": hashlib.sha256(
                json.dumps(bindings, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            "requests": [
                {
                    "lane": "primary",
                    "usage_status": "observed",
                    "provider_request_id": identity.run_id + "-provider",
                }
            ],
            "totals": {
                "model_requests": 7,
                "unknown_usage_requests": int(unreconciled),
                "unmatched_reservations": int(unreconciled),
                "unbounded_unknown_usage_requests": int(unreconciled),
                "input_tokens": 10,
                "output_tokens": 20,
                "cache_tokens": 1,
                "counted_tokens": 4,
                "conservative_tokens": 0,
                "observed_requests": 7 - int(unreconciled),
            },
            "allocations": {"primary_and_memory": 4, "deepseek_advisory": 3},
            "reconciled": not unreconciled,
        }

    def attest(root, *, run_id, task_id, **kwargs):
        assert kwargs["takeover_policy"] == policy
        assert kwargs["memory_model_bindings"] == bindings
        manifest = manifests[task_id]
        digest = hashlib.sha256(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        declaration = dict(declarations[task_id])
        if selection_change == "task":
            declaration["task_id"] = "wrong-task"
        if selection_change == "attempt":
            declaration["attempt_id"] = "wrong-attempt"
        final = json.dumps(declaration, sort_keys=True, separators=(",", ":")).encode()
        if selection_change == "missing":
            final = None
        if selection_change == "uncanonical":
            final += b" "
        return SimpleNamespace(
            run_id=run_id,
            task_id=task_id,
            attempt_id=run_id,
            request_accounting=SimpleNamespace(manifest=manifest, digest=digest),
            primary_final_selection=final,
        )

    monkeypatch.setattr(module, "verify_live_synthetic_fixture", attest)
    monkeypatch.setattr(
        module,
        "verify_primary_model_usage",
        lambda *args, **kwargs: pytest.fail("legacy primary verifier used in v2"),
    )
    monkeypatch.setattr(
        module,
        "verify_deepseek_model_usage",
        lambda *args, **kwargs: pytest.fail("legacy adviser verifier used in v2"),
    )
    monkeypatch.setattr(
        module, "verify_completed_capability_uses", lambda *args, **kwargs: {"cap-a": 1}
    )
    monkeypatch.setattr(module, "approved_capability_ids", lambda _: frozenset({"cap-a", "cap-b"}))

    def verify():
        return verify_raw_pair_coverage(
            raw,
            roots=roots,
            identities=identities,
            registry=registry,
            verifier=object(),
            takeover_policy=policy,
            memory_model_bindings=bindings,
        )

    if selection_change is not None:
        with pytest.raises(ValueError, match="final"):
            verify()
        return
    facts = verify()
    assert facts.schema_version == 2
    assert facts.model_requests == 14
    assert facts.unmatched_reservations == 2 * int(unreconciled)
    assert facts.reconciled is (not unreconciled)
    assert facts.missing_capability_ids == frozenset({"cap-b"})
    assert facts.allocations == {"primary_and_memory": 8, "deepseek_advisory": 6}
    assert set(facts.request_accounting) == set(identities)
    for fixture, declaration in declarations.items():
        assert facts.primary_final_selections[fixture] == {
            "declaration": declaration,
            "sha256": hashlib.sha256(
                json.dumps(declaration, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
        }
    assert not hasattr(facts, "certified")


def test_pair_v2_refuses_legacy_fixture_attestation(tmp_path, monkeypatch):
    import nooa_cybergym.leaderboard.raw_pair_coverage as module
    from nooa_cybergym.leaderboard.primary_takeover import PrimaryTakeoverPolicy

    raw, roots, identities, registry = _inputs(tmp_path)
    monkeypatch.setattr(module, "approved_capability_ids", lambda _: frozenset({"cap-a"}))
    monkeypatch.setattr(
        module,
        "verify_live_synthetic_fixture",
        lambda root, **kwargs: SimpleNamespace(
            run_id=kwargs["run_id"], task_id=kwargs["task_id"], attempt_id=kwargs["run_id"]
        ),
    )
    with pytest.raises(ValueError, match="accounting"):
        verify_raw_pair_coverage(
            raw,
            roots=roots,
            identities=identities,
            registry=registry,
            verifier=object(),
            takeover_policy=PrimaryTakeoverPolicy(),
            memory_model_bindings={
                "memory-model": {"provider": "memory-provider", "kind": "completion"}
            },
        )
