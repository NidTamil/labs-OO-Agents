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
