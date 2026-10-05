"""Certification can only use named synthetic fixtures and frozen policies."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from nooa_cybergym.leaderboard.certification import (
    CertificationPolicy,
    assert_synthetic_only,
    bind_certification_policy,
)

CONFIG = Path(__file__).parents[3] / "leaderboard" / "config"


def test_certification_rejects_cohort_ids_even_when_marked_synthetic() -> None:
    with pytest.raises(RuntimeError, match="official cohort"):
        assert_synthetic_only(
            requested_ids=["synthetic:length-header"],
            cohort_ids={"synthetic:length-header", "arvo:1065"},
        )


@pytest.mark.parametrize("requested", [["arvo:1065"], ["synthetic:unknown"], []])
def test_certification_rejects_unlisted_or_non_synthetic_ids(requested: list[str]) -> None:
    with pytest.raises(RuntimeError, match="synthetic fixture"):
        assert_synthetic_only(
            requested_ids=requested,
            cohort_ids={"arvo:42"},
            allowed_fixture_ids={"synthetic:length-header", "synthetic:chunk-table"},
        )


def test_policy_binds_active_role_limits_and_hashes() -> None:
    policy = CertificationPolicy.model_validate_json(
        (CONFIG / "certification-policy.json").read_text()
    )
    assert_synthetic_only(
        requested_ids=list(policy.fixture_ids),
        cohort_ids={"arvo:1065"},
        allowed_fixture_ids=set(policy.fixture_ids),
    )
    binding = bind_certification_policy(
        policy=policy,
        alternate_policy_path=CONFIG / "alternate-model.json",
        capability_registry_sha256="a" * 64,
        network_policy_sha256="b" * 64,
    )
    assert binding.alternate_policy_sha256 != binding.policy_sha256
    assert binding.capability_registry_sha256 == "a" * 64
    assert binding.network_policy_sha256 == "b" * 64


def test_certification_policy_rejects_mismatched_deepseek_calls() -> None:
    payload = json.loads((CONFIG / "certification-policy.json").read_text())
    payload["alternate_max_requests_by_role"]["independent_recon"] = 13
    with pytest.raises(ValueError, match="DeepSeek role limits"):
        CertificationPolicy.model_validate(payload)
