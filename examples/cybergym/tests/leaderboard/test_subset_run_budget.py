# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Inert signed budget verification; test values are not operator decisions."""

import copy
import hashlib
import json

import pytest
from nooa_cybergym.leaderboard.subset_dry_run_admission import OFFICIAL_SUBSET_TASK_IDS
from nooa_cybergym.leaderboard.subset_run_budget import verify_subset_run_budget


def payload():
    return {
        "schema_version": 1,
        "artifact_kind": "subset_run_budget",
        "scope": "native_subset_dry_run_level1",
        "run_id": "test-run",
        "epoch": "test-epoch",
        "task_ids": list(OFFICIAL_SUBSET_TASK_IDS),
        "campaign_policy_sha256": "a" * 64,
        "model_policy_sha256": "b" * 64,
        "metering_policy_sha256": "c" * 64,
        "max_model_requests": 15000,
        "max_requests_per_task": 1500,
        "primary_and_memory_requests_per_task": 1410,
        "deepseek_advisory_requests_per_task": 90,
        "max_elapsed_seconds": 7200,
        "max_spend_units": 1000000,
        "spend_unit": "usd_micros",
        "accounting_scope": "all_model_calls_including_memory_and_failed_reservations",
        "elapsed_scope": "first_preparation_through_final_cleanup",
        "exhaustion_action": "stop_run_preserve_task_terminals",
    }


class Authority:
    def __init__(self, data):
        self.data = data
        self.calls = []

    def attest_signed(self, kind, envelope):
        self.calls.append((kind, envelope))
        return copy.deepcopy(self.data)


def verify(data=None, **overrides):
    signed = b"opaque-test-envelope"
    args = {
        "signed_budget": signed,
        "authority": Authority(payload() if data is None else data),
        "expected_envelope_sha256": hashlib.sha256(signed).hexdigest(),
        "run_id": "test-run",
        "epoch": "test-epoch",
        "campaign_policy_sha256": "a" * 64,
        "model_policy_sha256": "b" * 64,
        "metering_policy_sha256": "c" * 64,
    }
    args.update(overrides)
    return verify_subset_run_budget(**args)


def test_signed_bytes_are_attested_and_all_limits_are_immutable():
    authority = Authority(payload())
    budget = verify(authority=authority)
    assert authority.calls == [("subset_run_budget", b"opaque-test-envelope")]
    assert budget.max_model_requests == 15000
    assert budget.max_elapsed_seconds == 7200
    assert budget.max_spend_units == 1000000
    assert budget.spend_unit == "usd_micros"
    assert budget.metering_policy_sha256 == "c" * 64
    assert budget.task_ids == OFFICIAL_SUBSET_TASK_IDS
    assert json.loads(budget.payload_json) == payload()
    budget.reverify(authority)
    assert len(authority.calls) == 2
    authority.data["max_elapsed_seconds"] = 9000
    with pytest.raises(RuntimeError, match="changed"):
        budget.reverify(authority)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("schema_version", True),
        ("schema_version", 2),
        ("artifact_kind", "subset_dry_run_admission"),
        ("scope", "full_cohort"),
        ("run_id", "different-run"),
        ("epoch", "different-epoch"),
        ("campaign_policy_sha256", "d" * 64),
        ("model_policy_sha256", "d" * 64),
        ("metering_policy_sha256", "not-a-digest"),
        ("max_model_requests", 15001),
        ("max_model_requests", 15000.0),
        ("max_requests_per_task", 600),
        ("primary_and_memory_requests_per_task", 1500),
        ("deepseek_advisory_requests_per_task", 36),
        ("max_elapsed_seconds", 0),
        ("max_elapsed_seconds", True),
        ("max_elapsed_seconds", 3600.5),
        ("max_spend_units", 0),
        ("max_spend_units", float("inf")),
        ("max_spend_units", True),
        ("spend_unit", "unmetered"),
        ("elapsed_scope", "provider_time_only"),
        ("exhaustion_action", "budget_stop_task_verdict"),
        ("accounting_scope", "successful_primary_only"),
    ],
)
def test_wrong_scope_types_policy_or_incomplete_limits_fail_closed(key, value):
    data = payload()
    data[key] = value
    with pytest.raises(RuntimeError):
        verify(data)


@pytest.mark.parametrize(
    "missing", ["max_elapsed_seconds", "max_spend_units", "metering_policy_sha256"]
)
def test_pending_operator_limits_cannot_be_admitted(missing):
    data = payload()
    del data[missing]
    with pytest.raises(RuntimeError):
        verify(data)


@pytest.mark.parametrize("task_change", ["reorder", "drop", "duplicate"])
def test_exact_official_ten_task_order_is_required(task_change):
    data = payload()
    tasks = data["task_ids"]
    if task_change == "reorder":
        tasks.reverse()
    elif task_change == "drop":
        tasks.pop()
    else:
        tasks[-1] = tasks[0]
    with pytest.raises(RuntimeError):
        verify(data)


def test_caller_hash_is_not_a_substitute_for_signed_budget_bytes():
    with pytest.raises(RuntimeError):
        verify(signed_budget=b"")
    with pytest.raises(RuntimeError):
        verify(signed_budget=b"different-envelope")
    with pytest.raises(RuntimeError):
        verify(authority=Authority(None))
    data = payload()
    data["extra_approval_claim"] = True
    with pytest.raises(RuntimeError):
        verify(data)


def test_signed_budget_must_match_independently_selected_metering_policy():
    data = payload()
    data["metering_policy_sha256"] = "d" * 64
    with pytest.raises(RuntimeError, match="metering"):
        verify(data)


def test_budget_payload_is_defensively_copied():
    authority = Authority(payload())
    budget = verify(authority=authority)
    before = budget.payload_json
    authority.data["task_ids"].reverse()
    assert budget.payload_json == before
    assert budget.task_ids == OFFICIAL_SUBSET_TASK_IDS


def test_actual_ed25519_authority_rejects_changed_or_noncanonical_budget():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from nooa_cybergym.leaderboard.xeus_authority import XeusCampaignAuthority
    from xeus_cybergym.canonical import canonical_json
    from xeus_cybergym.ledger import Ed25519Signer

    key = Ed25519PrivateKey.generate()
    signer = Ed25519Signer(private_key=key, key_id="test-budget")
    authority = XeusCampaignAuthority({"test-budget": key.public_key()})
    raw = canonical_json(signer.sign(canonical_json(payload())).model_dump())
    budget = verify(
        signed_budget=raw,
        authority=authority,
        expected_envelope_sha256=hashlib.sha256(raw).hexdigest(),
    )
    budget.reverify(authority)
    # A correctly signed but noncanonical payload is still inadmissible.
    noncanonical = canonical_json(
        signer.sign(json.dumps(payload(), indent=2).encode()).model_dump()
    )
    with pytest.raises(RuntimeError, match="verification"):
        verify(
            signed_budget=noncanonical,
            authority=authority,
            expected_envelope_sha256=hashlib.sha256(noncanonical).hexdigest(),
        )
    other = Ed25519PrivateKey.generate()
    with pytest.raises(RuntimeError, match="verification"):
        verify(
            signed_budget=raw,
            authority=XeusCampaignAuthority({"test-budget": other.public_key()}),
            expected_envelope_sha256=hashlib.sha256(raw).hexdigest(),
        )
