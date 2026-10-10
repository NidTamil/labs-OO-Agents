# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Synthetic signed-envelope and durable-ledger contracts; no official dispatch."""

import base64
import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest
from nooa_cybergym.leaderboard.campaign import CampaignState, check_go_live, next_action
from nooa_cybergym.leaderboard.deepseek import AlternateModelPolicy
from nooa_cybergym.leaderboard.workspace import ControllerPaths

CONFIG = Path(__file__).resolve().parents[2] / "leaderboard/config/campaign-policy.json"
ALTERNATE = CONFIG.with_name("alternate-model.json")
IDS = tuple(f"arvo:{index}" for index in range(1, 1508))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def oracle_receipt(task_id, *, status="oracle_false"):
    return {
        "schema_version": 1,
        "artifact_kind": "terminal_receipt",
        "run_id": "run-1",
        "epoch": "epoch-1",
        "task_id": task_id,
        "status": status,
        "final_sha256": "a" * 64,
        "final_declaration_sha256": "b" * 64,
        "parent_event_digest": "c" * 64,
        "oracle_request_sha256": "d" * 64,
        "oracle_verdict_sha256": "e" * 64,
        "oracle_true": status == "oracle_true",
    }


def failure_receipt(task_id, *, status="timeout"):
    return {
        "schema_version": 1,
        "artifact_kind": "terminal_receipt",
        "run_id": "run-1",
        "epoch": "epoch-1",
        "task_id": task_id,
        "status": status,
        "evidence_sha256": "f" * 64,
    }


class Authority:
    """A test double for Xeus signature attestation and atomic durable ledger."""

    def __init__(self, payloads):
        self.payloads = payloads
        self.invalid = set()
        self.events = []
        self.created_root = None
        self.append_calls = []
        self.signed_receipts = {}

    def attest_signed(self, kind, envelope):
        if kind in self.invalid:
            return None
        if kind == "terminal_receipt" and envelope in self.signed_receipts:
            return self.signed_receipts[envelope]
        return self.payloads.get(kind) if envelope == f"signed:{kind}".encode() else None

    def create_campaign_once(self, evidence_root, run_id, event):
        if self.created_root is not None:
            return False
        self.created_root = evidence_root
        self.events.append(event)
        return True

    def read_verified_events(self, evidence_root, run_id):
        assert evidence_root == self.created_root
        return tuple(dict(event) for event in self.events)

    def append_event(self, evidence_root, run_id, event, expected_revision):
        self.append_calls.append((event, expected_revision))
        if len(self.events) != expected_revision:
            return False
        self.events.append(dict(event))
        return True


def fixture(tmp_path):
    policy = json.loads(CONFIG.read_text())
    alternate = AlternateModelPolicy.model_validate_json(ALTERNATE.read_text())
    tasks_json = canonical([{"task_id": task_id} for task_id in IDS])
    envelopes = {
        kind: f"signed:{kind}".encode()
        for kind in ("decision", "certification", "harness_lock", "cohort")
    }
    policy_sha = sha(canonical(policy))
    payloads = {
        "cohort": {
            "schema_version": 1,
            "task_ids": list(IDS),
            "tasks_json_sha256": sha(tasks_json),
            "asset_hashes_sha256": "d" * 64,
            "benchmark_commit": "1" * 40,
            "dataset_commit": "2" * 40,
            "mask_map_sha256": "e" * 64,
            "generator_sha256": "f" * 64,
            "harness_manifest_sha256": "0" * 64,
        },
        "harness_lock": {
            "schema_version": 1,
            "epoch": "epoch-1",
            "campaign_policy_sha256": policy_sha,
            "alternate_policy_sha256": alternate.digest,
            "capability_registry_sha256": "b" * 64,
            "memory_policy_sha256": "c" * 64,
        },
        "certification": {
            "schema_version": 1,
            "status": "accepted",
            "scope": "live_native",
            "epoch": "epoch-1",
            "harness_sha256": sha(envelopes["harness_lock"]),
            "cohort_sha256": sha(envelopes["cohort"]),
            "campaign_policy_sha256": policy_sha,
            "alternate_policy_sha256": alternate.digest,
            "capability_registry_sha256": "b" * 64,
            "memory_policy_sha256": "c" * 64,
            "capability_coverage": "all_enabled_exercised",
            "memory_mode": "audited_hybrid",
            "controller_writes_after_true_oracle": True,
            "deepseek": {
                "status": "active",
                "provider": "https://api.deepseek.com",
                "model": "deepseek-flash",
                "thinking": {"type": "enabled"},
                "reasoning_effort": "max",
                "api": "chat_completions",
                "context_tokens": 1048576,
                "max_output_tokens": 128000,
                "max_requests": 36,
                "role_tokens": {
                    "independent_recon": 12582912,
                    "conditional_debug_recovery": 16777216,
                    "final_adversarial_critic": 8388608,
                },
                "role_seconds": {
                    "independent_recon": 3600,
                    "conditional_debug_recovery": 3600,
                    "final_adversarial_critic": 1800,
                },
                "role_requests": {
                    "independent_recon": 12,
                    "conditional_debug_recovery": 16,
                    "final_adversarial_critic": 8,
                },
            },
        },
        "decision": {
            "schema_version": 1,
            "run_id": "run-1",
            "official_launch_authorised": True,
            "epoch": "epoch-1",
            "certification_sha256": sha(envelopes["certification"]),
            "harness_sha256": sha(envelopes["harness_lock"]),
            "cohort_sha256": sha(envelopes["cohort"]),
            "campaign_policy_sha256": policy_sha,
        },
    }
    authority = Authority(payloads)
    inputs = {
        "decision": envelopes["decision"],
        "certification": envelopes["certification"],
        "harness_lock": envelopes["harness_lock"],
        "cohort": envelopes["cohort"],
        "campaign_policy": policy,
        "tasks_json": tasks_json,
        "authority": authority,
        "run_id": "run-1",
        "evidence_root": tmp_path / "evidence",
    }
    return inputs, authority, payloads


@pytest.mark.parametrize(
    "field",
    ("asset_hashes_sha256", "benchmark_commit", "dataset_commit", "mask_map_sha256"),
)
def test_signed_cohort_requires_every_input_identity_before_campaign_creation(tmp_path, field):
    inputs, authority, payloads = fixture(tmp_path)
    del payloads["cohort"][field]
    with pytest.raises(RuntimeError, match="cohort input identity"):
        check_go_live(**inputs)
    assert authority.events == []


def test_campaign_state_carries_signed_inputs_and_rejects_unpinned_asset_manifest(tmp_path):
    inputs, _, payloads = fixture(tmp_path)
    state = check_go_live(**inputs)
    assert state.asset_hashes_sha256 == payloads["cohort"]["asset_hashes_sha256"]
    assert state.benchmark_commit == payloads["cohort"]["benchmark_commit"]
    assert state.dataset_commit == payloads["cohort"]["dataset_commit"]
    assert state.mask_map_sha256 == payloads["cohort"]["mask_map_sha256"]
    manifest = tmp_path / "asset-hashes.json"
    manifest.write_bytes(b"{}")
    with pytest.raises(RuntimeError, match="asset manifest"):
        state.load_asset_registry(manifest)


def test_scored_started_event_digest_requires_exact_verified_request(tmp_path):
    inputs, authority, _ = fixture(tmp_path)
    state = check_go_live(**inputs)
    task_id = IDS[0]
    state.mark_prepared(task_id)
    state.mark_started(task_id, request_id="launch-1")
    expected = {"type": "started", "task_id": task_id, "request_id": "launch-1"}
    assert state.next_action().kind == "observe_started"
    assert state.started_event_sha256(task_id, "launch-1") == sha(canonical(expected))
    with pytest.raises(RuntimeError, match="started event differs"):
        state.started_event_sha256(task_id, "launch-2")
    authority.events[-1]["request_id"] = "tampered"
    with pytest.raises(RuntimeError, match="started event differs"):
        state.started_event_sha256(task_id, "launch-1")


def test_campaign_loads_only_signed_ordered_assets_and_mask_map(tmp_path):
    inputs, _, payloads = fixture(tmp_path)
    asset_bytes = canonical(
        {
            "schema_version": 1,
            "benchmark_commit": "1" * 40,
            "dataset_commit": "2" * 40,
            "assets": [
                {
                    "task_id": task_id,
                    "description_sha256": "a" * 64,
                    "description_bytes": 3,
                    "description_lfs_pointer": False,
                    "vulnerable_archive_sha256": "b" * 64,
                    "vulnerable_archive_bytes": 7,
                    "vulnerable_archive_lfs_pointer": True,
                }
                for task_id in IDS
            ],
        }
    )
    payloads["cohort"]["asset_hashes_sha256"] = sha(asset_bytes)
    payloads["cohort"]["mask_map_sha256"] = sha(b"{}")
    state = check_go_live(**inputs)
    manifest = tmp_path / "asset-hashes.json"
    manifest.write_bytes(asset_bytes)
    registry = state.load_asset_registry(manifest)
    assert registry.task_ids == IDS
    assert registry.inputs_for(IDS[0]).vulnerable_archive.sha256 == "b" * 64
    mask = tmp_path / "mask_map.json"
    mask.write_bytes(b"{}")
    state.assert_mask_map(mask)
    mask.write_bytes(b'{"changed":true}')
    with pytest.raises(RuntimeError, match="mask map hash mismatch"):
        state.assert_mask_map(mask)


@pytest.mark.parametrize("field", ["benchmark_commit", "dataset_commit"])
def test_campaign_rejects_asset_manifest_from_different_source_commit(tmp_path, field):
    inputs, _, payloads = fixture(tmp_path)
    asset_payload = {
        "schema_version": 1,
        "benchmark_commit": "1" * 40,
        "dataset_commit": "2" * 40,
        "assets": [
            {
                "task_id": task_id,
                "description_sha256": "a" * 64,
                "description_bytes": 3,
                "description_lfs_pointer": False,
                "vulnerable_archive_sha256": "b" * 64,
                "vulnerable_archive_bytes": 7,
                "vulnerable_archive_lfs_pointer": True,
            }
            for task_id in IDS
        ],
    }
    asset_payload[field] = "3" * 40
    asset_bytes = canonical(asset_payload)
    payloads["cohort"]["asset_hashes_sha256"] = sha(asset_bytes)
    state = check_go_live(**inputs)
    manifest = tmp_path / "asset-hashes.json"
    manifest.write_bytes(asset_bytes)
    with pytest.raises(RuntimeError, match=field.replace("_", " ")):
        state.load_asset_registry(manifest)


@pytest.mark.parametrize(
    "field", ["mask_map_sha256", "generator_sha256", "harness_manifest_sha256"]
)
def test_staging_paths_reject_identity_different_from_signed_cohort(tmp_path, field):
    inputs, _, payloads = fixture(tmp_path)
    manifest = tmp_path / "asset-hashes.json"
    manifest.write_bytes(
        canonical(
            {
                "schema_version": 1,
                "benchmark_commit": "1" * 40,
                "dataset_commit": "2" * 40,
                "assets": [
                    {
                        "task_id": task_id,
                        "description_sha256": "a" * 64,
                        "description_bytes": 3,
                        "description_lfs_pointer": False,
                        "vulnerable_archive_sha256": "b" * 64,
                        "vulnerable_archive_bytes": 7,
                        "vulnerable_archive_lfs_pointer": True,
                    }
                    for task_id in IDS
                ],
            }
        )
    )
    mask_map = tmp_path / "mask-map.json"
    mask_map.write_bytes(b"{}")
    payloads["cohort"]["asset_hashes_sha256"] = sha(manifest.read_bytes())
    payloads["cohort"]["mask_map_sha256"] = sha(mask_map.read_bytes())
    state = check_go_live(**inputs)
    paths = ControllerPaths(
        data_dir=tmp_path / "data",
        mask_map_path=mask_map,
        server="http://localhost",
        staging_root=tmp_path / "stage",
        evidence_root=tmp_path / "evidence",
        harness_dir=tmp_path / "harness",
        harness_manifest_path=tmp_path / "harness-manifest.json",
        harness_manifest_sha256=payloads["cohort"]["harness_manifest_sha256"],
        mask_map_sha256=payloads["cohort"]["mask_map_sha256"],
        generator_source=tmp_path / "generator.py",
        generator_sha256=payloads["cohort"]["generator_sha256"],
        official_registry=object(),
    )
    verified = state.verified_staging_paths(IDS[0], paths, manifest)
    assert verified.official_registry.task_ids == IDS
    assert verified.official_registry is not paths.official_registry
    with pytest.raises(RuntimeError, match="signed cohort"):
        state.verified_staging_paths(IDS[0], replace(paths, **{field: "1" * 64}), manifest)


def test_staging_paths_rejects_noncurrent_task(tmp_path):
    inputs, _, _ = fixture(tmp_path)
    state = check_go_live(**inputs)
    with pytest.raises(RuntimeError, match="current campaign task"):
        state.verified_staging_paths(IDS[1], object(), tmp_path / "missing.json")


@pytest.mark.parametrize("status", ["oracle_true", "oracle_false", "timeout", "failure"])
def test_signed_terminal_receipts_bind_oracle_or_failure_evidence(tmp_path, status):
    inputs, authority, payloads = fixture(tmp_path)
    state = check_go_live(**inputs)
    state.mark_prepared(IDS[0])
    state.mark_started(IDS[0], request_id="req-1")
    payloads["terminal_receipt"] = (
        oracle_receipt(IDS[0], status=status)
        if status.startswith("oracle_")
        else failure_receipt(IDS[0], status=status)
    )
    state.mark_terminal(IDS[0], b"signed:terminal_receipt")
    event = authority.events[-1]
    assert event["status"] == status
    assert event["receipt_sha256"] == sha(b"signed:terminal_receipt")
    assert base64.b64decode(event["receipt_envelope_b64"]) == b"signed:terminal_receipt"
    assert ("oracle_verdict_sha256" in event) is status.startswith("oracle_")
    assert ("evidence_sha256" in event) is not status.startswith("oracle_")
    assert next_action(state).task_id == IDS[1]


def test_replay_rejects_terminal_event_without_valid_signed_receipt(tmp_path):
    inputs, authority, payloads = fixture(tmp_path)
    state = check_go_live(**inputs)
    state.mark_prepared(IDS[0])
    state.mark_started(IDS[0], request_id="req-1")
    payloads["terminal_receipt"] = oracle_receipt(IDS[0])
    state.mark_terminal(IDS[0], b"signed:terminal_receipt")
    authority.events[-1]["receipt_envelope_b64"] = base64.b64encode(b"forged").decode()
    authority.events[-1]["receipt_sha256"] = sha(b"forged")
    with pytest.raises(RuntimeError, match="invalid or repeated transition"):
        next_action(state)


def test_terminal_receipt_size_is_bounded_before_attestation(tmp_path):
    inputs, authority, _ = fixture(tmp_path)
    state = check_go_live(**inputs)
    state.mark_prepared(IDS[0])
    state.mark_started(IDS[0], request_id="req-1")
    with pytest.raises(RuntimeError, match="signed terminal receipt size"):
        state.mark_terminal(IDS[0], b"x" * 65537)
    assert len(authority.events) == 3


@pytest.mark.parametrize("bad_field", ["oracle_true", "final_sha256", "oracle_verdict_sha256"])
def test_terminal_rejects_oracle_receipt_without_matching_verdict_and_final(tmp_path, bad_field):
    inputs, authority, payloads = fixture(tmp_path)
    state = check_go_live(**inputs)
    state.mark_prepared(IDS[0])
    state.mark_started(IDS[0], request_id="req-1")
    payloads["terminal_receipt"] = oracle_receipt(IDS[0], status="oracle_true")
    payloads["terminal_receipt"][bad_field] = False if bad_field == "oracle_true" else "bad"
    with pytest.raises(RuntimeError, match="terminal oracle receipt"):
        state.mark_terminal(IDS[0], b"signed:terminal_receipt")
    assert len(authority.events) == 3


def test_terminal_requires_signed_oracle_receipt_and_rejects_mismatched_task(tmp_path):
    inputs, authority, payloads = fixture(tmp_path)
    state = check_go_live(**inputs)
    state.mark_prepared(IDS[0])
    state.mark_started(IDS[0], request_id="req-1")
    with pytest.raises(RuntimeError, match="signed terminal receipt"):
        state.mark_terminal(IDS[0], "oracle_true")
    assert len(authority.events) == 3
    payloads["terminal_receipt"] = oracle_receipt(IDS[1], status="oracle_true")
    with pytest.raises(RuntimeError, match="terminal receipt identity"):
        state.mark_terminal(IDS[0], b"signed:terminal_receipt")
    assert len(authority.events) == 3


def test_missing_or_invalid_signature_rejects_before_campaign_created(tmp_path):
    inputs, authority, _ = fixture(tmp_path)
    inputs["decision"] = b""
    with pytest.raises(RuntimeError, match="signed decision"):
        check_go_live(**inputs)
    assert authority.events == []
    inputs, authority, _ = fixture(tmp_path)
    authority.invalid.add("certification")
    with pytest.raises(RuntimeError, match="signed certification"):
        check_go_live(**inputs)
    assert authority.events == []


def test_design_approval_is_not_official_launch_authorisation(tmp_path):
    inputs, authority, payloads = fixture(tmp_path)
    payloads["decision"]["official_launch_authorised"] = False
    with pytest.raises(RuntimeError, match="official launch"):
        check_go_live(**inputs)
    assert authority.events == []


@pytest.mark.parametrize("binding", ["certification_sha256", "harness_sha256", "cohort_sha256"])
def test_changed_signed_artifact_is_rejected(tmp_path, binding):
    inputs, authority, payloads = fixture(tmp_path)
    payloads["decision"][binding] = "f" * 64
    with pytest.raises(RuntimeError, match=binding.replace("_sha256", " hash")):
        check_go_live(**inputs)
    assert authority.events == []


def test_unaccepted_or_drifted_native_certification_is_rejected(tmp_path):
    inputs, authority, payloads = fixture(tmp_path)
    payloads["certification"]["status"] = "synthetic_pass"
    with pytest.raises(RuntimeError, match="live certification"):
        check_go_live(**inputs)
    assert authority.events == []
    inputs, authority, payloads = fixture(tmp_path)
    payloads["certification"]["epoch"] = "epoch-2"
    with pytest.raises(RuntimeError, match="epoch"):
        check_go_live(**inputs)
    assert authority.events == []


@pytest.mark.parametrize(
    "field",
    ["memory_mode", "controller_writes_after_true_oracle", "capability_coverage", "deepseek"],
)
def test_uncertified_memory_capability_or_model_route_is_rejected(tmp_path, field):
    inputs, authority, payloads = fixture(tmp_path)
    payloads["certification"][field] = None
    with pytest.raises(RuntimeError, match="certified policy"):
        check_go_live(**inputs)
    assert authority.events == []


def test_exact_tasks_json_order_and_all_1507_are_required(tmp_path):
    inputs, authority, payloads = fixture(tmp_path)
    payloads["cohort"]["task_ids"][0], payloads["cohort"]["task_ids"][1] = (
        payloads["cohort"]["task_ids"][1],
        payloads["cohort"]["task_ids"][0],
    )
    with pytest.raises(RuntimeError, match="tasks.json order"):
        check_go_live(**inputs)
    assert authority.events == []
    inputs, authority, payloads = fixture(tmp_path)
    payloads["cohort"]["task_ids"].pop()
    with pytest.raises(RuntimeError, match="1507"):
        check_go_live(**inputs)


def test_policy_must_equal_frozen_campaign_controls(tmp_path):
    inputs, authority, _ = fixture(tmp_path)
    inputs["campaign_policy"] = inputs["campaign_policy"] | {"max_parallel_tasks": 2}
    with pytest.raises(RuntimeError, match="campaign policy"):
        check_go_live(**inputs)
    assert authority.events == []
    inputs, authority, _ = fixture(tmp_path)
    inputs["campaign_policy"] = inputs["campaign_policy"] | {"max_parallel_tasks": True}
    with pytest.raises(RuntimeError, match="campaign policy"):
        check_go_live(**inputs)
    assert authority.events == []


def test_signed_payload_schema_must_be_integer_one(tmp_path):
    inputs, authority, payloads = fixture(tmp_path)
    payloads["decision"]["schema_version"] = True
    with pytest.raises(RuntimeError, match="signed decision verification failed"):
        check_go_live(**inputs)
    assert authority.events == []


@pytest.mark.parametrize(
    ("field", "wrong"),
    [
        ("context_tokens", 1000000),
        ("max_output_tokens", 200000),
        ("max_requests", 37),
        ("role_tokens", {"independent_recon": 12582913}),
        ("role_seconds", {"final_adversarial_critic": 1801}),
    ],
)
def test_signed_deepseek_limits_must_match_frozen_policy(tmp_path, field, wrong):
    inputs, authority, payloads = fixture(tmp_path)
    payloads["certification"]["deepseek"][field] = wrong
    with pytest.raises(RuntimeError, match="certified policy"):
        check_go_live(**inputs)
    assert authority.events == []


def test_signed_alternate_digest_cannot_only_match_harness(tmp_path):
    inputs, authority, payloads = fixture(tmp_path)
    payloads["harness_lock"]["alternate_policy_sha256"] = "a" * 64
    payloads["certification"]["alternate_policy_sha256"] = "a" * 64
    with pytest.raises(RuntimeError, match="certified policy"):
        check_go_live(**inputs)
    assert authority.events == []


def test_campaign_created_once_and_a_second_run_is_rejected(tmp_path):
    inputs, authority, payloads = fixture(tmp_path)
    state = check_go_live(**inputs)
    assert state.task_ids == IDS
    assert [event["type"] for event in authority.events] == ["campaign_created"]
    payloads["decision"]["run_id"] = "run-2"
    with pytest.raises(RuntimeError, match="already exists"):
        check_go_live(**(inputs | {"run_id": "run-2"}))


def test_restart_observes_started_task_without_relaunch(tmp_path):
    inputs, authority, _ = fixture(tmp_path)
    state = check_go_live(**inputs)
    assert next_action(state).kind == "prepare"
    state.mark_prepared(IDS[0])
    state.mark_started(IDS[0], request_id="req-1")
    assert next_action(state).kind == "observe_started"
    restarted = CampaignState(
        run_id=state.run_id,
        epoch=state.epoch,
        evidence_root=state.evidence_root,
        task_ids=state.task_ids,
        policy_sha256=state.policy_sha256,
        cohort_sha256=state.cohort_sha256,
        asset_hashes_sha256=state.asset_hashes_sha256,
        benchmark_commit=state.benchmark_commit,
        dataset_commit=state.dataset_commit,
        mask_map_sha256=state.mask_map_sha256,
        cohort_envelope=state.cohort_envelope,
        authority=authority,
    )
    assert next_action(restarted).kind == "observe_started"
    assert next_action(restarted).task_id == IDS[0]
    assert len(authority.append_calls) == 2


def test_terminal_advances_once_and_never_retries_first_task(tmp_path):
    inputs, authority, payloads = fixture(tmp_path)
    state = check_go_live(**inputs)
    state.mark_prepared(IDS[0])
    state.mark_started(IDS[0], request_id="req-1")
    payloads["terminal_receipt"] = oracle_receipt(IDS[0])
    state.mark_terminal(IDS[0], b"signed:terminal_receipt")
    assert authority.events[-1]["final_sha256"] == "a" * 64
    assert authority.events[-1]["oracle_verdict_sha256"] == "e" * 64
    action = next_action(state)
    assert (action.kind, action.task_id) == ("prepare", IDS[1])
    with pytest.raises(RuntimeError, match="already terminal"):
        state.mark_started(IDS[0], request_id="req-2")
    assert len([event for event in authority.events if event["type"] == "started"]) == 1


def test_ambiguous_append_has_no_retry_and_restart_reads_committed_event(tmp_path):
    inputs, authority, _ = fixture(tmp_path)
    state = check_go_live(**inputs)
    original = authority.append_event

    def commit_then_lose_ack(*args, **kwargs):
        original(*args, **kwargs)
        raise TimeoutError("ack lost")

    authority.append_event = commit_then_lose_ack
    with pytest.raises(RuntimeError, match="append acknowledgement"):
        state.mark_prepared(IDS[0])
    assert len(authority.append_calls) == 1
    authority.append_event = original
    assert next_action(state).kind == "observe_prepared"
    assert len(authority.events) == 2


def test_replayed_ledger_must_keep_signed_epoch_and_valid_transitions(tmp_path):
    inputs, authority, _ = fixture(tmp_path)
    state = check_go_live(**inputs)
    authority.events[0]["epoch"] = "different-epoch"
    with pytest.raises(RuntimeError, match="creation event"):
        next_action(state)
    authority.events[0]["epoch"] = state.epoch
    authority.events.append({"type": "started", "task_id": IDS[0], "request_id": "req-1"})
    with pytest.raises(RuntimeError, match="transition"):
        next_action(state)


def test_reconstructed_state_reverifies_signed_cohort_before_scheduling(tmp_path):
    inputs, authority, _ = fixture(tmp_path)
    state = check_go_live(**inputs)
    altered = replace(state, task_ids=tuple(reversed(state.task_ids)))
    with pytest.raises(RuntimeError, match="signed cohort"):
        next_action(altered)
    authority.invalid.add("cohort")
    with pytest.raises(RuntimeError, match="signed cohort"):
        next_action(state)


def test_complete_ledger_preserves_all_1507_task_positions(tmp_path):
    inputs, authority, _ = fixture(tmp_path)
    state = check_go_live(**inputs)
    for task_id in IDS:
        receipt = f"signed:terminal_receipt:{task_id}".encode()
        authority.signed_receipts[receipt] = failure_receipt(task_id)
        authority.events.extend(
            (
                {"type": "prepared", "task_id": task_id},
                {"type": "started", "task_id": task_id, "request_id": f"req:{task_id}"},
                {
                    "type": "terminal",
                    "task_id": task_id,
                    "status": "timeout",
                    "receipt_sha256": sha(receipt),
                    "receipt_envelope_b64": base64.b64encode(receipt).decode(),
                    "evidence_sha256": "f" * 64,
                },
            )
        )
    assert next_action(state).kind == "complete"
    assert next_action(state).task_id is None
    authority.events[-3]["task_id"] = IDS[-2]
    with pytest.raises(RuntimeError, match="order or retry"):
        next_action(state)
