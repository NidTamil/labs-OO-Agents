"""Offline admission/recovery tests; all signatures and budgets here are synthetic."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from dataclasses import replace

import pytest
from nooa_cybergym.leaderboard.budgeted_subset_admission import (
    bind_budgeted_subset_state,
    preview_budgeted_subset_admission,
)
from nooa_cybergym.leaderboard.campaign import CampaignAction, _json_bytes
from nooa_cybergym.leaderboard.subset_dry_run_admission import (
    OFFICIAL_SUBSET_REGISTRY_SHA256,
    OFFICIAL_SUBSET_TASK_IDS,
    PREVIOUSLY_EXPOSED_TASK_IDS,
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Authority:
    def __init__(self):
        self.artifacts = {}
        self.events = []
        self.acknowledge = True

    def put(self, kind, payload):
        envelope = _json_bytes({"test_kind": kind, "payload": payload})
        self.artifacts[(kind, envelope)] = copy.deepcopy(payload)
        return envelope

    def attest_signed(self, kind, envelope):
        return copy.deepcopy(self.artifacts.get((kind, envelope)))

    def attest_takeover_certification(self, envelope):
        return copy.deepcopy(self.artifacts.get(("certification", envelope)))

    def read_verified_events(self, _root, _run_id):
        return copy.deepcopy(self.events)

    def append_event(self, _root, _run_id, event, expected_revision):
        if expected_revision != len(self.events):
            return False
        self.events.append(copy.deepcopy(event))
        return self.acknowledge


class Readiness:
    def __init__(self):
        self.accepted = True
        self.calls = []

    def verify_subset_readiness(self, **kwargs):
        self.calls.append(kwargs)
        return self.accepted


class Resources:
    def __init__(self, budget_sha):
        self.data = {
            "run_id": "test-run",
            "epoch": "test-epoch",
            "budget_sha256": budget_sha,
            "closures": {},
            "accounting_sha256": "f" * 64,
            "stop": None,
            "tasks": {task: {"requests": 0} for task in OFFICIAL_SUBSET_TASK_IDS},
        }

    def snapshot(self):
        return copy.deepcopy(self.data)


def setup(tmp_path, authority=None):
    authority = Authority() if authority is None else authority
    budget = {
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
        "max_elapsed_seconds": 432000,
        "max_spend_units": 500000000,
        "spend_unit": "usd_micros",
        "accounting_scope": "all_model_calls_including_memory_and_failed_reservations",
        "elapsed_scope": "first_preparation_through_final_cleanup",
        "exhaustion_action": "stop_run_preserve_task_terminals",
    }
    budget_bytes = authority.put("subset_run_budget", budget)
    common = {
        "schema_version": 1,
        "epoch": "test-epoch",
        "source_commit": "d" * 40,
        "campaign_policy_sha256": "a" * 64,
        "model_policy_sha256": "b" * 64,
        "cohort_sha256": "e" * 64,
    }
    freeze = authority.put("harness_lock", dict(common))
    from nooa_cybergym.leaderboard.primary_takeover import PrimaryTakeoverPolicy

    takeover = PrimaryTakeoverPolicy()
    certification = authority.put(
        "certification",
        {
            **{
                key: value
                for key, value in common.items()
                if key not in {"source_commit", "model_policy_sha256"}
            },
            "schema_version": 2,
            "policy_sha256": "b" * 64,
            "harness_sha256": sha(freeze),
            "status": "accepted",
            "scope": "live_native",
            "takeover_policy_sha256": takeover.digest,
            "memory_model_bindings_sha256": "6" * 64,
            "primary_takeover": json.loads(takeover.manifest_json),
        },
    )
    admission = {
        "schema_version": 1,
        "artifact_kind": "budgeted_subset_admission",
        "scope": "native_subset_dry_run_level1",
        "run_id": "test-run",
        "epoch": "test-epoch",
        "source_commit": "d" * 40,
        "task_ids": list(OFFICIAL_SUBSET_TASK_IDS),
        "previously_exposed_task_ids": list(PREVIOUSLY_EXPOSED_TASK_IDS),
        "max_parallel_tasks": 1,
        "official_registry_sha256": OFFICIAL_SUBSET_REGISTRY_SHA256,
        "cohort_sha256": "e" * 64,
        "freeze_sha256": sha(freeze),
        "certification_sha256": sha(certification),
        "budget_sha256": sha(budget_bytes),
        "campaign_policy_sha256": "a" * 64,
        "model_policy_sha256": "b" * 64,
        "metering_policy_sha256": "c" * 64,
        "recovery_policy": "terminal_and_sealed_driver_quiescence",
    }
    admission_bytes = authority.put("budgeted_subset_admission", admission)
    args = {
        "signed_admission": admission_bytes,
        "signed_budget": budget_bytes,
        "authority": authority,
        "run_id": "test-run",
        "epoch": "test-epoch",
        "evidence_root": tmp_path,
        "expected_admission_sha256": sha(admission_bytes),
        "expected_budget_sha256": sha(budget_bytes),
        "expected_cohort_sha256": "e" * 64,
        "expected_freeze_sha256": sha(freeze),
        "expected_certification_sha256": sha(certification),
        "campaign_policy_sha256": "a" * 64,
        "model_policy_sha256": "b" * 64,
        "metering_policy_sha256": "c" * 64,
        "source_commit": "d" * 40,
    }
    readiness = Readiness()
    resources = Resources(sha(budget_bytes))
    bindings = {
        "authority": authority,
        "signed_freeze": freeze,
        "signed_certification": certification,
        "readiness_verifier": readiness,
        "resource_budget": resources,
    }
    return authority, args, bindings


def state_setup(tmp_path):
    authority, args, bindings = setup(tmp_path)
    preview = preview_budgeted_subset_admission(**args)
    state = bind_budgeted_subset_state(preview, **bindings)
    assert authority.events == []
    authority.events.append(state.creation_event())
    return authority, state, bindings


def start(state, number=0):
    task = OFFICIAL_SUBSET_TASK_IDS[number]
    state.mark_preparation_started(task, preparation_id=f"preparation-{number}")
    state.mark_prepared(task)
    state.mark_started(
        task, request_id=f"request-{number}", attempt_id=f"attempt-{number}", launch_sha256="1" * 64
    )
    return task


def terminal(authority, state, task):
    raw = authority.put(
        "terminal_receipt",
        {
            "schema_version": 1,
            "artifact_kind": "terminal_receipt",
            "run_id": state.run_id,
            "epoch": state.epoch,
            "task_id": task,
            "status": "timeout",
            "evidence_sha256": "2" * 64,
        },
    )
    state.mark_terminal(task, raw)
    return raw


def quiescence(authority, state, resources, task, terminal_bytes, number=0):
    payload = {
        "schema_version": 1,
        "artifact_kind": "subset_driver_quiescence",
        "run_id": state.run_id,
        "epoch": state.epoch,
        "task_id": task,
        "attempt_id": f"attempt-{number}",
        "request_id": f"request-{number}",
        "launch_sha256": "1" * 64,
        "terminal_receipt_sha256": sha(terminal_bytes),
        "budget_sha256": state.preview.budget.envelope_sha256,
        "final_accounting_sha256": "f" * 64,
        "owned_cleanup_sha256": "3" * 64,
        "owned_cleanup_complete": True,
        "driver_stopped": True,
        "accounting_closed": True,
    }
    raw = authority.put("subset_driver_quiescence", payload)
    resources.data["closures"][task] = {
        "attempt_id": f"attempt-{number}",
        "completion_sha256": sha(raw),
        "accounting_sha256": "f" * 64,
    }
    return raw, payload


def test_actual_budget_and_fresh_readiness_required_without_creating_ledger(tmp_path):
    authority, args, bindings = setup(tmp_path)
    preview = preview_budgeted_subset_admission(**args)
    assert preview.budget.max_elapsed_seconds == 432000
    assert preview.task_ids == OFFICIAL_SUBSET_TASK_IDS
    assert preview.previously_exposed_task_ids == PREVIOUSLY_EXPOSED_TASK_IDS
    bind_budgeted_subset_state(preview, **bindings)
    assert bindings["readiness_verifier"].calls
    assert authority.events == []
    with pytest.raises(RuntimeError):
        preview_budgeted_subset_admission(**{**args, "signed_budget": b""})
    with pytest.raises(RuntimeError):
        bind_budgeted_subset_state(preview, **{**bindings, "readiness_verifier": None})


@pytest.mark.parametrize(
    "field,value",
    [
        ("source_commit", "9" * 40),
        ("epoch", "old-epoch"),
        ("max_parallel_tasks", True),
        ("previously_exposed_task_ids", []),
        ("task_ids", list(reversed(OFFICIAL_SUBSET_TASK_IDS))),
        ("recovery_policy", "terminal_only"),
        ("model_policy_sha256", "9" * 64),
    ],
)
def test_admission_substitution_fails(tmp_path, field, value):
    authority, args, _ = setup(tmp_path)
    key = ("budgeted_subset_admission", args["signed_admission"])
    authority.artifacts[key][field] = value
    with pytest.raises(RuntimeError):
        preview_budgeted_subset_admission(**args)


@pytest.mark.parametrize(
    "field,value",
    [
        ("max_elapsed_seconds", 432001),
        ("max_elapsed_seconds", 431999),
        ("max_spend_units", 0),
        ("max_spend_units", 500000001),
        ("max_spend_units", 499999999),
        ("metering_policy_sha256", "9" * 64),
    ],
)
def test_unapproved_budget_scope_cannot_bind(tmp_path, field, value):
    authority, args, _ = setup(tmp_path)
    authority.artifacts[("subset_run_budget", args["signed_budget"])][field] = value
    with pytest.raises(RuntimeError):
        preview_budgeted_subset_admission(**args)


@pytest.mark.parametrize(
    "kind,field,value",
    [
        ("harness_lock", "source_commit", "9" * 40),
        ("harness_lock", "epoch", "old"),
        ("certification", "policy_sha256", "9" * 64),
        ("certification", "status", "component_only"),
        ("certification", "scope", "unverified"),
        ("certification", "harness_sha256", "9" * 64),
    ],
)
def test_fresh_signed_readiness_bound_to_exact_source_policies(tmp_path, kind, field, value):
    authority, args, bindings = setup(tmp_path)
    preview = preview_budgeted_subset_admission(**args)
    raw = bindings["signed_freeze" if kind == "harness_lock" else "signed_certification"]
    authority.artifacts[(kind, raw)][field] = value
    with pytest.raises(RuntimeError):
        bind_budgeted_subset_state(preview, **bindings)


def test_complete_report_verifier_cannot_be_replaced_by_accepted_summary(tmp_path):
    _, args, bindings = setup(tmp_path)
    preview = preview_budgeted_subset_admission(**args)
    bindings["readiness_verifier"].accepted = False
    with pytest.raises(RuntimeError):
        bind_budgeted_subset_state(preview, **bindings)


def test_terminal_recovery_waits_for_sealed_quiescence_then_advances_once(tmp_path):
    authority, state, bindings = state_setup(tmp_path)
    task = start(state)
    receipt = terminal(authority, state, task)
    assert state.next_action() == CampaignAction("observe_terminal", task)
    recovered = bind_budgeted_subset_state(state.preview, **bindings)
    assert recovered.next_action() == CampaignAction("observe_terminal", task)
    with pytest.raises(RuntimeError):
        recovered.mark_started(
            task, request_id="second-Send", attempt_id="attempt-0", launch_sha256="1" * 64
        )
    completion, _ = quiescence(authority, state, bindings["resource_budget"], task, receipt)
    recovered.mark_quiescent(task, completion)
    assert recovered.next_action() == CampaignAction("prepare", OFFICIAL_SUBSET_TASK_IDS[1])
    with pytest.raises(RuntimeError):
        recovered.mark_quiescent(task, completion)


@pytest.mark.parametrize(
    "field,value",
    [
        ("attempt_id", "other"),
        ("request_id", "other"),
        ("task_id", OFFICIAL_SUBSET_TASK_IDS[1]),
        ("run_id", "other"),
        ("epoch", "other"),
        ("launch_sha256", "9" * 64),
        ("terminal_receipt_sha256", "9" * 64),
        ("budget_sha256", "9" * 64),
        ("owned_cleanup_complete", False),
        ("driver_stopped", False),
        ("accounting_closed", False),
        ("owned_cleanup_complete", 1),
        ("final_accounting_sha256", "bad"),
    ],
)
def test_substituted_or_incomplete_completion_cannot_advance(tmp_path, field, value):
    authority, state, bindings = state_setup(tmp_path)
    task = start(state)
    receipt = terminal(authority, state, task)
    _, payload = quiescence(authority, state, bindings["resource_budget"], task, receipt)
    payload[field] = value
    raw = authority.put("subset_driver_quiescence", payload)
    bindings["resource_budget"].data["closures"][task]["completion_sha256"] = sha(raw)
    with pytest.raises(RuntimeError):
        state.mark_quiescent(task, raw)
    assert state.next_action() == CampaignAction("observe_terminal", task)


@pytest.mark.parametrize("mutation", ["missing", "attempt", "accounting", "envelope"])
def test_unsealed_or_raced_accounting_blocks_even_valid_signature(tmp_path, mutation):
    authority, state, bindings = state_setup(tmp_path)
    task = start(state)
    receipt = terminal(authority, state, task)
    raw, _ = quiescence(authority, state, bindings["resource_budget"], task, receipt)
    closures = bindings["resource_budget"].data["closures"]
    if mutation == "missing":
        closures.clear()
    else:
        key = {
            "attempt": "attempt_id",
            "accounting": "accounting_sha256",
            "envelope": "completion_sha256",
        }[mutation]
        closures[task][key] = "9" * 64
    with pytest.raises(RuntimeError):
        state.mark_quiescent(task, raw)


def test_run_stop_preserves_started_task_terminal_and_unattempted_remaining(tmp_path):
    authority, state, bindings = state_setup(tmp_path)
    task = start(state)
    bindings["resource_budget"].data["stop"] = {"reason": "spend_limit", "observed_ns": 123}
    state.request_stop()
    assert state.next_action() == CampaignAction("observe_started", task)
    with pytest.raises(RuntimeError):
        state.finalize_stop()
    receipt = terminal(authority, state, task)
    assert state.next_action() == CampaignAction("observe_terminal", task)
    raw, _ = quiescence(authority, state, bindings["resource_budget"], task, receipt)
    state.mark_quiescent(task, raw)
    assert state.next_action() == CampaignAction("finalize_stop", None)
    state.finalize_stop()
    assert state.next_action() == CampaignAction("stopped", None)
    assert [event["status"] for event in authority.events if event["type"] == "terminal"] == [
        "timeout"
    ]
    assert not any(
        event.get("task_id") == OFFICIAL_SUBSET_TASK_IDS[1] for event in authority.events
    )
    with pytest.raises(RuntimeError):
        state.mark_prepared(OFFICIAL_SUBSET_TASK_IDS[1])


def test_durable_resource_stop_blocks_preparation_before_ledger_stop_is_written(tmp_path):
    _, state, bindings = state_setup(tmp_path)
    bindings["resource_budget"].data["stop"] = {"reason": "elapsed_limit", "observed_ns": 123}
    assert state.next_action() == CampaignAction("request_stop", None)
    with pytest.raises(RuntimeError):
        state.mark_prepared(OFFICIAL_SUBSET_TASK_IDS[0])
    state.request_stop()
    state.finalize_stop()
    assert state.next_action() == CampaignAction("stopped", None)


def test_stop_after_preparation_requires_owned_cleanup_without_fake_terminal(tmp_path):
    authority, state, bindings = state_setup(tmp_path)
    task = OFFICIAL_SUBSET_TASK_IDS[0]
    state.mark_preparation_started(task, preparation_id="preparation-0")
    state.mark_prepared(task)
    bindings["resource_budget"].data["stop"] = {"reason": "request_limit", "observed_ns": 123}
    state.request_stop()
    assert state.next_action() == CampaignAction("cleanup_prepared", task)
    with pytest.raises(RuntimeError):
        state.finalize_stop()
    raw = authority.put(
        "subset_preparation_quiescence",
        {
            "schema_version": 1,
            "artifact_kind": "subset_preparation_quiescence",
            "run_id": state.run_id,
            "epoch": state.epoch,
            "task_id": task,
            "budget_sha256": state.preview.budget.envelope_sha256,
            "preparation_id": "preparation-0",
            "preparation_started_event_sha256": sha(
                _json_bytes(
                    {
                        "type": "preparation_started",
                        "task_id": task,
                        "preparation_id": "preparation-0",
                    }
                )
            ),
            "prepared_event_sha256": sha(_json_bytes({"type": "prepared", "task_id": task})),
            "owned_cleanup_sha256": "3" * 64,
            "owned_cleanup_complete": True,
            "native_send_occurred": False,
        },
    )
    state.mark_preparation_quiescent(task, raw)
    state.finalize_stop()
    assert state.next_action() == CampaignAction("stopped", None)
    assert not any(event["type"] in {"started", "terminal"} for event in authority.events)


def test_ambiguous_append_requires_replay_without_second_send_or_second_completion(tmp_path):
    authority, state, bindings = state_setup(tmp_path)
    task = OFFICIAL_SUBSET_TASK_IDS[0]
    state.mark_preparation_started(task, preparation_id="preparation-0")
    state.mark_prepared(task)
    authority.acknowledge = False
    with pytest.raises(RuntimeError, match="acknowledgement"):
        state.mark_started(
            task, request_id="request-0", attempt_id="attempt-0", launch_sha256="1" * 64
        )
    authority.acknowledge = True
    assert state.next_action() == CampaignAction("observe_started", task)
    with pytest.raises(RuntimeError):
        state.mark_started(
            task, request_id="second", attempt_id="attempt-0", launch_sha256="1" * 64
        )
    receipt = terminal(authority, state, task)
    raw, _ = quiescence(authority, state, bindings["resource_budget"], task, receipt)
    authority.acknowledge = False
    with pytest.raises(RuntimeError, match="acknowledgement"):
        state.mark_quiescent(task, raw)
    authority.acknowledge = True
    assert state.next_action() == CampaignAction("prepare", OFFICIAL_SUBSET_TASK_IDS[1])


def test_replay_reverifies_signatures_and_closed_accounting(tmp_path):
    authority, state, bindings = state_setup(tmp_path)
    task = start(state)
    receipt = terminal(authority, state, task)
    raw, _ = quiescence(authority, state, bindings["resource_budget"], task, receipt)
    state.mark_quiescent(task, raw)
    authority.artifacts.pop(("subset_driver_quiescence", raw))
    with pytest.raises(RuntimeError):
        state.next_action()


def test_spliced_terminal_only_or_cross_run_events_cannot_complete_task(tmp_path):
    authority, state, _ = state_setup(tmp_path)
    task = start(state)
    terminal(authority, state, task)
    authority.events.append({"type": "prepared", "task_id": OFFICIAL_SUBSET_TASK_IDS[1]})
    with pytest.raises(RuntimeError):
        state.next_action()


def test_mutated_preview_cannot_change_verified_budget_or_scope(tmp_path):
    _, args, bindings = setup(tmp_path)
    preview = preview_budgeted_subset_admission(**args)
    with pytest.raises(RuntimeError):
        bind_budgeted_subset_state(replace(preview, source_commit="9" * 40), **bindings)


def test_unsigned_quiescence_envelope_fails_before_store_check(tmp_path):
    authority, state, _ = state_setup(tmp_path)
    task = start(state)
    terminal(authority, state, task)
    with pytest.raises(RuntimeError):
        state.mark_quiescent(task, base64.b64encode(b"not signed"))


def test_all_ten_require_completion_and_old_closure_survives_later_accounting(tmp_path):
    authority, state, bindings = state_setup(tmp_path)
    resources = bindings["resource_budget"]
    for number, task in enumerate(OFFICIAL_SUBSET_TASK_IDS):
        assert state.next_action() == CampaignAction("prepare", task)
        start(state, number)
        receipt = terminal(authority, state, task)
        assert state.next_action() == CampaignAction("observe_terminal", task)
        raw, _ = quiescence(authority, state, resources, task, receipt, number)
        state.mark_quiescent(task, raw)
        # Later reservations change the global accounting digest. Previous
        # sealed closure snapshots must still be independently rechecked.
        resources.data["accounting_sha256"] = str(number) * 64
    assert state.next_action() == CampaignAction("complete", None)
    resources.data["closures"][OFFICIAL_SUBSET_TASK_IDS[0]]["accounting_sha256"] = "9" * 64
    with pytest.raises(RuntimeError):
        state.next_action()


def test_stop_evidence_is_immutable_and_cannot_be_added_without_store_stop(tmp_path):
    authority, state, bindings = state_setup(tmp_path)
    with pytest.raises(RuntimeError):
        state.request_stop()
    resources = bindings["resource_budget"]
    resources.data["stop"] = {"reason": "spend_limit", "observed_ns": 123}
    state.request_stop()
    resources.data["stop"]["reason"] = "elapsed_limit"
    with pytest.raises(RuntimeError):
        state.next_action()
    assert authority.events[-1]["type"] == "run_stop_requested"


def test_replay_rejects_any_new_event_after_finalized_stop(tmp_path):
    authority, state, bindings = state_setup(tmp_path)
    bindings["resource_budget"].data["stop"] = {"reason": "spend_limit", "observed_ns": 123}
    state.request_stop()
    state.finalize_stop()
    authority.events.append({"type": "prepared", "task_id": OFFICIAL_SUBSET_TASK_IDS[0]})
    with pytest.raises(RuntimeError):
        state.next_action()


def test_resource_store_from_different_run_cannot_be_bound(tmp_path):
    _, args, bindings = setup(tmp_path)
    preview = preview_budgeted_subset_admission(**args)
    bindings["resource_budget"].data["run_id"] = "different-run"
    with pytest.raises(RuntimeError):
        bind_budgeted_subset_state(preview, **bindings)


def test_unattempted_tasks_with_reservations_cannot_be_reported_as_stopped_unattempted(tmp_path):
    _, state, bindings = state_setup(tmp_path)
    resources = bindings["resource_budget"]
    resources.data["tasks"][OFFICIAL_SUBSET_TASK_IDS[4]]["requests"] = 1
    resources.data["stop"] = {"reason": "spend_limit", "observed_ns": 123}
    with pytest.raises(RuntimeError, match="unattempted"):
        state.request_stop()


class RealSignatureAuthority(Authority):
    """Use actual Xeus Ed25519 verification, with an in-memory ledger only."""

    def __init__(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from nooa_cybergym.leaderboard.xeus_authority import XeusCampaignAuthority
        from xeus_cybergym.ledger import Ed25519Signer

        super().__init__()
        key = Ed25519PrivateKey.generate()
        self.signer = Ed25519Signer(private_key=key, key_id="synthetic-readiness")
        self.verifier = XeusCampaignAuthority({"synthetic-readiness": key.public_key()})

    def put(self, kind, payload):
        raw = _json_bytes(self.signer.sign(_json_bytes(payload)).model_dump())
        self.artifacts[(kind, raw)] = copy.deepcopy(payload)
        return raw

    def attest_signed(self, kind, envelope):
        return self.verifier.attest_signed(kind, envelope)

    def attest_takeover_certification(self, envelope):
        return self.verifier.attest_takeover_certification(envelope)


def test_real_ed25519_actual_budget_admission_schema2_report_and_quiescence(tmp_path):
    authority, args, bindings = setup(tmp_path, RealSignatureAuthority())
    preview = preview_budgeted_subset_admission(**args)
    state = bind_budgeted_subset_state(preview, **bindings)
    assert authority.attest_signed("certification", bindings["signed_certification"]) is None
    authority.events.append(state.creation_event())
    task = start(state)
    receipt = terminal(authority, state, task)
    raw, _ = quiescence(authority, state, bindings["resource_budget"], task, receipt)
    state.mark_quiescent(task, raw)
    assert state.next_action() == CampaignAction("prepare", OFFICIAL_SUBSET_TASK_IDS[1])


def test_real_ed25519_untrusted_registry_rejects_admission(tmp_path):
    _, args, _ = setup(tmp_path, RealSignatureAuthority())
    args["authority"] = RealSignatureAuthority()
    with pytest.raises(RuntimeError, match="verification"):
        preview_budgeted_subset_admission(**args)


def test_real_ed25519_noncanonical_admission_payload_rejected_even_with_matching_pin(tmp_path):
    authority, args, _ = setup(tmp_path, RealSignatureAuthority())
    payload = authority.artifacts[("budgeted_subset_admission", args["signed_admission"])]
    raw = _json_bytes(authority.signer.sign(json.dumps(payload, indent=2).encode()).model_dump())
    args["signed_admission"] = raw
    args["expected_admission_sha256"] = sha(raw)
    with pytest.raises(RuntimeError, match="verification"):
        preview_budgeted_subset_admission(**args)


@pytest.mark.parametrize("mutation", ["wrong_key", "noncanonical"])
def test_real_completion_signature_checked_before_accepting_matching_store_closure(
    tmp_path, mutation
):
    authority, args, bindings = setup(tmp_path, RealSignatureAuthority())
    state = bind_budgeted_subset_state(preview_budgeted_subset_admission(**args), **bindings)
    authority.events.append(state.creation_event())
    task = start(state)
    receipt = terminal(authority, state, task)
    _, payload = quiescence(authority, state, bindings["resource_budget"], task, receipt)
    if mutation == "wrong_key":
        raw = RealSignatureAuthority().put("subset_driver_quiescence", payload)
    else:
        raw = _json_bytes(
            authority.signer.sign(json.dumps(payload, indent=2).encode()).model_dump()
        )
    bindings["resource_budget"].data["closures"][task]["completion_sha256"] = sha(raw)
    with pytest.raises(RuntimeError, match="verification"):
        state.mark_quiescent(task, raw)
    assert state.next_action() == CampaignAction("observe_terminal", task)


def large_report_bundle(tmp_path):
    """Build an accepted, signed schema-two report with eight calls per fixture."""
    from nooa_cybergym.leaderboard.certification_report import compare_runs, sign_report

    from examples.cybergym.tests.leaderboard.certification.test_report import _accounting_pair

    authority, args, bindings = setup(tmp_path, RealSignatureAuthority())
    first, second, expected = _accounting_pair()
    args["epoch"] = first["epoch"]
    args["model_policy_sha256"] = expected.binding.policy_sha256
    args["expected_cohort_sha256"] = expected.cohort_sha256
    budget = copy.deepcopy(authority.artifacts[("subset_run_budget", args["signed_budget"])])
    budget.update(epoch=args["epoch"], model_policy_sha256=args["model_policy_sha256"])
    args["signed_budget"] = authority.put("subset_run_budget", budget)
    args["expected_budget_sha256"] = sha(args["signed_budget"])
    freeze = copy.deepcopy(authority.artifacts[("harness_lock", bindings["signed_freeze"])])
    freeze.update(
        epoch=args["epoch"],
        model_policy_sha256=args["model_policy_sha256"],
        cohort_sha256=args["expected_cohort_sha256"],
    )
    bindings["signed_freeze"] = authority.put("harness_lock", freeze)
    args["expected_freeze_sha256"] = sha(bindings["signed_freeze"])
    expected = replace(
        expected,
        frozen_hashes={**expected.frozen_hashes, "harness_sha256": args["expected_freeze_sha256"]},
    )
    for run in (first, second):
        run["hashes"] = expected.all_hashes
        for entry in run["request_accounting"].values():
            manifest = entry["manifest"]
            rows = manifest["requests"]
            extra = copy.deepcopy(rows[0])
            for key in (
                "reservation_request_id",
                "request_id",
                "provider_attempt_id",
                "provider_request_id",
            ):
                extra[key] += "-additional"
            rows.insert(1, extra)
            allocations = {"primary_and_memory": 0, "deepseek_advisory": 0}
            for number, row in enumerate(rows, 1):
                allocations[row["allocation"]] += 1
                row.update(
                    task_ordinal=number,
                    run_ordinal=number,
                    allocation_ordinal=allocations[row["allocation"]],
                )
            manifest["allocations"] = allocations
            for key in manifest["totals"]:
                if key in {"model_requests", "observed_requests"}:
                    manifest["totals"][key] = len(rows)
                elif key in {
                    "input_tokens",
                    "output_tokens",
                    "cache_tokens",
                    "counted_tokens",
                    "conservative_tokens",
                }:
                    manifest["totals"][key] = sum(row[key] for row in rows)
            entry["sha256"] = sha(_json_bytes(manifest))
        for key in run["totals"]:
            if key != "tool_calls":
                run["totals"][key] = sum(
                    entry["manifest"]["totals"][key] for entry in run["request_accounting"].values()
                )
    independent = {
        run["run_id"]: copy.deepcopy(run["request_accounting"]) for run in (first, second)
    }
    old_attest = expected.attest_raw_run
    expected = replace(
        expected,
        attest_raw_run=lambda run: {
            **old_attest(run),
            "request_accounting": independent[run["run_id"]],
        },
    )
    report = compare_runs(first, second, expected=expected)
    assert report.passed, report.failures
    signed = sign_report(report, signer=authority.signer, verifier=authority.verifier._verifier)
    assert len(signed.envelope_json) > 65536
    bindings["signed_certification"] = signed.envelope_json
    args["expected_certification_sha256"] = sha(signed.envelope_json)
    admission = copy.deepcopy(
        authority.artifacts[("budgeted_subset_admission", args["signed_admission"])]
    )
    admission.update(
        epoch=args["epoch"],
        model_policy_sha256=args["model_policy_sha256"],
        cohort_sha256=args["expected_cohort_sha256"],
        freeze_sha256=args["expected_freeze_sha256"],
        certification_sha256=args["expected_certification_sha256"],
        budget_sha256=args["expected_budget_sha256"],
    )
    args["signed_admission"] = authority.put("budgeted_subset_admission", admission)
    args["expected_admission_sha256"] = sha(args["signed_admission"])
    resources = Resources(args["expected_budget_sha256"])
    resources.data["epoch"] = args["epoch"]
    bindings["resource_budget"] = resources

    class FullReportReadiness:
        def verify_subset_readiness(self, **facts):
            recomputed = compare_runs(first, second, expected=expected)
            return (
                recomputed.passed
                and recomputed.payload_sha256 == report.payload_sha256
                and facts["signed_certification"] == signed.envelope_json
                and facts["signed_freeze"] == bindings["signed_freeze"]
            )

    bindings["readiness_verifier"] = FullReportReadiness()
    return authority, args, bindings


def test_full_accepted_signed_schema2_report_above_64k_binds(tmp_path):
    authority, args, bindings = large_report_bundle(tmp_path)
    assert (
        authority.attest_takeover_certification(bindings["signed_certification"])["status"]
        == "accepted"
    )
    preview = preview_budgeted_subset_admission(**args)
    state = bind_budgeted_subset_state(preview, **bindings)
    assert state.creation_event()["certification_sha256"] == args["expected_certification_sha256"]


def test_certificate_size_limit_is_checked_before_signature_parsing(tmp_path, monkeypatch):
    from nooa_cybergym.leaderboard import budgeted_subset_admission as module

    authority, args, bindings = large_report_bundle(tmp_path)
    preview = preview_budgeted_subset_admission(**args)
    calls = []
    monkeypatch.setattr(authority, "attest_takeover_certification", lambda raw: calls.append(raw))
    # Exercise the exact rejection boundary with a smaller injected ceiling,
    # without allocating a production-sized hostile certificate in a unit test.
    monkeypatch.setattr(
        module, "_MAX_SIGNED_CERTIFICATION", len(bindings["signed_certification"]) - 1
    )
    with pytest.raises(RuntimeError, match="readiness bytes"):
        bind_budgeted_subset_state(preview, **bindings)
    assert calls == []


def test_certificate_size_allowance_does_not_expand_control_envelopes(tmp_path):
    _, args, bindings = setup(tmp_path)
    with pytest.raises(RuntimeError):
        preview_budgeted_subset_admission(**{**args, "signed_admission": b"x" * 65537})
    preview = preview_budgeted_subset_admission(**args)
    with pytest.raises(RuntimeError, match="readiness bytes"):
        bind_budgeted_subset_state(preview, **{**bindings, "signed_freeze": b"x" * 65537})
    authority, state, _ = state_setup(tmp_path)
    task = start(state)
    terminal(authority, state, task)
    with pytest.raises(RuntimeError, match="bounded signed quiescence"):
        state.mark_quiescent(task, b"x" * 65537)


def preparation_completion(authority, state, task):
    facts = state.preparation_binding(task)
    payload = {
        "schema_version": 1,
        "artifact_kind": "subset_preparation_quiescence",
        "run_id": state.run_id,
        "epoch": state.epoch,
        "task_id": task,
        "preparation_id": facts["preparation_id"],
        "preparation_started_event_sha256": facts["preparation_started_event_sha256"],
        "prepared_event_sha256": facts["prepared_event_sha256"],
        "budget_sha256": state.preview.budget.envelope_sha256,
        "owned_cleanup_sha256": "3" * 64,
        "owned_cleanup_complete": True,
        "native_send_occurred": False,
    }
    return authority.put("subset_preparation_quiescence", payload), payload


def test_prepared_cannot_be_recorded_without_preparation_ownership_commitment(tmp_path):
    _, state, _ = state_setup(tmp_path)
    task = OFFICIAL_SUBSET_TASK_IDS[0]
    with pytest.raises(RuntimeError):
        state.mark_prepared(task)


def test_crash_after_preparation_commitment_recovers_observation_and_never_restages(tmp_path):
    authority, state, bindings = state_setup(tmp_path)
    task = OFFICIAL_SUBSET_TASK_IDS[0]
    state.mark_preparation_started(task, preparation_id="owned-preparation")
    recovered = bind_budgeted_subset_state(state.preview, **bindings)
    assert recovered.next_action() == CampaignAction("observe_preparing", task)
    with pytest.raises(RuntimeError):
        recovered.mark_preparation_started(task, preparation_id="replacement-preparation")
    recovered.mark_prepared(task)
    assert recovered.next_action() == CampaignAction("observe_prepared", task)
    assert [event["type"] for event in authority.events] == [
        "campaign_created",
        "preparation_started",
        "prepared",
    ]


def test_expiry_during_preparation_requires_signed_owned_cleanup_before_stop(tmp_path):
    authority, state, bindings = state_setup(tmp_path)
    task = OFFICIAL_SUBSET_TASK_IDS[0]
    state.mark_preparation_started(task, preparation_id="owned-preparation")
    bindings["resource_budget"].data["stop"] = {"reason": "elapsed_limit", "observed_ns": 123}
    with pytest.raises(RuntimeError):
        state.mark_prepared(task)
    state.request_stop()
    assert state.next_action() == CampaignAction("cleanup_prepared", task)
    with pytest.raises(RuntimeError):
        state.finalize_stop()
    raw, payload = preparation_completion(authority, state, task)
    assert payload["prepared_event_sha256"] is None
    state.mark_preparation_quiescent(task, raw)
    state.finalize_stop()
    assert state.next_action() == CampaignAction("stopped", None)
    assert authority.events[-1]["unattempted_task_ids"] == list(OFFICIAL_SUBSET_TASK_IDS)
    assert not any(
        event["type"] in {"prepared", "started", "terminal"} for event in authority.events
    )


@pytest.mark.parametrize("prepared", [False, True])
@pytest.mark.parametrize(
    "field,value",
    [
        ("preparation_id", "other-owner"),
        ("preparation_started_event_sha256", "9" * 64),
        ("prepared_event_sha256", "9" * 64),
    ],
)
def test_cleanup_binds_exact_preparation_phase_and_owner(tmp_path, prepared, field, value):
    authority, state, bindings = state_setup(tmp_path)
    task = OFFICIAL_SUBSET_TASK_IDS[0]
    state.mark_preparation_started(task, preparation_id="owned-preparation")
    if prepared:
        state.mark_prepared(task)
    bindings["resource_budget"].data["stop"] = {"reason": "elapsed_limit", "observed_ns": 123}
    state.request_stop()
    _, payload = preparation_completion(authority, state, task)
    payload[field] = value
    raw = authority.put("subset_preparation_quiescence", payload)
    with pytest.raises(RuntimeError):
        state.mark_preparation_quiescent(task, raw)
    assert state.next_action() == CampaignAction("cleanup_prepared", task)


def test_ambiguous_preparation_commitment_requires_observation_after_restart(tmp_path):
    authority, state, bindings = state_setup(tmp_path)
    task = OFFICIAL_SUBSET_TASK_IDS[0]
    authority.acknowledge = False
    with pytest.raises(RuntimeError, match="acknowledgement"):
        state.mark_preparation_started(task, preparation_id="owned-preparation")
    authority.acknowledge = True
    recovered = bind_budgeted_subset_state(state.preview, **bindings)
    assert recovered.next_action() == CampaignAction("observe_preparing", task)
    with pytest.raises(RuntimeError):
        recovered.mark_preparation_started(task, preparation_id="retry")


def test_public_phase_bindings_are_defensive_and_terminal_is_available_through_stop(tmp_path):
    authority, state, bindings = state_setup(tmp_path)
    task = OFFICIAL_SUBSET_TASK_IDS[0]
    state.mark_preparation_started(task, preparation_id="preparation-0")
    preparing = state.preparation_binding(task)
    assert preparing["prepared"] is None
    assert preparing["prepared_event_sha256"] is None
    preparing["preparation_started"]["preparation_id"] = "mutated"
    assert state.preparation_binding(task)["preparation_id"] == "preparation-0"
    state.mark_prepared(task)
    assert state.preparation_binding(task)["prepared"] == {"type": "prepared", "task_id": task}
    state.mark_started(task, request_id="request-0", attempt_id="attempt-0", launch_sha256="1" * 64)
    started = state.started_binding(task)
    started["attempt_id"] = "mutated"
    assert state.started_binding(task)["attempt_id"] == "attempt-0"
    receipt = terminal(authority, state, task)
    assert state.current_terminal_receipt(task) == receipt
    bindings["resource_budget"].data["stop"] = {"reason": "elapsed_limit", "observed_ns": 123}
    state.request_stop()
    assert state.started_binding(task)["attempt_id"] == "attempt-0"
    assert state.current_terminal_receipt(task) == receipt
    with pytest.raises(RuntimeError):
        state.preparation_binding(OFFICIAL_SUBSET_TASK_IDS[1])


@pytest.mark.parametrize("prepared", [False, True])
def test_real_signed_cleanup_covers_committed_preparation_without_creating_terminal(
    tmp_path, prepared
):
    authority, args, bindings = setup(tmp_path, RealSignatureAuthority())
    state = bind_budgeted_subset_state(preview_budgeted_subset_admission(**args), **bindings)
    authority.events.append(state.creation_event())
    task = OFFICIAL_SUBSET_TASK_IDS[0]
    state.mark_preparation_started(task, preparation_id="owned-preparation")
    if prepared:
        state.mark_prepared(task)
    bindings["resource_budget"].data["stop"] = {"reason": "elapsed_limit", "observed_ns": 123}
    state.request_stop()
    raw, payload = preparation_completion(authority, state, task)
    assert (payload["prepared_event_sha256"] is not None) is prepared
    state.mark_preparation_quiescent(task, raw)
    state.finalize_stop()
    assert state.next_action() == CampaignAction("stopped", None)
    assert not any(event["type"] in {"started", "terminal"} for event in authority.events)


def test_preparation_owner_identity_cannot_be_reused_for_a_later_task(tmp_path):
    authority, state, bindings = state_setup(tmp_path)
    task = start(state)
    receipt = terminal(authority, state, task)
    raw, _ = quiescence(authority, state, bindings["resource_budget"], task, receipt)
    state.mark_quiescent(task, raw)
    with pytest.raises(RuntimeError):
        state.mark_preparation_started(OFFICIAL_SUBSET_TASK_IDS[1], preparation_id="preparation-0")
    assert state.next_action() == CampaignAction("prepare", OFFICIAL_SUBSET_TASK_IDS[1])
