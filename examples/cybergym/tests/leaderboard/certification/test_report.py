# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Synthetic report fixtures cannot substitute for a live native certification."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import replace
from pathlib import Path
from types import MappingProxyType

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nooa_cybergym.leaderboard.campaign import check_go_live
from nooa_cybergym.leaderboard.capabilities import (
    Capability,
    CapabilityRegistry,
    ControlLabel,
    Effect,
    Role,
    Status,
    ToolIdentity,
)
from nooa_cybergym.leaderboard.certification import CertificationBinding, CertificationPolicy
from nooa_cybergym.leaderboard.certification_report import (
    CertificationExpectations,
    compare_runs,
    sign_report,
)
from nooa_cybergym.leaderboard.deepseek import AlternateModelPolicy
from nooa_cybergym.leaderboard.xeus_authority import XeusCampaignAuthority
from xeus_cybergym.canonical import canonical_json
from xeus_cybergym.ledger.signing import (
    Ed25519Signer,
    Ed25519Verifier,
    SignatureVerificationError,
    SignedEnvelope,
)

CONFIG = Path(__file__).parents[3] / "leaderboard/config/certification-policy.json"
CAMPAIGN_CONFIG = CONFIG.with_name("campaign-policy.json")
ALTERNATE_CONFIG = CONFIG.with_name("alternate-model.json")
FROZEN_HASHES = {
    "harness_sha256": "1" * 64,
    "image_sha256": "2" * 64,
    "prompt_sha256": "3" * 64,
    "skill_sha256": "4" * 64,
    "workflow_sha256": "5" * 64,
    "extension_sha256": "6" * 64,
    "memory_seed_sha256": "7" * 64,
    "memory_policy_sha256": "8" * 64,
}
REQUIRED_GATES = (
    "native_vscode",
    "isolation_preflight",
    "model_gateway",
    "deepseek_roles",
    "capability_registry",
    "hybrid_memory",
    "single_final",
    "private_oracle",
    "interruption_reconnection",
    "timeout_failure",
    "version_drift",
    "negative_leakage_probes",
)


def _capability(name, tool, route, *, role=(Role.PARENT, Role.CHILD)):
    identity = ToolIdentity(
        "synthetic-service",
        "1",
        "a" * 64,
        tool,
        "1",
        "b" * 64,
        "synthetic-adapter",
        "1",
        "c" * 64,
    )
    return Capability(
        capability_id=name,
        identity=identity,
        operation="read",
        status=Status.APPROVED,
        control_label=ControlLabel.PERFORMANCE_OPTIMISATION,
        purpose="Synthetic read-only capability",
        roles=role,
        effects=(Effect.READ,),
        data_scopes=("synthetic-generic",),
        path_scopes=(),
        routes=(route,),
        provider_ids=(),
        model_ids=(),
        credential_refs=(),
        accounting="one call",
        log_schema="test-v1",
        evidence_refs=("synthetic-only",),
        certification_digest="d" * 64,
    )


def _expectations():
    policy = CertificationPolicy.model_validate_json(CONFIG.read_text())
    registry = CapabilityRegistry(
        (
            _capability("clangd.symbols", "clangd.symbols", "local/clangd"),
            _capability(
                "docs.compiler", "documentation.fetch", "documentation/compiler/reference-v1"
            ),
        )
    )
    binding = CertificationBinding(
        policy.sha256,
        "e" * 64,
        registry.digest,
        "f" * 64,
    )

    def attest(run):
        return {
            "run_id": run["run_id"],
            "evidence_root": run["evidence_root"],
            "manifest_sha256": run["manifest_sha256"],
            "signature_key_id": "synthetic-verifier-key",
            "verified": True,
        }

    return CertificationExpectations(
        policy=policy,
        binding=binding,
        registry=registry,
        required_approved_capability_ids=frozenset({"clangd.symbols", "docs.compiler"}),
        frozen_hashes=FROZEN_HASHES,
        cohort_sha256="9" * 64,
        campaign_policy_sha256="a" * 64,
        official_cohort_ids=frozenset({"arvo:1065"}),
        primary_provider="https://api.z.ai/api/anthropic",
        attest_raw_run=attest,
    )


def _model(role, *, request_id):
    deepseek = role != "glm_parent"
    return {
        "role": role,
        "model": "deepseek-flash" if deepseek else "glm-5.3[1m]",
        "provider": "https://api.deepseek.com" if deepseek else "https://api.z.ai/api/anthropic",
        "reasoning_effort": "max",
        "thinking": {"type": "enabled"} if deepseek else {"level": "max"},
        "context_tokens": 1_048_576 if deepseek else 1_000_000,
        "observed_version": None,
        "system_fingerprint": None,
        "version_metadata_status": "provider_omitted",
        "returned_model": "deepseek-flash" if deepseek else "glm-5.3",
        "alias_drift": False,
        "provider_request_ids": [request_id],
        "requests": 1,
        "input_tokens": 10,
        "output_tokens": 20,
        "cache_tokens": 0,
        "elapsed_seconds": 5,
        "trigger": {
            "glm_parent": "native_parent",
            "independent_recon": "independent",
            "conditional_debug_recovery": "controller_observed_vulnerable_failure",
            "final_adversarial_critic": "final_review",
        }[role],
    }


def _run(label, expected):
    policy = expected.policy
    root = f"/controller-evidence/certification/{label}"
    hashes = expected.all_hashes
    return {
        "schema_version": 1,
        "run_id": label,
        "scope": "live_native",
        "execution_source": "native-vscode-extension",
        "fixture_ids": list(policy.fixture_ids),
        "epoch": "synthetic-epoch-1",
        "hashes": hashes,
        "evidence_root": root,
        "manifest_sha256": hashlib.sha256(f"manifest:{label}".encode()).hexdigest(),
        "gates": {
            name: {
                "status": "PASS",
                "observed": True,
                "evidence_path": f"{root}/{name}.json",
                "sha256": "a" * 64,
            }
            for name in REQUIRED_GATES
        },
        "capabilities": {
            "enabled_ids": ["clangd.symbols", "docs.compiler"],
            "exercised_ids": ["clangd.symbols", "docs.compiler"],
            "tool_calls": [
                {
                    "capability_id": "clangd.symbols",
                    "tool_id": "clangd.symbols",
                    "route": "local/clangd",
                    "role": "child",
                    "count": 1,
                },
                {
                    "capability_id": "docs.compiler",
                    "tool_id": "documentation.fetch",
                    "route": "documentation/compiler/reference-v1",
                    "role": "parent",
                    "count": 1,
                },
            ],
            "undeclared_calls": [],
        },
        "models": [
            {
                **_model(role, request_id=f"{label}-{fixture_id}-{role}"),
                "fixture_id": fixture_id,
            }
            for fixture_id in policy.fixture_ids
            for role in (
                "glm_parent",
                "independent_recon",
                "conditional_debug_recovery",
                "final_adversarial_critic",
            )
        ],
        "totals": {
            "model_requests": 8,
            "input_tokens": 80,
            "output_tokens": 160,
            "cache_tokens": 0,
            "tool_calls": 2,
        },
        "orchestration": {
            "mode": "ultracode",
            "workflow_counts": {"recon": 1, "review": 1, "debug": 1},
            "max_concurrent_children": 2,
            "children": [
                {"model": "glm-5.3[1m]", "terminal_state": "completed", "read_only": True},
                {"model": "deepseek-flash", "terminal_state": "completed", "read_only": True},
            ],
        },
        "memory": {
            "mode": "audited_hybrid",
            "automatic_recall_exercised": True,
            "parent_child_recall_search_exercised": True,
            "native_started_empty": True,
            "native_prior_task_mounted": False,
            "agent_write_denied": True,
            "retrieval_events": [
                {"role": "parent", "source": "isolated-gbrain"},
                {"role": "child", "source": "isolated-gbrain"},
            ],
            "write_events": [
                {"actor": "controller", "oracle_true": True, "verdict_id": f"{label}-verdict"}
            ],
        },
        "attempts": [
            {
                "fixture_id": fixture_id,
                "start_count": 1,
                "launcher_receipts": 1,
                "final_selected_by": "glm-5.3[1m]",
                "agent_selected": True,
                "controller_selected_candidate": False,
                "final_sha256": "b" * 64,
                "oracle": {"vulnerable_exit": 1, "fixed_exit": 0, "source": "private-oracle"},
            }
            for fixture_id in policy.fixture_ids
        ],
        "negative_probes": dict.fromkeys(policy.required_denials, True),
        "provider_secret_exposure_surfaces": [],
        "interruption": {
            "reconnected_same_attempt": True,
            "timeout_without_final_terminal": True,
            "version_drift_paused": True,
        },
    }


@pytest.fixture
def complete_pair():
    expected = _expectations()
    return _run("synthetic-run-a", expected), _run("synthetic-run-b", expected), expected


def test_two_complete_synthetic_records_prepare_reviewable_report_without_launch(complete_pair):
    first, second, expected = complete_pair
    report = compare_runs(first, second, expected=expected)
    assert report.passed
    assert report.failures == ()
    assert report.payload["official_launch_authorised"] is False
    assert report.payload["status"] == "accepted"
    assert report.payload["harness_sha256"] == expected.frozen_hashes["harness_sha256"]
    assert report.payload["cohort_sha256"] == expected.cohort_sha256
    assert report.payload["campaign_policy_sha256"] == expected.campaign_policy_sha256
    assert len(report.payload["runs"]) == 2
    assert report.payload["capability_coverage"] == "all_enabled_exercised"
    assert report.payload["required_approved_capability_ids"] == [
        "clangd.symbols",
        "docs.compiler",
    ]
    assert report.payload["no_provider_weight_freeze_guarantee"] is True
    run = report.payload["runs"][0]
    assert run["gates"]["native_vscode"]["evidence_path"].endswith("native_vscode.json")
    assert run["enabled_capability_ids"] == run["exercised_capability_ids"]
    assert {item["route"] for item in run["tool_calls"]} == {
        "local/clangd",
        "documentation/compiler/reference-v1",
    }
    assert run["memory_retrieval_events"] == [
        {"role": "parent", "source": "isolated-gbrain"},
        {"role": "child", "source": "isolated-gbrain"},
    ]
    assert run["memory_write_events"][0]["oracle_true"] is True
    assert run["child_count"] == 2
    assert run["interruption"]["version_drift_paused"] is True
    assert run["negative_probes"]["external-target-patch"] is True


@pytest.mark.parametrize("local_route", [None, "", "registered-tool-gateway", "absent"])
def test_route_less_native_capability_requires_no_route(complete_pair, local_route):
    first, second, expected = complete_pair
    native = replace(_capability("native.read", "Read", "unused"), routes=())
    registry = CapabilityRegistry((*expected.registry.entries, native))
    expected = replace(
        expected,
        registry=registry,
        binding=replace(expected.binding, capability_registry_sha256=registry.digest),
        required_approved_capability_ids=expected.required_approved_capability_ids
        | frozenset({native.capability_id}),
    )
    for run in (first, second):
        run["hashes"] = expected.all_hashes
        run["capabilities"]["enabled_ids"].append(native.capability_id)
        run["capabilities"]["exercised_ids"].append(native.capability_id)
        call = {
            "capability_id": native.capability_id,
            "tool_id": "Read",
            "role": "parent",
            "count": 1,
        }
        if local_route != "absent":
            call["route"] = local_route
        run["capabilities"]["tool_calls"].append(call)
        run["totals"]["tool_calls"] += 1
    report = compare_runs(first, second, expected=expected)
    assert report.passed is (local_route is None)
    if local_route is not None:
        assert "synthetic-run-a:undeclared tool or MCP route" in report.failures


def test_multi_route_execution_capability_discloses_whole_admitted_route_set(complete_pair):
    first, second, expected = complete_pair
    native = replace(
        _capability("native.execute", "Bash", "model-gateway"),
        routes=("model-gateway", "registered-tool-gateway"),
    )
    registry = CapabilityRegistry((*expected.registry.entries, native))
    expected = replace(
        expected,
        registry=registry,
        binding=replace(expected.binding, capability_registry_sha256=registry.digest),
        required_approved_capability_ids=expected.required_approved_capability_ids
        | frozenset({native.capability_id}),
    )
    for run in (first, second):
        run["hashes"] = expected.all_hashes
        run["capabilities"]["enabled_ids"].append(native.capability_id)
        run["capabilities"]["exercised_ids"].append(native.capability_id)
        run["capabilities"]["tool_calls"].append(
            {
                "capability_id": native.capability_id,
                "tool_id": "Bash",
                "route": ["model-gateway", "registered-tool-gateway"],
                "role": "parent",
                "count": 1,
            }
        )
        run["totals"]["tool_calls"] += 1
    assert compare_runs(first, second, expected=expected).passed
    second["capabilities"]["tool_calls"][-1]["route"] = "model-gateway"
    assert (
        "synthetic-run-b:undeclared tool or MCP route"
        in compare_runs(first, second, expected=expected).failures
    )


def test_primary_client_context_suffix_has_pinned_wire_model(complete_pair):
    first, second, expected = complete_pair
    for run in (first, second):
        assert run["models"][0]["model"] == "glm-5.3[1m]"
        assert run["models"][0]["returned_model"] == "glm-5.3"
    assert compare_runs(first, second, expected=expected).passed
    second["models"][0]["returned_model"] = "glm-5.3-unexpected"
    report = compare_runs(first, second, expected=expected)
    assert not report.passed
    assert "synthetic-run-b:model alias drift" in report.failures


def test_provider_omission_and_fingerprint_only_are_disclosed(complete_pair):
    first, second, expected = complete_pair
    assert compare_runs(first, second, expected=expected).passed
    for run in (first, second):
        run["models"][1]["system_fingerprint"] = "observed-fingerprint"
        run["models"][1]["version_metadata_status"] = "fingerprint_only"
    assert compare_runs(first, second, expected=expected).passed
    second["models"][1]["version_metadata_status"] = "provider_omitted"
    report = compare_runs(first, second, expected=expected)
    assert not report.passed
    assert "synthetic-run-b:provider version metadata absent" in report.failures


def test_deepseek_budget_is_checked_per_fixture_not_across_two_tasks(complete_pair):
    first, second, expected = complete_pair

    def set_critic_requests(run, fixture_id, count):
        row = next(
            item
            for item in run["models"]
            if item["fixture_id"] == fixture_id and item["role"] == "final_adversarial_critic"
        )
        run["totals"]["model_requests"] += count - row["requests"]
        row["requests"] = count
        row["provider_request_ids"] = [
            f"{run['run_id']}-{fixture_id}-critic-{index}" for index in range(count)
        ]

    for run in (first, second):
        for fixture_id in expected.policy.fixture_ids:
            set_critic_requests(run, fixture_id, 7)
    assert compare_runs(first, second, expected=expected).passed
    set_critic_requests(second, expected.policy.fixture_ids[1], 9)
    report = compare_runs(first, second, expected=expected)
    assert not report.passed
    assert "synthetic-run-b:DeepSeek role budget" in report.failures


def test_empty_or_missing_approved_capability_baseline_cannot_certify():
    expected = _expectations()
    with pytest.raises(ValueError, match="nonempty frozen approved capability baseline"):
        replace(expected, required_approved_capability_ids=frozenset())
    empty_registry = CapabilityRegistry(())
    with pytest.raises(ValueError, match="nonempty frozen approved capability baseline"):
        replace(
            expected,
            registry=empty_registry,
            binding=replace(expected.binding, capability_registry_sha256=empty_registry.digest),
        )


@pytest.mark.parametrize(
    "key",
    [
        "harness_sha256",
        "image_sha256",
        "prompt_sha256",
        "skill_sha256",
        "workflow_sha256",
        "extension_sha256",
        "memory_seed_sha256",
        "policy_sha256",
        "alternate_policy_sha256",
        "capability_registry_sha256",
        "network_policy_sha256",
        "cohort_sha256",
        "campaign_policy_sha256",
    ],
)
def test_two_runs_require_identical_frozen_hashes(complete_pair, key):
    first, second, expected = complete_pair
    second["hashes"][key] = "0" * 64
    report = compare_runs(first, second, expected=expected)
    assert not report.passed
    assert f"{key} mismatch" in report.failures


@pytest.mark.parametrize(
    ("field", "message"),
    [
        ("evidence_root", "certification evidence root reused"),
        ("manifest_sha256", "certification manifest reused"),
    ],
)
def test_distinct_run_ids_cannot_reuse_one_evidence_or_manifest(complete_pair, field, message):
    first, second, expected = complete_pair
    prior_root = second["evidence_root"]
    second[field] = first[field]
    if field == "evidence_root":
        for gate in second["gates"].values():
            gate["evidence_path"] = gate["evidence_path"].replace(
                prior_root, first["evidence_root"]
            )
    report = compare_runs(first, second, expected=expected)
    assert not report.passed
    assert message in report.failures


def test_missing_or_unobserved_gate_is_red_even_if_other_run_passed(complete_pair):
    first, second, expected = complete_pair
    del second["gates"]["native_vscode"]
    first["gates"]["isolation_preflight"]["observed"] = False
    report = compare_runs(first, second, expected=expected)
    assert not report.passed
    assert "synthetic-run-b:native_vscode gate absent" in report.failures
    assert "synthetic-run-a:isolation_preflight gate not observed PASS" in report.failures


@pytest.mark.parametrize(
    "change,fragment",
    [
        (
            lambda run: run["capabilities"]["exercised_ids"].remove("docs.compiler"),
            "enabled capability not exercised",
        ),
        (
            lambda run: run["capabilities"]["tool_calls"].append(
                {
                    "capability_id": "unknown.mcp",
                    "tool_id": "unknown",
                    "route": "mcp/write",
                    "role": "child",
                    "count": 1,
                }
            ),
            "undeclared tool or MCP route",
        ),
        (
            lambda run: run["models"].append(_model("glm_parent", request_id="extra-model")),
            "undeclared model role",
        ),
        (
            lambda run: run["models"][2].update({"trigger": "self_claimed_failure"}),
            "DeepSeek debug trigger",
        ),
        (
            lambda run: run["models"][3].update({"reasoning_effort": "low"}),
            "DeepSeek role settings",
        ),
        (lambda run: run["models"][1].update({"requests": 13}), "DeepSeek role budget"),
        (
            lambda run: run["models"][1].update({"observed_version": ""}),
            "provider version metadata",
        ),
        (lambda run: run["models"][1].update({"alias_drift": True}), "model alias drift"),
        (
            lambda run: run["provider_secret_exposure_surfaces"].append(
                "provider key in child env"
            ),
            "provider secret exposure",
        ),
        (
            lambda run: run["negative_probes"].pop("external-target-patch"),
            "external-target-patch denial absent",
        ),
        (lambda run: run["attempts"][0].update({"start_count": 2}), "second start"),
        (
            lambda run: run["attempts"][0].update({"final_selected_by": "deepseek-flash"}),
            "non-GLM final",
        ),
        (
            lambda run: run["memory"].update({"native_prior_task_mounted": True}),
            "native memory carryover",
        ),
        (
            lambda run: run["memory"]["write_events"].append(
                {"actor": "child", "oracle_true": False}
            ),
            "unsafe GBrain write",
        ),
    ],
)
def test_any_capability_model_leakage_or_final_violation_fails(complete_pair, change, fragment):
    first, second, expected = complete_pair
    change(second)
    report = compare_runs(first, second, expected=expected)
    assert not report.passed
    assert any(fragment in failure for failure in report.failures)


def test_official_id_and_missing_independent_raw_attestation_fail(complete_pair):
    first, second, expected = complete_pair
    second["fixture_ids"][0] = "arvo:1065"
    expected = replace(expected, attest_raw_run=lambda _: None)
    report = compare_runs(first, second, expected=expected)
    assert not report.passed
    assert any("official or undeclared fixture" in item for item in report.failures)
    assert any("raw evidence attestation" in item for item in report.failures)


def test_signed_report_uses_injected_xeus_signer_and_verifier(complete_pair):
    first, second, expected = complete_pair
    report = compare_runs(first, second, expected=expected)
    private_key = Ed25519PrivateKey.generate()
    signer = Ed25519Signer(private_key=private_key, key_id="synthetic-test-key")
    verifier = Ed25519Verifier({"synthetic-test-key": private_key.public_key()})
    signed = sign_report(report, signer=signer, verifier=verifier)
    envelope = SignedEnvelope.model_validate_json(signed.envelope_json)
    assert verifier.verify(envelope) == signed.payload_json
    payload = json.loads(signed.payload_json)
    assert payload["official_launch_authorised"] is False
    tampered = json.loads(signed.envelope_json)
    tampered["payload"] = base64.b64encode(b"tampered").decode()
    with pytest.raises(SignatureVerificationError):
        verifier.verify(SignedEnvelope.model_validate(tampered))


def test_signed_comparison_report_supplies_campaign_admission_hashes(tmp_path):
    base = _expectations()
    private_key = Ed25519PrivateKey.generate()
    signer = Ed25519Signer(private_key=private_key, key_id="synthetic-test-key")
    verifier = Ed25519Verifier({"synthetic-test-key": private_key.public_key()})

    def signed(payload):
        envelope = signer.sign(canonical_json(payload))
        return canonical_json(envelope)

    campaign_policy = json.loads(CAMPAIGN_CONFIG.read_text())
    campaign_sha = hashlib.sha256(canonical_json(campaign_policy)).hexdigest()
    alternate = AlternateModelPolicy.model_validate_json(ALTERNATE_CONFIG.read_text())
    ids = [f"arvo:{index}" for index in range(1, 1508)]
    tasks_json = canonical_json([{"task_id": task_id} for task_id in ids])
    cohort = signed(
        {
            "schema_version": 1,
            "task_ids": ids,
            "tasks_json_sha256": hashlib.sha256(tasks_json).hexdigest(),
            "asset_hashes_sha256": "a" * 64,
            "benchmark_commit": "1" * 40,
            "dataset_commit": "2" * 40,
            "mask_map_sha256": "b" * 64,
        }
    )
    harness_lock = signed(
        {
            "schema_version": 1,
            "epoch": "synthetic-epoch-1",
            "campaign_policy_sha256": campaign_sha,
            "alternate_policy_sha256": alternate.digest,
            "capability_registry_sha256": base.registry.digest,
            "memory_policy_sha256": base.frozen_hashes["memory_policy_sha256"],
        }
    )
    harness_sha = hashlib.sha256(harness_lock).hexdigest()
    cohort_sha = hashlib.sha256(cohort).hexdigest()
    expected = replace(
        base,
        binding=replace(base.binding, alternate_policy_sha256=alternate.digest),
        frozen_hashes=dict(base.frozen_hashes) | {"harness_sha256": harness_sha},
        cohort_sha256=cohort_sha,
        campaign_policy_sha256=campaign_sha,
    )
    report = compare_runs(
        _run("synthetic-run-a", expected),
        _run("synthetic-run-b", expected),
        expected=expected,
    )
    assert report.passed
    certification = sign_report(report, signer=signer, verifier=verifier).envelope_json
    decision = signed(
        {
            "schema_version": 1,
            "official_launch_authorised": True,
            "run_id": "synthetic-campaign",
            "epoch": "synthetic-epoch-1",
            "certification_sha256": hashlib.sha256(certification).hexdigest(),
            "harness_sha256": harness_sha,
            "cohort_sha256": cohort_sha,
            "campaign_policy_sha256": campaign_sha,
        }
    )
    native_authority = XeusCampaignAuthority({"synthetic-test-key": private_key.public_key()})

    class VerifiedAuthority:
        events = None

        def attest_signed(self, kind, envelope):
            return native_authority.attest_signed(kind, envelope)

        def create_campaign_once(self, evidence_root, run_id, event):
            self.events = [event]
            return True

    authority = VerifiedAuthority()
    state = check_go_live(
        decision=decision,
        certification=certification,
        harness_lock=harness_lock,
        cohort=cohort,
        campaign_policy=campaign_policy,
        tasks_json=tasks_json,
        authority=authority,
        run_id="synthetic-campaign",
        evidence_root=tmp_path / "synthetic-evidence",
    )
    assert state.task_ids == tuple(ids)
    assert authority.events[0]["type"] == "campaign_created"


def test_report_signing_rejects_verifier_disagreement(complete_pair):
    first, second, expected = complete_pair
    report = compare_runs(first, second, expected=expected)
    private_key = Ed25519PrivateKey.generate()
    signer = Ed25519Signer(private_key=private_key, key_id="synthetic-test-key")

    class WrongVerifier:
        def verify(self, _):
            return b"different payload"

    with pytest.raises(RuntimeError, match="signature verification"):
        sign_report(report, signer=signer, verifier=WrongVerifier())


@pytest.mark.parametrize(
    "mutate",
    [
        lambda run: run["models"][0].update({"role": []}),
        lambda run: run["models"][1].update({"input_tokens": "ten"}),
        lambda run: run["models"][1].update({"requests": "one"}),
        lambda run: run["capabilities"]["tool_calls"][0].update({"capability_id": []}),
        lambda run: run["attempts"][0].update({"fixture_id": []}),
    ],
)
def test_malformed_nested_evidence_returns_red_report_not_exception(complete_pair, mutate):
    first, second, expected = complete_pair
    mutate(second)
    report = compare_runs(first, second, expected=expected)
    assert not report.passed
    assert report.payload["status"] == "rejected"


def test_rejected_report_does_not_copy_untrusted_tool_or_oracle_fields(complete_pair):
    first, second, expected = complete_pair
    second["capabilities"]["tool_calls"][0]["provider_secret"] = "SECRET-NEVER-REPORT"
    second["attempts"][0]["oracle"]["private_fixed_source"] = "SECRET-NEVER-REPORT"
    second["negative_probes"]["SECRET-NEVER-REPORT"] = False
    report = compare_runs(first, second, expected=expected)
    assert not report.passed
    assert "SECRET-NEVER-REPORT" not in json.dumps(report.payload)


def test_frozen_expectation_hashes_cannot_be_changed_after_validation(complete_pair):
    _, _, expected = complete_pair
    assert isinstance(expected.frozen_hashes, MappingProxyType)
    with pytest.raises(TypeError):
        expected.frozen_hashes["harness_sha256"] = "0" * 64


@pytest.mark.parametrize("field", ["cohort_sha256", "campaign_policy_sha256"])
def test_missing_campaign_binding_digest_rejects_expectations(complete_pair, field):
    _, _, expected = complete_pair
    with pytest.raises(ValueError, match="cohort, and campaign policy hashes"):
        replace(expected, **{field: "not-a-sha256"})


def test_nested_policy_mutation_after_binding_rejects_report(complete_pair):
    first, second, expected = complete_pair
    expected.policy.alternate_max_requests_by_role["independent_recon"] = 99
    report = compare_runs(first, second, expected=expected)
    assert not report.passed
    assert "certification policy changed after binding" in report.failures


def test_signing_rejects_report_payload_mutation_after_comparison(complete_pair):
    first, second, expected = complete_pair
    report = compare_runs(first, second, expected=expected)
    report.payload["status"] = "rejected"
    private_key = Ed25519PrivateKey.generate()
    signer = Ed25519Signer(private_key=private_key, key_id="synthetic-test-key")
    verifier = Ed25519Verifier({"synthetic-test-key": private_key.public_key()})
    with pytest.raises(ValueError, match="report changed"):
        sign_report(report, signer=signer, verifier=verifier)
