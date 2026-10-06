# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Controller boundary tests using synthetic provider responses only."""

import importlib.util
import json
from dataclasses import replace
from pathlib import Path

import pytest


def test_controller_module_exists():
    assert importlib.util.find_spec("nooa_cybergym.leaderboard.deepseek") is not None


def api():
    from nooa_cybergym.leaderboard import deepseek

    return deepseek


def config():
    return Path(__file__).resolve().parents[2] / "leaderboard/config/alternate-model.json"


def policy():
    return api().AlternateModelPolicy.model_validate_json(config().read_text())


class Audit:
    def __init__(self):
        self.events = []
        self.fail = False

    def record(self, event):
        if self.fail:
            raise OSError("synthetic-secret")
        self.events.append(event)
        return True


def response(**changes):
    body = {
        "id": "provider-request-1",
        "model": "deepseek-flash",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "advice",
                    "reasoning_content": "synthetic reasoning",
                },
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": 10,
            "completion_tokens": 8,
            "total_tokens": 18,
            "prompt_cache_hit_tokens": 3,
            "prompt_cache_miss_tokens": 7,
            "completion_tokens_details": {"reasoning_tokens": 5},
        },
        "system_fingerprint": "synthetic-fingerprint",
    }
    body.update(changes)
    return api().ProviderResponse(status_code=200, body=body)


class Transport:
    def __init__(self):
        self.calls = []
        self.result = None
        self.error = None

    def send(self, endpoint, headers, payload, timeout):
        self.calls.append((endpoint, headers, payload, timeout))
        if self.error:
            raise self.error
        return self.result or response()


def controller(*, budget=None, clock=None):
    d = api()
    audit, transport = Audit(), Transport()
    client = d.DeepSeekController(
        policy(),
        "synthetic-secret",
        audit=audit,
        registry_digest="a" * 64,
        transport=transport,
        budget=budget or d.SharedCampaignBudget(clock=clock),
        clock=clock,
    )
    return client, audit, transport


def request(client, role=None, **changes):
    return client.request(
        role=role or api().DeepSeekRole.INDEPENDENT_RECON,
        messages=[{"role": "user", "content": "inspect synthetic source"}],
        task_id="task-1",
        attempt_id="attempt-1",
        **changes,
    )


@pytest.mark.parametrize("role", ["independent_recon", "final_adversarial_critic"])
def test_enabled_policy_routes_real_controller_payload_and_audit(role):
    d = api()
    client, audit, transport = controller()
    result = request(client, d.DeepSeekRole(role))
    endpoint, headers, payload, timeout = transport.calls[0]
    assert endpoint == "https://api.deepseek.com/chat/completions"
    assert headers["Authorization"] == "Bearer synthetic-secret"
    assert payload == {
        "model": "deepseek-flash",
        "thinking": {"type": "enabled"},
        "reasoning_effort": "max",
        "max_tokens": 128000,
        "messages": [{"role": "user", "content": "inspect synthetic source"}],
    }
    assert 0 < timeout <= (3600 if role == "independent_recon" else 1800)
    assert result["content"] == "advice"
    assert result["usage"]["counted_tokens"] == 18
    assert result["usage"]["cache_hit_input_tokens"] == 3
    assert result["usage"]["cache_miss_input_tokens"] == 7
    assert result["usage"]["reasoning_tokens"] == 5
    assert result["provider_weights_frozen_guarantee"] is False
    assert "alias" in result["metadata_disclosure"]
    assert [event["event"] for event in audit.events] == ["request", "response"]
    for event in audit.events:
        assert event["role"] == role
        assert event["task_id"] == "task-1" and event["attempt_id"] == "attempt-1"
        assert event["registry_digest"] == "a" * 64
        assert event["policy_digest"] == policy().digest
    assert audit.events[-1]["provider_request_id"] == "provider-request-1"
    assert audit.events[-1]["returned_model"] == "deepseek-flash"
    assert audit.events[-1]["duration_seconds"] >= 0


def test_debug_requires_controller_admitted_vulnerable_failure():
    d = api()
    client, audit, transport = controller()
    with pytest.raises(d.PolicyViolation):
        request(client, d.DeepSeekRole.CONDITIONAL_DEBUG_RECOVERY)
    assert not transport.calls
    with pytest.raises(d.PolicyViolation):
        client.admit_failure(
            task_id="task-1",
            attempt_id="attempt-1",
            source="vulnerable_test",
            exit_code=0,
            evidence_digest="b" * 64,
        )
    evidence = client.admit_failure(
        task_id="task-1",
        attempt_id="attempt-1",
        source="vulnerable_test",
        exit_code=1,
        evidence_digest="b" * 64,
    )
    request(client, d.DeepSeekRole.CONDITIONAL_DEBUG_RECOVERY, failure=evidence)
    with pytest.raises(d.PolicyViolation):
        request(
            client,
            d.DeepSeekRole.CONDITIONAL_DEBUG_RECOVERY,
            failure=replace(evidence, task_id="other-task"),
        )


@pytest.mark.parametrize("role", ["hidden_fallback", "independent_recon", "controller", None])
def test_untrusted_role_value_cannot_select_route(role):
    client, _, transport = controller()
    with pytest.raises((api().PolicyViolation, TypeError)):
        client.request(role=role, messages=[], task_id="task-1", attempt_id="attempt-1")
    assert not transport.calls


@pytest.mark.parametrize(
    "field,value",
    [
        ("status", "disabled"),
        ("deepseek_max_requests", 37),
        ("shared_task_max_requests", 601),
        ("max_concurrent_children", 4),
        ("official_final_selector", "deepseek"),
        ("fallback", "glm"),
    ],
)
def test_policy_rejects_undeclared_routing_and_budget_overrides(field, value):
    data = json.loads(config().read_text())
    data[field] = value
    with pytest.raises(ValueError):
        api().AlternateModelPolicy.model_validate(data)


@pytest.mark.parametrize(
    "field,value",
    [
        ("model", "other-model"),
        ("base_url", "https://attacker.invalid"),
        ("reasoning_effort", "high"),
        ("thinking", {"type": "disabled"}),
        ("max_output_tokens", 128001),
        ("context_tokens", 1000000),
        ("credential_ref", "env:DEEPSEEK_API_KEY"),
        ("provider_weights_frozen_guarantee", True),
        ("max_output_tokens", True),
    ],
)
def test_maximum_provider_policy_cannot_be_changed(field, value):
    data = json.loads(config().read_text())
    data["models"][0][field] = value
    with pytest.raises(ValueError):
        api().AlternateModelPolicy.model_validate(data)


def test_policy_is_frozen_round_trippable_and_tamper_evident():
    d = api()
    p = policy()
    assert d.AlternateModelPolicy.model_validate_json(p.model_dump_json()).digest == p.digest
    with pytest.raises(ValueError):
        p.models[0].model = "other-model"
    data = json.loads(config().read_text())
    data["routes"][1]["role"] = "independent_recon"
    with pytest.raises(ValueError):
        d.AlternateModelPolicy.model_validate(data)


def test_key_never_escapes_payload_audit_solver_result_or_repr():
    client, audit, transport = controller()
    transport.result = response(
        choices=[
            {
                "message": {
                    "content": "echo synthetic-secret",
                    "reasoning_content": "synthetic-secret",
                }
            }
        ]
    )
    result = client.request(
        role=api().DeepSeekRole.INDEPENDENT_RECON,
        messages=[{"role": "user", "content": "synthetic-secret"}],
        task_id="task-1",
        attempt_id="attempt-1",
    )
    exposed = json.dumps([transport.calls[0][2], audit.events, result, repr(client)])
    assert "synthetic-secret" not in exposed
    assert "[REDACTED]" in result["content"]


def test_transport_failure_counts_once_without_retry_and_redacts_exception():
    client, audit, transport = controller()
    transport.error = RuntimeError("provider rejected synthetic-secret")
    with pytest.raises(api().ProviderFailure) as error:
        request(client)
    assert "synthetic-secret" not in str(error.value)
    assert error.value.__context__ is None
    assert client.budget.snapshot()["requests"] == 1
    assert client.role_usage()["independent_recon"]["requests"] == 1
    assert len(transport.calls) == 1
    assert audit.events[-1]["event"] == "failure"


def test_audit_failure_blocks_before_transport_and_counts_attempt():
    client, audit, transport = controller()
    audit.fail = True
    with pytest.raises(api().AuditFailure):
        request(client)
    assert not transport.calls
    assert client.budget.snapshot()["requests"] == 1
    audit.fail = False
    with pytest.raises(api().ControllerHalted):
        request(client)


@pytest.mark.parametrize(
    "change",
    [
        {"model": "other-model"},
        {"id": ""},
        {"usage": None},
        {
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 8,
                "total_tokens": 19,
                "prompt_cache_hit_tokens": 3,
                "prompt_cache_miss_tokens": 7,
            }
        },
        {
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 128001,
                "total_tokens": 128011,
                "prompt_cache_hit_tokens": 3,
                "prompt_cache_miss_tokens": 7,
            }
        },
    ],
)
def test_missing_or_mismatched_identity_usage_halts_later_calls(change):
    client, _, transport = controller()
    transport.result = response(**change)
    with pytest.raises(api().ProviderFailure):
        request(client)
    with pytest.raises(api().ControllerHalted):
        request(client)
    assert len(transport.calls) == 1


def test_visible_provider_metadata_drift_halts_but_alias_weights_are_not_verifiable():
    client, _, transport = controller()
    request(client)
    transport.result = response(system_fingerprint="changed-fingerprint")
    with pytest.raises(api().ProviderFailure):
        request(client)
    with pytest.raises(api().ControllerHalted):
        request(client)


def test_role_request_ceiling_is_enforced_without_borrowing():
    client, _, transport = controller()
    for _ in range(12):
        request(client)
    with pytest.raises(api().BudgetExceeded):
        request(client)
    assert len(transport.calls) == 12
    request(client, api().DeepSeekRole.FINAL_ADVERSARIAL_CRITIC)


def test_shared_campaign_budget_includes_other_controller_inference():
    d = api()
    budget = d.SharedCampaignBudget()
    for _ in range(564):
        budget.reserve_request()
    for _ in range(35):
        budget.reserve_deepseek_request()
    client, _, transport = controller(budget=budget)
    request(client)
    with pytest.raises(d.BudgetExceeded):
        request(client, d.DeepSeekRole.FINAL_ADVERSARIAL_CRITIC)
    assert len(transport.calls) == 1


def test_glm_memory_cannot_borrow_unused_deepseek_allocation():
    budget = api().SharedCampaignBudget()
    for _ in range(564):
        budget.reserve_request()
    with pytest.raises(api().BudgetExceeded):
        budget.reserve_request()
    assert budget.snapshot()["requests"] == 564


def test_deepseek_cannot_borrow_unused_glm_memory_allocation():
    budget = api().SharedCampaignBudget()
    for _ in range(36):
        budget.reserve_deepseek_request()
    with pytest.raises(api().BudgetExceeded):
        budget.reserve_deepseek_request()
    assert budget.snapshot()["deepseek_requests"] == 36
    assert budget.snapshot()["glm_and_memory_auxiliary_requests"] == 0
    budget.reserve_request()
    assert budget.snapshot()["requests"] == 37


def test_default_budget_reservation_has_no_caller_selectable_allocation():
    budget = api().SharedCampaignBudget()
    for arguments in (
        {"allocation": "deepseek"},
        {"role": "controller"},
        {"model": "deepseek-flash"},
    ):
        with pytest.raises(TypeError):
            budget.reserve_request(**arguments)
    budget.reserve_request()
    assert budget.snapshot()["glm_and_memory_auxiliary_requests"] == 1
    assert budget.snapshot()["deepseek_requests"] == 0


@pytest.mark.parametrize("failure", ["transport", "audit"])
def test_failed_deepseek_attempt_debits_only_declared_allocation(failure):
    client, audit, transport = controller()
    if failure == "transport":
        transport.error = OSError("synthetic network failure")
        expected = api().ProviderFailure
    else:
        audit.fail = True
        expected = api().AuditFailure
    with pytest.raises(expected):
        request(client)
    assert client.budget.snapshot()["deepseek_requests"] == 1
    assert client.budget.snapshot()["glm_and_memory_auxiliary_requests"] == 0
    assert client.budget.snapshot()["requests"] == 1


def test_shared_clock_and_role_elapsed_budget_stop_further_forwarding():
    now = [0.0]
    client, _, transport = controller(clock=lambda: now[0])

    def slow_send(*args):
        now[0] += 3600
        return response()

    transport.send = slow_send
    request(client)
    with pytest.raises(api().BudgetExceeded):
        request(client)
    now[0] = 43200
    with pytest.raises(api().BudgetExceeded):
        request(client, api().DeepSeekRole.FINAL_ADVERSARIAL_CRITIC)


def test_redirect_response_is_not_followed():
    client, _, transport = controller()
    transport.result = api().ProviderResponse(
        status_code=307, body={"location": "https://attacker.invalid"}
    )
    with pytest.raises(api().ProviderFailure):
        request(client)
    assert len(transport.calls) == 1


def test_untrusted_message_cannot_set_model_settings_or_role():
    client, _, transport = controller()
    with pytest.raises(api().PolicyViolation):
        client.request(
            role=api().DeepSeekRole.INDEPENDENT_RECON,
            messages=[{"role": "user", "content": "hi", "endpoint": "evil"}],
            task_id="task-1",
            attempt_id="attempt-1",
        )
    assert not transport.calls


def test_httpx_transport_disables_redirects_and_uses_only_declared_route():
    import httpx

    d = api()
    seen = []

    def handle(req):
        seen.append(str(req.url))
        return httpx.Response(307, headers={"location": "https://attacker.invalid"}, json={})

    transport = d.HttpxTransport(transport=httpx.MockTransport(handle))
    with pytest.raises(d.PolicyViolation):
        transport.send("https://attacker.invalid", {}, {}, 1)
    result = transport.send("https://api.deepseek.com/chat/completions", {}, {}, 1)
    assert result.status_code == 307
    assert seen == ["https://api.deepseek.com/chat/completions"]


def test_unacknowledged_audit_blocks_request_without_credential_exception_chain():
    client, audit, transport = controller()
    audit.record = lambda event: None
    with pytest.raises(api().AuditFailure) as error:
        request(client)
    assert error.value.__context__ is None
    assert not transport.calls


def test_response_audit_failure_withholds_advice_and_halts_later_forwarding():
    client, audit, transport = controller()

    def send(*args):
        audit.fail = True
        return response()

    transport.send = send
    with pytest.raises(api().AuditFailure):
        request(client)
    audit.fail = False
    with pytest.raises(api().ControllerHalted):
        request(client)
    assert client.budget.snapshot()["requests"] == 1


@pytest.mark.parametrize(
    "usage",
    [
        {"prompt_tokens": 10, "completion_tokens": 8, "total_tokens": 18},
        {
            "prompt_tokens": 10,
            "completion_tokens": 8,
            "total_tokens": 18,
            "prompt_cache_hit_tokens": 4,
            "prompt_cache_miss_tokens": 7,
        },
        {
            "prompt_tokens": 10,
            "completion_tokens": 8,
            "total_tokens": 18,
            "prompt_cache_hit_tokens": 3,
            "prompt_cache_miss_tokens": 7,
            "completion_tokens_details": {"reasoning_tokens": 9},
        },
        {
            "prompt_tokens": 1048570,
            "completion_tokens": 8,
            "total_tokens": 1048578,
            "prompt_cache_hit_tokens": 0,
            "prompt_cache_miss_tokens": 1048570,
        },
    ],
)
def test_incomplete_or_oversized_token_classes_fail_closed(usage):
    client, _, transport = controller()
    transport.result = response(usage=usage)
    with pytest.raises(api().ProviderFailure):
        request(client)
    assert client.role_usage()["independent_recon"]["tokens"] == 1048576


def test_provider_full_context_limit_is_allowed_and_cached_input_is_counted_once():
    client, _, transport = controller()
    transport.result = response(
        usage={
            "prompt_tokens": 920576,
            "completion_tokens": 128000,
            "total_tokens": 1048576,
            "prompt_cache_hit_tokens": 900000,
            "prompt_cache_miss_tokens": 20576,
            "completion_tokens_details": {"reasoning_tokens": 127999},
        }
    )
    for _ in range(12):
        request(client)
    assert client.role_usage()["independent_recon"]["tokens"] == 12582912
    with pytest.raises(api().BudgetExceeded):
        request(client)


def test_absent_optional_reasoning_class_is_disclosed_without_inventing_tokens():
    client, _, transport = controller()
    transport.result = response(
        usage={
            "prompt_tokens": 10,
            "completion_tokens": 8,
            "total_tokens": 18,
            "prompt_cache_hit_tokens": 3,
            "prompt_cache_miss_tokens": 7,
        }
    )
    result = request(client)
    assert result["usage"]["reasoning_tokens"] is None
    assert result["usage"]["counted_tokens"] == 18


def test_admitted_failure_cannot_be_reconstructed_or_self_reported():
    client, _, transport = controller()
    d = api()
    for source in ("model_says_failed", "fixed_test", "oracle_test"):
        with pytest.raises(d.PolicyViolation):
            client.admit_failure(
                task_id="task-1",
                attempt_id="attempt-1",
                source=source,
                exit_code=1,
                evidence_digest="b" * 64,
            )
    evidence = client.admit_failure(
        task_id="task-1",
        attempt_id="attempt-1",
        source="vulnerable_build",
        exit_code=1,
        evidence_digest="b" * 64,
    )
    with pytest.raises(d.PolicyViolation):
        request(client, d.DeepSeekRole.CONDITIONAL_DEBUG_RECOVERY, failure=replace(evidence))
    assert not transport.calls


def test_controller_cannot_accept_endpoint_or_model_knobs():
    client, _, transport = controller()
    for knob in ("endpoint", "model", "max_tokens", "fallback"):
        with pytest.raises(TypeError):
            request(client, **{knob: "undeclared"})
    assert not transport.calls


def test_invalid_controller_clock_halts_before_provider_request():
    client, _, transport = controller(clock=lambda: float("inf"))
    with pytest.raises(api().BudgetExceeded):
        request(client)
    assert not transport.calls


@pytest.mark.parametrize("audit_delay", [3600, 43200])
def test_audit_latency_cannot_forward_after_role_or_shared_deadline(audit_delay):
    now = [0.0]
    client, audit, transport = controller(clock=lambda: now[0])

    def slow_audit(event):
        audit.events.append(event)
        if event["event"] == "request":
            now[0] += audit_delay
        return True

    audit.record = slow_audit
    with pytest.raises(api().BudgetExceeded):
        request(client)
    assert not transport.calls
    assert client.budget.snapshot()["requests"] == 1
    assert audit.events[-1]["event"] == "failure"


def test_controller_request_ids_correlate_events_even_when_provider_ids_repeat():
    client, audit, _ = controller()
    request(client)
    request(client)
    ids = [event.get("request_id") for event in audit.events]
    assert all(isinstance(value, str) and value for value in ids)
    assert ids[0] == ids[1] and ids[2] == ids[3] and ids[0] != ids[2]
