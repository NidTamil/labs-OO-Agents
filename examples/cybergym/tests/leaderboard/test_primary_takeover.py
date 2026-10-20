# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Controller route changes use fixed policy and durable, distinct attempt evidence."""

import hashlib
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, asdict, replace

import pytest
from nooa_cybergym.leaderboard import primary_takeover


def test_policy_binds_exact_routes_and_shared_allocation_in_canonical_digest():
    from nooa_cybergym.leaderboard.primary_takeover import PrimaryTakeoverPolicy

    policy = PrimaryTakeoverPolicy()
    manifest = json.loads(policy.manifest_json)
    assert manifest["schema_version"] == 1
    assert manifest["initial"]["provider"] == "zai-coding-plan"
    assert manifest["initial"]["model"] == "glm-5.3[1m]"
    assert manifest["initial"]["wire_model"] == "glm-5.3"
    assert manifest["initial"]["base_url"] == "https://api.z.ai/api/anthropic"
    assert manifest["fallback"]["provider"] == "deepseek-official-api"
    assert manifest["fallback"]["model"] == "deepseek-flash"
    assert manifest["fallback"]["wire_model"] == "deepseek-flash"
    assert manifest["fallback"]["base_url"] == "https://api.deepseek.com/anthropic"
    assert manifest["fallback"]["provider_weights_frozen_guarantee"] is False
    assert manifest["fallback"]["metadata_policy"] == (
        "record_returned_model_version_fingerprint_when_available"
    )
    assert manifest["initial"]["allocation"] == "primary_and_memory"
    assert manifest["fallback"]["allocation"] == "primary_and_memory"
    assert manifest["max_transitions"] == 1
    assert manifest["require_no_response_started"] is True
    assert policy.manifest_json == json.dumps(manifest, sort_keys=True, separators=(",", ":"))
    assert policy.digest == hashlib.sha256(policy.manifest_json.encode()).hexdigest()


@pytest.mark.parametrize(
    "change",
    [
        {"schema_version": 2},
        {"schema_version": True},
        {"eligible_failure_kinds": ("refusal",)},
        {"eligible_failure_kinds": ("connection_failure",)},
        {"max_transitions": 2},
        {"max_transitions": True},
        {"require_no_response_started": False},
        {"require_no_response_started": 1},
    ],
)
def test_policy_rejects_changes_that_expand_or_change_signed_scope(change):
    with pytest.raises(ValueError, match="fixed"):
        primary_takeover.PrimaryTakeoverPolicy(**change)


@pytest.mark.parametrize("route_name", ["initial", "fallback"])
@pytest.mark.parametrize(
    "change",
    [
        {"provider": "other-provider"},
        {"model": "DeepSeekFlashV4.1-Flash-1017"},
        {"wire_model": "other-model"},
        {"base_url": "https://other.example/anthropic"},
        {"api": "chat_completions"},
        {"allocation": "deepseek_advisory"},
        {"metadata_policy": "discard_identity"},
        {"provider_weights_frozen_guarantee": True},
        {"provider_weights_frozen_guarantee": 0},
    ],
)
def test_policy_rejects_route_or_identity_reinterpretation(route_name, change):
    policy = primary_takeover.PrimaryTakeoverPolicy()
    route = replace(getattr(policy, route_name), **change)
    with pytest.raises(ValueError, match="fixed"):
        replace(policy, **{route_name: route})


def _new_state(writer, **changes):
    policy = primary_takeover.PrimaryTakeoverPolicy()
    values = {
        "task_id": "arvo:123",
        "attempt_id": "native-attempt-1",
        "policy": policy,
        "policy_sha256": policy.digest,
        "event_writer": writer,
    }
    return primary_takeover.PrimaryTakeoverState(**(values | changes))


def _switch(state, **changes):
    values = {
        "request_id": "native-request-1",
        "failure_kind": "provider_unavailable",
        "response_started": False,
        "failed_provider_attempt_id": "glm-dispatch-1",
        "fallback_provider_attempt_id": "deepseek-dispatch-2",
    }
    return state.switch(**(values | changes))


@pytest.mark.parametrize(
    "failure_kind",
    [
        "connection_failure",
        "connect_timeout",
        "read_timeout",
        "rate_limited",
        "provider_unavailable",
    ],
)
def test_eligible_failure_persists_exact_custody_before_exposing_fallback(tmp_path, failure_kind):
    event_path = tmp_path / "route.json"
    observations = []

    def writer(event):
        observations.append(state.route)
        with event_path.open("w", encoding="utf-8") as stream:
            json.dump(asdict(event), stream)
            stream.flush()
            os.fsync(stream.fileno())
        return True

    state = _new_state(writer)
    original_route = state.route
    fallback_route = _switch(state, failure_kind=failure_kind)
    event = json.loads(event_path.read_text(encoding="utf-8"))
    assert observations == [original_route]
    assert original_route.provider == "zai-coding-plan"
    assert state.route is fallback_route
    assert fallback_route.provider == "deepseek-official-api"
    assert fallback_route.allocation == "primary_and_memory"
    assert event == {
        "schema_version": 1,
        "event": "primary_route_switched",
        "task_id": "arvo:123",
        "attempt_id": "native-attempt-1",
        "policy_sha256": primary_takeover.PrimaryTakeoverPolicy().digest,
        "request_id": "native-request-1",
        "failed_provider_attempt_id": "glm-dispatch-1",
        "fallback_provider_attempt_id": "deepseek-dispatch-2",
        "failure_kind": failure_kind,
        "response_started": False,
        "from_route": asdict(original_route),
        "to_route": asdict(fallback_route),
    }
    with pytest.raises(FrozenInstanceError):
        original_route.provider = "deepseek-official-api"


@pytest.mark.parametrize(
    "failure_kind",
    [
        "refusal",
        "policy_denial",
        "authentication_failure",
        "authorization_failure",
        "cancellation",
        "budget_exhaustion",
        "task_deadline_exceeded",
        "identity_drift",
        "credential_disclosure",
        "invalid_usage",
        "malformed_arguments",
        "audit_failure",
        "provider_http_error",
        "other_failure",
        "",
        None,
        503,
        [],
    ],
)
def test_ineligible_or_unclassified_failure_never_writes_or_changes_route(failure_kind):
    events = []
    state = _new_state(lambda event: events.append(event) or True)
    before = state.route
    with pytest.raises(ValueError, match="eligible"):
        _switch(state, failure_kind=failure_kind)
    assert state.route is before
    assert events == []


@pytest.mark.parametrize("response_started", [True, 0, 1, None, "false"])
def test_any_response_exposure_or_ambiguous_flag_forbids_takeover(response_started):
    events = []
    state = _new_state(lambda event: events.append(event) or True)
    before = state.route
    with pytest.raises(ValueError, match="response"):
        _switch(state, response_started=response_started)
    assert state.route is before
    assert events == []


def test_second_switch_cannot_write_or_change_the_sticky_fallback():
    events = []
    state = _new_state(lambda event: events.append(event) or True)
    fallback = _switch(state)
    with pytest.raises(RuntimeError, match="already"):
        _switch(state, request_id="native-request-2")
    assert state.route is fallback
    assert len(events) == 1


@pytest.mark.parametrize("acknowledgment", [False, None, 1, "persisted", []])
def test_ambiguous_writer_acknowledgment_poisons_all_future_routing(acknowledgment):
    events = []
    state = _new_state(lambda event: events.append(event) or acknowledgment)
    with pytest.raises(primary_takeover.PrimaryTakeoverPersistenceError):
        _switch(state)
    with pytest.raises(primary_takeover.PrimaryTakeoverPersistenceError):
        _ = state.route
    with pytest.raises(primary_takeover.PrimaryTakeoverPersistenceError):
        _switch(state)
    assert len(events) == 1


@pytest.mark.parametrize("error", [OSError("disk full"), KeyboardInterrupt()])
def test_writer_error_even_after_partial_commit_permanently_poisons_state(error):
    events = []

    def writer(event):
        events.append(event)
        raise error

    state = _new_state(writer)
    expected = (
        primary_takeover.PrimaryTakeoverPersistenceError
        if isinstance(error, Exception)
        else KeyboardInterrupt
    )
    with pytest.raises(expected):
        _switch(state)
    with pytest.raises(primary_takeover.PrimaryTakeoverPersistenceError):
        _ = state.route
    with pytest.raises(primary_takeover.PrimaryTakeoverPersistenceError):
        _switch(state)
    assert len(events) == 1


def test_concurrent_switches_persist_one_transition_and_reject_the_other():
    entered = threading.Event()
    release = threading.Event()
    events = []

    def writer(event):
        events.append(event)
        entered.set()
        assert release.wait(5)
        return True

    state = _new_state(writer)
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(_switch, state)
        assert entered.wait(5)
        second = executor.submit(_switch, state, request_id="native-request-2")
        release.set()
        fallback = first.result(timeout=5)
        with pytest.raises(RuntimeError, match="already"):
            second.result(timeout=5)
    assert state.route is fallback
    assert len(events) == 1


def test_reentrant_writer_cannot_publish_a_second_transition():
    events = []

    def writer(event):
        events.append(event)
        with pytest.raises(RuntimeError, match="progress"):
            _switch(state, request_id="native-request-2")
        return True

    state = _new_state(writer)
    _switch(state)
    assert len(events) == 1


@pytest.mark.parametrize("field", ["task_id", "attempt_id"])
@pytest.mark.parametrize("value", ["", " ", "\nidentity", "x" * 129, None, 1])
def test_state_rejects_invalid_custody_identity(field, value):
    with pytest.raises(ValueError, match="identity"):
        _new_state(lambda event: True, **{field: value})


@pytest.mark.parametrize("value", ["0" * 64, "f" * 63, None, 1])
def test_state_rejects_policy_digest_mismatch(value):
    with pytest.raises(ValueError, match="policy"):
        _new_state(lambda event: True, policy_sha256=value)


@pytest.mark.parametrize(
    "field", ["request_id", "failed_provider_attempt_id", "fallback_provider_attempt_id"]
)
@pytest.mark.parametrize("value", ["", " ", "\nidentity", "x" * 129, None, 1])
def test_switch_rejects_invalid_request_or_dispatch_identity_without_writing(field, value):
    events = []
    state = _new_state(lambda event: events.append(event) or True)
    with pytest.raises(ValueError, match="identity"):
        _switch(state, **{field: value})
    assert events == []
    assert state.route.provider == "zai-coding-plan"


@pytest.mark.parametrize(
    "change",
    [
        {"failed_provider_attempt_id": "native-request-1"},
        {"fallback_provider_attempt_id": "native-request-1"},
        {"fallback_provider_attempt_id": "glm-dispatch-1"},
    ],
)
def test_local_request_and_provider_attempts_must_have_distinct_identity(change):
    events = []
    state = _new_state(lambda event: events.append(event) or True)
    with pytest.raises(ValueError, match="distinct"):
        _switch(state, **change)
    assert events == []


def test_async_writer_is_rejected_before_constructing_routable_state():
    async def writer(event):
        return True

    with pytest.raises(TypeError, match="synchronous"):
        _new_state(writer)
