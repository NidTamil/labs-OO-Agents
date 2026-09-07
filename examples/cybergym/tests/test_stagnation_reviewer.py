# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Inert unit tests for the one-shot stagnation reviewer."""

from __future__ import annotations

import asyncio
import inspect
import json
from types import SimpleNamespace

import pytest

pytest.importorskip("nooa")

from examples.cybergym.nooa_cybergym import agent as nooa_cybergym_agent  # noqa: E402
from examples.cybergym.nooa_cybergym import util as nooa_cybergym_util  # noqa: E402
from examples.cybergym.nooa_cybergym.stagnation import (  # noqa: E402
    StagnationConfig,
    StagnationState,
    build_stagnation_snapshot,
)
from examples.cybergym.nooa_cybergym.stagnation_reviewer import (  # noqa: E402
    MAX_ADVICE_CHARS,
    MAX_TASK_DESCRIPTION_CHARS,
    StagnationAdvice,
    StagnationReviewer,
    StagnationReviewInput,
    build_stagnation_review_input,
)
from nooa.agentdoc import doc  # noqa: E402
from nooa.strategies import PredictStrategy  # noqa: E402
from nooa.unifiedllm.fake import FakeLLMClient  # noqa: E402
from nooa.unifiedllm.retry_config import RetryConfig  # noqa: E402


class CloseableLLM(FakeLLMClient):
    def __init__(self, *, model: str = "alternate-reviewer") -> None:
        super().__init__()
        self.model = model
        self.closed = 0

    async def aclose(self) -> None:
        self.closed += 1


class HangingCloseLLM(CloseableLLM):
    def __init__(self) -> None:
        super().__init__()
        self.close_started = asyncio.Event()

    async def aclose(self) -> None:
        self.close_started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            await asyncio.sleep(0.02)


def _config(**overrides) -> StagnationConfig:
    values = {
        "model": "alternate-reviewer",
        "trigger_age_sec": 100,
        "quiet_window_sec": 20,
        "minimum_submissions": 1,
        "reviewer_timeout_sec": 1,
        "reviewer_max_output_tokens": 1234,
        "recovery_window_sec": 3600,
    }
    values.update(overrides)
    return StagnationConfig(**values)


def _eligible_state() -> StagnationState:
    state = StagnationState(started_at=0)
    state.observe(now=100, submission_count=1, family_count=0)
    return state


def _agent_with_portfolio() -> nooa_cybergym_agent.CyberGymAgent:
    submission = SimpleNamespace(
        status="no_crash",
        source_model="finder-model",
        hypothesis="Try a different parser branch.",
        candidate_bytes=b"must not reach reviewer",
        output_excerpt="must not reach reviewer",
        fixed_image="must not reach reviewer",
    )
    portfolio = nooa_cybergym_agent.Portfolio(SimpleNamespace())
    portfolio.submissions = [submission]
    agent = nooa_cybergym_agent.CyberGymAgent(llm=FakeLLMClient())
    agent._portfolio = portfolio
    agent.description = "A length disagreement reaches the alternate parser."
    return agent


def _direct_input_values() -> dict[str, object]:
    return {
        "submission_count": 1,
        "family_count": 0,
        "status_counts": (("no_crash", 1),),
        "source_model_counts": (("finder-model", 1),),
        "recent_hypotheses": ("bounded",),
        "task_description": "bounded",
    }


def _review_log_payloads(caplog) -> list[dict[str, object]]:
    return [
        json.loads(record.message.removeprefix("stagnation_review "))
        for record in caplog.records
        if record.message.startswith("stagnation_review ")
    ]


def test_stagnation_reviewer_is_predict_only_and_has_no_worker_tools():
    strategy = StagnationReviewer.review._plan_strategy
    reviewer = StagnationReviewer(llm=FakeLLMClient())
    api = doc(reviewer).lower()
    review_prompt = inspect.getdoc(StagnationReviewer.review).lower()

    assert isinstance(strategy, PredictStrategy)
    assert strategy.config.max_retries == 1
    assert strategy.config.max_tokens is None
    assert not hasattr(reviewer, "shell")
    assert "submit(" not in api
    assert "portfolio" not in api
    assert "shell" not in api
    assert "vulnerable-build crash is candidate evidence" in review_prompt
    assert "never claim that the task is solved" in review_prompt
    assert "patch-specific" in review_prompt
    with pytest.raises(ValueError):
        StagnationAdvice(guidance="x" * (MAX_ADVICE_CHARS + 1), reasoning="bounded")
    with pytest.raises(ValueError):
        StagnationAdvice(guidance="bounded", reasoning="x" * (MAX_ADVICE_CHARS + 1))


def test_stagnation_review_input_is_structurally_bounded_and_excludes_sensitive_fields():
    submission = SimpleNamespace(
        status="no_crash",
        source_model="finder-model",
        hypothesis="Try the secondary parser.",
        original_path="/secret/original.poc",
        submitted_path="/secret/submitted.poc",
        candidate_bytes=b"private candidate bytes",
        output_excerpt="private verifier output",
        fixed_image="private fixed image",
    )
    snapshot = build_stagnation_snapshot([submission], family_count=0)
    review_input = build_stagnation_review_input(
        snapshot=snapshot,
        task_description="  vulnerable\n parser  " + ("x" * 10_000),
    )
    payload = review_input.model_dump()

    assert payload.keys() == set(_direct_input_values())
    assert len(review_input.task_description) == MAX_TASK_DESCRIPTION_CHARS
    assert review_input.task_description.startswith("vulnerable parser ")
    serialized = repr(payload)
    assert "/secret/" not in serialized
    assert "private candidate bytes" not in serialized
    assert "private verifier output" not in serialized
    assert "private fixed image" not in serialized
    with pytest.raises(ValueError):
        StagnationReviewInput(
            **{
                **_direct_input_values(),
                "task_description": "x" * (MAX_TASK_DESCRIPTION_CHARS + 1),
            }
        )
    with pytest.raises(ValueError):
        StagnationReviewInput(
            **{
                **_direct_input_values(),
                "recent_hypotheses": tuple("x" for _ in range(13)),
            }
        )


@pytest.mark.asyncio
async def test_stagnation_review_success_uses_bounded_transport_retries_and_applies_guidance(
    monkeypatch, caplog
):
    agent = _agent_with_portfolio()
    state = _eligible_state()
    reviewer_llm = CloseableLLM()
    make_calls = []

    class FakeReviewer:
        def __init__(self, *, llm):
            self.llm = llm

        async def review(self, review_input):
            assert state.escalation_attempted is True
            assert review_input.task_description == agent.description
            assert review_input.recent_hypotheses == ("Try a different parser branch.",)
            return StagnationAdvice(guidance="Try alternate lengths.", reasoning="One path used.")

    monkeypatch.setattr(
        nooa_cybergym_agent,
        "make_llm",
        lambda model, **kwargs: make_calls.append((model, kwargs)) or reviewer_llm,
    )
    monkeypatch.setattr(nooa_cybergym_agent, "StagnationReviewer", FakeReviewer)

    with caplog.at_level("INFO", logger="nooa_cybergym"):
        audit = await agent._attempt_stagnation_review(state=state, now=100, config=_config())

    assert audit is not None and audit.outcome == "success"
    assert audit.trigger_reason == "age"
    assert audit.review_id is None
    assert agent._portfolio.guidance == "Try alternate lengths."
    assert reviewer_llm.closed == 1
    assert audit.cleanup_status == "success"
    assert len(make_calls) == 1
    model, kwargs = make_calls[0]
    assert model == "alternate-reviewer"
    assert kwargs["max_tokens"] == 1234
    assert kwargs["retry_config"].max_retries == 5
    assert kwargs["retry_config"].base_delay == 3.0
    assert kwargs["retry_config"].max_delay == 30.0
    assert kwargs["retry_config"].rate_limit_extra_retries == 3
    assert kwargs["provider_scoped"] is True
    assert kwargs["inherit_reasoning_effort"] is False
    payloads = _review_log_payloads(caplog)
    assert len(payloads) == 1
    payload = payloads[0]
    assert payload["failure_type"] is None
    assert payload["cleanup_status"] == "success"
    assert "failure_message" not in payload


@pytest.mark.asyncio
async def test_timeout_rejects_cancellation_suppressing_late_result(monkeypatch, caplog):
    agent = _agent_with_portfolio()
    original_guidance = agent._portfolio.guidance
    reviewer_llm = CloseableLLM()
    reviewer_started = asyncio.Event()
    cancellation_seen = asyncio.Event()
    release_late_result = asyncio.Event()
    late_result = asyncio.Event()
    clock = SimpleNamespace(now=0.0)

    class FakeReviewer:
        def __init__(self, *, llm):
            self.llm = llm

        async def review(self, review_input):
            reviewer_started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cancellation_seen.set()
                await release_late_result.wait()
                late_result.set()
                return StagnationAdvice(guidance="late mutation", reasoning="too late")

    monkeypatch.setattr(nooa_cybergym_agent, "make_llm", lambda *args, **kwargs: reviewer_llm)
    monkeypatch.setattr(nooa_cybergym_agent, "StagnationReviewer", FakeReviewer)
    monkeypatch.setattr(agent, "_monotonic", lambda: clock.now)

    with caplog.at_level("WARNING", logger="nooa_cybergym"):
        attempt = asyncio.create_task(
            agent._attempt_stagnation_review(
                state=_eligible_state(), now=100, config=_config(reviewer_timeout_sec=0.001)
            )
        )
        await asyncio.wait_for(reviewer_started.wait(), timeout=1)
        clock.now = 1.0
        await asyncio.wait_for(cancellation_seen.wait(), timeout=1)
        audit = await asyncio.wait_for(attempt, timeout=1)

    assert audit is not None and audit.outcome == "timeout"
    payloads = _review_log_payloads(caplog)
    assert len(payloads) == 1
    assert payloads[0]["cleanup_status"] == "success"
    assert late_result.is_set() is False
    release_late_result.set()
    await asyncio.wait_for(late_result.wait(), timeout=1)
    assert agent._portfolio.guidance == original_guidance


@pytest.mark.asyncio
async def test_provider_failure_is_redacted_and_never_retried(monkeypatch, caplog):
    agent = _agent_with_portfolio()
    state = _eligible_state()
    reviewer_llm = CloseableLLM()
    attempts = 0

    class FakeReviewer:
        def __init__(self, *, llm):
            self.llm = llm

        async def review(self, review_input):
            nonlocal attempts
            attempts += 1
            raise RuntimeError("secret provider response")

    monkeypatch.setattr(nooa_cybergym_agent, "make_llm", lambda *args, **kwargs: reviewer_llm)
    monkeypatch.setattr(nooa_cybergym_agent, "StagnationReviewer", FakeReviewer)

    with caplog.at_level("WARNING", logger="nooa_cybergym"):
        first = await agent._attempt_stagnation_review(state=state, now=100, config=_config())
        second = await agent._attempt_stagnation_review(state=state, now=200, config=_config())

    assert first is not None and first.outcome == "failure"
    assert first.failure_type == "RuntimeError"
    assert second is None
    assert attempts == 1
    assert reviewer_llm.closed == 1
    assert "secret provider response" not in caplog.text
    payloads = _review_log_payloads(caplog)
    assert len(payloads) == 1
    assert payloads[0]["outcome"] == "failure"
    assert payloads[0]["cleanup_status"] == "success"


@pytest.mark.asyncio
async def test_whitespace_only_advice_fails_open_once_and_preserves_guidance(monkeypatch):
    agent = _agent_with_portfolio()
    original_guidance = agent._portfolio.guidance
    state = _eligible_state()
    reviewer_llm = CloseableLLM()
    attempts = 0

    class FakeReviewer:
        def __init__(self, *, llm):
            self.llm = llm

        async def review(self, review_input):
            nonlocal attempts
            attempts += 1
            return StagnationAdvice(guidance=" \n\t", reasoning=" \t")

    monkeypatch.setattr(nooa_cybergym_agent, "make_llm", lambda *args, **kwargs: reviewer_llm)
    monkeypatch.setattr(nooa_cybergym_agent, "StagnationReviewer", FakeReviewer)

    first = await agent._attempt_stagnation_review(state=state, now=100, config=_config())
    second = await agent._attempt_stagnation_review(state=state, now=200, config=_config())

    assert first is not None and first.outcome == "failure"
    assert first.failure_type == "ValidationError"
    assert second is None
    assert attempts == 1
    assert reviewer_llm.closed == 1
    assert agent._portfolio.guidance == original_guidance


@pytest.mark.asyncio
async def test_cancellation_suppressing_late_result_never_applies(monkeypatch, caplog):
    agent = _agent_with_portfolio()
    original_guidance = agent._portfolio.guidance
    reviewer_llm = CloseableLLM()
    started = asyncio.Event()
    late_result = asyncio.Event()

    class FakeReviewer:
        def __init__(self, *, llm):
            self.llm = llm

        async def review(self, review_input):
            started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                await asyncio.sleep(0.01)
                late_result.set()
                return StagnationAdvice(guidance="late mutation", reasoning="too late")

    monkeypatch.setattr(nooa_cybergym_agent, "make_llm", lambda *args, **kwargs: reviewer_llm)
    monkeypatch.setattr(nooa_cybergym_agent, "StagnationReviewer", FakeReviewer)
    with caplog.at_level("WARNING", logger="nooa_cybergym"):
        task = asyncio.create_task(
            agent._attempt_stagnation_review(state=_eligible_state(), now=100, config=_config())
        )
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    await asyncio.wait_for(late_result.wait(), timeout=0.1)

    assert agent._portfolio.guidance == original_guidance
    assert agent._stagnation_review_audit.outcome == "cancelled"
    payloads = _review_log_payloads(caplog)
    assert len(payloads) == 1
    assert payloads[0]["cleanup_status"] == "success"


@pytest.mark.asyncio
async def test_hanging_close_is_bounded_and_records_cleanup_timeout(monkeypatch, caplog):
    agent = _agent_with_portfolio()

    class BlockingAfterCancellationCloseLLM(CloseableLLM):
        def __init__(self) -> None:
            super().__init__()
            self.close_started = asyncio.Event()
            self.close_cancelled = asyncio.Event()
            self.release_close = asyncio.Event()
            self.close_finished = asyncio.Event()

        async def aclose(self) -> None:
            self.close_started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                self.close_cancelled.set()
                await self.release_close.wait()
            finally:
                self.close_finished.set()

    reviewer_llm = BlockingAfterCancellationCloseLLM()

    class FakeReviewer:
        def __init__(self, *, llm):
            self.llm = llm

        async def review(self, review_input):
            return StagnationAdvice(guidance="bounded", reasoning="bounded")

    monkeypatch.setattr(nooa_cybergym_agent, "make_llm", lambda *args, **kwargs: reviewer_llm)
    monkeypatch.setattr(nooa_cybergym_agent, "StagnationReviewer", FakeReviewer)
    monkeypatch.setattr(nooa_cybergym_agent, "REVIEWER_CLEANUP_TIMEOUT_SEC", 0.001)

    with caplog.at_level("INFO", logger="nooa_cybergym"):
        attempt = asyncio.create_task(
            agent._attempt_stagnation_review(state=_eligible_state(), now=100, config=_config())
        )
        await asyncio.wait_for(reviewer_llm.close_started.wait(), timeout=0.1)
        await asyncio.wait_for(reviewer_llm.close_cancelled.wait(), timeout=0.1)
        audit = await asyncio.wait_for(attempt, timeout=0.1)

    assert audit is not None and audit.outcome == "success"
    assert audit.cleanup_status == "timeout"
    assert audit.cleanup_failure_type == "TimeoutError"
    assert audit.one_shot_outcome == "timeout"
    assert audit.recovery_result == "not_entered"
    payloads = _review_log_payloads(caplog)
    assert len(payloads) == 1
    assert payloads[0]["cleanup_status"] == "timeout"
    assert reviewer_llm.release_close.is_set() is False
    reviewer_llm.release_close.set()
    await asyncio.wait_for(reviewer_llm.close_finished.wait(), timeout=0.1)


@pytest.mark.asyncio
async def test_repeated_cancellation_preserves_audit_during_hanging_cleanup(monkeypatch, caplog):
    agent = _agent_with_portfolio()
    reviewer_llm = HangingCloseLLM()
    review_started = asyncio.Event()

    class FakeReviewer:
        def __init__(self, *, llm):
            self.llm = llm

        async def review(self, review_input):
            review_started.set()
            await asyncio.Event().wait()

    monkeypatch.setattr(nooa_cybergym_agent, "make_llm", lambda *args, **kwargs: reviewer_llm)
    monkeypatch.setattr(nooa_cybergym_agent, "StagnationReviewer", FakeReviewer)
    with caplog.at_level("WARNING", logger="nooa_cybergym"):
        task = asyncio.create_task(
            agent._attempt_stagnation_review(state=_eligible_state(), now=100, config=_config())
        )
        await review_started.wait()
        task.cancel()
        await reviewer_llm.close_started.wait()
        assert agent._stagnation_review_audit.outcome == "cancelled"
        assert not [
            record for record in caplog.records if record.message.startswith("stagnation_review ")
        ]
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    assert agent._stagnation_review_audit.outcome == "cancelled"
    assert agent._stagnation_review_audit.cleanup_status == "cancelled"
    payloads = _review_log_payloads(caplog)
    assert len(payloads) == 1
    payload = payloads[0]
    assert payload["outcome"] == "cancelled"
    assert payload["cleanup_status"] == "cancelled"


@pytest.mark.asyncio
async def test_cleanup_exception_emits_one_final_redacted_audit(monkeypatch, caplog):
    agent = _agent_with_portfolio()

    class FailingCloseLLM(CloseableLLM):
        async def aclose(self) -> None:
            raise RuntimeError("secret cleanup detail")

    reviewer_llm = FailingCloseLLM()

    class FakeReviewer:
        def __init__(self, *, llm):
            self.llm = llm

        async def review(self, review_input):
            return StagnationAdvice(guidance="bounded", reasoning="bounded")

    monkeypatch.setattr(nooa_cybergym_agent, "make_llm", lambda *args, **kwargs: reviewer_llm)
    monkeypatch.setattr(nooa_cybergym_agent, "StagnationReviewer", FakeReviewer)
    with caplog.at_level("INFO", logger="nooa_cybergym"):
        audit = await agent._attempt_stagnation_review(
            state=_eligible_state(), now=100, config=_config()
        )

    assert audit is not None and audit.cleanup_status == "failure"
    assert audit.cleanup_failure_type == "RuntimeError"
    assert audit.one_shot_outcome == "failure"
    assert audit.recovery_result == "not_entered"
    payloads = _review_log_payloads(caplog)
    assert len(payloads) == 1
    assert payloads[0]["cleanup_status"] == "failure"
    assert "secret cleanup detail" not in caplog.text


@pytest.mark.asyncio
async def test_input_builder_failure_is_fail_open_with_state_fallback_and_redacted_log(
    monkeypatch, caplog
):
    agent = _agent_with_portfolio()
    state = _eligible_state()

    monkeypatch.setattr(
        nooa_cybergym_agent,
        "build_stagnation_snapshot",
        lambda *args, **kwargs: (_ for _ in ()).throw(ValueError("secret builder detail")),
    )
    monkeypatch.setattr(
        nooa_cybergym_agent,
        "make_llm",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("must not construct")),
    )

    with caplog.at_level("WARNING", logger="nooa_cybergym"):
        audit = await agent._attempt_stagnation_review(state=state, now=100, config=_config())

    assert audit is not None and audit.outcome == "failure"
    assert audit.submission_count == state.submission_count
    assert audit.family_count == state.family_count
    assert audit.failure_type == "ValueError"
    assert state.escalation_attempted is True
    assert "secret builder detail" not in caplog.text


def test_make_llm_preserves_worker_defaults_and_accepts_explicit_zero_retries(monkeypatch):
    captured = []
    fake_llm = FakeLLMClient()

    monkeypatch.setenv("NVIDIA_INTERNAL_API_KEY", "test-key")
    monkeypatch.setattr(
        nooa_cybergym_util,
        "get_llm_client",
        lambda model, **kwargs: captured.append((model, kwargs)) or fake_llm,
    )
    nooa_cybergym_util.make_llm("worker")
    no_retry = RetryConfig(max_retries=0, rate_limit_extra_retries=0)
    nooa_cybergym_util.make_llm("reviewer", retry_config=no_retry)

    assert captured[0][1]["retry_config"] == RetryConfig(max_retries=3)
    assert captured[1][1]["retry_config"] is no_retry


def test_provider_scoped_llm_uses_alias_endpoint_and_credential(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "worker-key-must-not-cross-provider")
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "glm-plan-key")
    monkeypatch.setattr(
        nooa_cybergym_util,
        "get_registry_config",
        lambda model: {
            "model_name": "openai/glm-5.3",
            "api_base": "https://api.z.ai/api/coding/paas/v4",
            "api_key_env": "ANTHROPIC_AUTH_TOKEN",
        },
    )

    kwargs = nooa_cybergym_util._provider_scoped_llm_client_kwargs("glm-5.3", 32768)

    assert kwargs["api_base"] == "https://api.z.ai/api/coding/paas/v4"
    assert kwargs["api_key"] == "glm-plan-key"
    assert kwargs["api_key"] != "worker-key-must-not-cross-provider"
    assert kwargs["max_tokens"] == 32768


def test_provider_scoped_llm_fails_closed_without_its_credential(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "worker-key-must-not-cross-provider")
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    monkeypatch.setattr(
        nooa_cybergym_util,
        "get_registry_config",
        lambda model: {
            "model_name": "openai/glm-5.3",
            "api_base": "https://api.z.ai/api/coding/paas/v4",
            "api_key_env": "ANTHROPIC_AUTH_TOKEN",
        },
    )

    with pytest.raises(RuntimeError, match="ANTHROPIC_AUTH_TOKEN"):
        nooa_cybergym_util._provider_scoped_llm_client_kwargs("glm-5.3", 32768)


def test_provider_scoped_reviewer_does_not_inherit_worker_reasoning_effort(monkeypatch):
    captured = []
    fake_llm = FakeLLMClient()
    monkeypatch.setenv("NOOA_CYBERGYM_REASONING_EFFORT", "max")
    monkeypatch.setattr(
        nooa_cybergym_util,
        "_provider_scoped_llm_client_kwargs",
        lambda model, max_tokens: {"max_tokens": max_tokens},
    )
    monkeypatch.setattr(
        nooa_cybergym_util,
        "get_llm_client",
        lambda model, **kwargs: captured.append((model, kwargs)) or fake_llm,
    )
    monkeypatch.setattr(
        nooa_cybergym_util,
        "_apply_reasoning_effort",
        lambda *args: (_ for _ in ()).throw(
            AssertionError("worker reasoning_effort must not cross providers")
        ),
    )

    nooa_cybergym_util.make_llm(
        "glm-5.3",
        provider_scoped=True,
        inherit_reasoning_effort=False,
    )

    assert captured[0][0] == "glm-5.3"


@pytest.mark.asyncio
async def test_empty_escalation_model_preserves_v1_without_constructing_reviewer(monkeypatch):
    agent = _agent_with_portfolio()

    monkeypatch.setattr(
        nooa_cybergym_agent,
        "make_llm",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("disabled escalation must not construct an LLM")
        ),
    )
    audit = await agent._attempt_stagnation_review(
        state=_eligible_state(), now=100, config=_config(model="")
    )

    assert audit is None
