# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Inert orchestration tests for v2 stagnation timer and recovery wiring."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest

pytest.importorskip("nooa")

from examples.cybergym.nooa_cybergym import agent as agent_module  # noqa: E402
from examples.cybergym.nooa_cybergym.stagnation import StagnationConfig  # noqa: E402
from examples.cybergym.nooa_cybergym.stagnation_reviewer import (  # noqa: E402
    StagnationAdvice,
)
from nooa.unifiedllm.fake import FakeLLMClient  # noqa: E402


class FakeClock:
    def __init__(self, now: float = 0) -> None:
        self.now = now

    def monotonic(self) -> float:
        return self.now


class FakeFinder:
    shell = None

    def record_portfolio_context_if_changed(self, reason: str) -> None:
        pass


class TerminalStorageManager:
    def __init__(self) -> None:
        self.failure = agent_module.SubmissionStorageError("latched storage failure")
        self.failed = asyncio.Event()

    async def wait_for_storage_failure(self):
        await self.failed.wait()
        return self.failure


def _config(**overrides) -> StagnationConfig:
    values = {
        "model": "alternate-reviewer",
        "trigger_age_sec": 10,
        "quiet_window_sec": 5,
        "minimum_submissions": 1,
        "reviewer_timeout_sec": 2,
        "reviewer_max_output_tokens": 128,
        "recovery_window_sec": 20,
    }
    values.update(overrides)
    return StagnationConfig(**values)


def _crash_submission(number: int, cluster_key: str) -> SimpleNamespace:
    return SimpleNamespace(
        submission_number=number,
        status="crashed",
        source_agent="finder",
        source_model="finder",
        hypothesis=f"exercise {cluster_key}",
        fingerprint=SimpleNamespace(
            kind="crash",
            cluster_key=cluster_key,
            top_frames=(cluster_key,),
            summary=f"verified {cluster_key}",
        ),
        submitted_path=f"/workspace/{number}.poc",
        original_path=f"/tmp/{number}.poc",
    )


def _patch_inert_solve(monkeypatch, tmp_path, config: StagnationConfig, *, fake_final: bool = True):
    description = tmp_path / "description.txt"
    description.write_text("A parser length disagreement reaches a vulnerable branch.")
    portfolio = agent_module.Portfolio(SimpleNamespace())
    portfolio.submissions = [
        SimpleNamespace(
            submission_number=1,
            status="no_crash",
            hypothesis="first attempt",
            source_model="finder",
        )
    ]

    monkeypatch.setattr(agent_module, "DESCRIPTION_PATH", description)
    monkeypatch.setattr(agent_module, "STAGNATION_CONFIG", config)
    monkeypatch.setattr(agent_module, "LANES", [SimpleNamespace(label="lane")])
    monkeypatch.setattr(agent_module, "SOFT_TIMEOUT_SEC", 1_000)
    monkeypatch.setattr(agent_module, "_get_rss_mb", lambda: 0)
    monkeypatch.setattr(agent_module, "Portfolio", lambda manager: portfolio)
    monkeypatch.setattr(agent_module, "SubmissionManager", lambda shell: SimpleNamespace())

    class InertSolveAgent(agent_module.CyberGymAgent):
        def _make_finder(self, lane):
            return FakeFinder()

        async def _run_finder(self, finder):
            await asyncio.Event().wait()

        async def shutdown(self):
            self._shutdown_complete = True

    if fake_final:

        class InertSolveAgentWithFinal(InertSolveAgent):
            async def _finalize_portfolio(self):
                return SimpleNamespace(
                    poc_path="/logs/artifacts/final_submission/poc", sha256="abc"
                )

        return portfolio, InertSolveAgentWithFinal
    return portfolio, InertSolveAgent


@pytest.mark.asyncio
async def test_timer_wakeup_uses_event_gate_without_real_sleep(monkeypatch):
    clock = FakeClock(10)
    timer_started = asyncio.Event()
    release_timer = asyncio.Event()
    release_worker = asyncio.Event()
    real_sleep = asyncio.sleep

    class TimerAgent(agent_module.CyberGymAgent):
        @staticmethod
        def _monotonic() -> float:
            return clock.monotonic()

    agent = TimerAgent(llm=FakeLLMClient())
    agent._portfolio = agent_module.Portfolio(SimpleNamespace())

    async def fake_sleep(delay):
        if delay == 0:
            await real_sleep(0)
            return
        assert delay == 5
        timer_started.set()
        await release_timer.wait()

    async def worker():
        await release_worker.wait()

    monkeypatch.setattr(agent_module.asyncio, "sleep", fake_sleep)
    worker_task = asyncio.create_task(worker())
    wait_task = asyncio.create_task(agent._wait_until({worker_task}, deadline=15))
    await timer_started.wait()
    release_timer.set()

    assert await wait_task == set()
    assert not worker_task.done()
    worker_task.cancel()
    await asyncio.gather(worker_task, return_exceptions=True)


@pytest.mark.asyncio
async def test_timer_wait_cancellation_cleans_up_auxiliary_tasks(monkeypatch):
    timer_started = asyncio.Event()
    timer_cancelled = asyncio.Event()
    worker_release = asyncio.Event()
    real_sleep = asyncio.sleep

    class TimerAgent(agent_module.CyberGymAgent):
        @staticmethod
        def _monotonic() -> float:
            return 10

    agent = TimerAgent(llm=FakeLLMClient())
    agent._portfolio = agent_module.Portfolio(SimpleNamespace())

    async def fake_sleep(delay):
        if delay == 0:
            await real_sleep(0)
            return
        timer_started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            timer_cancelled.set()
            raise

    async def worker():
        await worker_release.wait()

    monkeypatch.setattr(agent_module.asyncio, "sleep", fake_sleep)
    worker_task = asyncio.create_task(worker())
    wait_task = asyncio.create_task(agent._wait_until({worker_task}, deadline=15))
    await timer_started.wait()
    wait_task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await wait_task
    assert timer_cancelled.is_set()
    worker_task.cancel()
    await asyncio.gather(worker_task, return_exceptions=True)


@pytest.mark.asyncio
async def test_enabled_solve_claims_once_and_enters_honest_no_final_path_at_deadline(
    monkeypatch, tmp_path
):
    config = _config()
    _portfolio, InertSolveAgent = _patch_inert_solve(
        monkeypatch, tmp_path, config, fake_final=False
    )
    clock = FakeClock()
    wakeups = []
    claims = []

    class RecoveryExpiryAgent(InertSolveAgent):
        @staticmethod
        def _monotonic() -> float:
            return clock.monotonic()

        async def _wait_until(self, active, *, deadline):
            wakeups.append(deadline)
            clock.now = deadline
            return set()

        async def _wait(self, active):
            raise AssertionError("enabled deterministic deadlines must use the timer wait")

        async def _attempt_stagnation_review(self, *, state, now, config):
            assert state.claim_escalation(now=now, config=config) is True
            claims.append((now, state.family_count_at_escalation))
            return SimpleNamespace(outcome="failure")

    agent = RecoveryExpiryAgent(llm=FakeLLMClient())
    with pytest.raises(RuntimeError, match="No verified crashing PoC"):
        await agent.solve("inert")

    assert wakeups == [10, 30]
    assert claims == [(10, 0)]


@pytest.mark.asyncio
async def test_reviewer_stop_finalizes_without_respawning_finished_finder(monkeypatch, tmp_path):
    portfolio, InertSolveAgent = _patch_inert_solve(monkeypatch, tmp_path, _config(model=""))
    portfolio.submissions = [
        SimpleNamespace(
            submission_number=1,
            status="crashed",
            source_agent="expander",
            source_model="finder",
            hypothesis="verified target crash",
            fingerprint=SimpleNamespace(
                kind="crash",
                cluster_key="msan:target-family",
                top_frames=("target_parser",),
                summary="verified target crash",
            ),
            submitted_path="/workspace/submissions/poc_001",
            original_path="/tmp/poc_001",
        )
    ]
    finder_runs = 0
    review_calls = 0

    class StopAgent(InertSolveAgent):
        async def _run_finder(self, finder):
            nonlocal finder_runs
            finder_runs += 1

        async def _review(self, current_portfolio_state):
            nonlocal review_calls
            review_calls += 1
            return agent_module.Review(
                on_target=True,
                guidance="portfolio exhausted",
                stop=True,
                reasoning="no distinct path remains",
            )

    agent = StopAgent(llm=FakeLLMClient())
    result = await agent.solve("inert")

    assert finder_runs == 1
    assert review_calls == 1
    assert portfolio.stop is True
    assert "Final PoC:" in result


@pytest.mark.asyncio
async def test_new_family_during_recovery_resumes_normal_orchestration(monkeypatch, tmp_path):
    config = _config()
    portfolio, InertSolveAgent = _patch_inert_solve(monkeypatch, tmp_path, config)
    clock = FakeClock()
    wakeups = []
    claims = []
    normal_wait_calls = 0

    new_family = SimpleNamespace(
        submission_number=2,
        status="crashed",
        source_agent="expander",
        source_model="finder",
        hypothesis="new parser branch",
        fingerprint=SimpleNamespace(
            kind="crash",
            cluster_key="asan:new-family",
            top_frames=("parse_new",),
            summary="new verified family",
        ),
        submitted_path="/workspace/new.poc",
        original_path="/tmp/new.poc",
    )

    class RecoveryProgressAgent(InertSolveAgent):
        @staticmethod
        def _monotonic() -> float:
            return clock.monotonic()

        async def _wait_until(self, active, *, deadline):
            wakeups.append(deadline)
            if deadline == 10:
                clock.now = 10
            else:
                clock.now = 20
                portfolio.submissions.append(new_family)
            return set()

        async def _wait(self, active):
            nonlocal normal_wait_calls
            normal_wait_calls += 1
            self._stop_event.set()
            return set()

        async def _attempt_stagnation_review(self, *, state, now, config):
            assert state.claim_escalation(now=now, config=config) is True
            claims.append((now, state.family_count_at_escalation))
            return SimpleNamespace(outcome="failure")

        async def _review(self, current_portfolio_state):
            return agent_module.Review(
                on_target=True,
                guidance="continue normal exploration",
                stop=False,
                reasoning="a new family appeared",
            )

    agent = RecoveryProgressAgent(llm=FakeLLMClient())
    result = await agent.solve("inert")

    assert wakeups == [10, 30]
    assert claims == [(10, 0)]
    assert normal_wait_calls == 1
    assert portfolio.distinct_families == 1
    assert "Final PoC:" in result


@pytest.mark.asyncio
async def test_disabled_solve_uses_original_wait_and_no_v2_decision_points(monkeypatch, tmp_path):
    _portfolio, InertSolveAgent = _patch_inert_solve(monkeypatch, tmp_path, _config(model=""))
    original_wait_calls = 0

    class DisabledAgent(InertSolveAgent):
        async def _wait(self, active):
            nonlocal original_wait_calls
            original_wait_calls += 1
            self._stop_event.set()
            return set()

        async def _wait_until(self, active, *, deadline):
            raise AssertionError("disabled v2 must not add a timer decision point")

        async def _attempt_stagnation_review(self, *, state, now, config):
            raise AssertionError("disabled v2 must not attempt escalation")

    agent = DisabledAgent(llm=FakeLLMClient())
    result = await agent.solve("inert")

    assert original_wait_calls == 1
    assert "Final PoC:" in result


@pytest.mark.asyncio
async def test_stale_ordinary_review_is_rejected_and_fresh_review_is_scheduled(
    monkeypatch, tmp_path, caplog
):
    config = _config(trigger_age_sec=1_000, minimum_submissions=10)
    portfolio, InertSolveAgent = _patch_inert_solve(monkeypatch, tmp_path, config)
    first_family = _crash_submission(1, "family-one")
    second_family = _crash_submission(2, "family-two")
    portfolio.submissions = [first_family]
    portfolio.mark_expanded(first_family.submission_number)
    review_calls = 0

    class StaleReviewAgent(InertSolveAgent):
        async def _wait(self, active):
            task = next(iter(active))
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            return {task}

        async def _review(self, current_portfolio_state):
            nonlocal review_calls
            review_calls += 1
            if review_calls == 1:
                portfolio.submissions.append(second_family)
                portfolio.mark_expanded(second_family.submission_number)
                return agent_module.Review(
                    on_target=True,
                    guidance="stale guidance",
                    stop=True,
                    reasoning="superseded while awaiting",
                )
            assert portfolio.guidance != "stale guidance"
            return agent_module.Review(
                on_target=True,
                guidance="fresh guidance",
                stop=True,
                reasoning="latest snapshot",
            )

    with caplog.at_level("INFO", logger="nooa_cybergym"):
        result = await StaleReviewAgent(llm=FakeLLMClient()).solve("inert")

    assert review_calls == 2
    assert portfolio.guidance == "fresh guidance"
    assert portfolio.stop is True
    assert "Final PoC:" in result
    review_events = [
        record.message
        for record in caplog.records
        if record.message.startswith("portfolio_review_event ")
    ]
    assert '"outcome": "stale"' in review_events[0]
    assert '"outcome": "completed"' in review_events[1]
    assert '"review_id": 1' in review_events[0]
    assert '"review_id": 2' in review_events[1]


@pytest.mark.asyncio
async def test_plateau_callback_is_one_shot_and_local_stops_defer_until_progress(
    monkeypatch, tmp_path
):
    config = _config(
        trigger_age_sec=1_000,
        minimum_submissions=1,
        consecutive_no_growth_reviews=2,
    )
    portfolio, InertSolveAgent = _patch_inert_solve(monkeypatch, tmp_path, config)
    first_family = _crash_submission(1, "family-one")
    second_family = _crash_submission(2, "family-two")
    portfolio.submissions = [first_family]
    portfolio.mark_expanded(first_family.submission_number)
    review_calls = 0
    callback_calls = 0

    class PlateauAgent(InertSolveAgent):
        async def _wait(self, active):
            if review_calls == 4:
                portfolio.submissions.append(second_family)
                portfolio.mark_expanded(second_family.submission_number)
            task = next(iter(active))
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            return {task}

        async def _wait_until(self, active, *, deadline):
            return await self._wait(active)

        async def _review(self, current_portfolio_state):
            nonlocal review_calls
            review_calls += 1
            return agent_module.Review(
                on_target=True,
                guidance=f"ordinary review {review_calls}",
                stop=review_calls >= 3,
                reasoning="synthetic plateau sequence",
            )

        async def _attempt_stagnation_review(self, *, state, now, config):
            nonlocal callback_calls
            assert state.escalation_reason(now=now, config=config) == "plateau"
            assert state.claim_escalation(now=now, config=config) is True
            callback_calls += 1
            portfolio.apply_review(
                agent_module.Review(
                    on_target=True,
                    guidance="stronger callback guidance",
                    stop=False,
                    reasoning="one-shot callback",
                )
            )
            return SimpleNamespace(outcome="success", cleanup_status="success")

    result = await PlateauAgent(llm=FakeLLMClient()).solve("inert")

    assert review_calls == 5
    assert callback_calls == 1
    assert portfolio.distinct_families == 2
    assert portfolio.stop is True
    assert "Final PoC:" in result


@pytest.mark.asyncio
async def test_callback_failure_discards_triggering_stop_but_next_review_may_stop(
    monkeypatch, tmp_path
):
    config = _config(
        trigger_age_sec=1_000,
        minimum_submissions=1,
        consecutive_no_growth_reviews=1,
    )
    portfolio, InertSolveAgent = _patch_inert_solve(monkeypatch, tmp_path, config)
    first_family = _crash_submission(1, "family-one")
    portfolio.submissions = [first_family]
    portfolio.mark_expanded(first_family.submission_number)
    review_calls = 0
    callback_calls = 0

    class FailedCallbackAgent(InertSolveAgent):
        async def _wait(self, active):
            if review_calls >= 3:
                raise AssertionError("a later completed review should have stopped the loop")
            task = next(iter(active))
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            return {task}

        async def _wait_until(self, active, *, deadline):
            return await self._wait(active)

        async def _review(self, current_portfolio_state):
            nonlocal review_calls
            review_calls += 1
            return agent_module.Review(
                on_target=True,
                guidance=f"review {review_calls}",
                stop=review_calls >= 2,
                reasoning="synthetic callback failure",
            )

        async def _attempt_stagnation_review(self, *, state, now, config):
            nonlocal callback_calls
            assert state.claim_escalation(now=now, config=config) is True
            state.cancel_recovery()
            callback_calls += 1
            return SimpleNamespace(outcome="failure", cleanup_status="success")

    failed_agent = FailedCallbackAgent(llm=FakeLLMClient())
    result = await failed_agent.solve("inert")

    assert review_calls == 3
    assert callback_calls == 1
    assert portfolio.stop is True
    assert "Final PoC:" in result


@pytest.mark.asyncio
async def test_external_stop_cancels_inflight_callback_and_is_audited(monkeypatch):
    portfolio = agent_module.Portfolio(SimpleNamespace())
    portfolio.submissions = [_crash_submission(1, "family-one")]
    agent = agent_module.CyberGymAgent(llm=FakeLLMClient())
    agent._portfolio = portfolio
    agent.description = "bounded synthetic description"
    review_started = asyncio.Event()
    review_cancelled = asyncio.Event()

    class FakeReviewer:
        def __init__(self, *, llm):
            self.llm = llm

        async def review(self, review_input):
            review_started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                review_cancelled.set()
                raise

    monkeypatch.setattr(agent_module, "make_llm", lambda *args, **kwargs: FakeLLMClient())
    monkeypatch.setattr(agent_module, "StagnationReviewer", FakeReviewer)
    state = agent_module.StagnationState(started_at=0)
    state.observe(now=0, submission_count=1, family_count=1)

    attempt = asyncio.create_task(
        agent._attempt_stagnation_review(state=state, now=10, config=_config())
    )
    await review_started.wait()
    agent.request_stop()
    audit = await asyncio.wait_for(attempt, timeout=0.2)

    assert audit is not None and audit.outcome == "cancelled"
    assert review_cancelled.is_set()
    assert state.recovery_expired_without_progress(now=30, config=_config()) is False


@pytest.mark.asyncio
async def test_callback_result_at_recovery_deadline_is_rejected(monkeypatch):
    clock = FakeClock(10)
    portfolio = agent_module.Portfolio(SimpleNamespace())
    portfolio.submissions = [_crash_submission(1, "family-one")]

    class DeadlineAgent(agent_module.CyberGymAgent):
        @staticmethod
        def _monotonic() -> float:
            return clock.monotonic()

    agent = DeadlineAgent(llm=FakeLLMClient())
    agent._portfolio = portfolio
    agent.description = "bounded synthetic description"

    class FakeReviewer:
        def __init__(self, *, llm):
            self.llm = llm

        async def review(self, review_input):
            clock.now = 30
            return StagnationAdvice(guidance="too late", reasoning="deadline reached")

    monkeypatch.setattr(agent_module, "make_llm", lambda *args, **kwargs: FakeLLMClient())
    monkeypatch.setattr(agent_module, "StagnationReviewer", FakeReviewer)
    state = agent_module.StagnationState(started_at=0)
    state.observe(now=0, submission_count=1, family_count=1)

    audit = await agent._attempt_stagnation_review(
        state=state,
        now=10,
        config=_config(reviewer_timeout_sec=100, recovery_window_sec=20),
    )

    assert audit is not None and audit.outcome == "timeout"
    assert portfolio.guidance != "too late"
    assert state.recovery_expired_without_progress(now=30, config=_config()) is True


@pytest.mark.asyncio
async def test_ordinary_review_completing_at_recovery_expiry_is_not_applied(monkeypatch):
    clock = FakeClock(10)
    portfolio = agent_module.Portfolio(SimpleNamespace())
    portfolio.submissions = [_crash_submission(1, "family-one")]
    original_guidance = portfolio.guidance
    config = _config(reviewer_timeout_sec=2, recovery_window_sec=20)
    state = agent_module.StagnationState(started_at=0)
    state.observe(now=0, submission_count=1, family_count=1)
    assert state.claim_escalation(now=10, config=config) is True

    class LateOrdinaryReviewAgent(agent_module.CyberGymAgent):
        @staticmethod
        def _monotonic() -> float:
            return clock.monotonic()

        async def _review(self, current_portfolio_state):
            clock.now = 30
            return agent_module.Review(
                on_target=True,
                guidance="late ordinary guidance",
                stop=True,
                reasoning="completed at recovery expiry",
            )

    agent = LateOrdinaryReviewAgent(llm=FakeLLMClient())
    agent._portfolio = portfolio

    review, event = await agent._run_portfolio_review(state, config=config)

    assert review is None
    assert event is not None and event.outcome == "failed"
    assert portfolio.guidance == original_guidance
    assert state.recovery_expired_without_progress(now=30, config=config) is True


@pytest.mark.asyncio
async def test_family_growth_during_ordinary_review_releases_recovery_before_expiry():
    clock = FakeClock(10)
    portfolio = agent_module.Portfolio(SimpleNamespace())
    portfolio.submissions = [_crash_submission(1, "family-one")]
    config = _config(recovery_window_sec=20)
    state = agent_module.StagnationState(started_at=0)
    state.observe(now=0, submission_count=1, family_count=1)
    assert state.claim_escalation(now=10, config=config) is True

    class ProgressReviewAgent(agent_module.CyberGymAgent):
        @staticmethod
        def _monotonic() -> float:
            return clock.monotonic()

        async def _review(self, current_portfolio_state):
            portfolio.submissions.append(_crash_submission(2, "family-two"))
            clock.now = 29
            return agent_module.Review(
                on_target=True,
                guidance="superseded ordinary guidance",
                stop=True,
                reasoning="new family arrived",
            )

    agent = ProgressReviewAgent(llm=FakeLLMClient())
    agent._portfolio = portfolio

    review, event = await agent._run_portfolio_review(state, config=config)

    assert review is None
    assert event is not None and event.outcome == "stale"
    assert state.family_count == 2
    assert state.recovery_active(now=29, config=config) is False
    assert state.recovery_expired_without_progress(now=31, config=config) is False


@pytest.mark.asyncio
@pytest.mark.parametrize("callback_outcome", ["failure", "timeout"])
async def test_callback_failure_at_recovery_expiry_preserves_terminal_claim(
    callback_outcome,
):
    clock = FakeClock(10)
    portfolio = agent_module.Portfolio(SimpleNamespace())
    portfolio.submissions = [_crash_submission(1, "family-one")]
    config = _config(
        trigger_age_sec=1_000,
        minimum_submissions=1,
        consecutive_no_growth_reviews=1,
        recovery_window_sec=20,
    )
    state = agent_module.StagnationState(started_at=0)
    state.observe(now=0, submission_count=1, family_count=1)
    state.complete_review(state.begin_review(), parsed=True)
    state.complete_review(state.begin_review(), parsed=True)

    class ExpiredCallbackAgent(agent_module.CyberGymAgent):
        @staticmethod
        def _monotonic() -> float:
            return clock.monotonic()

        async def _attempt_stagnation_review(self, *, state, now, config):
            assert state.claim_escalation(now=now, config=config) is True
            clock.now = 30
            return SimpleNamespace(outcome=callback_outcome, cleanup_status="success")

    agent = ExpiredCallbackAgent(llm=FakeLLMClient())
    agent._portfolio = portfolio
    should_stop = await agent._apply_review_with_arbitration(
        agent_module.Review(
            on_target=True,
            guidance="pending local stop",
            stop=True,
            reasoning="plateau",
        ),
        state=state,
        config=config,
    )

    assert should_stop is False
    assert state.escalation_claimed_at == 10
    assert state.recovery_expired_without_progress(now=30, config=config) is True


@pytest.mark.asyncio
async def test_coincident_recovery_and_soft_expiry_fails_before_finalize_or_respawn(
    monkeypatch, tmp_path
):
    config = _config(
        trigger_age_sec=1_000,
        consecutive_no_growth_reviews=1,
        recovery_window_sec=20,
    )
    portfolio, InertSolveAgent = _patch_inert_solve(monkeypatch, tmp_path, config, fake_final=False)
    portfolio.submissions = [_crash_submission(1, "family-one")]
    portfolio.mark_expanded(1)
    monkeypatch.setattr(agent_module, "SOFT_TIMEOUT_SEC", 30)
    clock = FakeClock()
    finder_runs = 0
    finalize_calls = 0

    class CoincidentExpiryAgent(InertSolveAgent):
        @staticmethod
        def _monotonic() -> float:
            return clock.monotonic()

        async def _run_finder(self, finder):
            nonlocal finder_runs
            finder_runs += 1

        async def _wait_until(self, active, *, deadline):
            clock.now = 10
            done, _ = await asyncio.wait(active)
            return done

        async def _run_portfolio_review(self, state, *, config):
            state.complete_review(state.begin_review(), parsed=True)
            state.complete_review(state.begin_review(), parsed=True)
            return (
                agent_module.Review(
                    on_target=True,
                    guidance="defer this stop to the stronger callback",
                    stop=True,
                    reasoning="synthetic plateau",
                ),
                None,
            )

        async def _attempt_stagnation_review(self, *, state, now, config):
            assert state.claim_escalation(now=now, config=config) is True
            clock.now = 30
            return SimpleNamespace(outcome="failure", cleanup_status="success")

        async def _finalize_portfolio(self):
            nonlocal finalize_calls
            finalize_calls += 1
            raise AssertionError("recovery expiry must prevent finalization")

    agent = CoincidentExpiryAgent(llm=FakeLLMClient())
    with pytest.raises(RuntimeError, match="stagnation recovery window ended"):
        await agent.solve("inert")

    assert finder_runs == 1
    assert finalize_calls == 0
    assert agent._active_tasks == set()


@pytest.mark.asyncio
async def test_disabled_review_parent_cancellation_cancels_inner_review_without_orphan():
    manager = TerminalStorageManager()
    portfolio = agent_module.Portfolio(manager)
    review_started = asyncio.Event()
    review_cancelled = asyncio.Event()

    class HangingReviewAgent(agent_module.CyberGymAgent):
        async def _review(self, current_portfolio_state):
            review_started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                review_cancelled.set()
                raise

    agent = HangingReviewAgent(llm=FakeLLMClient())
    agent._portfolio = portfolio
    pending = asyncio.create_task(agent._run_portfolio_review(None))
    await asyncio.wait_for(review_started.wait(), timeout=0.2)
    pending.cancel()

    with pytest.raises(asyncio.CancelledError):
        await pending

    await asyncio.wait_for(review_cancelled.wait(), timeout=0.2)


@pytest.mark.asyncio
async def test_terminal_storage_interrupts_ordinary_review_and_propagates_original_error():
    manager = TerminalStorageManager()
    portfolio = agent_module.Portfolio(manager)
    portfolio.submissions = [_crash_submission(1, "family-one")]
    review_started = asyncio.Event()
    review_cancelled = asyncio.Event()

    class HangingReviewAgent(agent_module.CyberGymAgent):
        async def _review(self, current_portfolio_state):
            review_started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                review_cancelled.set()
                raise

    agent = HangingReviewAgent(llm=FakeLLMClient())
    agent._portfolio = portfolio
    started_at = agent._monotonic()
    state = agent_module.StagnationState(started_at=started_at)
    state.observe(now=started_at, submission_count=1, family_count=1)
    pending = asyncio.create_task(agent._run_portfolio_review(state))
    await asyncio.wait_for(review_started.wait(), timeout=0.2)
    manager.failed.set()

    with pytest.raises(agent_module.SubmissionStorageError) as raised:
        await asyncio.wait_for(pending, timeout=0.2)

    assert raised.value is manager.failure
    assert review_cancelled.is_set()


@pytest.mark.asyncio
async def test_terminal_storage_interrupts_stronger_callback_and_propagates_original_error(
    monkeypatch,
):
    manager = TerminalStorageManager()
    portfolio = agent_module.Portfolio(manager)
    portfolio.submissions = [_crash_submission(1, "family-one")]
    review_started = asyncio.Event()
    review_cancelled = asyncio.Event()

    class HangingReviewer:
        def __init__(self, *, llm):
            self.llm = llm

        async def review(self, review_input):
            review_started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                review_cancelled.set()
                raise

    agent = agent_module.CyberGymAgent(llm=FakeLLMClient())
    agent._portfolio = portfolio
    agent.description = "bounded synthetic description"
    state = agent_module.StagnationState(started_at=0)
    state.observe(now=0, submission_count=1, family_count=1)
    monkeypatch.setattr(agent_module, "make_llm", lambda *args, **kwargs: FakeLLMClient())
    monkeypatch.setattr(agent_module, "StagnationReviewer", HangingReviewer)
    pending = asyncio.create_task(
        agent._attempt_stagnation_review(state=state, now=10, config=_config())
    )
    await review_started.wait()
    manager.failed.set()

    with pytest.raises(agent_module.SubmissionStorageError) as raised:
        await asyncio.wait_for(pending, timeout=0.2)

    assert raised.value is manager.failure
    assert review_cancelled.is_set()


@pytest.mark.asyncio
async def test_terminal_storage_interrupts_callback_cleanup_and_propagates_original_error(
    monkeypatch,
):
    manager = TerminalStorageManager()
    portfolio = agent_module.Portfolio(manager)
    portfolio.submissions = [_crash_submission(1, "family-one")]
    cleanup_started = asyncio.Event()
    cleanup_cancelled = asyncio.Event()

    class HangingCleanupLLM(FakeLLMClient):
        async def aclose(self):
            cleanup_started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cleanup_cancelled.set()
                raise

    class ImmediateReviewer:
        def __init__(self, *, llm):
            self.llm = llm

        async def review(self, review_input):
            return StagnationAdvice(guidance="bounded", reasoning="bounded")

    reviewer_llm = HangingCleanupLLM()
    agent = agent_module.CyberGymAgent(llm=FakeLLMClient())
    agent._portfolio = portfolio
    agent.description = "bounded synthetic description"
    state = agent_module.StagnationState(started_at=0)
    state.observe(now=0, submission_count=1, family_count=1)
    monkeypatch.setattr(agent_module, "make_llm", lambda *args, **kwargs: reviewer_llm)
    monkeypatch.setattr(agent_module, "StagnationReviewer", ImmediateReviewer)
    pending = asyncio.create_task(
        agent._attempt_stagnation_review(state=state, now=10, config=_config())
    )
    await cleanup_started.wait()
    manager.failed.set()

    with pytest.raises(agent_module.SubmissionStorageError) as raised:
        await asyncio.wait_for(pending, timeout=0.2)

    assert raised.value is manager.failure
    assert cleanup_cancelled.is_set()


@pytest.mark.asyncio
async def test_cooperative_stop_during_callback_cleanup_cancels_cleanup(monkeypatch):
    cleanup_started = asyncio.Event()
    cleanup_cancelled = asyncio.Event()

    class HangingCleanupLLM(FakeLLMClient):
        async def aclose(self):
            cleanup_started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cleanup_cancelled.set()
                raise

    class ImmediateReviewer:
        def __init__(self, *, llm):
            self.llm = llm

        async def review(self, review_input):
            return StagnationAdvice(guidance="must not apply", reasoning="cleanup pending")

    reviewer_llm = HangingCleanupLLM()
    portfolio = agent_module.Portfolio(SimpleNamespace())
    portfolio.submissions = [_crash_submission(1, "family-one")]
    original_guidance = portfolio.guidance
    agent = agent_module.CyberGymAgent(llm=FakeLLMClient())
    agent._portfolio = portfolio
    agent.description = "bounded synthetic description"
    state = agent_module.StagnationState(started_at=0)
    state.observe(now=0, submission_count=1, family_count=1)
    monkeypatch.setattr(agent_module, "make_llm", lambda *args, **kwargs: reviewer_llm)
    monkeypatch.setattr(agent_module, "StagnationReviewer", ImmediateReviewer)

    attempt = asyncio.create_task(
        agent._attempt_stagnation_review(state=state, now=10, config=_config())
    )
    await cleanup_started.wait()
    agent.request_stop()
    done, _ = await asyncio.wait({attempt}, timeout=0.1)

    assert attempt in done
    audit = attempt.result()
    assert audit is not None and audit.outcome == "cancelled"
    assert audit.cleanup_status == "cancelled"
    assert cleanup_cancelled.is_set()
    assert portfolio.guidance == original_guidance


@pytest.mark.asyncio
async def test_ordinary_review_authority_paths_emit_terminal_events(monkeypatch, caplog):
    portfolio = agent_module.Portfolio(SimpleNamespace())
    portfolio.submissions = [_crash_submission(1, "family-one")]
    review_started = asyncio.Event()

    class HangingReviewAgent(agent_module.CyberGymAgent):
        async def _review(self, current_portfolio_state):
            review_started.set()
            await asyncio.Event().wait()

    agent = HangingReviewAgent(llm=FakeLLMClient())
    agent._portfolio = portfolio
    state = agent_module.StagnationState(started_at=agent._monotonic())
    state.observe(now=state.started_at, submission_count=1, family_count=1)
    with caplog.at_level("WARNING", logger="nooa_cybergym"):
        pending = asyncio.create_task(agent._run_portfolio_review(state))
        await review_started.wait()
        agent.request_stop()
        review, event = await pending

    assert review is None
    assert event is not None and event.outcome == "cancelled"
    assert '"review_id": 1' in caplog.text

    memory_agent = HangingReviewAgent(llm=FakeLLMClient())
    memory_agent._portfolio = portfolio
    memory_state = agent_module.StagnationState(started_at=memory_agent._monotonic())
    memory_state.observe(
        now=memory_state.started_at,
        submission_count=1,
        family_count=1,
    )
    monkeypatch.setattr(agent_module, "_get_rss_mb", lambda: agent_module.MEMORY_LIMIT_MB + 1)
    review, event = await memory_agent._run_portfolio_review(memory_state)
    assert review is None
    assert event is not None and event.outcome == "failed"

    clock = FakeClock(10)

    class SoftDeadlineAgent(HangingReviewAgent):
        @staticmethod
        def _monotonic() -> float:
            return clock.monotonic()

    monkeypatch.setattr(agent_module, "_get_rss_mb", lambda: 0)
    monkeypatch.setattr(agent_module, "SOFT_TIMEOUT_SEC", 10)
    deadline_agent = SoftDeadlineAgent(llm=FakeLLMClient())
    deadline_agent._portfolio = portfolio
    deadline_state = agent_module.StagnationState(started_at=0)
    deadline_state.observe(now=0, submission_count=1, family_count=1)
    review, event = await deadline_agent._run_portfolio_review(deadline_state)
    assert review is None
    assert event is not None and event.outcome == "failed"


@pytest.mark.asyncio
async def test_callback_audit_records_opaque_trigger_claim_and_recovery_facts(monkeypatch, caplog):
    portfolio = agent_module.Portfolio(SimpleNamespace())
    portfolio.submissions = [_crash_submission(1, "family-one")]
    agent = agent_module.CyberGymAgent(llm=FakeLLMClient())
    agent._portfolio = portfolio
    agent.description = "bounded synthetic description"
    config = _config(consecutive_no_growth_reviews=1)
    state = agent_module.StagnationState(started_at=0)
    state.observe(now=0, submission_count=1, family_count=1)
    state.complete_review(state.begin_review(), parsed=True)
    latest = state.begin_review()
    state.complete_review(latest, parsed=True)

    class ImmediateReviewer:
        def __init__(self, *, llm):
            self.llm = llm

        async def review(self, review_input):
            return StagnationAdvice(guidance="bounded", reasoning="bounded")

    monkeypatch.setattr(agent_module, "make_llm", lambda *args, **kwargs: FakeLLMClient())
    monkeypatch.setattr(agent_module, "StagnationReviewer", ImmediateReviewer)

    with caplog.at_level("INFO", logger="nooa_cybergym"):
        audit = await agent._attempt_stagnation_review(state=state, now=10, config=config)

    assert audit is not None
    assert audit.trigger_reason == "plateau_and_age"
    assert audit.review_id == latest.review_id == 2
    assert audit.consecutive_no_growth_reviews == 1
    assert audit.one_shot_claimed is True
    assert audit.one_shot_outcome == "success"
    assert audit.recovery_result == "entered"
    payload = next(
        json.loads(record.message.removeprefix("stagnation_review "))
        for record in caplog.records
        if record.message.startswith("stagnation_review ")
    )
    assert payload["submission_count"] == 1
    assert payload["family_count"] == 1
    assert payload["consecutive_no_growth_reviews"] == 1
    assert not ({"prompt", "review_input", "guidance", "reasoning"} & payload.keys())


def test_recovery_audit_is_append_only_and_contains_only_opaque_runtime_facts(caplog):
    agent = agent_module.CyberGymAgent(llm=FakeLLMClient())
    state = agent_module.StagnationState(started_at=0)
    state.observe(now=0, submission_count=4, family_count=1)
    state.complete_review(state.begin_review(), parsed=True)
    state.complete_review(state.begin_review(), parsed=True)
    config = _config(consecutive_no_growth_reviews=1)
    assert state.claim_escalation(now=10, config=config) is True

    with caplog.at_level("INFO", logger="nooa_cybergym"):
        assert agent._record_recovery_result_if_needed(state=state, now=11, config=config) is None
        state.observe(now=12, submission_count=5, family_count=2)
        assert (
            agent._record_recovery_result_if_needed(state=state, now=12, config=config)
            == "new_family"
        )
        assert agent._record_recovery_result_if_needed(state=state, now=13, config=config) is None

    payloads = [
        json.loads(record.message.removeprefix("stagnation_recovery "))
        for record in caplog.records
        if record.message.startswith("stagnation_recovery ")
    ]
    assert payloads == [
        {
            "claim_family_count": 1,
            "claim_review_id": 2,
            "family_count": 2,
            "result": "new_family",
            "submission_count": 5,
        }
    ]
    assert not ({"prompt", "review_input", "guidance", "reasoning"} & payloads[0].keys())


def test_recovery_audit_records_exact_expiry_once(caplog):
    agent = agent_module.CyberGymAgent(llm=FakeLLMClient())
    state = agent_module.StagnationState(started_at=0)
    state.observe(now=0, submission_count=4, family_count=1)
    config = _config(recovery_window_sec=20)
    assert state.claim_escalation(now=10, config=config) is True

    with caplog.at_level("WARNING", logger="nooa_cybergym"):
        assert (
            agent._record_recovery_result_if_needed(state=state, now=30, config=config)
            == "expired_without_progress"
        )
        assert agent._record_recovery_result_if_needed(state=state, now=31, config=config) is None

    messages = [
        record.message
        for record in caplog.records
        if record.message.startswith("stagnation_recovery ")
    ]
    assert len(messages) == 1
