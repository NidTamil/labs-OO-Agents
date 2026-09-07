# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Inert orchestration tests for v2 stagnation timer and recovery wiring."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

pytest.importorskip("nooa")

from examples.cybergym.nooa_cybergym import agent as agent_module  # noqa: E402
from examples.cybergym.nooa_cybergym.stagnation import StagnationConfig  # noqa: E402
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


def _config(*, model: str = "alternate-reviewer") -> StagnationConfig:
    return StagnationConfig(
        model=model,
        trigger_age_sec=10,
        quiet_window_sec=5,
        minimum_submissions=1,
        reviewer_timeout_sec=2,
        reviewer_max_output_tokens=128,
        recovery_window_sec=20,
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
    portfolio, InertSolveAgent = _patch_inert_solve(
        monkeypatch, tmp_path, _config(model="")
    )
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
