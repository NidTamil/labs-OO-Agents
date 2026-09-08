# SunChaser Evidence Gates Implementation Plan

> **For Codex:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Prevent ambiguous vulnerable-build crashes, verifier transport failures, and exhausted reasoning contexts from being mistaken for valid CyberGym outcomes, then retest the two diagnostic failures.

**Architecture:** Keep GLM-5.3 as the primary orchestrator and Kimi K3 as the independent reviewer. Treat every primary stop as a proposal: Kimi receives a bounded, immutable portfolio snapshot and returns a structured target-specific verdict. Reject ambiguous or failed adjudications and continue exploration. Trigger the same reviewer earlier when a zero-family run accumulates excessive submissions. Make post-run fixed-build verification fail on HTTP errors and incomplete database results. Use the existing provider-reported token accounting to force context archival before a request would leave less than the configured reasoning floor.

**Tech Stack:** Python 3.12, asyncio, Pydantic, NOOA CodeAct/Predict strategies, httpx, SQLAlchemy CyberGym models, pytest, uv, Bash runners.

---

### Task 1: Make fixed-build validation fail closed

**Files:**
- Create: `examples/cybergym/scripts/verify_agent_result_strict.py`
- Modify: `examples/cybergym/scripts/validate.sh`
- Test: `examples/cybergym/tests/test_strict_validation.py`

- [x] Write tests proving non-2xx responses raise and vulnerable-crashing rows with `fix_exit_code=None` raise.
- [x] Run the focused tests and confirm the expected failures.
- [x] Implement the strict verifier and replace the upstream fail-open script call.
- [x] Run the focused tests and confirm they pass.

### Task 2: Trigger alternate review on excessive submission volume

**Files:**
- Modify: `examples/cybergym/nooa_cybergym/stagnation.py`
- Modify: `examples/cybergym/nooa_cybergym/run.py`
- Modify: `examples/cybergym/tests/test_stagnation.py`
- Modify: `examples/cybergym/tests/test_runner_preflight.py`

- [x] Add failing tests for a zero-family volume trigger, exact boundary, one-shot behavior, next wakeup, environment/CLI wiring, and policy serialization.
- [x] Add `submission_trigger_count` with a default of 100 and the explicit trigger reason `submission_volume`.
- [x] Keep disabled configurations behavior-preserving.
- [x] Run the focused tests and confirm they pass.

### Task 3: Independently adjudicate every proposed final candidate

**Files:**
- Modify: `examples/cybergym/nooa_cybergym/stagnation_reviewer.py`
- Modify: `examples/cybergym/nooa_cybergym/agent.py`
- Modify: `examples/cybergym/tests/test_stagnation_reviewer.py`
- Modify: `examples/cybergym/tests/test_stagnation_wiring.py`
- Modify: `examples/cybergym/tests/test_portfolio_agent.py`

- [x] Add a bounded `FinalCandidateVerdict` contract requiring target path, unsafe operation, input structure, description alignment, and an explicit ambiguity flag.
- [x] Add failing tests showing approval is valid only for a specific, unambiguous verdict.
- [x] Add failing orchestration tests showing rejection, timeout, parse failure, or reviewer failure suppresses primary stop and applies continued-search guidance.
- [x] Add a passing orchestration test showing a specific unambiguous verdict permits stop.
- [x] Emit redacted append-only adjudication audit facts without prompt or reasoning text.
- [x] Run the focused tests and confirm they pass.

### Task 4: Archive context before output room falls below the reasoning floor

**Files:**
- Modify: `src/nooa/unifiedllm/unifiedllm.py`
- Modify: `tests/unifiedllm/test_dynamic_output_budget.py`
- Modify: `examples/cybergym/nooa_cybergym/util.py`
- Modify: `examples/cybergym/tests/test_portfolio_main.py`
- Modify: `examples/cybergym/tests/test_runner_preflight.py`

- [x] Add a failing test proving the client refuses to issue a request whose provider-reported prior prompt would leave less than the configured reasoning floor.
- [x] Surface the refusal as a context-window error so the existing actor archives old events and retries with rebuilt messages.
- [x] Set the max-effort floor from observed Task 13 usage with a conservative margin and record it in the immutable runtime policy.
- [x] Run the focused framework and CyberGym tests and confirm they pass.

### Task 5: Verify, package, and run a new diagnostic revision

**Files:**
- Modify: `examples/cybergym/README.md`
- Modify: `docs/plans/2026-09-08-sunchaser-glm53-kimi-k3-retake.md`
- Modify: `C:/Users/IronHawk/projects/sunchaser-ops/run-alt-retake.sh`

- [x] Run formatting/lint checks required by the repository.
- [x] Run the full Linux-compatible CyberGym test suite: 284 passed, plus 80
  focused core context and summarization tests.
- [ ] Commit and push the harness branch, then build an immutable image labelled with that commit.
- [ ] Update and push the operations runner with the new image, revision, submission-volume trigger, and reasoning floor.
- [ ] Start clean diagnostic reruns of Task 8 and Task 13 in parallel without fixed images or prior agent artifacts.
- [ ] Record timestamped launch evidence and update the SunChaser brain page.

### Task 6: Escalation policy if the revised two-model run fails

**Files:**
- Modify later only if Task 8 or Task 13 remains unconfirmed.

- [ ] Verify exact API model IDs, endpoints, reasoning controls, and credentials for GPT-6, GPT-5.6, and DeepSeek V4 Pro before wiring them.
- [ ] Run reviewers sequentially as independent structured adjudicators: Kimi K3, GPT-6, GPT-5.6, then DeepSeek V4 Pro.
- [ ] Fail closed on disagreement or missing target-specific evidence; do not use majority vote over free-form prose.
- [ ] Record that council runs form a new diagnostic harness revision and do not alter prior signed results.
