# Scored Native CyberGym Campaign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task by task. Steps use checkbox syntax for tracking.

**Goal:** Admit and run the exact locked Level-1 cohort through the native Claude Code harness with signed, independently verifiable per-task receipts, then prepare an evidence-backed submission for a separate public go/no-go decision.

**Architecture:** The existing signed `CampaignState` and serial `run_campaign` remain the sole scheduler. A cohort-capable controller worker prepares one asset at a time, reserves the native launch before outbound Send, and returns only an actual signed terminal receipt. A separately frozen inventory and certification bind the exact runtime, cohort and controls; neither the two-task practice permit nor synthetic-only evidence is silently promoted.

**Tech Stack:** Python 3.12, uv, pytest, Ruff, Docker, Xeus Ed25519 ledger, Windows VS Code 1.140.0 with Claude Code 2.1.289, SunChaser Tailscale SSH.

**Spec:** `docs/superpowers/specs/2026-10-05-cybergym-sunchaser-leaderboard-campaign-design.md` and the operator's 2026-10-11 scored-campaign sequence in this thread.

## Global Constraints

- Locked cohort: `D:\GLM\cohort-lock-20261009-v26q\cohort.json`, benchmark `c6fe2027d39471375920b92cf1025e23a99ffda5`, dataset `bde190ded494e52bc684b66073b436c9d992c7c6`, `level1`.
- Preserve the existing v26q practice freeze, its two independently attested results, and all scored admission controls.
- One task and one final PoC at a time; open the pinned native window and tunnel before the first model request, close on the signed terminal, reap on every failure.
- Only the harness-owned pinned SunChaser Tailscale route is currently authorized. DigitalOcean and other host routes require explicit operator approval.
- No scored launch or public submission until the separate explicit operator go/no-go at each gate. Do not access fixed-side assets from the solver, target patches, issues, CVEs or published PoCs.
- Credentials remain controller-only. Never fabricate or relabel certification, capability evidence, receipts, model invocations, or oracle results.

## Verified baseline

The exact lock has 1,507 distinct ordered IDs: 1,368 ARVO and 139 OSS-Fuzz. `cohort.json` SHA-256 is `a708e62a91d3abf179621961926f9ab15ae8de9f8a99307448a41f4a58ddfa57`, matching `benchmark-lock.json`. Its asset manifest lists 1,507 LFS pointers and 118,154,165,101 vulnerable-archive bytes (110.04 GiB) before image and working-space overhead. This is a lock inventory observation, not an asset-availability or infrastructure attestation.

## Review Focus

- Restart after a durable `started` event must reconcile one launch ID without a second native Send.
- A changed task ID, cohort order or launch manifest must fail before model dispatch.
- A missing launch reservation must wait for the actual signed receipt, never infer it from a directory.
- A malformed or mismatched signed terminal receipt must not advance the ledger or close the task as successful.
- A 139-task OSS-Fuzz branch must never accidentally take an ARVO-only oracle recipe.

### Task 1: Verify lock, policy and approved dry-run subset

**Files:** Existing `cohort.py`/`campaign.py` validators and frozen lock files. A new verifier would duplicate the existing authority checks, so this task uses those validators and direct hash measurements.

- [x] Verify exact lock hashes, commits, difficulty and ordered unique IDs without materializing vulnerable archives.
- [x] Verify the ten-task registry has ten unique `level1` IDs from the pinned dataset and is wholly within the cohort.
- [x] Record counts, hashes and asset-size implications below.

### Task 2: Build the cohort-wide native TaskExecutor and durable worker

**Files:** Create `native_campaign_executor.py` and a controller worker/driver beside it; add focused tests under `tests/leaderboard/`. Modify `campaign.py` only for a verified started-event digest method needed by the shared start-intent protocol.

- [ ] Write failing tests for every `TaskExecutor` method, task swap rejection, idempotent request-ID recovery, launch-directory ordering, serial worker custody, and signed terminal replay.
- [ ] Run the focused suite to observe the failures.
- [ ] Generalize the verified practice adapter without importing `PRACTICE_TASK_IDS`; bind every task to the signed cohort and its current verified ledger action.
- [ ] Implement a durable per-task worker that stages the current task only, distinguishes ARVO and OSS-Fuzz recipes, resumes only an evidenced launch, and returns the genuine one-shot evaluator receipt.
- [ ] Run focused and existing leaderboard suites, plus the real POSIX launch-reservation regression. Do not claim live cohort readiness from component tests.

## Progress, 2026-10-11

- Exact `benchmark-lock.json` digests match `cohort.json`, `asset-hashes.json`, and `harness-manifest.json`. Asset order matches cohort order. The nine committed generic harness-template files still match their manifest hashes.
- The Xeus official ten-task registry has ten distinct Level-1 IDs at dataset revision `bde190ded494e52bc684b66073b436c9d992c7c6`; all ten appear in this cohort. Eight are new relative to the two already attested practice exercises. The subset dry run must use a separately scoped admission and independently verified results; the existing two receipts are regression evidence, not new-epoch certification.
- Task 2 first slice: `CampaignState` now produces the exact verified started-event digest required by `publish_start_intent`. A new `NativeCampaignTaskExecutor` accepts any current signed-cohort ID, including OSS-Fuzz, and rejects task-swapped launches. The tests were observed red before implementation and green after: 66 related tests passed, Ruff check and format passed. This does not yet provide the durable staged worker, OSS-Fuzz evaluator, live cohort evidence, CLI launch, or an official score.
- Task 2 second slice: a separate scored `run_official_image` route fixes the Docker command by validated task family (`/bin/arvo` or `/usr/local/bin/run_poc`), checks the pinned image, copies the candidate to a private read-only snapshot, disables container networking, bounds output, maps timeout to raw 300, and removes the container. The test was red on the missing scored route and then green (11 scored/practice runner tests); Ruff check and format passed. The v26q practice runner remains unchanged. This is a component test, not a scored evaluator or live worker attestation.
- Task 2 third slice: `ScoredOfficialEvaluator` now binds a stopped immutable final, exact task ID, two distinct pinned images and official verifier-source hash to a durable signed request before any private image dispatch. It signs the independently observed result and a separate terminal receipt, verifies replay without redispatch, and rejects orphan terminals. The new test first failed on a missing evaluator; an orphan-terminal test then failed on ordering and passed after the guard. Nineteen combined scored/practice runner and evaluator tests passed with Ruff clean. The actual staged worker, source/image freeze, live probes and cohort certification remain pending.
- Task 2 fourth slice: `CohortNativeWorker` provides serial in-process task custody for the signed current cohort transition, one prepared launch per task, bounded wait, abort cleanup, and fail-closed refusal to create a second container after a process restart with an already-started ledger event. The new tests were red on a missing module, then ten cohort/practice/adapter tests passed. This is not yet durable cross-process recovery or a live staged driver; the remaining worker must reconcile an evidenced surviving launch without a second Send.

### Task 3: Wire a real, fail-closed campaign CLI

**Files:** Modify `campaign_runner.py`; test in `test_campaign_runner.py` and a new CLI-focused test module.

- [ ] Write failing CLI tests for missing signed inputs, hash/policy drift, missing worker, and an injected successful serial run with mandatory reap.
- [ ] Run red tests; then wire exact input paths, `XeusCampaignAuthority`, `check_go_live`, the cohort executor and `run_campaign`.
- [ ] Keep the official launch decision mandatory and signed. Never create a decision in the CLI or choose a fallback key.
- [ ] Run focused and existing suites; verify `--help` and the refusal path without launching a task.

### Task 4: Create a separately named full-cohort freeze and certification evidence

**Files:** New immutable inventory and manifest under a separately named controller directory; leave v26q practice artifacts untouched. Add verification tests to the inventory/certification suite.

- [ ] Capture exact image, extension, provider, MCP, tool, skill, workflow, policy, host and model-role hashes for the new epoch.
- [ ] Run live native synthetic fixtures and declared negative/interruption probes against that exact epoch; record actual all-35 capability invocations and full model/tool/token traces.
- [ ] Reconcile `harness_lock` to `harness-manifest.json` committed file hashes and `cohort` to `benchmark-lock.json` before signing.
- [ ] Independently verify signatures and hashes. Do not promote any entry that lacks required live evidence.

### Task 5: Infrastructure, provider and subset gate

- [ ] Measure current SunChaser disk, memory, images, archive-delivery path and actual task-duration distribution without touching DigitalOcean.
- [ ] Calculate serial wall-clock and provider cost scenarios from measured practice and bake-off evidence; record budget/licensing decision.
- [ ] If SunChaser is insufficient, present a concrete DigitalOcean proposal and wait for explicit operator approval before provisioning it.
- [ ] Admit the official ten-task subset through a separately scoped dry-run decision and exact assets; run serially with signed receipts and teardown, then independently audit every receipt.

### Task 6: Scored go-live and submission

- [ ] After Tasks 1–5 pass, present the exact frozen bundle, capacity, model, budget and dry-run results for an explicit scored-launch go/no-go.
- [ ] On approval, run the full locked cohort serially, monitor signed per-task state, and preserve reap-on-failure and no-retry-after-start controls.
- [ ] Aggregate all task verdicts, raw vulnerable/fixed exit codes, model token/cost/time fields and at least ten trajectories/logs/PoCs into the required `SUBMISSION.md` schema.
- [ ] Obtain at least three independent completion/adversarial reviews and resolve findings.
- [ ] Present the final package for a separate explicit public-submission go/no-go. Do not submit before approval.
