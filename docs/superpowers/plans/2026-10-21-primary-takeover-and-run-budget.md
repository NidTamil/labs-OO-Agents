# Primary takeover and ten-task budget implementation plan

> **For agentic workers:** Use superpowers:subagent-driven-development or superpowers:executing-plans, with focused red/green tests and independent review. Continue the existing review branch; do not launch live controls from this plan.

**Goal:** Implement the operator-approved automatic GLM-to-DeepSeek takeover and 15,000-request aggregate ceiling without resetting task custody or misattributing evidence.

**Architecture:** A controller-owned, one-way route transition keeps the existing native session, task clock and tool state. Every provider dispatch consumes a durable request reservation. DeepSeek primary requests share the 1,410 primary/memory pool; its 90 advisory requests retain the 30/40/20 role allocations. A separate signed ten-task budget binds the aggregate ceiling and eventual time/spend decisions.

**Tech stack:** Existing Python controller, SQLite, Anthropic-format streaming, pytest and uv. No new dependency.

**Spec:** Direct decisions recorded in `reviews/scored-ten-task-prep-decisions_2026-10-20.md`; this document specifies their implementation. The parent readiness ledger is `docs/superpowers/plans/2026-10-11-scored-native-campaign.md`.

## Constraints and design rulings

- Per task: 1,500 total, 1,410 shared primary/memory requests, 90 DeepSeek advisory requests. Per ten-task run: 15,000 total. Failed, cancelled and ambiguous dispatches consume reservations; no refunds.
- The operator directly approved DeepSeek using the remaining primary pool, so total DeepSeek use may exceed 90. Existing advisory token/time limits and the 43,200-second task clock remain unchanged. The four-hour limit applies only to the next reconnect control.
- Start on GLM; switch once to DeepSeek only for classified availability failure before any downstream response. No switch back, new attempt, new native home, second Send or replay after text/tool output. Keep already admitted concurrent calls bound to their original provider.
- Ruling: initially restrict transparent takeover to a pre-response failure. Midstream failures retain existing bounded interruption/halt semantics. This avoids splicing providers into one SSE message or duplicating a tool; wider recovery requires additional native evidence.
- Never switch for refusal, policy denial, authentication failure, cancellation, budget exhaustion, identity drift, credential disclosure, invalid usage, malformed arguments or audit failure.
- Ruling: use DeepSeek's documented Anthropic-compatible endpoint, `https://api.deepseek.com/anthropic`, for the primary role. This avoids inventing a Chat Completions adapter. Validate unsupported features before dispatch and keep advisory Chat Completions unchanged. Public documentation is not live certification.
- DeepSeek documents `deepseek-flash` as currently served by V4.1-Flash-1017. This remains a moving API alias, not immutable weights. Preserve returned identity/version/fingerprint separately; final signed identity acceptance remains an admission decision.
- Preserve all historical signed epochs and exact old loaders. New route/accounting/final-proof behavior requires explicit new versioned identities; no silent upgrade of old evidence.
- Aggregate time/spend, signer/public trust, live certification, root reserve and signed admission remain pending. A request-only component cannot be promoted to admission-ready.

Sources checked 21 October 2026: [DeepSeek Anthropic compatibility](https://api-docs.deepseek.com/guides/anthropic_api/) and [current model mapping](https://api-docs.deepseek.com/updates). The former documents streaming, tools and message support along with ignored/unsupported fields. The latter maps the API alias to the 1017 release at the observation time.

## Review focus

1. Concurrent requests at a final allocation/run slot must not overshoot; ambiguous writes cannot release a dispatch.
2. Local request IDs, provider-attempt IDs and actual model identities must not collapse into one falsely attributed request.
3. A provider failure after response exposure cannot replay tools or cause a new Send.
4. Post-oracle memory calls must consume the same run budget before next-task advancement.
5. Old signed evidence must remain verifiable under its original schema, without accepting new evidence through old proof rules.

## Task 1: Durable request reservations

**Files:** new `examples/cybergym/nooa_cybergym/leaderboard/run_request_budget.py` and focused tests under `examples/cybergym/tests/leaderboard/`.

**Interface:** `RunRequestBudget.create(path, *, run_id, epoch, policy_sha256, ordered_task_ids)` and `.open(path, *, run_id, epoch, policy_sha256, ordered_task_ids)` bind an existing controller-private database to exactly ten unique ordered tasks. `.reserve(*, task_id, attempt_id, request_id, allocation)` returns an immutable reservation with run/task/allocation ordinals. Allocations are `primary_and_memory` and `deepseek_advisory`. `.snapshot()` returns authoritative consumed counts. Duplicate IDs fail closed; reopening does not grant permission to restart a native attempt.

- [x] Red tests: exact identity mismatch, missing/corrupt store, duplicate reservation, per-task/per-allocation/run limits, concurrent last slot, retained debit after reopening.
- [x] Implement atomic SQLite transactions with strict schema/identity checks and no refunds. Enforce 15,000/1,500/1,410/90 constants; no solver-selected allocation.
- [x] Green focused tests and Ruff; independent review before integration.

## Task 2: Takeover route policy and custody

**Files:** new `examples/cybergym/nooa_cybergym/leaderboard/primary_takeover.py` and focused tests.

**Interface:** `PrimaryTakeoverPolicy` is a versioned, canonical-digest specification with fixed initial/fallback identities/endpoints, eligibility categories and shared-primary allocation. `PrimaryTakeoverState` accepts task/attempt/policy identity and a synchronous durable event writer. `.route` returns the active route. `.switch(*, request_id, failure_kind, response_started)` records the one-way transition before exposing the new route; rejects ineligible failure, any exposed response, repeated transition or failed persistence. Request and provider-attempt identity are explicit in emitted records.

- [x] Red tests: eligible availability categories, every excluded failure, response exposure, repeated switch, durable writer failure and concurrent switching.
- [x] Implement controller-only state without resetting clocks, sessions, counters or native custody.
- [x] Green focused tests and Ruff; independent review.

## Task 3: DeepSeek native request compatibility

**Files:** new `examples/cybergym/nooa_cybergym/leaderboard/deepseek_native.py` and focused tests.

**Interface:** `prepare_deepseek_native_request(payload)` returns a deep-copied Anthropic body with exact `deepseek-flash` selector. Validate a supported native message/tool subset, preserve tool IDs/results and conversation ordering, reject unsupported blocks or semantics before provider admission. Do not manufacture thinking signatures or silently remove conversation content. No network or credentials in this module.

- [x] Red tests: multi-turn text/tools/thinking, strict output bounds, immutable input, undeclared model, malformed/unsupported content and tool choice.
- [x] Implement the documented native compatibility boundary with explicit error cases.
- [x] Green focused tests and Ruff; independent review.

## Task 4: Integrate provider attempts and native custody

**Files:** `model_gateway.py`, `native_tool_runtime.py`, `services_runtime.py`, `model_runtime.py`, runtime configuration/policy loaders and their tests.

- [x] Write gateway integration tests using fake transport: eligible GLM pre-response failure then exactly one DeepSeek dispatch; two consumed requests; durable switch first; no provider response splicing.
- [x] Separate native request completion from provider-attempt settlement. Track actual provider identity per admitted request, preserve failed GLM usage as unavailable/conservative, and do not let a successful fallback erase it.
- [x] Bind the native DeepSeek endpoint and validated request to the approved controller credential. Maintain existing secret, usage, capability, scope and deadline guards. Never turn safety/identity/audit failures into availability retries.
- [x] Integrate the shared primary allocation and durable run reservations for primary, count-token, advisory, auxiliary-memory and post-oracle calls. No second reservation for the same dispatch audit event. The context accepts the aggregate ledger; creating and supplying one across the actual ten-task execution path remains Task 6.
- [x] Keep takeover disabled for old runtime schemas. Select it only through the new frozen policy/source configuration.
- [x] Run focused transport, custody, budget and native integration tests; independent review.

## Task 5: Truthful final attribution and full accounting

**Files:** `finalize.py`, `finalization_runtime.py`, `certification_report.py`, `raw_fixture_attestor.py`, `raw_pair_coverage.py`, relevant proof/policy schemas and tests.

- [x] Add explicit new proof/report versions binding the final selector to its admitted active primary provider and request. Keep old GLM-only proof verification exact.
- [x] Account for all primary providers and memory auxiliary calls, plus advisory calls, failed reservations and post-oracle usage. Fix the pre-existing gap that excludes memory inference from report totals.
- [x] Reject a child/adviser selecting final, unexplained route transition, missing reservation, excess allocation and false GLM attribution of DeepSeek activity.
- [x] Run focused proof/attestor tests and independent review. A report passes only with real independent raw evidence. These checks validate source behavior; the two live repetitions remain Task 7.

## Task 6: Ten-task budget admission and stop behavior

**Files:** new versioned subset budget artifact; `subset_dry_run_admission.py`, subset executor/runner/worker binding and tests. Preserve full-cohort and historical-pair validators.

- [ ] Validate actual canonical budget bytes/signature and run/epoch/ordered IDs/policy, not a caller-supplied hash alone.
- [ ] Require operator-selected aggregate time/spend bounds before admission. Request-only drafts remain incomplete.
- [ ] Add a run-level exhaustion stop distinct from existing task terminal statuses. Stop before new preparation/start/Send, keep remaining tasks unattempted, and perform only owned cleanup.
- [ ] Reconcile an already started task and its authentic terminal before stopping. Require post-oracle writer/driver accounting quiescence before advancing.
- [ ] Exercise crash/recovery/no-second-Send/cleanup and historical validator regressions.

## Task 7: Exact source verification and live readiness

- [ ] Integrate and review the full change; pin the completed code/policy/configuration once.
- [ ] Run required Windows checks and a fresh complete offline Linux suite on that exact candidate. Do not repeat prior suites merely for heartbeat.
- [ ] Preflight source/profile/capacity/provider budget, then perform separately identified bounded takeover/reconnect/timeout/drift controls and two complete independently attested two-fixture repetitions.
- [ ] Finish signer/trust, harness/image lock, root reserve, credits, freeze and distinct ten-task admission. Stop at the separate explicit scored go/no-go.

## Execution ledger

- 21 October: operator approved 15,000 aggregate requests, automatic DeepSeek takeover, and sharing the remaining primary pool while retaining 90 advisory calls. No provider dispatch authorized by this ledger.
- Existing report allocation correction `b1a024b4` passed the intended red test then 63 report/policy tests. It is later than the host-installed `803c52d5` and has not been installed/live-certified.
- 21 October component implementation: durable reservations passed 46 tests after an independent reviewer found an index/table-corruption case; replacing the insufficient SQLite quick check with full integrity validation fixed the three intended corruption regressions. Takeover state passed 103 tests and native DeepSeek request compatibility passed 120. Ruff passed, and independent component review found no remaining P1/P2 issues.
- Gateway/native integration passed 194 focused tests. Review-driven regressions fixed cancellation during failed-response cleanup and concurrent GLM failures; TLS identity failures are excluded from takeover. A late failing concurrent GLM request may receive one separately charged continuation under the already persisted switch, with its own provider-attempt identities and a transition reference. No request is replayed after response exposure. DeepSeek count-token support remains unverified and fails closed.
- Explicit runtime schema 2 and services wiring passed 54 tests with one POSIX-only skip. Legacy schema 1 retains its exact field set and digest behavior. New final-selection proofs bind the actual primary provider; 80 finalization tests passed with five POSIX skips and independent review found no remaining P1/P2 issues.
- Fixture and post-oracle debit auditing passed 25 focused custody/driver tests with one POSIX skip after intended missing-feature failures. Synthetic fixtures record each task debit before lane permission without inventing a ten-task run identity; aggregate-bound tasks use the durable run ledger. Both new-schema drivers propagate the audit mode and post-oracle allocation ordinals. Independent review found no P1/P2 issues. Scored worker binding, complete raw/report accounting, actual ten-task admission/stop wiring and live certification remain unfinished.
- These are source-only fake-transport/component results. No provider request, host runtime switch, image/registry operation, signed freeze or scored admission occurred. The installed host component baseline remains `803c52d5`; a finished integrated source must be pinned and Linux-verified later.
- The reviewed takeover/configuration/final-proof/request-ledger components above were committed and pushed in `081a403d`. A subsequent scored-binding audit found three reconstructed model policies omitted the explicit takeover policy; all three now preserve it, with three intended failing takeover cases followed by six passing legacy/takeover tests. Full-cohort admission checks remain unchanged.
- The inert `subset_run_budget.py` verifier requires actual signed budget bytes, the exact ordered ten IDs, the approved request allocations, explicit positive elapsed-time/spend limits, and an independently supplied metering-policy digest. It has no default operational time/spend values and cannot launch or enforce a run by itself. An independent reviewer found the first version checked only the metering digest's format; the intended mismatch regression failed, then the verifier was corrected to compare the independent pin and retain it during re-verification. The budget/authority suite passed 45 tests, including actual Ed25519 signature, noncanonical-payload and untrusted-key checks. Test limit values are synthetic data, not operator decisions.
- Task 6 audit: the existing subset preview accepts a budget hash but not actual budget bytes, and existing scored worker/staging/capability bindings require the full cohort. A new explicitly budgeted subset path is still needed. Normal worker completion waits through post-oracle memory and cleanup, but terminal-only recovery can advance earlier; the future subset recovery must require independently verified driver/accounting quiescence and atomically close the task's budget phase. Preserve old terminal statuses and full-cohort checks. None of this missing integration is implied by the standalone budget verifier.
- Raw request accounting now reconciles every reservation across primary, count-token, advisory, memory and post-oracle lanes. Failed or missing usage remains explicitly unknown; unmatched reservations and unbounded unknown usage prevent certification. Synthetic offline integration exercises recorded provider attempts, the runtime audit chain, native custody, final SSE/tool arguments, the locked candidate and signed oracle evidence. The report and pair schema 2 preserve all twelve gates and require two distinct complete repetitions. Historical schema 1 is unchanged.
- Independent review found that the first report integration could select another observed primary request while leaving its independent accounting unchanged. The correction propagates the exact independently verified final declaration and requires canonical equality, including provider/request, task/attempt, native session/tool and candidate identity. Thirteen report regressions and ten pair-propagation cases failed before the correction and passed afterward; scoped report/pair verification passed 97 tests. The reviewer found no remaining P1/P2 issues in this correction.
- Final combined Windows verification for this component slice: **797 passed, 7 skipped in 47.82 seconds**, across 20 affected test files, using offline `uv`, cached Docker dependency and the existing external Xeus source path. All 18 changed/new Python files passed Ruff check and format; `git diff --check` passed. This is component/integration evidence only. No provider request, live fixture, SSH operation, registry query, layer pull, host installation, scored freeze or admission occurred. Aggregate elapsed time is still the pending operator question; aggregate spend and signing/trust remain later decisions.
