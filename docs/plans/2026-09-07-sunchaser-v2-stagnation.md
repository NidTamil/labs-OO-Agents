# SunChaser v2 stagnation escalation plan

## Goal

Add an opt-in, one-time alternate-model review when a CyberGym run has exceeded
the configured age and stopped producing new verified crash families. Preserve
the frozen v1 behavior when the feature is not configured.

## Constraints

- Never expose the hidden fixed image, verifier internals, or cross-task data.
- Keep one task per run and preserve the single-owner submission path.
- Do not mutate or deploy the frozen v1 branch or the active task 14 service.
- Bound reviewer input, output, wall time, and invocations.
- Record trigger state, model, outcome, elapsed time, and failures in logs and
  run arguments.
- Fail open for exploration if the reviewer is unavailable: log the failure,
  close its resources, and continue the original workers without retry loops.
- Diagnostic reruns of tasks 8 and 13 are non-held-out. Task 15 is the first
  eligible held-out v2 measurement after the policy and commit are frozen.

## Task 1: Deterministic stagnation state and bounded snapshot

- Add configuration for escalation model, trigger age, quiet window, minimum
  submissions, reviewer timeout, reviewer output budget, and recovery window.
- Track elapsed time, last new-family time, submission count, family count, and
  whether escalation has already been attempted.
- Build a bounded snapshot of aggregate counts and recent candidate hypotheses;
  include no candidate bytes and no verifier/fixed-image data.
- Unit-test threshold boundaries, progress resets, one-shot behavior, and input
  bounds.

## Task 2: One-time alternate-model reviewer

- Add a structured, tool-free reviewer using `PredictStrategy`, on a separate
  agent that has no shell or submission tools, returning guidance and reasoning.
- Instantiate it only when an escalation model is configured.
- Apply successful guidance through the existing Portfolio interface so live
  Finder context updates without direct worker mutation.
- Wrap the review in a hard timeout. Treat timeout, provider failure, malformed
  output, and cancellation as logged escalation failures; never retry and never
  stop the original exploration solely because review failed.
- Close the reviewer LLM and summarizer resources during shutdown.
- Unit-test success, timeout, provider failure, cancellation cleanup, and exactly
  one invocation.

## Task 3: Recovery-window termination and runner wiring

- After a successful or attempted escalation, allow the configured recovery
  window. If no verified family appears by its end, stop exploration and enter
  the existing honest no-final path.
- Add runner CLI/environment forwarding and persist effective v2 settings in
  args.json.
- Verify that omitted v2 options reproduce the existing v1 orchestration.
- Add preflight validation for positive, internally consistent durations and
  budgets.

## Task 4: Measurement-integrity boundaries

- Keep diagnostic reruns in a separate run root from held-out cohorts.
- Make final-score aggregation fail closed on duplicate task IDs, mixed harness
  cohorts, or missing cohort metadata instead of recursively counting every
  `args.json` it encounters.
- Name signed evidence by cohort and attempt so a diagnostic rerun cannot
  overwrite held-out evidence for the same task ID.
- Add regression tests for duplicate attempts, mixed cohorts, and separation of
  diagnostic task 8/task 13 results from official held-out v2 results.

## Task 5: Documentation and qualification

- Document v2 controls, audit events, and the measurement-integrity boundary.
- Run focused CyberGym tests, Ruff, and the broader relevant suite.
- Review the complete diff for fixed-image leakage, unbounded context, duplicate
  reviewer calls, resource leaks, and accidental v1 default changes.
- Commit and push the v2 branch, but do not deploy until task 14 has completed
  and the qualification evidence is reviewed.
