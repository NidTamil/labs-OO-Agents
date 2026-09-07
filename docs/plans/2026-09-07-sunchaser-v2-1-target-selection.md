# SunChaser v2.1 target-selection recovery plan

## Objective

Prevent a single repeatedly reproduced but weakly grounded crash family from
ending a CyberGym run before the stronger reviewer has examined the stalled
search. Make submission staging deterministic, preserve full audit identity,
and keep all existing held-out evidence immutable.

## Global constraints

- Never expose the hidden fixed image, fixed patch, earlier PoCs, earlier
  trajectories, or post-run Task 8 findings to an agent during a run.
- Existing v1 evidence and the frozen 12/14 claim are read-only and outside
  this branch.
- Default behavior remains unchanged when v2 escalation is disabled.
- Escalation is one-shot and fail closed. Provider or reviewer failure must be
  audited and must not silently approve a stop or candidate.
- A plateau may accelerate the existing time-based escalation; it must not
  weaken minimum-submission or immutable-policy controls. The recovery window
  remains a hard upper bound.
- Final selection ranks description and source-path alignment before size.
- Candidate bytes are copied to an immutable staged artifact before verifier
  execution. Missing or changed source paths are classified locally and do not
  poison the shell or masquerade as verifier infrastructure failures.
- No diagnostic run in this plan may create signed official evidence.

## State and outcome contract

Each ordinary portfolio review receives a monotonic `review_id` and an immutable
invocation snapshot containing submission count and family count. Only a
successfully parsed, non-cancelled response for the latest outstanding review
may become a completed review event. If the live family count changes while the
review is awaited, the response is stale: do not apply its guidance or stop
decision, do not count it toward a plateau, and schedule a fresh review.
Duplicate, failed, cancelled, and stale responses never count. The first valid
review establishes the baseline at zero no-growth reviews. Each later valid
review with the same family count increments the sequence; family growth resets
it to zero. Reviews may count before the minimum-submission threshold, but
plateau escalation is eligible only with exactly one family, the configured
minimum submissions, and the configured number of consecutive no-growth review
events.

Plateau eligibility bypasses the elapsed-age and quiet-window predicates only.
The existing age-plus-quiet-window predicate remains an independent trigger.
If both predicates are true, record `plateau_and_age`; otherwise record
`plateau` or `age`. Trigger configuration and its semantics belong in the
pre-run hashed policy. The observed trigger reason and counters belong only in
the append-only runtime audit.

One-shot means one in-process orchestration claim and one reviewer method
invocation per agent run. Provider strategy retries inside that invocation keep
their existing bound and are separately visible in provider telemetry. It does
not promise a durable cross-process claim after restart.

For an ordinary `stop=True` that is plateau-eligible and unclaimed, defer and
discard that stop, claim escalation, and invoke the stronger reviewer. A valid
review enters the existing recovery state and applies guidance with effective
`stop=False`, then resets the no-growth counter so recovery evidence is fresh.
While recovery is active, an individual ordinary stop is deferred. A new family
ends recovery and normal stopping resumes. If the configured number of fresh
no-growth reviews all return a decisive stop, recovery terminates early as an
explicit failed search; expiry without progress is the same terminal failure at
the hard upper bound. Provider construction failure, invalid response, reviewer
timeout, cleanup failure, or callback cancellation records its exact failure
and makes the pending stop ineffective; a later, distinct successful ordinary
review may stop after the consumed attempt. External cancellation, cooperative
stop, memory limit, soft deadline, and outer hard timeout retain authority.

The stronger reviewer sees no hidden fixed-build evidence. Its prompt must call
every vulnerable-build crash candidate evidence, forbid solved or sole-bug
claims, and rank new directions by patch-specific alignment and family
diversity. This preserves isolation while preventing generic sanitizer crashes
from being reinforced as proven answers.

The recovery deadline remains the existing upper bound measured from claim
time, so reviewer execution consumes the window. Preflight must require the
reviewer timeout to be strictly shorter than the recovery window. A callback
finishing at or after the recovery deadline proceeds directly to the existing
no-progress failure rather than silently extending runtime.

## Artifact and compatibility contract

Staging opens the candidate once, captures descriptor identity and metadata,
streams it to a uniquely named exclusive temporary file while computing SHA-256
and byte length, checks for detectable descriptor changes, fsyncs, atomically
publishes it without overwrite, and makes the published file read-only. Path
replacement after open cannot change the bytes staged. Same-size adversarial
in-place rewrites that evade filesystem metadata are outside the trusted-writer
model; the durable guarantee is that the published bytes, digest, verifier
input, submission record, and final artifact all share one identity.

Staging runs before rate-slot acquisition and verifier invocation. Missing,
unreadable, directory, disappeared, or detectably changed sources produce
`local_candidate_error`; destination publication or audit-write failure is a
fatal local storage error. Neither category is a verifier transport failure and
neither may respawn or increment the shell breaker. Submission numbers remain
monotonic and unique. A successful record persists staged path, digest, and
byte length. Finalization consumes only that recorded staged identity and rejects
any mismatch; it never falls back to another path. `verify_existing()` verifies
an already published artifact and does not create a new staged submission.
Audit persistence failures are raised and cannot be reported as durable audit
success.

New normal selections use schema version 2. Required trimmed, non-empty grounds
are `target_path`, `unsafe_operation`, `description_alignment`,
`crash_stability`, and `remaining_ambiguity`; identifiers and existing digest
and length fields retain current validation. The hard-timeout recovery writer
also emits schema version 2 with `selection_source=hard_timeout_recovery` and an
explicit `grounds_status=unavailable`, without fabricating model evidence.
Normal model selections use `selection_source=model` and
`grounds_status=provided`. Readers accept historical schema-version-1 documents
unchanged, accept additive unknown artifact keys for forward compatibility, and
strictly reject incomplete newly generated schema-version-2 metadata. Existing
evidence files are never rewritten.

## Task 1: Implement the pure review-event state contract

Add deterministic, orchestration-independent review snapshot/event types and
plateau state transitions. Cover baseline, exact threshold, family reset,
duplicate/stale/failed/cancelled reviews, progress during an awaited review,
eligibility before and after minimum submissions, simultaneous trigger
predicates, and one-shot claim semantics. Do not wire the live agent loop yet.
Preserve the existing disabled and monotonic-state tests.

## Task 2: Harden candidate staging and durable identity

Implement staging, no-substitution finalization, persisted digest/length/path,
the local candidate-error taxonomy, and visible audit-write failures together
in `submissions.py`. Use bounded-memory streaming and harmless temporary-file
tests. Cover missing/unreadable/directory inputs, replacement/disappearance,
detectable mutation during copy, post-stage mutation, no-clobber publication,
partial-copy cleanup, no verifier/rate/shell/breaker side effects for local
rejections, and the child-exit-124 versus transport-death boundary.

## Task 3: Add compatible selection metadata end to end

Extend the model output, prompt, manager boundary, final artifact, normal writer,
outer hard-timeout writer, and legacy reader using the artifact contract above.
Persist honest provenance only. Tests must cover old minimal documents, valid
new documents, incomplete and whitespace-only new grounds, invalid identifiers,
additive unknown keys, both writers, and unchanged digest/length rejection.

## Task 4: Implement plateau-trigger and stop arbitration

Implement explicit review events and stale-response rejection, then add the
plateau predicate beside the age predicate. Apply the outcome contract to
ordinary stops, reviewer invocation, recovery, external stop, and deadlines.
The stronger review input remains bounded and receives only current-run source
and portfolio evidence already allowed by v2. Tests must exercise the complete
Task 8-shaped synthetic sequence and all control paths without running a target.

## Task 5: Wire configuration, policy, audit, and documentation

Expose the plateau threshold through environment and CLI configuration; add it
to preflight, runtime-policy hashing, `args.json`, and the concise CyberGym
README. Store only configured predicates in immutable policy and actual trigger
facts in runtime audit. Document both triggers, the state/outcome contract, and
the diagnostic evidence boundary. Keep defaults inert when escalation is
disabled. Tests cover precedence, invalid values, strict timeout/window
validation, policy hashing, serialized identity, and disabled compatibility.

## Task 6: Integration qualification

Run focused tests for every changed surface, the complete Linux CyberGym suite,
Ruff, formatting checks, and Bash syntax checks. Obtain a final Ultra
whole-branch review. Deploy only the reviewed commit to the DO v2 checkout and
build a new immutable image. Then run clean diagnostic practice checks on Tasks
1 and 10 before any new Task 8 diagnostic.
