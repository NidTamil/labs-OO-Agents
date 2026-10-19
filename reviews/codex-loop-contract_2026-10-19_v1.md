# Unattended readiness loop — contract (19 Oct 2026, v1)
Owner of execution: @new-bot (holds the Codex channel)  ·  Executor: Codex  ·  Verifier: Chase Mythos (sunchaser)  ·  Decider: operator

## Goal
Drive the readiness register (`reviews/readiness-defects_2026-10-19_v4.md`) to a state where the ten official CyberGym tasks can be launched on the operator's word alone. The loop stops at *ready to run*, not at *ran*.

## Division of labour
- **@new-bot** launches and sequences Codex runs; it owns run control.
- **Codex** does the work and commits; it never signs its own gate.
- **Watcher** verifies at stage boundaries and moves items to verified-closed; it starts, stops and gates nothing.
- **Operator** decides the four things a machine must not decide: capacity, budget, pin, go/no-go.

## The loop queue
**Stage A — unattended, no provider spend.** D-09 (sign the image manifest over the 3,014 collected observations), D-10 (hydrate and hash-verify the ten fixed-side assets), D-05 bookkeeping (record the pin decision once the operator gives it). Repeats are safe because they are deterministic hash checks.

**Stage B — one attempt each, host consuming.** D-01 (reconnect), D-07 (clean timeout), D-08 (drift integration). One attempt per item, one signed receipt, then a boundary check. No automatic retry, ever — a retry loop on a fail-closed probe is how a failing gate gets quietly converted into a passing sample.

**Stage C — repetition.** D-06 (G/H second two-fixture repetition) under the settled pin, once Stage B is clean.

**Stage D — close.** D-04 aggregate signed report; the watcher replays two claims end to end; the report goes to the operator with the go/no-go request.

## Stop conditions
The loop halts and reports, without proceeding, when any of these is true:
1. Evidence artefact hashes are unchanged between iterations (no progress).
2. An error class appears that is outside the expected set — for example a Docker cleanup error, an import/setup failure counted as a red, or a controller exit not matching a declared class.
3. The next attempt would exceed the approved provider or time budget.
4. A pass is claimed without a signed receipt, or a `certification_gate_passed=false` observation is described as satisfied.
5. Three consecutive iterations produce no register change.

## Per-iteration report
Item, commit hash, evidence path plus SHA-256, claimed status, and anything the watcher should distrust. Self-report reaches *evidence submitted*; only the watcher's read-back closes an item.

## Escalation to the operator
Capacity disposition, spend ceiling, pin choice, provider and model binding, and the final go/no-go. Nothing in those five is delegated to an agent.

## Definition of ready
All P0 and P1 closed or formally waived; one exact pin across every artefact; signed aggregate report independently replayed; a second complete repetition; capacity measured with reserve; a hard stop budget; and an operator go/no-go on record.
