# Instruction to Codex — readiness register hand-off (19 Oct 2026, v1)
From: Chase Mythos (watcher, profile sunchaser)  ·  To: Codex (CyberGym harness work, D:\GLM\Xeus CyberBench)
Register: `reviews/readiness-defects_2026-10-19_v1.md`  ·  Full document: `D:\Documents\Hermes\sunchaser\cybergym-10task-readiness-defects_2026-10-19_v1.0.docx`

## Why this file exists
The watcher has produced a prioritised defect register for ten-task readiness. It is written from evidence re-verified on 19 Oct between 00:51 and 00:52 UTC: the on-host reconnect diagnostic, `campaign_runner.py:352-353`, the drift observation hash, `git status`, and `df` on the run host. Codex has not yet reviewed it. Read it before continuing.

## What Codex should do next, in this order
1. **Read** `reviews/readiness-defects_2026-10-19_v1.md` in full, then the tracker if useful: `D:\Documents\Hermes\sunchaser\cybergym-10task-readiness-tracker_2026-10-19_v1.0.xlsx`.
2. **D-13 — correct the ledger.** The SunChaser SSH entry says the gate awaits operator authentication. Read-only SSH to `root@sunchaser-20260905` succeeded at 00:51 and 00:52 UTC on 19 Oct. Record that it is resolved, with the timestamp, so you are not idling on a dead blocker.
3. **D-02 — land the worker cleanup fix.** `campaign_runner.py:352-353` calls `run_campaign(...)` with no `finally: worker.abort()`, unlike `practice_campaign_cli.py:182`. The test already exists, uncommitted, in `test_scored_campaign_cli.py`. Observe it red on Linux first, implement, then green, then commit and push. Record both run ids.
4. **D-12 — clean the working tree.** 31 untracked `.pytest-*` directories are sitting in the repo root. Gitignore or remove them, keeping the intentional abort-test change.
5. **Then stop and report**, rather than proceeding into Phase 1. D-01 (reconnect) and D-03 (capacity) need a decision from the operator before another host run, because both consume host state and provider budget.

## Boundaries this instruction does not lift
- Do not advance the runtime source pin, and do not promote any raw observation to a pass. Several carry `certification_gate_passed=false` and must stay that way until signed evidence exists.
- Do not start a scored, official or calibration run under this instruction.
- Do not treat the synthetic E/F pair, the timeout control or the drift control as benchmark results.
- The watcher will not edit, run, start, stop or gate any of this. Verification stays read-only and lands in `reviews/`.

## Reporting back
For each item, state what changed, the commit hash, and the evidence path a reviewer can open. Items reach *evidence submitted* on self-report; only the watcher's read-back moves them to *verified closed*. If you disagree with a finding, say so with the evidence rather than silently diverging — that is how the two tracks stay in sync.
