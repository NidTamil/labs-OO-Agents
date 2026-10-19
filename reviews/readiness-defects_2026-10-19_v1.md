# Readiness defect register — ten-task admission (19 Oct 2026, v1)
Watcher: Chase Mythos (sunchaser)  ·  Work path: D:/GLM/Xeus CyberBench  ·  Evidence cut-off: 2026-10-19 00:52 UTC
Full document: `D:\Documents\Hermes\sunchaser\cybergym-10task-readiness-defects_2026-10-19_v1.0.docx`
Tracker: `D:\Documents\Hermes\sunchaser\cybergym-10task-readiness-tracker_2026-10-19_v1.0.xlsx`

This is a readiness register for Codex to work from. It is not a certification and confers no run authority. Only the watcher's verification column may move an item to verified-closed; self-report reaches evidence-submitted at most.

## P0 — these block admission outright

**D-01 Reconnect control fails certification.** One reconnect observed, but the model session never closes, there is no `SessionEnd`, zero cancelled requests, and no terminal result. Evidence: on-host `evidence/synthetic-scored-20261017-reconnect-v4-synthetic-length-header/reconnect-failed-gate-diagnostic.json` (`certification_gate_passed=false`, `completed=9`, `cancelled=0`, `model_session_closed=false`, `session_ends=0`), ledger L260. Close: root-cause by diffing v26q (2 sessions closed, 1 SessionEnd, 1 cancellation) against this run, then one clean same-attempt attempt with a signed interruption receipt. If the gate definition itself is wrong, change it explicitly with written rationale — never silently.

**D-02 Missing `finally: worker.abort()` on the scored path.** `examples/cybergym/nooa_cybergym/leaderboard/campaign_runner.py:352-353` calls `run_campaign(...)` with no cleanup, unlike `practice_campaign_cli.py:182`. A runner failure leaves a live worker, container or tunnel behind and contaminates the next task. The test that expects abort is already written and uncommitted (`test_scored_campaign_cli.py`, +42/−2). Close: implement, observe red before green on Linux, commit.

**D-03 Capacity unproven.** Root is 98% used, 7.9 GB free (`/dev/vda1 303G of 310G`, measured 00:51 UTC), and kernel `memory.peak` is unavailable so peak is unmeasured. Close: reclaim or add capacity, re-measure at launch, record sampled and peak evidence or its documented unavailability.

**D-04 No signed aggregate report.** Every control is a raw observation, several explicitly `certification_gate_passed=false`. There is no go/no-go basis. Close: aggregate, sign, and have the report independently replayed.

## P1 — required before the ten tasks
- **D-05 Pin drift.** A/B were produced at `2f7bd235`; the Windows UI preflight guard landed later and never ran for them. Re-collect rather than grandfather.
- **D-06 No second repetition.** G/H profiles are pre-staged only; no host key, config or launch.
- **D-07 Timeout receipt carries a disclosed secondary `ValueError`** from Docker cleanup on a closed file (ledger L258).
- **D-08 Drift control not integrated.** The v6 observation is genuine and hash-verified, but `certification_gate_passed=false` and has no place in any report.
- **D-09 Image manifest still an unsigned candidate** (3,014/3,014 observations, drift pass clean).
- **D-10 Fixed-side assets are LFS pointers** for all ten tasks, so fixed-side exit codes cannot be produced.
- **D-11 No hard budget; model identity drifts.** `deepseek-flash` now serves V4.1-Flash-1017, so the alias no longer pins weights.

## P2 — hygiene and accuracy
- **D-12** 31 untracked `.pytest-*` directories in the repo root.
- **D-13** Ledger still records SunChaser SSH as awaiting operator authentication; read-only SSH succeeded at 00:51 and 00:52 UTC. Treat the gate as resolved and say so in the ledger.

## Order of work
0. D-13, D-12, D-02 (same day).
1. D-01 and D-03 — the two hard blockers.
2. D-05 pin decision, then D-07, D-08, D-09, D-10.
3. D-06 second repetition under the settled pin.
4. D-04 signed report, D-11 budget and model binding, then operator go/no-go.

Do not start Phase 2 re-collection while D-01/D-03 are open, and do not start the second repetition before the pin is settled.

## Integrity rules for the run itself
Clean 192 eval split, never the raw 200. Report both any-of and final metrics. A vulnerable-only crash is not a solve. Negative controls stay in the same run. No retry after a task has started.
