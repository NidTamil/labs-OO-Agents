# Readiness defect register — ten-task admission (19 Oct 2026, v2)
Watcher: Chase Mythos (sunchaser)  ·  Work path: D:/GLM/Xeus CyberBench  ·  Evidence cut-off: 2026-10-19 00:52 UTC
Supersedes v1: D-12 count corrected — 30 untracked `.pytest-*` directories, not 31 (the 31st untracked entry is this `reviews/` folder).
Full document: `D:\Documents\Hermes\sunchaser\cybergym-10task-readiness-defects_2026-10-19_v1.0.docx`
Tracker: `D:\Documents\Hermes\sunchaser\cybergym-10task-readiness-tracker_2026-10-19_v1.0.xlsx`

## P0 — blocks admission
**D-01 Reconnect control fails certification.** One reconnect observed, but the model session never closes, there is no `SessionEnd`, zero cancelled requests, and no terminal result. Evidence: on-host `evidence/synthetic-scored-20261017-reconnect-v4-synthetic-length-header/reconnect-failed-gate-diagnostic.json` (`certification_gate_passed=false`, `completed=9`, `cancelled=0`, `model_session_closed=false`, `session_ends=0`), ledger L260.
**D-02 Missing `finally: worker.abort()`.** `campaign_runner.py:352-353` calls `run_campaign(...)` with no cleanup, unlike `practice_campaign_cli.py:182`. A runner failure leaves a live worker, container or tunnel behind. The test that expects abort is already written and uncommitted (`test_scored_campaign_cli.py`, +42/−2).
**D-03 Capacity unproven.** Root 98% used, 7.9 GB free (`/dev/vda1 303G of 310G`, measured 00:51 UTC); kernel `memory.peak` unavailable, so peak is unmeasured.
**D-04 No signed aggregate report.** Every control is a raw observation, several `certification_gate_passed=false`.

## P1 — required before the ten tasks
**D-05 Pin drift.** A/B produced at `2f7bd235`; the Windows UI preflight guard landed later and never ran for them.
**D-06 No second repetition.** G/H profiles pre-staged only; no host key, config or launch.
**D-07 Timeout receipt carries a disclosed secondary `ValueError`** from Docker cleanup on a closed file (ledger L258).
**D-08 Drift control not integrated.** v6 observation is genuine and hash-verified, but `certification_gate_passed=false` and appears in no report.
**D-09 Image manifest still an unsigned candidate** (3,014/3,014 observations, drift pass clean).
**D-10 Fixed-side assets are LFS pointers** for all ten tasks, so fixed-side exit codes cannot be produced.
**D-11 No hard budget; model identity drifts.** `deepseek-flash` now serves V4.1-Flash-1017, so the alias no longer pins weights.

## P2 — hygiene and accuracy
**D-12** 30 untracked `.pytest-*` directories in the repo root.
**D-13** Ledger records SunChaser SSH as awaiting operator authentication; read-only SSH succeeded at 00:51 and 00:52 UTC.

## Execution order
1. D-13, 2. D-12, 3. D-02, 4. D-01, 5. D-03, 6. D-05, 7. D-07, 8. D-08, 9. D-09, 10. D-10, 11. D-06, 12. D-04, 13. D-11.

Integrity rules for the run itself: clean 192 eval split, never the raw 200; both any-of and final metrics; a vulnerable-only crash is not a solve; negative controls inside the same run; no retry after a task has started.
