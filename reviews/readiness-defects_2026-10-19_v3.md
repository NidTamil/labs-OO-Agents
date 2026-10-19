# Readiness defect register — ten-task admission (19 Oct 2026, v3)
Watcher: Chase Mythos (sunchaser)  ·  Work path: D:/GLM/Xeus CyberBench  ·  Read-back at 2026-10-19 12:2x pm Sydney
Supersedes v2. Three items moved to **verified closed** on independent read-back, not on self-report.

## Verified closed this pass
**D-13 Ledger accuracy — CLOSED.** Commit `8b20de81` rewrites the SunChaser access gate to record the 00:52 UTC read-only SSH as resolved. Verified by reading the committed diff.
**D-02 Missing `finally: worker.abort()` — CLOSED.** Commit `83941d18`. `campaign_runner.py:354-358` now wraps `run_campaign` in try/finally with `binding.worker.abort()`, matching `practice_campaign_cli.py:182`. Genuine red first: `d02-red-20261019-03.log` fails with `assert ['run'] == ['run', 'abort']` on two tests. Green: 5 passed (`d02-green-20261019-01.log`), 13 passed (`d02-runner-20261019-02.log`). The two earlier red runs were import/setup failures and are disclosed as such in the README — correct not to count them.
**D-12 Repo hygiene — CLOSED.** Commit `76593420`. Root-anchored `/.pytest-*/` rule at `.gitignore:65`; directories left on disk deliberately. `git status --porcelain` is empty and the branch is level with origin.

## P0 — still blocking
**D-01 Reconnect control fails certification.** Model session never closes, no `SessionEnd`, zero cancelled requests, no terminal result. Evidence: on-host reconnect-failed-gate-diagnostic.json, ledger L260.
**D-03 Capacity unproven.** Root 98% used, 7.9 GB free at 00:51 UTC; kernel `memory.peak` unavailable.
**D-04 No signed aggregate report.**

## P1 — required before the ten tasks
**D-05** A/B built at `2f7bd235`, before the UI preflight guard.
**D-06** No second two-fixture repetition.
**D-07** Timeout receipt carries a disclosed secondary Docker cleanup `ValueError`.
**D-08** Drift control unintegrated, `certification_gate_passed=false`.
**D-09** Image manifest is an unsigned candidate.
**D-10** Fixed-side assets are LFS pointers for all ten tasks.
**D-11** No hard budget; `deepseek-flash` no longer pins weights.

## Remaining execution order
1. D-01 · 2. D-03 · 3. D-05 · 4. D-07 · 5. D-08 · 6. D-09 · 7. D-10 · 8. D-06 · 9. D-04 · 10. D-11

Integrity rules for the run itself: clean 192 eval split, never the raw 200; both any-of and final metrics; a vulnerable-only crash is not a solve; negative controls inside the same run; no retry after a task has started.
