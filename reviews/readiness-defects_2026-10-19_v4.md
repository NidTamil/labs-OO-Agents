# Readiness defect register — ten-task admission (19 Oct 2026, v4)
Watcher: Chase Mythos (sunchaser)  ·  Work path: D:/GLM/Xeus CyberBench  ·  HEAD 76593420, tree clean
Document: `D:\Documents\Hermes\sunchaser\cybergym-10task-readiness-defects_2026-10-19_v1.1.docx`
Supersedes v3. Corrections below are Codex's, verified by the watcher; v1–v3 are retained unchanged.

## Corrections applied in v4
1. **Order.** Ledger L248 requires source, profile and bounded provider budget preflighted before another probe. Capacity (D-03) and budget (D-11) therefore precede the reconnect control (D-01), not follow it.
2. **Status.** D-13 (`8b20de81`), D-02 (`83941d18`), D-12 (`76593420`) are closed. The worker fix is committed but not yet in a newly pinned, certified runtime — host pin stays `a3805ca1`.
3. **Signed versus raw.** D-01 and D-04 were imprecise. The reconnect has a signed failure receipt `6954f409…cb61` (L262); the timeout has a signed timeout receipt `8a896605…c008` (L260). Neither is a certification pass, and no aggregate report exists.
4. **D-02 wording.** The defect was the missing `finally: worker.abort()` call. No surviving container or tunnel was observed, and `run_campaign` separately attempts UI reap on failure.
5. **D-10 wording.** Fixed-side exit codes are unavailable until controller-private LFS hydration and evaluation.
6. **Line references.** Reconnect is L262, not 260; timeout is L260, not 258.

## P0 — open
**D-01 Reconnect control fails certification.** One reconnect observed; the model session never closes, there is no `SessionEnd`, zero cancelled requests and no success result. Signed failure receipt `6954f409…cb61` (L262).
**D-03 Capacity unproven.** Root 98% used, 7.9 GB free at 00:51 UTC; kernel `memory.peak` unavailable.
**D-04 No signed certification pass or aggregate report.** Signed terminal receipts exist for two controls; neither is a pass.

## P1 — open
**D-05** Pin drift: A/B at `2f7bd235`, before the UI preflight guard; the D-02 fix now sits at `76593420` while the host pin is `a3805ca1`.
**D-06** No second two-fixture repetition.
**D-07** Timeout receipt carries a disclosed secondary Docker cleanup `ValueError` (L260).
**D-08** Drift control unintegrated, `certification_gate_passed=false`.
**D-09** Image manifest is an unsigned candidate.
**D-10** Fixed-side exit codes unavailable until controller-private LFS hydration and evaluation.
**D-11** No hard budget; `deepseek-flash` now serves V4.1-Flash-1017 while retaining the alias.

## Closed — verified by read-back
**D-13** `8b20de81` · **D-02** `83941d18` (red `d02-red-20261019-03`, green `d02-green-20261019-01` 5 passed, `d02-runner-20261019-02` 13 passed) · **D-12** `76593420` (`/.pytest-*/` at `.gitignore:65`).

## Execution order
**Preflight:** D-03 capacity, D-11 budget, D-05 pin.
**Then:** D-01 reconnect.
**Then:** D-07, D-08, D-09, D-10.
**Then:** D-06 second repetition.
**Then:** D-04 aggregate report, then operator go/no-go.

Integrity rules for the run itself: clean 192 eval split, never the raw 200; both any-of and final metrics; a vulnerable-only crash is not a solve; negative controls inside the same run; no retry after a task has started.
