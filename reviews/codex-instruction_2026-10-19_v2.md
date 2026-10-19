# Codex — readiness defects: review and execute (19 Oct 2026, v2)
From: Chase Mythos (watcher)  ·  To: Codex
Register: `reviews/readiness-defects_2026-10-19_v2.md`  ·  Full detail: `D:\Documents\Hermes\sunchaser\cybergym-10task-readiness-defects_2026-10-19_v1.0.docx`

## Ask
Review the register and execute the defects in the priority order below.

## Priority order

| # | ID | Sev | Defect | Action |
|---|----|-----|--------|--------|
| 1 | D-13 | P2 | Ledger still records SunChaser SSH as awaiting operator auth | Update the ledger entry — SSH succeeded 00:51 and 00:52 UTC |
| 2 | D-12 | P2 | 30 untracked `.pytest-*` directories in the repo root | Clear or ignore them, keeping the abort-test change |
| 3 | D-02 | P0 | `campaign_runner.py:352-353` has no `finally: worker.abort()` | Implement, red then green on Linux, commit |
| 4 | D-01 | P0 | Reconnect control fails: session never closes, no `SessionEnd`, zero cancellations | Root-cause against v26q, then one clean same-attempt reconnect with a signed receipt |
| 5 | D-03 | P0 | Root 98% full, 7.9 GB free; peak memory unmeasured | Reclaim or add capacity, re-measure at launch |
| 6 | D-05 | P1 | A/B built at `2f7bd235`, before the UI preflight guard | Settle one pin for all evidence |
| 7 | D-07 | P1 | Timeout receipt carries a secondary Docker cleanup `ValueError` | Clean cleanup, re-sign |
| 8 | D-08 | P1 | Drift control observed but `certification_gate_passed=false`, unintegrated | Integrate with written pass criteria |
| 9 | D-09 | P1 | Image manifest is an unsigned candidate | Sign it |
| 10 | D-10 | P1 | Fixed-side assets are LFS pointers for all ten tasks | Materialise and hash-verify |
| 11 | D-06 | P1 | No second two-fixture repetition | Run G/H under the settled pin |
| 12 | D-04 | P0 | No signed aggregate report | Aggregate and sign, independently replayed |
| 13 | D-11 | P1 | No hard ten-task budget; `deepseek-flash` alias no longer pins weights | Set stop budget, bind returned model metadata |

Report back per item with the change, the commit hash and the evidence path.
