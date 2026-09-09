# SunChaser v2.2 qualification — 2026-09-09

The qualified source revision is
`258476ba883345d5346023e6397adbf82103855d` on
`feat/sunchaser-v2-2-task13-debug`. Later documentation-only commits record
this qualification; they do not represent a new runtime test or diagnostic run.
Use this immutable source revision as the operations pin. A subsequent source
change needs its own qualification record before this pin can be replaced.

## Scope and audit trail

| Change | Revision | Status |
| --- | --- | --- |
| Explicit Pro provider alias and registry-contract test | `73132ed54da9ee2bc4963ce1c8b258d97c79a03b` | Task 1 review PASS; configuration tests pass |
| Diagnostic procedure, provenance and evidence limits | `6ebbd86`, corrected by `0ae3ac1` | Task 2 re-review PASS; PoC identifier label clarified in the README |
| Versioned implementation plan | `6e8b6abe8f8a3d22c20ecc95ae5fef0705fde9e2` | Records the three-task scope |
| Timeout test clock and late-result isolation | `258476ba883345d5346023e6397adbf82103855d` | Test-only change; production timeout and cancellation behavior unchanged |

Production-equivalent fixtures, evaluator preflight, and the diagnostic
provenance checks remain documented workflow requirements. This revision does
not implement automatic enforcement of those enhancements. The provider test
checks the registry contract; qualification did not call the provider or
validate its live parameter acceptance.

## Reproducible checks

Checks ran on the Linux worker with Python 3.13.15. The working directory was
`/srv/sunchaser/labs-OO-Agents-kimi-test/examples/cybergym`, with
`PYTHONPATH=/srv/sunchaser/xeus-cybergym/src:/srv/sunchaser/labs-OO-Agents-kimi-test`.
The executables were `/srv/sunchaser/.venv-v22/bin/python` and
`/srv/sunchaser/.venv-v22/bin/ruff`. Commands below use those executables as
`python` and `ruff`.

| Command at qualified revision | Result | Pytest duration | Process wall time |
| --- | --- | --- | --- |
| `python -m pytest tests/test_portfolio_main.py -q` | 11 passed | 0.22 s | 4.88 s |
| `python -m pytest tests/test_stagnation_reviewer.py::test_final_candidate_timeout_does_not_wait_for_cancellation_suppressing_reviewer -q` | 1 passed | 0.53 s | 5.36 s |
| `ruff check tests/test_portfolio_main.py tests/test_stagnation_reviewer.py` | All checks passed | — | 0.01 s |
| `python -m pytest tests -q` | 285 passed | 4.74 s | 9.46 s |

These are qualification test timings, separate from the historical diagnostic
timings in the README. Wall times include process startup/imports and are not a
performance comparison. This record summarizes the observed worker results;
it is not a raw log or signed attestation.

## Baseline failure and test-isolation correction

Before the test correction, the same full-suite command produced:

| Revision / attempt | Result | Pytest duration | Process wall time |
| --- | --- | --- | --- |
| `6e8b6abe`, first full run | 284 passed, 1 failed | 5.64 s | 10.52 s |
| `6e8b6abe`, failing test alone | 1 passed | 0.16 s | 5.71 s |
| `6e8b6abe`, full rerun | 284 passed, 1 failed | 5.79 s | 10.93 s |
| Base `b7ab22b8807855b07a95f977fbe9a4ac8e3308c5`, full run | 283 passed, 1 failed | 5.64 s | 10.89 s |

Every full-suite failure was the final-candidate timeout test, at the wait for
`reviewer_started` (then line 277). The base reproduces the failure, so it was
not introduced by the v2.2 provider or documentation changes. The original
branch's focused configuration tests also passed (11 tests, 0.29 s; wall
4.94 s), as did Ruff on `test_portfolio_main.py` (wall 0.01 s).

Source inspection explains a startup race: the test's real 1 ms deadline starts
before synchronous setup and the first event-loop yield. If setup consumes
that budget, the implementation correctly cancels the scheduled reviewer
before its body starts. The test then waits for an event that cannot fire.
This mechanism is consistent with the isolated pass and suite-order failures;
the failed runs did not instrument individual setup timings.

The correction follows the neighboring timeout test: freeze the instance's
injected monotonic clock through startup, wait for `reviewer_started`, then
advance the clock past the deadline. The original 100 ms bound still checks
that cancellation suppression cannot delay the returned timeout. The test
also checks that the late result is pending at return, releases and awaits it,
and confirms that only one audit record exists. No production code or timeout
budget was relaxed. The corrected focused test and full suite pass at the pin.

Windows collection was previously blocked by the POSIX-only `fcntl` import.
Initial Linux collection attempts lacked runner dependencies; these were
environment setup faults, not executed test failures. They are not counted as
passes. No baseline qualification exception remains after the test correction.

## Evidence boundaries

The historical Task 13 diagnostic retains its original source revision
`b7ab22b8807855b07a95f977fbe9a4ac8e3308c5`. This qualification contains no
new candidate replay, verifier result, or model-performance evidence. Frozen v1
claims, signed v2 cohort records, and earlier run roots are unchanged.
