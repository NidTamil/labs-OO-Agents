# D-02 scored worker cleanup: Linux test record

Date: 2026-10-19. Host: `sunchaser-20260905`. These are unit tests only; no scored, official, or calibration campaign was started.

The uncommitted `test_scored_campaign_cli.py` regression was copied byte-for-byte to `/tmp/codex-d02-20261019/`. The pre-fix package came from the clean, pinned `a3805ca1` worktree. The fixed package was copied to the same isolated `/tmp` directory and its `campaign_runner.py` SHA-256 matched the local source: `89e05868a2b57599213b843e435b4a5e3b7f67875a7986655a8c9cf7792a0003`. The runtime source pin was not changed.

| Run ID | Result | Evidence |
| --- | --- | --- |
| `d02-red-20261019-03` | Expected red: two tests fail because `abort` is absent after normal return and injected runner failure. | [Red log](d02-red-20261019-03.log) |
| `d02-green-20261019-01` | Five scored CLI tests pass with the `try/finally` fix. | [Green log](d02-green-20261019-01.log) |
| `d02-runner-20261019-02` | Thirteen related campaign runner tests pass with the fixed source copy. | [Runner log](d02-runner-20261019-02.log) |

Setup runs `d02-red-20261019-01` and `d02-red-20261019-02` failed during import for missing `docker` and `xeus_cybergym`, respectively; neither counts as the expected red. The first broader runner run, `d02-runner-20261019-01`, failed because the isolated copy lacked `leaderboard/config/campaign-policy.json`. The fixture was copied from the pinned source before the passing runner run. Their logs are retained in this directory.

Local `uvx ruff check` passed on both changed Python files, and `uvx ruff format --check` reported both formatted. The test harness used `uv run` with the existing host Python environment and a temporary Docker SDK overlay. No production dependency or pinned worktree was modified.
