# Native launch reservation lifecycle audit and repair

The two authorized Level-1 practice attempts remain unstarted by the model. No new launch occurs until this plan's verification and freeze finish.

1. Trace preparation, signed start intent, window open, extension reservation, outbound Send, first model-request witness, locked final, evaluator verdict, and signed terminal receipt. Record the owner and path creation point of each artifact.
2. Add a regression starting with a verified but unreserved launch, constructing the submitter before the extension reserves it, and ending with an actual verified synthetic signed terminal receipt. Observe the current failure first.
3. Make the submitter validate immutable launch identity at construction and the launch directory and receipt only after reservation is observed. Preserve symlink, canonical receipt, single-Send, and timeout denials.
4. Run focused and existing leaderboard tests, lint, and a Linux test of the real atomic reservation. Report red-to-green evidence to the user before any launch.
5. Build a new exact practice freeze, verify it, then run arvo:47101 followed by arvo:3938 with pinned native UI and per-task teardown. Commit only independently verified signed practice receipts.

The Xeus `NativeTerminalReceiptPublisher` consumes signed kernel/evaluator contracts. The practice driver uses `PracticeArvoEvaluator` to sign the equivalent receipt after the official ARVO raw-exit evaluation. Both require a prepared evidence directory, stopped solver, and locked final; neither should create or require the launch reservation directory before extension activation.

## Verified outcome, 2026-10-10

- The new preparation-through-signed-receipt regression failed at `MailboxNativeSubmitter.__init__` before the fix, then passed on Windows and on SunChaser Linux with the real atomic reservation. The post-format leaderboard suite passed: 1,033 passed, 23 skipped, 2 deselected. Ruff and `git diff --check` passed.
- Runtime archive `native-practice-code-r5.tar` has 93 exact source members; only `native_task_executor.py` differs from r4. Its SHA-256 is `d83bd5040785fbf18c1762600a198a60f5de9bf5876f61a3e88e78b5e541a41c`. All 93 deployed files match. Practice freeze SHA-256 is `4a1dcf6f1c6d0261db7393a7023100ffdcf06198baf845e36e1ec21703cc938f`.
- `arvo:47101` was run once through pinned VS Code 1.140.0 and Claude Code 2.1.289. At its terminal, the independently verified Xeus ledger had four events. The signed practice verdict was `oracle_true` (vulnerable raw exit 1, fixed raw exit 0). Receipt SHA-256: `bbcc19ebbe4fed5734f25a5dccb064aa4fa0df3dcb798e960f06c253a9cd1c6a`.
- Only after that signed terminal and UI teardown, `arvo:3938` was run once. The complete Xeus ledger had seven events. The signed practice verdict was `oracle_false` (vulnerable raw exit 1, fixed raw exit 1). Receipt SHA-256: `26fe95d54433da23a812b49d3413ed7cff7c56e215f3ea736649490785b537d9`.
- An independent verifier checked controller/evaluator signatures, request and result digests, final hash, and Xeus event-chain receipt binding for each task. Both owned windows and tunnels closed on terminal; final reap killed zero processes, and no practice task container remained. Only the signed terminal receipts and sanitized verification summaries were committed; private evaluator output remains outside the branch.
- These are practice verdicts. They do not start or certify the scored 1,507-task campaign.
