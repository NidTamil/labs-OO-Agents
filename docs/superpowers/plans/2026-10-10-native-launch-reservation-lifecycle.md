# Native launch reservation lifecycle audit and repair

The two authorized Level-1 practice attempts remain unstarted by the model. No new launch occurs until this plan's verification and freeze finish.

1. Trace preparation, signed start intent, window open, extension reservation, outbound Send, first model-request witness, locked final, evaluator verdict, and signed terminal receipt. Record the owner and path creation point of each artifact.
2. Add a regression starting with a verified but unreserved launch, constructing the submitter before the extension reserves it, and ending with an actual verified synthetic signed terminal receipt. Observe the current failure first.
3. Make the submitter validate immutable launch identity at construction and the launch directory and receipt only after reservation is observed. Preserve symlink, canonical receipt, single-Send, and timeout denials.
4. Run focused and existing leaderboard tests, lint, and a Linux test of the real atomic reservation. Report red-to-green evidence to the user before any launch.
5. Build a new exact practice freeze, verify it, then run arvo:47101 followed by arvo:3938 with pinned native UI and per-task teardown. Commit only independently verified signed practice receipts.

The Xeus `NativeTerminalReceiptPublisher` consumes signed kernel/evaluator contracts. The practice driver uses `PracticeArvoEvaluator` to sign the equivalent receipt after the official ARVO raw-exit evaluation. Both require a prepared evidence directory, stopped solver, and locked final; neither should create or require the launch reservation directory before extension activation.
