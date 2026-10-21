# Held Linux manager create/arm protocol review — 2026-10-21

Status: **HELD, untracked, conditional fake-backed source only.** Task 3 of the [Linux manager custody plan](../docs/superpowers/plans/2026-10-21-scored-subset-linux-manager-custody.md) remains incomplete. No production integration, worker release, process-supervisor P1 closure or readiness gate is established.

## Stable reviewed snapshot

All paths below are relative to `examples/cybergym/`.

| File | SHA-256 |
| --- | --- |
| `nooa_cybergym/leaderboard/subset_linux_manager.py` | `2912F164AF432FF252654E829EB6E62C5729E535DAFBDA3796396612E8283C36` |
| `nooa_cybergym/leaderboard/subset_linux_held_worker.py` | `69A5BEEC7CFB1D9783F70B218CB70E5D0B5D309AE260B7E93CABA88AB2D60130` |
| `tests/leaderboard/test_subset_linux_manager.py` | `6DA364C42AB4997EA67F8ECF6CFE53B14D23ECB1F019A1C3F4BF3F6972FD0279` |
| `tests/leaderboard/test_subset_linux_held_worker.py` | `D1DC95447B0307818541AD2CD1A061AAEC666180DB5ACB90ACB26C5539B2E81E` |

The manager uses the separate held Task 2 intent protocol only with synthetic authorities. It validates declared wrapper/bootstrap, manager and retained endpoint prerequisites, consumes the original creation attempt internally before its sole fake create call, and binds a bounded created record to explicit job-to-invocation correlation. It requires exact retained-cgroup join and continuity, exclusive canonical arm publication, sync/readback, and subsequent clock/identity checks. The default manager backend is absent/refused; accepted test backends explicitly identify themselves as fake. These are conditional interfaces, not independent provenance.

The wrapper module is a pure bounded event/message state model. It creates no socket or process, imports no payload, and grants no release even for a matching message. An executable wrapper, material/descriptor validation and Task 4 exchange are absent.

## Independent review and focused evidence

Independent read-only dependency preflight found that this isolated source protocol could proceed while Task 1 material and production authorities remained open. It verified the relevant pinned v255 D-Bus spellings and identified that original creation correlation cannot come from a later same-name lookup. The plan now records the exact wire types and separate correlation requirement. No real manager observation occurred.

The implementer observed missing-feature and initial correlation/bounds failures, then the expanded pre-review pair passed **90 focused synthetic cases: 59 manager and 31 wrapper**, in 0.44 seconds. Review identified bounded-input validation and post-I/O clock gaps, and required explicit authority separation and stronger partial-record evidence. Corrections bound profile/property/receipt/job values before serialization or copying, rechecked boot/time after readback, allowed the original current job to clear while refusing a new job, rounded required stop grace upward within the floored total budget, and rejected manager-backend self-attestation of the cgroup join.

Review-driven RED selections produced seven failures, then two, then one additional unknown-job-primitive failure. A correction selection passed **13 / 59 deselected**. Because shared create/read/arm helpers changed, the implementer ran the affected manager file: **72 passed / 1 failed**; the remaining failure was a test-authoring `NameError` caused by misplaced crash assertions. Those assertions were restored, and the final covering selection (`partial_or_wrong_record or unknown_job_path`) passed **5 / 68 deselected** in 0.17 seconds. The unchanged wrapper's 31 cases were not repeated. These are implementer-observed results; no final full-state manager/combined suite or independently executed test result is claimed.

The stable independent read-only correction review found **no remaining actionable P1/P2 within conditional fake-backed scope**, verified all four hashes, and confirmed partial/wrong records remain retained and deny retry in the test model. Root inspected the final source/hashes and independently ran Ruff check and format check successfully on all four files. No old recorded suite was rerun.

## Open requirements

- The actual wrapper executable, interpreter/loader/import graph, environment and worker material are not independently identified, sealed or held through use.
- There is no production D-Bus backend, marshaling/normalization proof, authenticated manager registration, create/job-to-original-invocation correlation, real endpoint/FD lifetime or retained cgroup continuity proof. Fake properties and identities establish none of these.
- Startup/runtime/stop arithmetic is provisional. No calibrated operational duration, independent boot/clock authority, continuously armed suspend-aware hard watchdog, post-resume fencing or actual containment/termination proof exists.
- Memory-backed sync, concurrency, partial writes and crash observations do not prove Linux filesystem durability, protected custody or cross-process behavior. A live unit lookup is not atomic invocation custody, and no name-based stop was added.
- No real worker, staging, fresh cross-store lease, provider accounting recovery, remote-session closure or after-cleanup signed completion is wired. Task 4 release remains disabled; Task 5 platform proof remains pending.

All four source/test files remain untracked and unpromoted. The older held process, custody and journal drafts were not imported or executed. No worker/service/socket, SSH, provider, production key, host configuration, live control or scored action occurred.
