# Held Linux manager intent protocol review — 2026-10-21

Status: **HELD, source-only, untracked and unaccepted for integration or effects.**

This checkpoint covers Task 2 of the [Linux manager custody plan](../docs/superpowers/plans/2026-10-21-scored-subset-linux-manager-custody.md). It records a new protocol candidate, not acceptance or execution of the older process-supervisor draft. The three process-supervisor P1s remain open. No readiness gate passes.

## Reviewed files and scope

- `examples/cybergym/nooa_cybergym/leaderboard/subset_linux_manager_intent.py`, SHA-256 `47BC38881142A4669F89692394144A789167F7B4BFC6A4C6ABF25F5742C6B7BD`.
- `examples/cybergym/tests/leaderboard/test_subset_linux_manager_intent.py`, SHA-256 `0D77832FA10ED829DF747C6DDEB17C3B4D370E6432028D361AE7AA2CE54C2056`.

Both files remain untracked. The source supplies protocols for independently trusted directory/ancestor custody, an exact boot/domain clock and an exclusive transaction. It supplies no production implementation of those authorities. Within those conditional protocols, it publishes a bounded canonical immutable intent, derives the unit name from the full run/task/preparation/attempt identity, and durably consumes one `creation_attempted` record with file/directory sync and exact readback before returning. Recovery reads exact pinned records without refreshing their original deadline. The returned observation is always `HELD` and cannot serve as a standalone service-creation capability.

Source/material digests are declarations. The exact worker and immutable dependency graph remain missing; developing this fake-backed protocol independently does not permit integration and may require rework if the eventual graph changes the identity contract.

## Verification and independent review

The implementer observed the missing-feature RED case and a separate noninteger-schema RED case, then **44 focused synthetic tests passed in 0.22 seconds**. The root Windows conftest imports unavailable `fcntl`; the new isolated file therefore used the existing root environment through `uv run --offline --no-sync`, with `--confcutdir=examples/cybergym/tests/leaderboard`. No dependency installation or old suite rerun was performed.

Independent read-only review found no actionable P1/P2 within this conditional source protocol. It identified two test limitations: fake trust ignored backend identity, and record-stage crash branches lacked post-crash assertions. Test-only corrections registered the exact backend object and identity, rejected replacement/rebound fake identities, and added explicit durable/absent recovery and unchanged-byte assertions. Two new RED checks exposed the fake-trust gaps. The final affected selection was **11 passed / 35 deselected in 0.13 seconds**; the completed full suite was not repeated. These test results are implementer-observed, not an independent execution claim.

Independent read-only delta review confirmed both test gaps addressed within fake scope, with no new P1/P2. Root inspected the final source/test and hashes and independently ran Ruff check and format check successfully. No full final-state suite or Linux platform control is claimed.

## Remaining boundaries

- The fake backend models memory durability and thread exclusion, not POSIX fsync, cross-process locking, held descriptors, trusted ancestor acquisition or an independently retained recovery pin.
- Fake clock samples are not independent boot/clock authority. No continuous hard watchdog, suspend/resume fencing or calibrated operational cleanup reserve exists.
- Lost pre-fsync bytes leave recovery unresolved; their absence cannot establish prior creation, new authority or permission to start a fresh deadline.
- A future manager API must consume internally before its one allowed creation call. No manager API, D-Bus call, wrapper, worker release, staging, cgroup identity/closure, fresh cross-store lease or production caller is supplied here.
- The only local platform inventory found WSL `docker-desktop` stopped, with no separate disposable Linux distribution listed. Nothing was started, installed or configured. This is not evidence about the production host or systemd.

No old held draft was imported or executed, and no provider, SSH, production host, key, scored task or live control action occurred. Source remains held for the exact worker/material boundary, independent authorities, production backend, independent integration review and disposable Linux proof.
