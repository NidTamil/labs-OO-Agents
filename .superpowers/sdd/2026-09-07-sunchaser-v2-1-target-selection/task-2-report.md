# Task 2 report: candidate staging and durable identity

## Status

Implemented and ready for integration on `feat/sunchaser-v2-1-target-selection`
from base `6c7c14bc7315fa696970bb5efd9060f006232a7c`.

## Changes

- Public `submit()` now allocates its monotonic submission number and stages the
  candidate before rate-slot acquisition or verifier invocation.
- Staging opens the source once, captures descriptor metadata, copies with
  bounded 1 MiB reads into a unique exclusive temporary file, computes SHA-256
  and byte length during that copy, checks descriptor and path identity for
  detectable changes, fsyncs the temporary file, and publishes without
  overwriting an existing submission.
- Published candidates are read-only. Linux publication uses a hard link for an
  atomic no-clobber operation; Windows uses atomic non-replacing rename because
  Windows cannot unlink a read-only temporary hard-link name.
- Missing, unreadable, non-regular, disappeared, detectably replaced, and
  detectably mutated sources return `local_candidate_error`. These attempts are
  recorded under their consumed submission number and durably appended to the
  JSONL audit without reserving a rate slot or touching the verifier shell.
- Destination staging and audit persistence failures raise
  `SubmissionStorageError` instead of falling back or being suppressed.
- Successful `PocSubmission` state and JSONL audit records now retain the staged
  path, SHA-256 digest, and byte length. The verifier is invoked with that staged
  path.
- Finalization requires the recorded staged path, digest, and length; it streams
  only that staged file, rejects missing or changed identity, and writes the same
  digest and length into the final manifest. It has no original-path or latest
  artifact fallback.
- `verify_existing()` remains a direct verifier operation and creates no public
  staged submission.
- Child exit 124 remains a framed verifier timeout result. Transport timeout or
  framing death retains the existing poison, respawn, and breaker behavior.

## Test coverage

Added regressions for staging order, single source open, bounded reads, persisted
identity, read-only publication, source mutation after staging, missing and
directory inputs, unreadable input, disappearance, replacement, mutation during
copy, partial-copy cleanup, publication no-clobber, staging and audit storage
failures, monotonic numbering after local rejection, direct `verify_existing()`,
and final identity mismatch or absence.

TDD red evidence: the staging-order test failed against the base because the
verifier ran before `submission_1.poc` existed. After implementation, the focused
submit/finalize/verify-existing selection passed 26 tests.

Validation at the final code state:

- `test_portfolio_agent.py`, Windows-compatible selection: 58 passed, 1
  deselected.
- Complete `test_portfolio_agent.py`: 58 passed, 1 failed only at the existing
  Unix production-process boundary because Windows Python rejects asyncio
  `pass_fds`. The adjacent child-exit-124 and transport-death unit regressions
  passed. Native collection also requires temporary `fcntl` and `SIGUSR2` shims
  because the repository imports Unix-only runtime facilities.
- `ruff check`: passed.
- `ruff format --check`: passed.
- `git diff --check`: passed.

## Self-review

The implementation preserves source-local versus destination-local error
boundaries, closes descriptors on all exits, cleans incomplete temporary files,
does not overwrite a pre-existing numbered candidate, and keeps the verifier
shell owner untouched on local rejection. The trusted-writer limitation remains
explicit in the design: a same-size rewrite that also restores all checked
metadata is outside this contract.

No plateau logic or selection metadata was added.

## Concerns

The host has no runnable Linux test environment, and Docker Desktop did not
become ready during a bounded startup attempt. The Unix-only BashSession
process-boundary integration therefore could not be executed successfully on
this host; its behavior was preserved and its focused unit coverage passes.
