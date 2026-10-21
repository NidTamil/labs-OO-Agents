# Standalone inherited-listener primitive source review

Status: **HELD, untracked, source-only; no native execution approved or observed.**
This small experiment prepares a concrete Linux primitive under the approved
[UI route design](scored-subset-rpc-route-decision_2026-10-21.md). It imports none
of the held broker, transport, manager, worker or process-supervisor candidates.
It does not implement their missing production bootstrap or close their defects.

## Reviewed snapshot

All three files remain under `experiments/cybergym_rpc_fd_probe/`:

| File | SHA-256 |
| --- | --- |
| `probe.py` | `62de49ce495067c04a54bbec3023e3f5458f67164d602e8bf6a69df362f8ea5a` |
| `test_probe.py` | `269f7fce57dc9d20128dd3e96a0416598c455c749ce12244f6299408c2e23931` |
| `README.md` | `c87819c4254b10ecf3fc539d57f336ba3dc45ef550490bdbb3cc8d844e477f3d` |

The 273-line standalone stdlib source has explicit broker/client entrypoints.
The broker duplicates borrowed activation FD 3 before wrapping it, validates one
listener's kernel type/name and activation environment shape, accepts one peer,
records SO_PEERCRED and exchanges one fixed bounded nonce frame with EOF. The
client records raw peer credentials without misidentifying the listener creator
as the accepting broker. Path and FD inode observations stay separate.

The frame is 42 bytes; at most 43 bytes are received to detect excess input.
One cooperative monotonic duration, at most five seconds, supplies residual
socket timeouts before blocking calls and checks after return. Cleanup closes
only owned sockets. The source never binds, unlinks, reaps, launches a process
or dispatches arbitrary commands; destructive negative controls report
`NOT_IMPLEMENTED`. Manager provenance always remains `UNPROVEN`.

Duplicating the socket does not isolate open-file-description flags. Timeout
mode temporarily changes shared O_NONBLOCK, then cleanup restores the sampled
flag. The future exact fixture must provide exclusive use/custody and external
observation of this change and any restoration failure. This is not established
by the current source. Nor do point-in-time path metadata, environment values,
FD names or nonce equality authenticate the manager or its retained lifetime.

## Evidence and independent review

The implementer observed missing-feature RED, then a native-boundary RED batch
of **15 failed / 17 passed**. Expanded fact reporting had a further intended
**1 failed / 43 deselected** case. Final formatted-source verification observed
**44 focused synthetic cases passed in 0.22 seconds**, Ruff check passed, and
Ruff format check reported two files already formatted. All OS/socket/clock
boundaries were substituted. The isolated command used the existing root
environment without synchronization:

```text
uv run --offline --no-sync pytest --confcutdir=experiments/cybergym_rpc_fd_probe experiments/cybergym_rpc_fd_probe/test_probe.py -q
```

Independent read-only code/spec review verified all three final hashes and
found no P1/P2 within the stated source-observation scope. It checked borrowed
FD handling, residual I/O deadlines, bounded framing, cleanup and fact/authority
distinctions. Optional coverage gaps noted were originally nonblocking listeners,
restoration/close failures and CLI error output. Those cases were not executed.
Root inspected the source and README. Neither root nor reviewer repeated the
author's suite; no independent test execution is claimed.
Root confirmed the final three hashes and byte preservation of all 32 preexisting
modified/untracked held files. Independent documentation review found the scope
and evidence accurately recorded; the scoped Git diff check was clean.

**Zero Linux observations, real sockets, activation events, distro boots,
services, probe users, provider requests or production host actions occurred.**
No old suite or held source was executed, and no runtime/readiness proof follows
from the synthetic tests. The experiment README retains detailed metrics and
the unresolved platform requirements.

## Next boundary

Exact disposable environment, identities, unit configuration, source/runtime
custody, fixture/ancestor custody, retained manager descriptor lifetime, negative
permissions controls, independent hard bounds and cleanup still need proof.
The [separate local preparation proposal](scored-subset-disposable-linux-proposal_2026-10-21.md)
requests only a new WSL environment's setup and read-only inventory; it is not
approval to execute this probe or any held candidate. No production SSH change
or handshake is included. The source remains held and untracked, and the last
reviewed committed source component remains `42a33385`.
