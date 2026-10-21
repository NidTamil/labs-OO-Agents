# Held activated UI broker owner review — 2026-10-21

Status: **HELD, untracked, conditional source-only adapter.** This is a partial
implementation of item 1 of the approved [route design](scored-subset-rpc-route-decision_2026-10-21.md).
It does not close the existing route P2, enable a claim, or establish readiness.

## Stable reviewed snapshot

| File, relative to `examples/cybergym/` | SHA-256 |
| --- | --- |
| `nooa_cybergym/leaderboard/subset_ui_activated_broker.py` | `9ddb8ffbb11ca4b2ae67cccc0c5ca689b9b6af2e9ced3849aa3b9c6dc277c243` |
| `tests/leaderboard/test_subset_ui_activated_broker.py` | `c26ffd55a7a408cb5091cc8194ef9496d1790b10dbb31d24c8fcdce777f9d368` |

The new owner acquires one listener through an explicit bootstrap boundary,
accepts connections itself, obtains their peer credentials through that same
boundary and privately dispatches bounded schema-two `poll` or `ack` frames.
It has no public dispatch API accepting a socket or peer numbers. `claim` always
rejects. The default bootstrap refuses every platform; only the new synthetic
tests supply an implementation. Registration objects, paths, FD numbers and
environment values do not establish independent manager provenance.

ACK processing makes distinct commit and fresh committed-readback calls before
echoing exact bytes. Serial owner calls share a local failure latch: an ACK
followed by a readback, write, close or clock failure retains a may-have-committed
disposition and denies further dispatch in that instance. Each request checks
one residual monotonic duration through accept/read/mailbox/write/close work;
these are cooperative checks and cannot interrupt a blocked backend.

The owner closes only connections it has classified as newly accepted and owned.
It retains strong references to all such objects, rejects later reuse, and denies
before accepting beyond a provisional 64-connection limit. There is no identity
eviction or restart adoption. Unclassifiable resources remain the trusted
bootstrap's responsibility. The limit is not calibrated for a real preparation's
polling or ACK workload.

## Verification and independent review

The implementer observed an initial missing-feature RED case, two later
registration-boundary RED cases and one clock-after-accept cleanup RED case.
The pre-review focused suite passed **90 synthetic cases in 0.33 seconds**. An
earlier run encountered oversized pytest parameter IDs exceeding Windows'
environment-variable limit; short fixture IDs corrected the test setup. An
initial Ruff import-location finding was also corrected. No dependency sync or
old suite was repeated.

Independent source review found one P2: keeping only the immediately previous
connection did not reject the nonadjacent reuse sequence A, B, A. Two new RED
tests exposed the lifetime-history and capacity gaps. The correction retains
all owned identities without eviction and checks capacity before accept. Test
fakes now register the exact accepted object and derive its actual closed state;
an explicitly malicious live rebind is confined to the negative reuse test.

The implementer observed **4 ownership cases passed / 88 deselected**, followed
by **85 affected serve-path cases passed / 7 deselected in 0.26 seconds**. The
seven unchanged module/default-bootstrap/registration-constructor cases were
not repeated. No full final-state 92-case execution or independent test execution
is claimed. The isolated commands used the existing root environment via
`uv run --offline --no-sync`, `PYTHONPATH=examples/cybergym`, and
`--confcutdir=examples/cybergym/tests/leaderboard`.

Independent read-only correction review verified the final hashes and found no
remaining P1/P2 **within conditional fake scope**. Root inspected the source,
test changes and hashes, and independently ran Ruff check and format check on
the two files successfully. This review does not approve integration or the
production route.

## Open requirements

- No native bootstrap, authenticated manager registration, retained descriptor
  or ancestor custody, actual listener/peer observation or matching restricted
  forced-command shim exists. The old held RPC/broker/transport files are unchanged.
- The injected mailbox protocol does not establish signed command/claim/ACK
  verification, real store durability or adoption of the cross-store guard.
- The ambiguity latch is in memory only. Restart reconciliation, exact durable
  ACK recovery and calibrated lifetime capacity remain open; constructing a new
  owner cannot be treated as permission to retry an uncertain ACK.
- No hard watchdog, independent boot clock, Windows Job/ACL proof, actual SSH
  handshake, remote-session closure or disposable Linux proof was supplied.

No held original module was imported or executed. No real socket, worker,
service, provider, host, production key or scored action occurred. Both new
files remain untracked and unpromoted; all original process-supervisor P1s and
live admission gates remain open.
