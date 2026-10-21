# Approved local WSL setup: stopped before import

Date: 21 October 2026, Australia/Sydney. The operator directly answered
**"Approve this WSL setup"** to the exact
[local preparation proposal](scored-subset-disposable-linux-proposal_2026-10-21.md).
The single approved image download failed. **No WSL distribution was imported
or booted, and no native probe or held component was run.**

## Observed operations

The Windows controller checked the current process token was not elevated,
recorded its current-user SID, rejected reparse ancestors, and found the exact
new workspace and distribution name absent. It observed 847,344,959,488 free
bytes on D:, then created only
`D:\GLM\cybergym-disposable-linux\listener-proof-20261021` with `images` and
`evidence` children. Current-user WSL registrations contained only
`docker-desktop`. This was the new setup's absence preflight, not a distro start
or repeat of historical platform tests.

The controller began one request for the exact approved HTTPS Ubuntu image,
using a separate owned downloader process bounded by the lesser of ten minutes
and the original fifteen-minute setup deadline. It retained stdout/stderr and
the exit receipt. The downloader exited 1 after **32.224 seconds** with:

```text
URLError: <urlopen error _ssl.c:1015: The handshake operation timed out>
```

The image placeholder contains **zero bytes**. No image checksum was verified;
the expected digest remains only the approved download pin. No HTTP image body,
archive parsing/rewrite, import, boot, account/unit creation, inventory command
inside Linux or distribution termination occurred. No running distribution was
created, so there was no owned distribution to terminate. The historical Docker
distribution and all production host/runtime state were untouched.

## Retained evidence and stopped state

Evidence remains in the approved workspace's `evidence` directory:

- `preflight.json`: SHA-256
  `6bed969ff1bb4768376fb7ca9ebdfb15e9d8bcfd9ad7a940e9136cefbbff0ff3`.
- `download-process.stderr`: SHA-256
  `5d03a64accd5e73d2fdb3a909fb9e0c3e5be09029b160167442b70261638c598`.
- `download-process.json` records the owned executable/argv, exit 1 and elapsed
  time; stdout and the zero-byte image placeholder are also retained.
- `setup-failed.json` records `STOPPED_BEFORE_IMPORT`, one download attempt,
  zero import/boot/termination attempts and no retry authority.

The local helper now rejects later setup operations when that failure receipt
exists. No import retry, alternate image, relaxed TLS check, delete, unregister
or cleanup mutation was attempted. The proposal's **"Download once"** boundary
has been consumed. Another attempt needs its own explicit bounded authorization
and must preserve this failure, the existing workspace and prior deadline;
the existing workspace cannot be treated as a fresh absent target.

Independent read-only receipt/documentation review confirmed the elapsed/exit
receipt, TLS error, zero-byte placeholder, both evidence hashes and the failure
latch. Root separately verified all 32 preexisting held files were byte-preserved.

## Source preparation limits

Before the operational attempt, independent read-only review of the ignored
Windows helper corrected download slow-trickle timing, partial registry reads,
prelaunch deadline evaluation and final stopped-registration comparison. It
approved only `preflight` and the separately bounded `fetch`; future import
would still require exact image/derived-archive review. Python syntax checking
passed; no production component acceptance follows from this helper.

The ignored file-only archive helper and synthetic fixtures are separate source
preparation. They have never inspected real image bytes or run inside Linux.
Author-observed pre-review verification was 18 synthetic passes. Independent
review found a stacked-PAX parsing gap; its new regression failed, then the six
affected PAX cases passed with thirteen deselected and Ruff clean. No complete
final nineteen-case run or independent test execution is claimed. Independent
read-only correction review found no remaining P1/P2 within file-only scope.
Final helper SHA-256 is
`bd38b7f30d82c0ba31410ee2788640dec7414688f97be518946e8ac60937f4f3`;
test SHA-256 is
`23670cd2ec49d13f69b1739ed8ea71f0c7bb5cbadb00f347d621c8178cc49b43`.
They do not authorize a new download, archive use, import or boot after this
failure. Held probe and production source remain untracked and unpromoted.

This result establishes only a failed local setup attempt. It proves no Linux
platform gate, listener custody, process cleanup, twelve-gate PASS or scored
readiness. The last reviewed committed source component remains `42a33385`.
