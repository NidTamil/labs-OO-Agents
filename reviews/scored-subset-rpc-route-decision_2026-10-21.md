# Schema-two subset UI RPC route decision

Status: operator approved the route **design for source and disposable-platform preparation** on 21 October 2026 (Australia/Sydney), in a direct reply to the exact question naming this document. This is not permission to change the production host, create or install a **production** account/key, run a production handshake or control, issue a provider request, sign an artifact or admit a scored task. Production account, credential, forced-command and manager configuration plus the host handshake require a later direct approval of their exact reviewed configuration and rollback. Source and fake-backend observations remain below the production proof threshold.

## Decision and source-only follow-up

At the design decision, the held schema-two transport called the pinned SunChaser alias as `root@...`; its candidate forced-command shim checked a root-owned Unix-socket pathname and then connected. No forced command is installed. A same-UID root process can replace that listener between check and connect. Another pathname check or `SO_PEERCRED` against UID 0 does not identify the genuine broker. The independent RPC0 review leaves this as P2. `claim` remains disabled, so there is currently no effect permission through this route.

The approved **schema-two-only** design is a dedicated restricted SSH identity and manager-created socket-activated broker route. The account would execute only the fixed RPC shim, without an interactive shell, PTY, port forwarding or arbitrary command. Reviewed Unix permissions must let that account traverse and connect without unlinking, replacing or rebinding the listener or its parent directory. The held shim instead requires root-owned mode-0700 socket custody and assumes UID/GID 0; those checks, the broker's expected peer identity and their platform proof must change together. The trust boundary includes the privileged manager and broker: a privileged root actor is not excluded by account separation alone. Inherited-FD listener custody and protected directory proof are still required. The broker must inherit the manager's listener FD and remain verifier-only for `poll` and exact durable `ack`; a separate controller-side fresh-lease authority is required before any `claim`. Bind the listener registration to exactly one preparation and mailbox. The historical schema-one route and currently installed scored runtime must remain untouched during preparation.

This design replaces the design-time hard-coded `root@` transport, `User root` SSH config and UID-0 shim assumptions. It requires a new exact source/configuration pin and independently verified identities for all route files. The approved `D:\GLM\secrets\cybergym-tailscale-v25i-known_hosts` file, SHA-256 `a1c2ebbffa50d9ea4e495a44b85a0199cc0f5a4ee2e387431148eb6a5dd056fc`, ED25519 fingerprint `SHA256:IAz92Tj6Vu4i7amh+63hrR6DFIdKqGwuD2AdHTvRjsg`, and strict OpenSSH-over-Tailscale behavior remain mandatory; an account change does not relax host authentication. No private approval key belongs on the host or in the shim.

## Work required after an affirmative route decision

1. Implement and independently review the fixed-account transport, restricted forced command, manager-owned listener activation, exact Unix permissions, verifier-only broker peer/registration checks and fail-closed absence/restart behavior. Preserve the existing disabled `claim` until the separate fresh-lease source and its state/resource/fence checks are reviewed.
2. Prove on a disposable Linux setup that the restricted account cannot replace the socket or parent, that the broker uses the inherited listener FD for the exact preparation, and that lost or crashed ACK paths return only exact durable mailbox bytes. Verify remote session closure separately from local SSH/tunnel exit.
3. Independently pin the finished source, restricted authentication key/account, forced-command and manager unit configuration, route identities, public trust, and host-key file. The client must select only the dedicated identity (`IdentityFile` with `IdentitiesOnly yes` and `IdentityAgent none`), deny password/interactive fallback, and independently verify the actual public key and any implicit certificate sidecar. A path or caller-supplied digest alone is not credential custody. Present the exact reviewed host change, account/key scope, validation and rollback for separate direct operator approval before production installation or handshake. After approval and the relevant source/platform gates, perform a separately preflighted strict pinned SSH handshake. Retain the original host checkout/runtime and evidence; rollback must remove only the new account/key/forced-command/socket configuration after its owned session and writers are quiescent.
4. Require fresh effect leases, owned Windows Job/route-file proof, remote closure and all twelve raw readiness gates before any live certification or scored admission. No control is authorized by this route decision alone.

If production configuration is rejected or deferred, keep `claim` disabled and the RPC0 and transport candidates held. Do not replace the listener under `root@` or treat same-UID peer credentials as proof of broker identity.

Evidence at the design decision: the held `budgeted_subset_ui_transport.py` supplied `root@` and `User root`; `budgeted_subset_ui_rpc.py` checked then connected to the fixed socket; `budgeted_subset_ui_broker.py` was verifier-only and rejected `claim`. The takeover plan records the independent P2 route audit and the controller-side fresh-lease design. No host/account/SSH/process/provider action was performed to prepare this decision.

Source-only follow-up: the untracked transport candidate now requires a separately supplied restricted account, exact identity path and public-key digest claim, matches them against its SSH configuration and argv, and disables implicit agent/default-key and interactive fallback in the declared route. Fifteen focused fake-SSH cases passed with Ruff/format clean after review-driven negative cases; independent re-review found no P1/P2 within fake-backed declaration scope. It does not inspect the actual credential or certificate sidecar, hold route/identity paths through launch, prove Windows owned-Job cleanup, run a handshake, or close the remote session. The candidate remains **HELD and uninstalled**. The RPC shim and broker remain unchanged with their root/UID-0 and caller-supplied-socket gaps; no `claim` or effect permission is enabled.

Later source-only owner checkpoint: a separate `subset_ui_activated_broker.py`
candidate now acquires a listener through a refusing-by-default bootstrap and
accepts its own connections before private bounded poll/ACK dispatch. It retains
exact owned connection identities, uses separate ACK commit/readback and latches
ambiguous ACK outcomes within the activation instance. Independent correction
review found no P1/P2 within conditional fake scope after fixing nonadjacent
connection reuse. The [review record](scored-subset-activated-broker-review_2026-10-21.md)
preserves hashes and scoped evidence. Source and tests remain **HELD/untracked**.
No native bootstrap, protected registration, matching restricted shim, durable
recovery, calibrated 64-connection capacity, OS peer/ACK proof or remote closure
exists. The original held route files remain unchanged; neither their P2 nor
the production approval/platform requirements are closed by this adapter.

Standalone primitive preparation: a new held experiment now contains a concrete
one-shot Linux inherited-listener/client observation path with no imports of the
held candidates. Its [source review](scored-subset-native-listener-probe-review_2026-10-21.md)
records 44 author-observed synthetic passes and independent read-only review,
with zero native observations. Environment/FD/path facts do not authenticate a
manager; destructive permission controls remain unimplemented. A separate
[local WSL preparation choice](scored-subset-disposable-linux-proposal_2026-10-21.md)
is proposed for exact setup and read-only inventory only. The prior route-design
approval is preserved; neither the local setup nor probe execution is inferred
from a generic acknowledgement or this documentation.
