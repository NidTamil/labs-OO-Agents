# Scoped gateway runtime

`HostBoundaryRuntime` is a trusted Linux-controller adapter for
`start_task_container(..., host_gateway_sentinel=runtime)`. Construct it with an
empty dedicated internal Docker bridge and an exact handler for every logical
endpoint. Enter the context **before** creating the container. Stop/remove its
containers before closing it. Map logical endpoint names to
`runtime.boundary.gateway` in the container's hosts file.

The runtime creates a unique `inet cg_<random>` nftables table. Input rules apply
only to the pinned `br-<network-id>` interface; they permit gateway TCP 80 and
replies to host-initiated connections, and drop other host-bound traffic. Forward
rules drop traffic into or out of that bridge. One exact bridge/IP/TCP-80
exception is inserted into the host INPUT chain so later UFW policies cannot
drop the permitted route. It is inspected and removed by its full specification.
SSH, Tailscale, other Docker networks and existing rules are preserved. The proxy binds only the bridge's
gateway address and terminates requests into controller-supplied handlers. It
rejects CONNECT, absolute-form targets, unknown/IP Host headers, ambiguous
framing, upgrades, and unadmitted source addresses.

Handlers receive an immutable `GatewayRequest.peer` derived from Docker identity
and the observed TCP source address. Request headers are never trusted identity.
`GatewayReply.body` accepts bytes or a byte iterator (including streamed SSE).
`GatewayRequest.disconnected` is a controller-created event set on socket EOF;
long-running handlers/iterators must honor it. The model adapter uses it to
cancel the upstream and finish durable usage accounting, including disconnects
before response headers. Response iterators are closed even if header writes
fail, and their `close()` must work before first iteration and across threads.
Handlers are responsible for capability admission, task credentials, endpoint
semantics, provider quotas, output filtering and model/tool telemetry. The
boundary audit records hashes, byte counts, status, and exact container/network
identity; it does not persist credentials or raw request paths/bodies.

Attestation starts a real canary listener on a forbidden gateway port and proves
it is reachable from the host both before and after container denial. It probes
all permitted logical Host routes with a fresh identity-bound challenge, then
observes explicit HTTP rejections for unknown Host, direct IP, host passthrough
and CONNECT. Challenge success means transport reachability; it is **not** a
provider, GBrain, model, native-extension or official certification result.

A watchdog inspects the live rule set; drift stops only the runtime's admitted
containers. Closing a runtime under a running admitted container fails and keeps
its rules. Rules remain after a controller crash; a lost proxy removes the sole
permitted route. The controller owns recovery and must stop the exact affected
containers before removing that exact leftover table.

## Disposable proof

On the Linux Docker host, from this repository's root:

```sh
PYTHONPATH=examples/cybergym uv run --no-project --with docker --with pydantic \
  python examples/cybergym/leaderboard/network-runtime/prove_boundary.py \
  --evidence /srv/sunchaser/evidence/network-boundary-UNIQUE \
  --image node:22-bookworm-slim
```

This uses a synthetic container and synthetic permitted handlers, runs all live
denials, verifies close refuses under a live task, adds a harmless scoped rule
to prove watchdog drift detection, and removes only its exact resources. It
retains `boundary-proof.json` and `gateway-audit.jsonl`, including IDs, hashes,
actual statuses and cleanup observations. No benchmark task/provider is used.

Unit tests run with `uv run ... pytest
examples/cybergym/tests/leaderboard/test_host_boundary_runtime.py`. Production
native-extension and backend adapters need their separate certification gates.

## Observed result (2026-10-05)

The retained private evidence records a successful SunChaser run against the
existing pinned Node image. Five challenge routes and
five synthetic handler calls succeeded; all four L7 denial probes returned 403;
the active forbidden-port canary timed out from the container. Closing while the
task was live was refused, and an added scoped firewall rule triggered the
watchdog to stop that container. Cleanup restored the original network IDs,
firewall table names and exact host INPUT rules. Source hashes are included.

`boundary-proof.json` SHA-256:
`88b580773694829be04e471bb092a41faa1ea1f718417bb8f5cf8abb1764bd3d`.
Remote evidence is retained at
`/srv/sunchaser/evidence/network-boundary-20261005-f/`. Earlier failed setup
attempts are retained in sibling `-a` through `-c` evidence directories; they
were cleaned up. This is synthetic network evidence, not native harness or
official campaign certification.

The recorded source hash precedes the later socket-disconnect cancellation
changes. Those changes passed 161 focused local model/HTTP/boundary/container
tests, including real socket EOF before and during a stalled provider stream.
The final Linux rerun requires renewed Tailscale SSH authentication; do not
interpret the older artifact as certification of the updated source.
