# Dedicated CyberGym native GBrain bridge

This controller-only sidecar reuses the installed GBrain package, dedicated
profile and PostgreSQL database. It does not restart or replace the existing
HTTP service. There is no network listener. The solver only receives the
filtered `MemoryFacade` tools, never this process, OAuth files, database access
or provider credentials.

`runtime.ts` verifies the actual OAuth credential against GBrain's native
`GBrainOAuthProvider.verifyAccessToken` before every request. The read client
must have exactly the CyberGym source, exactly `read`, and exactly
`recall/search/get_page`. The server passes that authenticated context into
GBrain's installed `dispatchToolCall` and encloses it in the installed
`withAIInvocationGuard`. Source and guard evidence comes from that live
authenticated execution context. Source arguments cannot widen it.

The Python `GBrainControllerBridge` synchronously reserves the shared task
budget before acknowledging each native chat, embedding or rerank admission.
It acknowledges settlement only after the audit sink records actual token
classes or null usage. Native crashes leave reservations spent and record
unknown usage. Provider/model kinds must match the frozen model map. Sidecar
failure, audit failure and malformed protocol frames fail closed. Native error
details and subprocess stderr never enter solver responses.

GBrain's search response includes one JSON block and a retrieval summary. The
sidecar recognizes that native shape and retains the summary in `_meta` while
returning one JSON block to the strict decoder. Other ambiguous content fails.

## Deployment and credentials

Copy these scripts to
`/srv/sunchaser/cybergym-leaderboard/ops/gbrain/runtime/`. Run with Bun and:

```sh
export GBRAIN_HOME=/srv/sunchaser/gbrain-profiles/xeus-cybergym
export GBRAIN_DISABLE_DIRECT_POOL=1 GBRAIN_POOL_SIZE=2
export PATH=/root/.bun/bin:$PATH
bun runtime/provision.ts
bun runtime/provision.ts --writer
```

Provisioning creates independent native OAuth grants and stores only the client
credentials in the private profile's `controller/` directory (0700), in
`read-client.json` and `write-client.json` (0600). It reuses and verifies these
files on subsequent runs. It never changes existing clients or personal data.
OAuth access tokens are acquired and refreshed in memory, never printed.
The runtime reads only the dedicated service's historical `.gbrain/env` file
for its two declared provider keys; it does not load the personal profile.
Native model discovery is disabled to keep auxiliary identities deliberate.

Launch the read session as the controller:

```sh
bun runtime/runtime.ts "$GBRAIN_HOME/controller/read-client.json"
```

For the independent writer:

```sh
bun runtime/runtime.ts "$GBRAIN_HOME/controller/write-client.json" --writer
```

The controller may launch the command locally on SunChaser or over its trusted
SSH channel. In scored operation, use the local controller process so a
workstation disconnect does not own the task lifetime. Freeze the reported
runtime, source-tree, native-guard and backend-identity hashes with the signed
authenticated catalog before admitting reads. A runtime or package update
requires renewed evidence and signing.

## Controller integration

Construct `GBrainControllerBridge(command, budget=shared_budget,
audit=durable_audit, allowed_models=frozen_models)`, then inject it into
`ControllerMemoryTransport` with the authority-verified catalog. The existing
`MemoryFacade` handles signed page provenance, outcome/answer filters and the
12-result/2,000-token cap. The bridge is task-scoped and must be closed after
the task. The budget and audit objects remain private to the controller.

`OracleMemoryWriter` receives a distinct writer bridge, the frozen guard
binding digest, a verifier for the Xeus `terminal_receipt` envelope, campaign
identity and a private evidence directory. After the solver is stopped and
the official oracle receipt is signed, call
`publish(signed_receipt, task_id=task_id)`. Actual positive and negative
verdicts produce deterministic episodic outcome records. Missing, unknown or
infrastructure-only results are rejected. A durable exclusive marker is
created before capture; an ambiguous write cannot be retried automatically.

The writer's native grant permits only `capture`, only the CyberGym source,
and only the `cybergym/episodic/` prefix. The read session rejects its custom
write method. Episodes are excluded from solver retrieval by `MemoryFacade`;
publishing an episode does not promote it or add it to the signed readable
manifest. Reviewed semantic/procedural/principle promotion must separately
produce canonical numeric IDs, native hashes, hydrated content hashes and
the authority-signed allowlist required by `AllowedPage`.

## Verification

Use `uv` for Python. With `PYTHONPATH=examples/cybergym`, the Python tests are
`tests/leaderboard/test_gbrain_bridge.py` and `test_gbrain_writer.py` under the
CyberGym example. The root repository test configuration imports POSIX-only
`fcntl`; on Windows the focused tests can run with the CyberGym pyproject as
the pytest config. Native tests use the real installed invocation guard:

```sh
bun test runtime/runtime.test.ts
```

`probe.py --output <private-evidence-dir> -- <runtime-command...>` exercises
fixed generic expansion/reranking inputs and automatic/parent/child recall,
search and forbidden-source/write denials. It writes sanitized native
metadata/catalog/results and a fsynced invocation ledger. These are synthetic
boundary checks, not evidence of an official benchmark attempt.

`probe_writer.py` uses the writer command and performs `dry_run: true` only.
It proves authenticated capture validation and namespace denial without
adding a page. Neither script accesses official tasks or their artifacts.

On 2026-10-05 the live read probe made six admitted native provider calls:
one `openai:gpt-5.6-luna` expansion, one `voyage:rerank-2.5` rerank, and four
`openai:text-embedding-3-large` embeddings. All settled with measured usage.
The dedicated source returned clean empty reads. The writer's native capture
dry-run passed and no page was created by these probes.
