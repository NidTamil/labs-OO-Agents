# Native controller integration

These are executable adapters with explicit dependency injection. Production
must supply the actual registered capability, memory, Docker and provider
adapters; synthetic transports used by unit tests are not live certification.

`ChildCapacity(database, run_id=..., task_id=..., attempt_id=..., launch_id=...)`
is the one durable three-child ledger. Before an authorized native Agent call
is released, reserve its actual provider tool ID and frozen subtype with
`reserve_native(tool_id, agent_type)`. The hook collector receives this same
object as `NativeHookCollector(..., capacity=capacity)`. It binds native start
IDs and releases stopped children. Supply `capacity.advisory_slot` to the
advisory runtime. Pending native reservations, active native children and active
advisors count together. A crash retains reservations and active slots.

Native Workflow calls use `native_workflows.frozen_workflows()` and the three
packaged scripts. Stage those exact bytes read-only under
`/workspace/.claude/workflows/{recon,debug,review}.js`, include their hashes in
the signed launch, and authorize the actual script digest before calling
`native_workflows.reserve_workflow`. It reserves the real Workflow tool ID and
the script's declared batch (two recon children, one debug or review child).
These use separate Workflow capacity records, not fabricated Agent tool calls.
Only `scriptPath` and `args` are admitted; inline overrides and resume are
rejected. Debug requires controller-observed vulnerable failure. The native
scripts use the observed `agent`, `parallel`, and `phase` APIs and explicit
read-only `agentType` definitions, inheriting the session model and max effort.
The managed settings enable `enableWorkflows` and `ultracode`; actual feature
availability and native execution must be observed during Linux calibration.

Native start hooks do not expose their spawning provider tool ID. Reservations
are therefore fungible within the observed child type; the capacity ledger
explicitly records that exact tool-to-child pairing is unavailable. This does
not manufacture identity evidence. Same-type concurrent children are supported.

`AdvisoryRuntime` reuses the existing `DeepSeekController` and its exact model,
thinking, effort and shared budgets. The provider supports text messages in
this adapter, so each response is an explicit JSON action or completed advice.
The runtime records the actual response and an `AdvisoryAction` before invoking
a read capability. Each callback receives `(arguments, role, action)`; the
action carries a unique controller action ID, actual provider request ID,
task/attempt, role, capability and argument hash. It is never a fabricated
native tool call.

`AdvisoryTools(...).callbacks()` supplies the four concrete routes:

- `local_read`: direct Docker exec of the fixed isolated Python source reader,
  as the task agent. Every path component uses `O_NOFOLLOW`; only frozen source
  roots are admitted. Read/list/literal search have bounded output and disclose
  truncation or skipped files. No shell or model-provided code is executed.
- `clangd_read`: the existing same-container `ClangdClient.invoke` interface.
- `gbrain_recall` and `gbrain_search`: the actual `MemoryFacade.model_tool`,
  caller `CHILD`, model `deepseek-flash`, actual advisory action ID, signed
  dedicated-source provenance and shared native GBrain invocation budget.

All four require `CapabilityRuntime.authorize_advisory` with separately
observed advisory adapter bindings. The native `Read` binary's identity must
not stand in for this controller reader's code/schema identity.

Independent recon is started by the controller with `run_recon()`. Native
parent tools may read `recon_status`, request the conditional debug lane, or
request `critic`. The MCP facade requires an actual correlated parent grant.
Debug remains unavailable until the controller calls
`observe_vulnerable_failure` with an admitted actual process failure. Native
hook failure text cannot provide this evidence.

The critic requires an absolute `/workspace/output/...` candidate path and
controller `resolve_candidate(path, sha256)` callback. The finalizer's actual
safe reader supplies full hash/length and up to 64 KiB of candidate bytes,
with explicit truncation. Parent rationale remains separate untrusted context.
`require_critic(sha256)` gates final selection on the completed corresponding
critic and completed independent recon.

`VulnerableRunner` executes only frozen vulnerable build/test recipes. A fixed
supervisor streams and hashes combined output while retaining a 64 KiB prefix,
enforces process-group timeout, and rejects incomplete capture. Its start and
completed evidence audits must acknowledge durable custody before execution
or `DeepSeekController.admit_failure`. Candidate bytes are checked through a
controller no-follow snapshot before and after the run. No fixed-side oracle
is exposed by this parent-only MCP route.

The image's managed MCP file contains GBrain, clangd, documentation, advisor,
finalizer and vulnerable services. Children receive only read tools. The
advisor's one-hour native MCP timeout permits its approved long-running lane;
controller role and campaign budgets remain authoritative. Actual native
startup, provider settings, child roster, hooks, MCP tool-use metadata, process
timeouts and reconnect survival still require the isolated Linux smoke run.

`NativeCalibration` is a separate callable model-gateway handler for a fresh
signed synthetic launch. It requires the actual Docker peer/image, consumed
launcher receipt, and observed session hook, persists the exact advertised
tool schemas with redacted request evidence, and always returns HTTP 503. It
has no provider transport. Do not compose automatic GBrain/advisory/model
lanes into this calibration: those could issue independent provider requests.
The exclusive `*-calibration-only.json` marker makes the attempt ineligible for
benchmark promotion or resume. Inspect an artifact using
`python -m nooa_cybergym.leaderboard.native_calibration inspect PATH --sha256 SHA`.
Inventory artifacts use scope `native_schema_discovery_no_provider` and
`provider_dispatched: false`. An initial parent request provides no evidence
of child schemas; no child inventory may be invented from that capture.
