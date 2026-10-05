# Observed native capability inventory

`nooa_cybergym.leaderboard.capability_inventory` freezes the real tool declarations
captured by `native_calibration.NativeCalibration`. Calibration records the
admitted container's first model request, returns a failure locally, and never
dispatches that request to a model provider. This discovers schemas; it does not
prove a native workflow, child, or tool has executed.

The freeze factory produces `component_verified_synthetic_only` capabilities.
Runtime admission restricts that registry to the explicit synthetic fixtures
`synthetic:length-header` and `synthetic:chunk-table`. Official tasks require
separate full native certification. Passing component JUnit reports are hashed
from their actual files; they are never described as native certification.

## Inputs and CLI

Run with the controller's existing environment:

```text
uv run python -m nooa_cybergym.leaderboard.capability_inventory --config /absolute/controller/freeze-config.json --output-directory /absolute/controller/new-inventory
```

The config JSON requires `schema_version: 1` and these fields:

| Field | Required content |
| --- | --- |
| `calibration` | Actual no-provider calibration artifact pin |
| `component_evidence` | Nonempty array of fresh successful component JUnit artifact pins |
| `network_policy` | Frozen network-policy artifact pin |
| `gbrain_provider_ids`, `gbrain_model_ids` | Actual dedicated GBrain auxiliary dispatch inventory |
| `services` | Observed service and adapter definitions for `native`, `gbrain`, `clangd`, `documentation`, `advisor`, `finalizer`, `vulnerable`, `advisory` |

Each artifact pin has exactly `name`, absolute `path`, and the SHA-256 of the
actual file bytes in `sha256`. Each service definition has `service_id`,
`service_version`, `service_files` (artifact pins), `adapter_id`,
`adapter_version`, and `adapter_files` (artifact pins). All files are verified
both at freeze time and when the bindings load. The native service must pin
the observed native binary itself or the actual `native-runtime.json` with its
matching binary/extension hashes. Include the actual launcher, policy adapter,
frozen workflow scripts and skill templates among the applicable adapter pins.
The advisory schema declaration source is included automatically.

Optional `source_roots`, `read_roots`, and `write_roots` arrays customize the
explicit task-container paths. Defaults match `/workspace/src`,
`/workspace/output`, the isolated agent HOME, and the frozen generic templates.
The parent supplies absolute paths to native Read/Grep/Glob/Write/Edit; the
controller never guesses the native process's current working directory.

The output directory must not exist. The command writes `registry.json`,
`capability-bindings.json`, and `inventory.json`, then prints their paths and
hashes. Freeze those hashes in the runtime config. No credential belongs in
this config or these outputs.

## Python integration

`freeze_inventory(...)` takes `ArtifactPin`, `ObservedService`, the frozen
`NetworkPolicy`, actual GBrain dependencies, and optional root overrides.
`write_inventory(directory, inventory)` writes the artifacts.
`load_frozen_bindings(path, registry)` returns the exact tuple accepted by
`CapabilityRuntime(bindings=...)`, checking every identity, schema and scope
against the supplied pinned registry and retained observations.

`inventory.parent_tools` and `inventory.child_tools` give the actual approved
rosters. Extra advertised tools remain visible in
`unsupported_advertised_tools`; they receive no approval. The native schemas
for all required tools, including MCP services, must be present in the actual
calibration. Deferred tool discovery must be disabled or completed before
freezing; manually reconstructed schemas are not accepted.

The pinned 2.1.289 native handlers for TodoWrite and TaskCreate/Get/Update/List
use session task state. TaskStop resolves only the native task registry. These
tools are optional and become parent-only capabilities when actually
advertised. TaskUpdate cannot assign an external team owner; TaskStop cannot
target a remote host. No TaskOutput handler has been established in this
binary, so that legacy name is not synthesized.

Workflow admission checks the exact frozen `scriptPath` and actual container
content digest, then `authorized_workflow_digest(call)` rechecks it before
the controller reserves the script's declared child capacity. Skill admission
requires an explicit frozen skill-name to path/hash mapping. The controller
supplies `DockerPathObserver.digest` as the content reader; it runs as the task
container's agent with isolated Python and refuses symlink traversal.

## Verification

Focused tests cover round trips, schema and artifact drift, duplicate JSON
keys, exact dependency declarations, synthetic-only scope, actual advertised
optional tools, CLI serialization, native role restrictions, and observed
workflow content checks. They use explicitly synthetic fixtures; live native
calibration and execution remain distinct required evidence.
