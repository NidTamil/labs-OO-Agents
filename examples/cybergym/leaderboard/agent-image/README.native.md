# Frozen native extension image

Build `Dockerfile.native` only after the hardened base image is built and its
immutable image ID is recorded. The overlay adds the pinned Microsoft VS Code
1.140.0 server (commit `07f806f999227108933c2e30515b26eecc1fda74`), the official
Claude Code 2.1.289 Linux VSIX, and the reviewed local launcher VSIX. The installer
verifies both vendor archive hashes before extracting any artifact. It also
writes `/opt/sunchaser/native-runtime.json` with extension/binary/config hashes.

The root-owned code lives in `/opt/sunchaser`. Only fresh, empty `/home/agent`
tmpfs is initialized. Links expose installed extensions and server to VS Code;
the frozen Machine settings supply the public model-gateway sentinel, GLM
aliases, `claudeCode.allowDangerouslySkipPermissions: true`, and
`claudeCode.initialPermissionMode: bypassPermissions`. The launcher checks both
effective VS Code settings before reserving a task; the managed
`bypassPermissions` default alone does not select bypass for a new native panel.
No OAuth state, provider key, prior session or workstation home is copied.
Use a dedicated workstation VS Code profile with
`remote.SSH.useExecServer=false` to select the preinstalled
`~/.vscode-server/bin/<commit>` server. Personal profiles remain separate.

`native-entrypoint.sh` runs the home initializer before the original unchanged
base entrypoint. That entrypoint still verifies required tmpfs/mount isolation,
extracts the vulnerable archive as the agent, and starts SSH. The controller must
mount public trust at `/etc/sunchaser/native-launch-trust.json` read-only and
provide the signed `/workspace/.sunchaser/launch.json` before native connection.

Root-owned `/etc/claude-code/managed-settings.json` sets `allowManagedHooksOnly`
and invokes immutable hook scripts. It denies built-in writable child types;
the three frozen custom child types expose Read, Grep, Glob, GBrain recall/search,
clangd document_symbols/hover/definition/references, and documentation fetch.
Their model is inherited GLM. The shared campaign limits govern requests and
elapsed time; no additional child turn cap is imposed. The controller separately
limits active children to three and verifies actual provider tool lists and
arguments.

The managed `permissions.defaultMode` and each custom child's `permissionMode`
are `bypassPermissions` to avoid native approval stalls. The managed
`PreToolUse` hook still sends each tool call to `/native-tools/authorize` and
honors a controller `deny`; `allowManagedHooksOnly` and the existing deny rules
remain in force. A disposable offline probe must verify this behavior against
the rebuilt image before its ID is frozen. The probe uses a deterministic model
and deny gateway on an internal Docker network, with no provider credential or
benchmark task. This component check does not substitute for a VS Code-owned
bypass-mode run through the real controller. Before freezing, verify that the
native extension uses bypass mode, still calls the production
`/native-tools/authorize` hook, and denies a deliberate known-deny request
without executing it.

Managed `enableWorkflows: true` and `ultracode: true` enable the native dynamic
workflow surface where the pinned runtime makes it available. The packaged
recon/debug/review JavaScript scripts call the actual native workflow API with
the frozen read-only agent types. The controller stages their exact hashes at
`/workspace/.claude/workflows/`, admits only those script paths, and reserves
their children in the same shared ledger as Agent and advisory calls. Feature
availability is checked from the real advertised tool inventory before a run.
Frozen `ENABLE_TOOL_SEARCH=false` selects the native standard tool mode: every
connected MCP tool's actual schema is advertised directly, so calibration can
capture the complete roster without a provider-generated ToolSearch request.

The immutable `/etc/claude-code/managed-mcp.json` supplies the complete native
MCP roster, with no workstation MCP import or provider credentials:

| Server | Public task route | Tools |
| --- | --- | --- |
| gbrain | `http://gbrain-read-gateway/mcp` | recall, search |
| clangd | `http://registered-tool-gateway/mcp/clangd` | document_symbols, hover, definition, references |
| documentation | `http://registered-tool-gateway/mcp/documentation` | fetch |
| advisor | `http://registered-tool-gateway/advisor/mcp` | recon_status, debug, critic |
| finalizer | `http://registered-tool-gateway/mcp/finalizer` | select_final |
| vulnerable | `http://cybergym-submit/mcp` | run_test |

The managed file exclusively controls MCP servers in the pinned native binary;
`allowedMcpServers: []` also denies user-added entries. Advisor, finalizer and
vulnerable run_test are available only to the parent. The native child allowlist contains the exact
`mcp__gbrain__`, `mcp__clangd__`, and `mcp__documentation__` names above. Each
server still requires its audited controller adapter and real tool-use-ID grant.
The advisor server alone has a one-hour native MCP timeout, matching its longest
approved lane; the controller still enforces the shorter critic budget. This
prevents the native HTTP client's default one-minute response timeout from
cutting off a budgeted advisory lane.

On SunChaser (use a fresh `--output-dir` on each build):

```sh
uv run --no-project python examples/cybergym/leaderboard/native-launcher/package-vsix.py --out /srv/sunchaser/cache/sunchaser-cybergym-launcher.vsix
BASE_IMAGE=$(docker image inspect sunchaser/cybergym-agent:local --format '{{.Id}}')
LAUNCHER_SHA256=$(sha256sum /srv/sunchaser/cache/sunchaser-cybergym-launcher.vsix | cut -d ' ' -f 1)
test -n "$BASE_IMAGE" && test -n "$LAUNCHER_SHA256"
uv run --no-project python examples/cybergym/leaderboard/agent-image/prepare-native-build.py \
  --vendor-dir /srv/sunchaser/cache/audited-native-runtime-1.140.0-2.1.289 \
  --launcher-vsix /srv/sunchaser/cache/sunchaser-cybergym-launcher.vsix \
  --output-dir /srv/sunchaser/cache/native-image-build-001
docker build -f /srv/sunchaser/cache/native-image-build-001/Dockerfile.native \
  --build-arg BASE_IMAGE="$BASE_IMAGE" \
  --build-arg LAUNCHER_SHA256="$LAUNCHER_SHA256" \
  -t sunchaser/cybergym-native:local /srv/sunchaser/cache/native-image-build-001
```

Image build and unit tests do not certify native startup or reconnect survival.
The actual remote native VS Code smoke run must verify the pinned runtime IDs,
one controller reservation, real GLM Max request, native child tool restrictions,
managed hooks, MCP tool-use-ID correlation, and remote process survival after
workstation disconnect. Freeze the resulting image ID only after those checks.
