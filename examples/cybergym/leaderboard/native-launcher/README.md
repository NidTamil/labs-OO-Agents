# Native task launcher

This workspace-host extension implements the native command contract inspected in
Claude Code **2.1.289**, on VS Code **1.140.0**. It does not contact a model by
itself. It calls `claude-vscode.editor.open(undefined, prompt, undefined,
undefined, true, {programmatic: "pin-to-panel"})` once after controller custody.
The inspected command returns no conversation ID. Receipts therefore record
`session_id: null`; actual IDs arrive through native session hooks.

## Provisioning

Install the VSIX and certified Linux Claude extension in the fresh task remote
home. Keep local/personal VS Code profiles and Claude/GBrain configuration out of
this task. Provision these controller-owned read-only inputs before connecting:

- `/workspace/.sunchaser/launch.json`: native Xeus `SignedEnvelope` containing
  the exact `native_launcher.build_launch_manifest(...)` result.
- `/etc/sunchaser/native-launch-trust.json`: map from trusted key ID to Ed25519
  **public** SPKI PEM. Never provide a private key.
- The exact manifest-bound task files, including `CLAUDE.md` and frozen settings.
- The native image installs root-owned managed hooks calling immutable
  `native-hook.js` in `/opt/sunchaser/vscode-extensions/`. The standalone
  `hooks-settings.json` is the input template rewritten by that image installer.

The launch manifest pins the observed Docker container ID, hostname, non-root
UID, PID and mount namespace IDs, exact remote Claude extension bytes, versions,
task manifest digest and staged file hashes. Read namespaces from the running
task container with `readlink /proc/self/ns/pid` and `readlink /proc/self/ns/mnt`.
The extension independently observes its execution host and compares the pins.
`claudeCode.useTerminal` must be false. The extension environment must exactly
match `machine-settings.json`, including the public `xeus-container-peer-auth`
sentinel and GLM aliases. Provider credentials remain in the controller.
Unfrozen process wrappers or environment overrides fail the runtime check.

The gateway route is exactly `http://registered-tool-gateway/native-launch`.
Resolve that logical name to the controller gateway using container `extra_hosts`.
Register `native_launch_handler(authority, network_id=...)` for `/reserve` and
`/events`, and `native_hook_handler(collector, container_id=..., network_id=...)`
for `/hooks`. The actual gateway peer is authoritative for container/network;
request headers do not substitute for it. **There is no token file or secret in
the launcher.** Its one-shot authorization is the preloaded signed manifest plus
the actual isolated peer. The controller must independently authorize synthetic
or official scope before it instantiates the authority.

## Durability and interpretation

`NativeLaunchAuthority` atomically creates and fsyncs a controller-only reservation
directory and receipt before replying. A lost acknowledgement, write failure or
command exception consumes the reservation permanently. The task output copy and
VS Code globalState are secondary reconnect guards. Reconnection never opens a
new conversation or resends the prompt. A consumed reservation with no first
model request is an explicit launch failure requiring controller reconciliation.

The gateway binds peer identity; it cannot distinguish arbitrary solver code from
the extension inside the same UID/container. A solver can forge observations or
consume its own launch permission. It cannot obtain a second controller
reservation. These observations are **not** signed live certification, proof of
isolation, or model admission. Keep controller snapshots, provider-stream evidence
and native transcripts to corroborate them.

The native binary's hook schema exposes `session_id`, optional child `agent_id`,
`tool_use_id`, and `effort.level`. The API client emits
`x-claude-code-agent-id` / `x-claude-code-parent-agent-id` from agent context;
`metadata.user_id` JSON carries `session_id` and optional `parent_session_id`.
`native_request_identity` extracts only these claims. It does not grant a role
or create `TrustedAdmission`. The SQLite hook collector checks lifecycle pairing
and retains metadata plus a hash of the full native hook input. Tool inputs,
responses, error text, account IDs and device IDs are omitted. This collector is
not a substitute for the complete redacted trajectory archive. Missing tool/child
terminals remain visible in `summary()` and must fail certification. A hook
delivery failure denies `PreToolUse`; other hook kinds report failure but their
native execution semantics must be verified in the live smoke run.

Before any `PreToolUse` observation, the sender submits the exact native input to
`/native-tools/authorize`. It accepts only an explicit controller allow/deny and
returns a fixed native hook decision without echoing response data. Post-tool
hooks must receive `{recorded: true}` from `/native-tools/result` before their
observation succeeds. Both use the existing peer-bound controller gateway. The
controller correlates these inputs against actual provider tool IDs and arguments.
Native MCP requests carry that same ID in `params._meta["claudecode/toolUseId"]`,
as observed in both client branches of the installed 2.1.289 binary.
The SDK also adds `_meta.progressToken` for progress-capable calls. Optional
metadata is telemetry; role authority still comes from the actual provider call
and native lifecycle correlation. See [controller integration](CONTROLLER-INTEGRATION.md)
for shared native/advisory capacity and controller-owned active role bindings.

## Checks and packaging

```powershell
node --test examples/cybergym/leaderboard/native-launcher/test/*.test.js
uv run --no-project python examples/cybergym/leaderboard/native-launcher/package-vsix.py --out D:/GLM/tmp/sunchaser-cybergym-launcher.vsix
```

Run the Python launcher and hook tests with the controller test invocation in the
parent leaderboard README. POSIX reservation tests run on SunChaser. Validate the
VSIX using a fresh isolated VS Code user-data and extensions directory. Any Claude
extension version/source change or VS Code version change invalidates this
command contract until re-inspected and tested. Unit tests and installation do
not replace the required native synthetic session/reconnect smoke test.
