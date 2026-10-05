# CyberGym leaderboard controller: development runbook

This is an implementation work area, not a certified or approved campaign. The
controller code is in `../nooa_cybergym/leaderboard/`; this directory holds the
agent image, frozen policy files, and synthetic fixtures. Do not start an
official task from this checkout. The next gate is an independently attested
live-native **synthetic** certification, followed by a signed go-live decision
and explicit operator approval.

| Control | Label | Current gate |
| --- | --- | --- |
| One agent-selected final, private fixed-side oracle, and complete result/model disclosure | `official requirement` | Final/terminal evidence and submission audit remain incomplete. |
| Clean task boundary; no fixed-side answer, provider key, or host credential exposure | `leakage boundary` | Native execution, credential delivery, and the Docker bridge host-gateway boundary are not certified. |
| Signed cohort, exact harness manifest, capability scopes, and audited GBrain reads | `leakage boundary` | The signed artifacts and native dispatch evidence must be joined before launch. |
| Locked 1,507-task order, serial execution, no started-task retry, finite budgets, and active declared DeepSeek roles | `performance optimisation` | These are campaign choices, not CyberGym limits. The signed launch guard must accept them together. |
| Signed live certification and explicit go-live approval before the locked campaign | `leakage boundary` | No accepted live-native report or go-live approval is present. |
| Workstation observation and reconnection | `optional` | Observation cannot create another Claude conversation or alter a started task. |

## Local build and checks

On Windows, keep temporary files and the `uv` cache on `D:\GLM` (the C: drive
is space-constrained):

The local unit-test command requires the inspected Xeus source copy at
`D:\GLM\tmp\xeus-cybergym-src\src`; verify that path exists before running it.
The helper sets temporary files, package caches, and future `uv` Python/tool
installations to `D:\GLM`. The supported Python 3.13.13 runtime is installed
at `D:\GLM\python\cpython-3.13.13-windows-x86_64-none\python.exe`:

```powershell
Set-Location 'D:\GLM\Xeus CyberBench'
. 'D:\GLM\use-d-drive.ps1'
$env:PYTHONPATH = 'examples/cybergym;D:\GLM\tmp\xeus-cybergym-src\src'
$python = 'D:\GLM\python\cpython-3.13.13-windows-x86_64-none\python.exe'
uv run --offline --no-project --with pytest --with pydantic --with httpx --with docker --with cryptography --python $python python -m pytest examples/cybergym/tests/leaderboard -q -m 'not docker' --confcutdir=examples/cybergym/tests/leaderboard
```

The final local Python 3.13.13 suite yielded **529 passed, 6 skipped, 2 Docker
tests deselected**. This verifies local logic; it is not live certification.

The agent-image build is development work on the isolated SunChaser worktree,
`/srv/sunchaser/labs-OO-Agents-audited-build`. The existing authority checkout
at `/srv/sunchaser/xeus-cybergym` supplies signing and ledger interfaces; do
not replace it or build in the original remote labs checkout.

```sh
cd /srv/sunchaser/labs-OO-Agents-audited-build
docker build -f examples/cybergym/leaderboard/agent-image/Dockerfile -t sunchaser/cybergym-agent:local examples/cybergym/leaderboard/agent-image
PYTHONPATH=examples/cybergym:/srv/sunchaser/xeus-cybergym/src /srv/sunchaser/labs-OO-Agents/examples/cybergym/.venv/bin/python -m pytest examples/cybergym/tests/leaderboard -q -m 'not docker' --confcutdir=examples/cybergym/tests/leaderboard
PYTHONPATH=examples/cybergym:/srv/sunchaser/xeus-cybergym/src /srv/sunchaser/labs-OO-Agents/examples/cybergym/.venv/bin/python -m pytest examples/cybergym/tests/leaderboard/test_container_integration.py -q -m docker --confcutdir=examples/cybergym/tests/leaderboard
```

The final isolated Linux suite yielded **531 passed, 4 skipped, 2 Docker tests
deselected**. The Docker selection yielded **1 passed, 1 skipped**: the
disposable network correctly blocks launch without a scoped gateway sentinel;
the live image/SSH proof is disabled until that sentinel exists. An earlier
two-container synthetic image/SSH proof passed before the stricter gateway
gate was added. These are build/test commands, not a launch sequence. Pin the
resulting image digest in the harness lock; a mutable local tag is not a frozen
identity.

The read-only native inventory is executable as
`uv run --offline --no-project --with pytest --with pydantic --with httpx --with docker --with cryptography --python $python python -m nooa_cybergym.leaderboard.native_readiness --repo-root <repo> --extension-dir <installed-Claude-extension>`
from the repository root after setting `PYTHONPATH` above. It exits nonzero while the live interfaces below are
missing. Its local command-source observation is not a native launch test.

The separate scored GBrain audit can be run from the repository root after the
Windows setup above:

```powershell
uv run --offline --no-project --with pytest --with pydantic --with httpx --with docker --with cryptography --python $python python -m nooa_cybergym.leaderboard.memory_readiness --repo-root 'D:\GLM\Xeus CyberBench'
```

This command was run read-only and reported `gate=blocked`. It remains blocked
until the signed memory policy, exact backend and
OAuth scope, concrete authenticated MCP bridge, native AI invocation guard,
catalog, and provenance have live evidence. Local adapter hashes alone cannot
clear this gate.

## Signed launch inputs

`campaign.check_go_live` requires four Xeus-verified envelopes: the explicit
go-live **decision**, an accepted `live_native` **certification** from two
independent synthetic runs, a frozen
**harness_lock**, and the exact 1,507-ID **cohort**. It also compares the
canonical `campaign-policy.json`, raw `tasks.json` order, run ID, epoch, and
cross-artifact SHA-256 bindings. The cohort binds benchmark/dataset commits,
`asset-hashes.json`, `mask_map.json`, generator source, and
`harness-manifest.json`; staging must use
`CampaignState.verified_staging_paths(...)` so its asset registry and paths
come from the signed state. A terminal task additionally needs an Xeus-signed
terminal receipt tied to the parent final and oracle evidence, or to documented
timeout/failure evidence. Synthetic unit envelopes are not launch authority.

## Native readiness blockers

The read-only audit currently observes workstation VS Code `1.140.0`, Claude
Code extension `2.1.289`, and the registered
`claude-vscode.editor.open` initial-prompt argument path. It does **not**
observe a launched remote session. The missing interfaces are:

1. A workspace-host launcher with one durable launch receipt, one conversation,
   and no second prompt on reconnect; plus remote extension-host/container
   identity and signed harness/workspace bindings. **Leakage boundary.**
2. A real `ProbeExecutor.mode=native` running pre-model probes from the exact
   parent and local-child processes in the same task container. **Leakage
   boundary.**
3. **P0 host boundary:** the internal Docker bridge and exact container peer set
   do not block access to the bridge gateway IP and host services bound there.
   Docker [documents this internal-network behavior](https://docs.docker.com/reference/cli/docker/network/create/#network-internal-mode---internal).
   `start_task_container` now refuses to launch without a controller-owned
   `HostGatewaySentinel`. For each launch, that sentinel must prove an active,
   bridge-scoped, default-deny host firewall with exactly the approved logical
   gateway routes on TCP 80, plus a live host-gateway canary listener that the
   task container cannot reach. It must also show the active port-80 gateway
   rejecting unknown Host, direct-IP, forbidden host-service passthrough, and
   CONNECT-to-canary requests from the container. The evidence is bound to the current Docker
   network ID, bridge, subnet, gateway, container ID, and a fresh challenge.
   The code validates evidence but does not install firewall rules; no live
   sentinel is wired, so official launches remain blocked. The signed native
   readiness record requires a separate `host_gateway_boundary` raw-evidence
   digest. **Leakage boundary.**
4. An authenticated listener injecting `xeus.model_connection` into the ASGI
   scope, with a controller resolver that derives `TrustedAdmission` parent or
   child roles from runtime identity. Solver headers/body cannot grant roles.
   **Leakage boundary.**
5. A native tool-call lifecycle feed (start, result, failure, terminal) joined
   one-to-one by stable call ID and trusted parent/child context to an approved
   signed capability registry, exact `ToolIdentity`, actual `CapabilityRequest`, and durable
   `AuthorizationEvent`. No capability identity is pre-approved by this README.
   **Leakage boundary.**
6. The controller-held GBrain MCP bridge with authenticated exact-source scope
   and its native AI invocation guard, including parent/child read evidence.
   **Leakage boundary.**
7. An authenticated way to supply only the task-scoped model token to native
   requests without exposing it in agent environment or output. Container PID 1
   currently removes its startup `CYBERGYM_TASK_TOKEN` before SSH agent
   sessions, while `ModelHTTPService` requires authorization. Provider keys must
   remain controller-only. **Leakage boundary.**
8. Live evidence that the parent selected the single final, the container
   stopped before private oracle submission, and the signed terminal receipt
   joins back to that final. **Official requirement.**

`native_readiness` reports the missing integration interfaces, including the
host-gateway boundary. Neither static code,
synthetic probes, nor a fake attestor count as certification. Do not use official
cohort tasks as fixtures or run the campaign start path until the signed
go-live gate has been independently reviewed and approved.
