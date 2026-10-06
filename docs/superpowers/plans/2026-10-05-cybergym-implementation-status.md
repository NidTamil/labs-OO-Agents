# CyberGym Leaderboard Implementation Status

Updated 2026-10-05. This ledger records recovered evidence and current work; it does not certify a working campaign or a leaderboard score.

The pending acceptance/certification/launch flags below apply to the amended campaign. They do not erase earlier live model runs or completed harness/service validation. The 185-test Python pass is separate from those historical results.

- design_commit: 5b9dbe37cae7abbd28b521db75a6d10f267d978e
- baseline_commit: 55d63ff3317ef6102354ba413b6ee32cf66f5ae5
- implementation_branch: codex/audited-maximum-capability
- written_design_and_plans_approved: true
- policy_amendment_approved: true
- official_launch_authorised: false
- implementation_accepted: false
- live_certification_verified: false
- official_campaign_started: false
- alternate_model_policy: active_deepseek_official_api_thinking_max
- scored_memory_mode: audited_hybrid
- capability_policy: audited_maximum_permissible_capability

| Work | State | Evidence / remaining acceptance |
|---|---|---|
| Baseline and approvals | recovered | Existing approved specification and six plans; baseline commit above |
| Earlier native solver results | recovered passes | Prior chat Review GitHub for CyberGym updates records GLM-5.3 Max through native VS Code/Claude Code solving development/rescue Tasks 8 and 13. Tasks 17 and 18 also passed verifier reproduction, but later review classified them as assisted because patch/reference/fixed material was accessed. Preserve these development successes; they are not new amended-campaign certification or a clean leaderboard score |
| Earlier NOOA evaluator results | recovered passes, attribution/eligibility not established | September 6 release-10task-20260906T083144Z/official_evidence_recovered/summary.json records 10/10 solved, each with nonzero vulnerable exit and zero fixed exit. Submission numbers range 1–7 and model attribution is unverified here. These recorded passes do not establish a single-attempt leaderboard score or validate the amended native configuration |
| Earlier GBrain live validation | passed, historical | Remote ops/gbrain/VALIDATION-2026-09-12.md records scoped OAuth authentication, MCP initialization/discovery, Claude Code connection, restart health and 10/10 parallel HTTPS initialization probes. Current endpoint connectivity was rechecked after the hostname repair; changed scope/guard/facade still requires its own evidence |
| Policy amendment | amended in place | Existing specification/plans retain their structure and substantive code tasks; no repeated design approval |
| Documentation checks | passed | 35 Python example syntax parses, 11 JSON parses, balanced fences, stale-policy scan, cross-plan request/token/time/config consistency and git diff --check; no future implementation examples were executed |
| Remote authority | inspected read-only | Trusted Tailscale SSH reached /srv/sunchaser/xeus-cybergym; clean e28f33d45390c64f338d5520e68f53f4d8b50ce8 on chore/move-sunchaser-prep, five commits ahead; canonical_json, SqliteEventLedger, kernel state_machine/tool_broker inspected; signed core reused rather than recreated |
| Isolated build checkout | created | /srv/sunchaser/labs-OO-Agents-audited-build, codex/audited-maximum-capability at the recovered labs baseline; original labs checkout untouched |
| 01 control/isolation | additive component tested, not accepted | Frozen capability registry and trusted role-bound authorizer implemented; 67 synthetic tests pass, including required actual paths and credential-safe audit failures; actual dispatcher/container/extension-context boundary acceptance still required |
| 02 harness/telemetry | pending integration acceptance | Existing successful native VS Code/Claude harness retained; controller gateway, actual child/tool/MCP route logging and full remote session certification remain required |
| 03 memory/multimodel | additive component tested, not accepted | Official DeepSeek advisory adapter and active policy implemented; 58 synthetic tests pass, including separate 36/564 allocations. Deployed GBrain retained and native read/accounting interfaces inspected; hybrid facade, provenance filters, true-oracle writes, scheduling and signed-ledger wiring still require implementation/integration evidence |
| 04 synthetic certification | not run / not accepted | Must exercise real native harness, official DeepSeek thinking/max roles, deployed GBrain and every enabled useful capability, with negative leakage/credential/host probes |
| 05 campaign/audit/submission | not started | Await accepted live certification and separate explicit official-launch approval; all campaign flags remain false |

The reused remote test runtime is Python 3.13.15, pytest 9.1.1 and Pydantic 2.13.4. The existing plans target Python 3.12; reconcile and freeze the actual runtime during certification rather than treating this observation as acceptance.

Combined verification on the existing CyberGym example virtualenv passed all 185 CyberGym tests (125 new component tests and 60 existing harness/scorer tests), with the final formatted tree passing in 2.74 seconds. Ruff checks passed for all new Python source/tests. An initial collection attempt with the repository-level virtualenv lacked the already-installed runner dependencies; selecting the existing example virtualenv resolved this without installing or rebuilding dependencies. Independent review reproduced the corrected path checks and checked the amended budgets and scored memory scope. The default synchronous DeepSeek transport has per-I/O timeouts; total deadline cancellation remains a native watchdog/transport integration requirement, not an accepted guarantee.

Historical native metadata was independently located under /srv/sunchaser/runs: claudecode-task8-solver-20260909T1145Z/RUN-MANIFEST.txt records glm-5.3[1m] and max; claudecode-task13-solver-20260910T042739Z/FINAL-REPORT.md identifies Claude Code and glm-5.3[1m], with a reproducing submission response. The Task 17/18 reports likewise record SUCCESS / SOLVED_SUBMITTED and GLM identity. Only manifest/report fields and submission metadata were inspected; no PoC bytes, target source or private configuration was read. These establish that the native GLM harness already ran successfully; it is not merely a proposed setup.

GBrain reuse evidence: the existing loopback service reports status ok, engine postgres and version 0.50.0.0. Its Tailscale Serve mapping retained an old tailnet hostname. A private Serve mapping to the same 127.0.0.1:3132 backend was added for the current hostname, and certificate-validated HTTPS health passed from SunChaser and this Windows host. The current endpoint is https://sunchaser-20260905.cinnamon-gamut.ts.net/mcp. The prior Serve configuration was saved under the isolated build checkout's .local-evidence directory. No database, memory content, personal profile or provider credentials were changed. This verifies connectivity only.

Installed GBrain source already supplies recall, search, get_page and capture, plus withAIInvocationGuard for per-provider admission/settlement. Reuse those interfaces. Native recall uses authenticated source grants, returns facts and pages separately, and lacks signed provenance; the scored facade must narrow source access, hydrate against signed manifests and enforce 12 total results / 2,000 tokens. Existing lossy telemetry is insufficient for authoritative task accounting. The current starter surface's exclusion of admin get_stats/get_usage conflicts with an older validation note, so fresh controller tools/list evidence is required.

No live DeepSeek request has been made during this amendment's component-test pass. DEEPSEEK_API_KEY is absent from the checked local and remote shells; an existing controller-held secret may still be reusable once its reference is identified. The older DeepSeek V4 Flash pilot YAML uses OPENAI_API_KEY and different settings and is not evidence that the new V4.1 Flash thinking/max route is configured or certified. Earlier live model passes remain distinct historical evidence rather than being relabelled as mocks or dismissed.

The approved budgets reuse 600 shared model requests per task, 128,000 maximum output tokens per request, 43,200 seconds wall time and three children. DeepSeek allocations are recon 12 requests / 12,582,912 counted tokens / 3,600 seconds; conditional debugging/recovery 16 / 16,777,216 / 3,600; final critic 8 / 8,388,608 / 1,800. Total DeepSeek ceilings are 36 requests / 37,748,736 tokens / 9,000 seconds, with 564 requests remaining for GLM and all memory auxiliary models. Count input plus output including thinking and cached input once; every model invocation debits the shared counter. Primary context stays 1,000,000; DeepSeek may use the documented 1,048,576 total context after actual request acceptance is certified. GBrain retains 2,000 tokens / 12 results per query, with inference/time usage counted in the same task limits.

DeepSeek is active policy, not a live-certification claim: official https://api.deepseek.com chat completions, deepseek-flash, enabled thinking, reasoning_effort=max. The controller holds DEEPSEEK_API_KEY; solver/child files, env, prompts, logs, argv and process inspection must never contain it. GLM alone selects the one official final. Provider alias metadata is recorded and disclosed; frozen provider weights are not guaranteed.

Control labels in the amended plans distinguish official requirements, leakage boundaries, performance optimisations and optional local choices. Documentation review, mocked/unit tests and read-only remote inspection cannot substitute for live capability certification. No official cohort task may be opened as a certification fixture, retried after start, or launched before separate approval.

## 2026-10-06 runtime integration update

The requested native runtime build is in progress. This update supersedes earlier
statements about missing credentials and component availability; it does not
change the unapproved/unstarted official campaign or certify a benchmark result.

- Reused the existing Z.ai Coding Plan credential. Live benign GLM-5.3 requests
  with thinking enabled and effort max succeeded (74 tokens non-streaming and
  58 tokens streaming). The check found and fixed two real provider mismatches:
  the gateway must preserve `/v1/messages`, and Claude's `glm-5.3[1m]` context
  selector becomes API model `glm-5.3`. Provider/task keys remain controller-only.
- Official DeepSeek connectivity was independently exercised with the supplied
  controller credential (two benign calls, 124 tokens). The active advisory
  runtime now runs a bounded read-only action loop through the existing budgeted
  controller; native campaign recon/debug/critic execution remains to be proved.
- GBrain's dedicated native sidecar authenticated an exact-source read grant.
  Four embeddings, one query expansion and one rerank completed with six shared
  request reservations and settlements. Separate oracle-gated capture authority
  passed a dry run; no memory pages were written. Signed catalog/facade integration
  is implemented and tested, with a fresh final remote probe still required.
- A concrete per-container network boundary passed live SunChaser probes:
  approved synthetic routes, active host-canary denial, four HTTP bypass denials,
  drift-triggered container stop, and restoration of pre-existing network rules.
  Later socket-disconnect improvements have local HTTP tests and await fresh Linux
  verification. Evidence is under the leaderboard network-runtime directory.
- The native launcher and one-shot controller reservation, managed hooks,
  provider-stream/tool correlation, parent/child read-only scopes and exact MCP
  tool-use-ID attribution are implemented. Pinned Linux VS Code/Claude packages
  are downloaded. The base image is built; the native overlay and actual native
  session/reconnect proof are outstanding. Personal VS Code/Claude settings were
  not changed.
- `arvo:1065` and `arvo:3938` were previously staged from the official ten-task
  sample only; neither has been attempted by the new native solver.

Tailscale requested renewed human SSH authentication during this work. Remote
verification is pending that check; local integration, tests and review continue.
Do not treat component tests, successful API probes, or signed observations as
accepted native certification. The two matching synthetic native runs, complete
capability evidence and frozen manifests remain prerequisites for test readiness.

## Native calibration update (2026-10-06 local)

Tailscale SSH is restored. A disposable native container ran VS Code 1.140.0
Remote SSH and the official Claude Code 2.1.289 extension in a dedicated D:
profile. The one-shot launcher reserved and returned, and six scoped MCP servers
initialized. The extension's initial-prompt argument placed text in the composer
but did not send it. After a controller-directed Send action in the isolated
window, the provider-free calibration gateway received an actual parent
`/v1/messages` request and captured 36 real tool schemas. Its redacted artifact
SHA-256 is `e9f60403ce650fa01b80bfbec3c5bb2fc2071a584c73690639bb011555e357d3`.
No model was dispatched or synthetic task solved. The collector now accommodates
bounded preliminary and concurrent native sessions, then locks to the first model
session; focused tests passed on Windows and SunChaser. The actual tool inventory
omits legacy `Grep` and `Glob`, which the capability builder no longer invents.
Automatic controlled submission, exact registry freeze and the full live
model/memory/tool/DeepSeek/oracle path remain outstanding. The official scored
campaign remains unapproved and unstarted.

## Synthetic native readiness update (2026-10-06 local)

The amended runtime reached the live synthetic readiness gate under the single
v23 controller freeze (`51f7116a75b93f1741776216efdd385698ebfe93f0edcbf1b08c267d0db727e9`).
Four real native tasks, two executions each of the private `chunk-table` and
`length-header` fixtures, returned `oracle_true=true` and
`boundary_failed=false`. Each dispatched GLM-5.3 through Claude Code 2.1.289
in VS Code Remote SSH 1.140.0, used parent and child tool sessions, completed
the three active DeepSeek advisory roles, selected one final, and recorded a
controller-only GBrain episode after the signed synthetic verdict. The private
fixtures are not official benchmark tasks or scored campaign results.

The independent audit at `/srv/sunchaser/runs/synthetic-readiness-v23-audit.json`
(SHA-256 `24a077581ba67e08b657a2717856e76fac9ac96cdcb78a5423cf24a224cf44cf`)
verified four Ed25519 oracle signatures, the pinned run/task/freeze/candidate
identities, 745 sequential runtime-audit records and their hash chains, child
GBrain and clangd calls, controlled documentation calls, all three DeepSeek
roles, one final selection per task, and post-verdict memory ordering. The
audit records 151 GLM requests: 148 with observed provider usage and three
interrupted at controller stop. Those three lack final provider token counts;
the ledger transparently charges their full one-million-token reservations
instead of treating them as observed usage. DeepSeek returned the moving
`deepseek-flash` alias and per-call usage, but did not return a fixed weight
version or fingerprint. Native Claude requested `max_tokens=32000` with
`output_config.effort=max`, despite the larger frozen policy ceiling. These
provider-disclosed limits must accompany any later benchmark report.

The live network denial proof at
`/srv/sunchaser/evidence/network-boundary-20261006-v19/boundary-proof.json`
passed canary, gateway-bypass, drift and cleanup checks; its boundary-runtime
source hash still matches v23. The v23 policy separately freezes the five
logical endpoints and six denied leakage categories. The remote component
suite passed 898 tests with five skips and two deselections after the final
test-file cleanup. Ruff passed across the leaderboard source, tests and scripts;
the native launcher passed 27 Node tests. This establishes readiness
for the already-authorised two practice exercises from the official ten-task
subset, subject to maintaining the same freeze and reporting the real oracle
results. No official scored campaign has started or been authorised.

## Parent fuzzing and serial runner review update (2026-10-06 local)

`review/cybergym-parent-fuzzing` is a pushed review branch. It does not replace
the certified v23 controller freeze. The branch includes the serial campaign
runner, parent Bash/fuzzing guidance, an offline bottleneck report, scoped
Windows window/tunnel ownership, and the previously ignored frozen `.claude`
template assets. The clean SunChaser checkout at commit `26662ca` passed 977
tests with five skips and two deselections; Ruff and the 1047-file SPDX check
passed. The first clean-checkout run exposed the ignored template assets, which
were then added and verified byte-for-byte against the v23 manifest.

The runner now appends first-request intent before dispatch and requires a
stable, idempotent request ID on resume. A concrete `TaskExecutor` that durably
deduplicates and recovers model submission is still required before using the
runner for a campaign. The Windows UI helper now closes only windows and SSH
tunnels identified with the specified run and task; its PowerShell syntax and
mocked runner lifecycle passed, but no live window teardown was executed. Its
reviewed source is tracked at `examples/cybergym/scripts/cybergym-windows.ps1`;
the configured host copy remains at `D:\GLM\cybergym-windows.ps1`.

The original native image lacked Clang's libFuzzer and ASan runtime archives.
A new base image (`sha256:97dae9c525f644bdfa10b0419e822ff691a82652bceb65f0921ecba98cdb198d`)
includes `libclang-rt-14-dev`; a disposable compiler and one-run libFuzzer
probe passed. Its native overlay
(`sha256:510c635fb76d47904dde8e523ec900e359e02f7327f9c6a4c83980554d0a8ff1`)
uses the exact v23 launcher VSIX and reproduces the v23
`native-runtime.json` hash. This new image has **not** been certified: the
frozen native capability inventory names the old image ID. A fresh provider-free
schema capture was started on the clean checkout, but the Windows workstation
was locked before the Claude Code composer could receive the required Send
action. The disposable calibration driver, container, tunnel, and VS Code
window were stopped; no model request was dispatched.

Agent-written fuzz statistics cannot prove host CPU saturation. The offline
report therefore returns `insufficient_telemetry` and makes no parallel
exec-child recommendation until controller-owned CPU/cgroup sampling exists.
The template's fuzz-stat fields match the parser, but no new live solver run
has yet exercised them. Re-stage and re-freeze the changed template and image,
recalibrate the native inventory, and obtain live synthetic model/memory/tool/
boundary/finalization evidence before promoting this branch. The two authorized
practice exercises and the official scored campaign remain unstarted.
