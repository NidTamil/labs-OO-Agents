# CyberGym Leaderboard Campaign Master Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (\`- [ ]\`) syntax for tracking.

**Goal:** Build, certify, and operate a clean 1,507-task CyberGym Level 1 leaderboard campaign around the native VS Code Claude Code extension and GLM-5.3 Max.

**Architecture:** SunChaser is the trusted controller and evidence authority. Reuse the existing remote authority at /srv/sunchaser/xeus-cybergym, the successful native VS Code/Claude harness and the deployed isolated GBrain service. Inspect its existing signing, ledger and legacy scorer contracts before adding missing interfaces; do not recreate working equivalents. Each scored task runs in a new SSH-accessible container with task-owned source/output/home surfaces, while the Windows VS Code client displays the native Claude Code session and a version-locked launcher supplies the initial generic prompt. Capability audit, active DeepSeek routing, hybrid memory, certification, campaign scheduling, aggregation, and independent audit remain reviewable implementation stages.

**Tech Stack:** Python 3.12, uv, Pydantic 2, Docker, CyberGym, VS Code 1.140.0 or the recertified launch version, Claude Code extension 2.1.289 or the recertified launch version, Node.js built-in test runner, GLM-5.3 Max through Z.ai Coding Plan, GBrain MCP, JSON/JSONL, Ed25519, SHA-256.

## Global Constraints

- The official cohort is exactly the 1,507 Level 1 task IDs from the locked CyberGym tasks.json.
- C:\GLM is development-only and is never mounted into a scored container.
- The fixed image, repo-fix.tar.gz, patch.diff, error.txt, reference PoC, Git history, prior task state, controller source, Docker socket, and host homes are outside the agent boundary.
- The first primary-solver request irrevocably starts the single scored attempt.
- A started task receives one terminal result and is never rerun in the same official cohort.
- The agent selects exactly one final PoC; the controller never substitutes a timeout candidate.
- GLM-5.3 Max uses the Z.ai Coding Plan entitlement, not pay-as-you-go model billing.
- Active DeepSeek official-API deepseek-flash thinking/max roles are one independent recon lane, conditional debugging/recovery, and the final adversarial critic; GLM chooses the single official final.
- Claude native auto memory is enabled only inside one fresh task home and is archived without crossing tasks.
- The deployed dedicated Xeus-CyberGym GBrain uses audited_hybrid scored mode: automatic and parent/child initiated read-only recall/search; controller-only writes after a true oracle verdict.
- Enable useful permissible tools, plugins, MCP/connectors and controlled generic documentation routes after capability audit. Deny external target repositories/patches/issues/CVEs/published PoCs, credentials and host interfaces across every route; the provided vulnerable archive remains permitted evidence. Human steering after start remains prohibited.
- DEEPSEEK_API_KEY stays controller-only and absent from solver/child files, environment, prompts, logs, command lines and process inspection; no broad workstation credential pass-through.
- Freeze and disclose capability/model/role policies, every request/token/tool event, provider metadata and alias drift limitations. Certification exercises enabled capabilities and checks no undeclared calls.
- Auto-updates remain enabled, but one 1,507-task headline cohort uses one certified harness epoch. A detected activation pauses scheduling.
- The official launch requires a separate approval after certification; executing these plans does not authorise it.

**Control labels:** Official requirements cover the agent-designated single final/final-submission metric, private submission host, fixed-only verifier, and complete settings/model/network/usage/trajectory/exit-code disclosure. Leakage boundaries cover answer-bearing artifacts, secrets and host access. The 1,507-task locked cohort, no retries, frozen epoch, registry, memory routing and numeric budgets are performance optimisations chosen for this campaign. Remote observation, guarded auto-updates and future GEPA are optional local choices. Unlabelled implementation mechanics inherit their applicable category; do not call local optimisations official requirements.

---

## Plan Set

| Order | Plan | Independent deliverable |
|---|---|---|
| 1 | 2026-10-05-cybergym-01-control-isolation.md | Locked cohort, clean workspaces, isolated task containers, network boundary, and one-attempt state machine |
| 2 | 2026-10-05-cybergym-02-vscode-claude-harness-telemetry.md | Native VS Code launch path, generic Claude harness, bounded workflows, model gateway, and immutable final-selection telemetry |
| 3 | 2026-10-05-cybergym-03-memory-multimodel.md | Task-local native memory, audited_hybrid GBrain, preseed controls, oracle writes, and active declared DeepSeek roles |
| 4 | 2026-10-05-cybergym-04-synthetic-certification.md | Synthetic-only end-to-end certification with crash, reconnect, isolation, model, memory, and version-drift evidence |
| 5 | 2026-10-05-cybergym-05-campaign-audit-submission.md | Crash-safe scheduler, 1,507-task ledger, official oracle path, aggregation, independent audit, and leaderboard package |

## Dependency graph

    control and isolation
            |
            v
    VS Code harness and telemetry
            |
            v
    memory and multimodel policy
            |
            v
    synthetic certification
            |
            v
    explicit go-live approval
            |
            v
    campaign, audit, submission

No plan may skip its predecessor. Plan 5 may build and test its scheduler before approval, but the command that starts the official cohort must reject a missing signed go-live record.

## Operational sequence from the recovered checkpoint

This is the execution path through the approved plans, not another design phase. Preserve earlier live GLM/native harness and GBrain validation; keep historical development scores separate from the new campaign. The new 185-test pass verifies additive components, not end-to-end readiness.

1. Complete the missing integration in Plans 01–03 and the scheduler/audit preparation in Plan 05. Reuse the native VS Code/Claude Code GLM-5.3 Max harness, deployed GBrain and signed Xeus authority. Wire actual capability dispatch and parent/child logging, controller-bound DeepSeek recon/debug/critic routes, total request cancellation, GBrain exact-source signed provenance and auxiliary accounting, true-oracle controller writes, clean task containers, immutable GLM-selected finals and durable submission/recovery records. Resolve the existing DeepSeek secret reference and native workstation access without forwarding ambiguous or broad credentials.
2. Run both non-cohort synthetic fixtures through the real native path and repeat the complete certification suite twice with identical configuration hashes. Exercise every enabled useful capability, real GLM/DeepSeek/GBrain calls, final selection and external oracle, answer/credential/host denials, memory state separation, deadlines, quota admission, interruption/reconnect and backup recovery. Record actual provider settings, returned metadata and auxiliary usage; old successful connection probes and mocked tests remain useful evidence but do not certify new behavior.
3. Freeze the launch manifest and sign the readiness report. Lock the 1,507-task dataset/order, sanitized inputs/images, prompts/skills/workflows, tool/MCP/route inventory, model/role/budget policy, clean memory seed and write/promotion policy, observed runtime versions and evidence schemas. Reconcile Python 3.12 plans with the tested 3.13.15 runtime. Measure actual quota, tokens/cost, disk needs and throughput to publish a realistic schedule. Default task concurrency is one; any higher setting must be chosen, tested and recorded before launch. Dynamic GBrain contents evolve only through the frozen audited policy. The finite 12-hour/600-request budgets and concurrency are our performance choices, not official benchmark limits.
4. Present the concrete signed certification, independent synthetic 1,507-row audit, capacity estimate, backup/recovery proof and disclosure draft for the previously agreed official launch approval. No official task is a tuning or certification fixture. Implementation work continues without another design/provider-choice approval.
5. Start the one locked official cohort and continue in its declared order. Each task has a fresh native session/container, one started attempt, iterative vulnerable-side work within the budget, one GLM-designated final and a private true-oracle result. Checkpoint and back up every terminal task; failures remain in the denominator. No separate pilot/restart is added: any early progress inspection observes the same cohort without changing settings, steering tasks or rerunning them. Quota shortage delays new starts. An activated version change pauses scheduling until the certified version is restored; adopting a new version creates a separate epoch and cannot be silently merged with the incomplete cohort.
6. Derive results from raw signed evidence, run the independent audit, and prepare the agent-focused leaderboard package. Include all 1,507 final exit-code pairs, every invoked model and its usage/cost/time, complete scaffold/tool/network/dynamic-memory disclosure, public writeup and at least ten reviewable trajectories/logs/PoCs. Prepare the submission for review; sending an email, posting an issue or publishing artifacts still requires the user's explicit authorization for that external action.

The immediate implementation work is step 1. The next demonstrated milestone is a signed complete native certification pass, not another unit-test count or a reused development score.

### Task 1: Establish the implementation branch and execution record

**Files:**
- Create: docs/superpowers/plans/2026-10-05-cybergym-implementation-status.md
- Modify: none
- Test: repository status and plan hash checks

**Interfaces:**
- Consumes: this master plan and the approved campaign design
- Produces: a single branch name, baseline commit, and checkbox ledger used by all five plans

- [x] **Step 1: Recover and select the existing approved baseline**

The approved plan-suite baseline was recovered at 55d63ff3317ef6102354ba413b6ee32cf66f5ae5 on NidTamil/labs-OO-Agents, with approved-design ancestor 5b9dbe37cae7abbd28b521db75a6d10f267d978e. Continue on codex/audited-maximum-capability. Trusted Tailscale SSH reached the remote authority at /srv/sunchaser/xeus-cybergym, clean HEAD e28f33d45390c64f338d5520e68f53f4d8b50ce8 on chore/move-sunchaser-prep, five commits ahead of its tracked source. Existing canonical_json, SqliteEventLedger, kernel state_machine and tool_broker interfaces were inspected read-only and the signed core was not recreated. The isolated build worktree is /srv/sunchaser/labs-OO-Agents-audited-build at the recovered labs baseline; the original remote labs checkout remains untouched. Preserve the native harness and GBrain deployment. Reconcile source/API changes as implementation proceeds; read-only inspection is not full integration acceptance.

- [x] **Step 2: Write the execution record**

Completed in 9cc8f83 and extended with prior live validation evidence in 95a0fde. Maintain the existing tracked status record; do not overwrite it with the original starting template below.

Create docs/superpowers/plans/2026-10-05-cybergym-implementation-status.md with:

~~~markdown
# CyberGym Leaderboard Implementation Status

- design_commit: 5b9dbe37cae7abbd28b521db75a6d10f267d978e
- baseline_commit: 55d63ff3317ef6102354ba413b6ee32cf66f5ae5
- implementation_branch: codex/audited-maximum-capability
- policy_amendment_approved: true
- official_launch_authorised: false
- alternate_model_policy: active_deepseek_official_api_thinking_max
- scored_memory_mode: audited_hybrid
- implementation_verified: false
- live_certification_verified: false
- remote_authority_inspected: true
- remote_authority_commit: e28f33d45390c64f338d5520e68f53f4d8b50ce8

| Plan | State | Review commit | Evidence |
|---|---|---|---|
| 01 control/isolation | not started | | |
| 02 harness/telemetry | blocked on 01 | | |
| 03 memory/multimodel | blocked on 02 | | |
| 04 synthetic certification | blocked on 03 | | |
| 05 campaign/audit/submission | blocked on certification and go-live approval | | |
~~~

- [x] **Step 3: Verify the baseline and plan files**

The baseline and approved plans were recovered and verified. Approved-design ancestry was also checked successfully on the full SunChaser repository; the local clone is shallow. Both build checkouts now include the additive checkpoints, so HEAD is a descendant of the original baseline rather than equal to it.

Run:

    git rev-parse HEAD
    git merge-base --is-ancestor 5b9dbe37cae7abbd28b521db75a6d10f267d978e HEAD
    git status --short
    sha256sum docs/superpowers/specs/2026-10-05-cybergym-sunchaser-leaderboard-campaign-design.md
    find docs/superpowers/plans -maxdepth 1 -name '2026-10-05-cybergym-*.md' -print | sort

Expected at the recovered local baseline: HEAD equals 55d63ff3317ef6102354ba413b6ee32cf66f5ae5, the approved-design ancestor check exits zero, and all six approved plan files are present alongside the new honest status ledger. Policy amendments remain reviewable changes; no implementation or live certification claim follows from this check.

- [x] **Step 4: Commit the execution record**

Completed by the recorded checkpoints above; no duplicate initialization commit is needed.

    git add docs/superpowers/plans/2026-10-05-cybergym-implementation-status.md
    git commit -m "chore: start CyberGym leaderboard implementation"

### Task 2: Execute and review Plans 01 through 03

**Files:**
- Modify: docs/superpowers/plans/2026-10-05-cybergym-implementation-status.md
- Test: each subplan's named unit and integration suites

**Interfaces:**
- Consumes: Tasks and acceptance gates in Plans 01, 02, and 03
- Produces: three independently reviewable commits and evidence links

- [ ] **Step 1: Execute Plan 01 task-by-task**

Use subagent-driven-development or executing-plans. Do not start Plan 02 until every Plan 01 test and the independent isolation review pass.

- [ ] **Step 2: Record Plan 01 acceptance**

Set its row to accepted only after recording the commit hash, pytest command, test count, and negative-preflight evidence path.

- [ ] **Step 3: Execute and review Plan 02**

Require a real VS Code extension smoke test in a synthetic workspace. A unit test of the launcher command is necessary but not sufficient.

- [ ] **Step 4: Execute and review Plan 03**

Implement the approved active DeepSeek policy and audited_hybrid GBrain integration. Tests must prove approved roles and parent/child read-only routes work, while undeclared calls, answer leakage, agent memory writes and credential/host access fail. No new design approval is required.

- [ ] **Step 5: Commit the updated status ledger**

    git add docs/superpowers/plans/2026-10-05-cybergym-implementation-status.md
    git commit -m "docs: record core CyberGym harness acceptance"

### Task 3: Certify without touching the official cohort

**Files:**
- Modify: docs/superpowers/plans/2026-10-05-cybergym-implementation-status.md
- Create at runtime: evidence/certification/certification-20261005T000000Z/REPORT.md (example generated certification-ID path)
- Test: Plan 04's full synthetic certification suite

**Interfaces:**
- Consumes: accepted outputs of Plans 01 through 03
- Produces: a signed certification report and a frozen harness epoch

- [ ] **Step 1: Execute Plan 04 only against synthetic fixtures**

The certification runner must reject every task ID present in the locked 1,507-task cohort.

- [ ] **Step 2: Review all red gates**

Any failure in isolation, exact model identity, native extension launch, reconnection, final locking, memory separation, network denial, or evidence completeness leaves certification failed.

- [ ] **Step 3: Freeze the epoch**

Write accepted extension, bundled Claude binary, launcher, image, prompt, skill, workflow, model/role, hybrid-memory, capability-registry, network-policy, provider metadata and controller source hashes into harness-lock.json. Provider alias/version metadata is a disclosure record, not a guarantee of immutable provider weights.

- [ ] **Step 4: Update the status record without authorising launch**

Set synthetic certification to accepted and leave official_launch_authorised false.

### Task 4: Hold the pre-go-live decision review

**Files:**
- Create: config/pre-go-live-decision.json
- Modify: docs/superpowers/plans/2026-10-05-cybergym-implementation-status.md
- Test: schema validation and certification-hash binding

**Interfaces:**
- Consumes: signed synthetic certification report
- Produces: the only record that may enable an official campaign

- [ ] **Step 1: Present the certification evidence to the operator**

The review covers the already approved active DeepSeek roles, hybrid GBrain retrieval/controller writes, complete capability registry, exact versions/provider metadata, auto-update epoch behavior, network boundary, task budget, and campaign order. This is a live-certification and launch review, not a repeated design decision.

- [ ] **Step 2: Bind the active DeepSeek policy to certification**

The JSON references the complete certified model policy from Plan 03, including:

~~~json
{"status":"active","provider":"deepseek-official-api","base_url":"https://api.deepseek.com","api":"chat_completions","model":"deepseek-flash","thinking":{"type":"enabled"},"reasoning_effort":"max","roles":["independent_recon","conditional_debug_recovery","final_adversarial_critic"],"max_requests":36}
~~~

Record all route triggers, concrete token/time limits, controller-only credential reference, provider response metadata, capability-policy hash and certification hash. The alias may drift; disclose that metadata pinning does not freeze provider weights. These excerpts are not substitutes for the full Plan 03 schema.

- [ ] **Step 3: Bind audited_hybrid GBrain to certification**

Record scored_mode=audited_hybrid and certified automatic-recall, parent/child read-only recall/search, filtering, failure behavior and controller-only oracle-write hashes. Both retrieval paths are approved and audited; no agent capture/promotion/database access is permitted.

- [ ] **Step 4: Request separate official-launch approval**

Do not infer approval from design approval, plan approval, successful tests, or certification.

### Task 5: Execute Plan 05 after approval

**Files:**
- Modify: docs/superpowers/plans/2026-10-05-cybergym-implementation-status.md
- Test: campaign dry-run, aggregation parity, independent audit

**Interfaces:**
- Consumes: signed pre-go-live decision and explicit official-launch approval
- Produces: complete run evidence and the leaderboard submission package

- [ ] **Step 1: Verify the launch guard**

Run:

    uv run sunchaser-cybergym campaign check-go-live \
      --decision config/pre-go-live-decision.json \
      --harness-lock config/harness-lock.json

Expected: PASS only when approval and certification hashes match.

- [ ] **Step 2: Execute the fixed cohort**

Run the Plan 05 scheduler without changing cohort order, harness epoch, model policy, memory policy, or task budgets.

- [ ] **Step 3: Aggregate and independently audit**

The primary aggregation and clean-room audit must match on 1,507 task IDs, terminal-record count, solved count, success rate, every final PoC hash, both exit codes, and per-model usage.

- [ ] **Step 4: Produce the public package and submission**

Redact secrets, publish the reproducible non-secret artifacts, and submit only after the final audit is accepted.

## Master acceptance

The master plan is complete only when all five subplans are accepted, the 1,507-task ledger has one terminal row per task, aggregation and independent audit match, and the public package satisfies CyberGym SUBMISSION.md. Plan completion alone never implies a successful score or leaderboard acceptance.
