# CyberGym SunChaser Leaderboard Campaign Design

**Date:** 2026-10-05

**Status:** Written design and implementation plans approved; policy amendment approved; implementation and live certification pending

**Supersedes:** The policy assumptions in `2026-09-12-cybergym-level1-leaderboard-clean-run.md` where they conflict with this document

## Objective

Run a clean, reproducible CyberGym Level 1 campaign that is eligible for the public leaderboard, uses the strongest permitted Claude Code harness, and leaves enough evidence for an independent reviewer to reproduce the score and inspect every material agent decision.

The target is the complete locked cohort of 1,507 Level 1 tasks. The official score must have no omitted started tasks, no result-informed retries, one agent-selected final input per task, and the official vulnerable/fixed oracle result for every task. Development runs, including the successful Task 8 and Task 13 work and the assisted Task 17/18 work, remain useful engineering evidence but are excluded from the clean score.

This is an agent-focused submission. The system being measured is the complete frozen scaffold: native VS Code, the Claude Code extension, GLM-5.3 Max through Z.ai Coding Plan, active DeepSeek advisory roles, skills, workflows, bounded subagents, task-scoped native memory, the deployed dedicated CyberGym GBrain service, audited useful tools and MCP routes, and the trusted SunChaser controller. Reuse the successful native harness and deployed GBrain service; build the missing controller and audited integrations without replacing them.

## Non-goals

- Do not score from `C:\GLM`; it contains historical task artifacts and remains the development workspace.
- Do not reproduce or import reference patches, fixed-source material, hidden crash traces, known final inputs, issue reports, or prior task solutions into a scored workspace or memory store.
- Do not claim that development trials are official benchmark results.
- Do not optimise GEPA or add a larger adaptive layer before the simpler memory and telemetry system proves useful.
- Do not use unregistered external assistance or a human operator to steer a task after its first scored model request. Useful documentation and review capabilities may operate only through their audited registry entries and leakage boundary.

## Governing benchmark interpretation

The design follows the current CyberGym submission and FAQ requirements:

- **Official requirement:** Generate the declared Level 1 task bundles and disclose the benchmark revision, settings, dynamic vulnerable environment, test-time memory, and network behavior.
- **Official requirement:** Network access is permitted with disclosure and trajectory audit; multiple models are permitted and every main-loop, subagent, judge, and auxiliary model is disclosed with its role and usage.
- **Official requirement:** The fixed version is available only to the verifier. The agent designates exactly one official final candidate; report the final-submission metric using the official vulnerable/fixed oracle.
- **Official requirement:** Keep submission services private and retain full settings, request counts, token classes, timing, estimated costs (nullable when unpriced), at least ten example trajectories, and all final exit-code pairs.
- **Leakage boundary:** Deny task-answer sources, fixed artifacts, historical task solutions, credentials, and host interfaces independently of which tool or model requests them.
- **Performance optimisation:** The 1,507-task locked cohort, one-attempt/no result-informed retry rule, frozen harness epoch, bounded workflows, capability allowlist, and budget allocation are this campaign's chosen reproducibility controls. They are not presented as additional FAQ mandates.
- **Optional:** Native observation/reconnection, auto-updates with an epoch guard, and future GEPA evaluation are local choices; GEPA is excluded from this initial epoch.

If the official documentation changes before launch, the controller records the new revision, the change is reconciled into this policy, and certification is repeated. No benchmark-policy change is silently absorbed during a scored cohort.

## System boundaries

### 1. Workstation presentation plane

The operator uses the native VS Code application and the Claude Code extension on the workstation. This provides the session manager, live output, approval visibility, agent map, and reconnection surface the successful development harness used.

The workstation is not the trusted data plane. It must not hold the cohort dataset, verifier, fixed images, official evidence database, or clean task state. Closing VS Code or losing the workstation must not kill an already-started remote task. Reopening VS Code may reattach to the existing session for observation, but it may not inject task-specific guidance after the first model request.

`C:\GLM` is allowed for harness development, documentation, and synthetic certification preparation only. It is never mounted into a scored container.

### 2. SunChaser control plane

SunChaser owns the benchmark lock, cohort order, clean task generation, task containers, submission service, official verifier, append-only telemetry, evidence backups, and campaign ledger. The controller is trusted and inaccessible to the scored agent.

The controller distinguishes three task states:

1. **Prepared, not started:** preflight may fail and be repaired without consuming the attempt because no model request has occurred.
2. **Started:** the first solver-model request irrevocably starts the single scored attempt.
3. **Terminal:** success, oracle failure, timeout, missing final, provider failure, agent/UI crash, or infrastructure failure after start. A terminal task is never rerun inside the same official cohort.

Long-running controller processes run under a crash-resilient service or terminal session on SunChaser. The campaign ledger and logs are flushed remotely throughout execution.

### 3. Clean task execution plane

Every task gets a fresh isolated environment containing only:

- the official Level 1 task description and README;
- the vulnerable repository archive and task submission helper;
- the frozen generic Claude instructions, skills, workflows, and settings;
- an empty task output directory; and
- audited network routes to approved inference gateways, read-only memory, controlled generic documentation/package routes, and the private submission endpoint.

The environment cannot see the CyberGym master dataset, fixed images, patch data, reference inputs, earlier run folders, sibling tasks, controller source, Docker socket, host homes, workstation files, or prior Claude native-memory directories. `.git` metadata and `/tmp/poc` are removed before the first model request.

VS Code connects to this boundary through Remote SSH and the selected remote/container mechanism. The Claude Code extension's actual execution location, process tree, mounts, environment-key names, and reachable paths are captured during synthetic certification. The official run does not begin merely because the UI appears connected; the negative isolation probes must pass from the exact extension execution context.

### 4. Inference plane

The primary solver is GLM-5.3 Max through the user's Z.ai Coding Plan entitlement, not direct pay-as-you-go API billing. The exact provider-visible model identifier, context ceiling, reasoning setting, sampling values, extension version, bundled Claude Code version, and authenticated entitlement type are captured from live requests and account/session evidence before launch.

The currently observed development versions are VS Code `1.140.0` and Claude Code extension `2.1.289`. They are observations, not eternal pins. The official lock records the versions actually certified immediately before the cohort.

The harness supports multiple declared model roles because CyberGym's submission schema supports main-loop, subagent, and judge models. It does not permit an implicit provider fallback. Every model invocation must have a declared role, an exact model identifier, a trigger, a request budget, and a trajectory record.

#### Active declared DeepSeek policy

**Performance optimisation:** DeepSeek is ACTIVE in the approved policy, through the official API at `https://api.deepseek.com`, chat completions, model alias `deepseek-flash`, thinking enabled, and `reasoning_effort: max`. One independent reconnaissance lane uses DeepSeek; one conditional debugging/recovery lane runs only after an observable failure; one final adversarial critic reviews vulnerable-side evidence. DeepSeek may propose PoCs. The GLM parent evaluates the advice and selects the single official final. This is declared model routing, with no hidden alternate-model approval gate or undeclared fallback.

Reuse the existing per-task ceilings: 600 total model requests, 128,000 maximum output tokens per request, 1,000,000 primary-context ceiling, 43,200 seconds wall time, and three concurrent children. Allocate at most 12 requests / 12,582,912 counted input-plus-output tokens / 3,600 seconds to DeepSeek recon, 16 / 16,777,216 / 3,600 to conditional debugging/recovery, and 8 / 8,388,608 / 1,800 to the final critic. DeepSeek totals are 36 requests, 37,748,736 counted tokens, and 9,000 seconds; the remaining 564 requests are shared by GLM and all declared memory auxiliary models. Every invocation, including embedding/reranking/query-expansion, debits the shared 600-request counter. DeepSeek may use its documented 1,048,576-token total input-plus-output context, with output capped at 128,000 including thinking; cached input is counted once in usage ceilings. All phases share the 43,200-second task clock; allocations cannot extend it or the three-child limit. Unused DeepSeek allocations are not silently borrowed. Certification must verify the actual accepted provider settings and limits; the primary's 1,000,000-token setting is not an artificial DeepSeek input cap.

**Leakage boundary:** `DEEPSEEK_API_KEY` is held only by the controller gateway. It never appears in solver or child files, environments, prompts, logs, command lines, or process inspection. No workstation credential store or broad credential environment is passed through. Agents receive task-scoped gateway authorization only.

**Official requirement / performance optimisation:** Disclose every model role, invocation, request, token class, tool use, and provider response metadata, and freeze the model policy in the launch manifest. The alias `deepseek-flash` may drift: pin request settings, API endpoint, returned model/version metadata and any provider fingerprint when available, and disclose that these records do not guarantee frozen provider weights. No undisclosed provider change is accepted.

### 5. Memory plane

Memory has two intentionally different layers.

**Claude native auto memory** is enabled for the task because it is part of the current high-performing extension. It is task-scoped: each task starts with a new empty native-memory location, the location and final contents are archived with that task's private evidence, and the contents are never mounted into another task. This permits within-task continuity without creating an opaque cross-task channel.

**Xeus-CyberGym GBrain** is the declared cross-task memory layer. It uses the separate GBrain profile and Supabase database already deployed behind loopback plus Tailscale Serve HTTPS. It is not the personal brain. Its source corpus, model dependencies, schema, recall results, write events, promotions, and snapshots are auditable.

The memory record model uses four tiers:

- `episodic`: what happened in one task, labelled with the real oracle outcome;
- `semantic`: format or vulnerability facts with source provenance;
- `procedural`: reusable, parameterised diagnostic methods;
- `principle`: scarce cross-cutting heuristics promoted only with repeated evidence.

The controller, not the solver's self-report, writes authoritative outcome labels. A failed task may contribute an episode and a bounded hypothesis, but a single failure is never promoted as a general fact. Promotion requires repeated structural matches and outcomes. Retrieval and outcome logs preserve at least `(run_id, task_id, memory_id, retrieved_at, used, model_role, final_oracle_outcome)` so negative memories can be audited and down-ranked rather than overwhelming the store.

Preseed content is limited to general, externally sourced knowledge such as file-format structure, sanitizer interpretation, debugger methods, fuzzing procedures, and abstract recovery principles. It is scanned against the CyberGym corpus and prohibited artifacts before freezing.

**Performance optimisation:** Scored GBrain mode is `audited_hybrid`: automatic harness recall plus model-initiated read-only `recall`/`search` for the parent and children, through an audited gateway to the deployed service. Preserve the existing 2,000-token / 12-result recall budget per query. The gateway applies the same provenance and leakage filters to both retrieval paths and records queries, results, selected IDs, caller roles, token/model/tool usage, and latency. A logical `search` route may map to an audited available read operation; do not assume an unverified service tool exists. Useful general semantic knowledge, principles, and matching procedures are eligible; raw task episodes and answer-bearing material are not.

**Leakage boundary:** Agents have no GBrain write, capture, promotion, or database credential. Automatic remembering is a controller-only epilogue after the true official oracle verdict, never an agent self-report. Terminal attempts without a true verdict may be logged in controller evidence but cannot publish an oracle-labelled memory write. Use the existing separate CyberGym profile/database and keep the personal brain inaccessible. Implement and certify this already approved policy without a new design or strict-hook authorization decision. Official launch approval remains separate.

GEPA remains out of the initial campaign. The outcome table may later become its offline reward input, but GEPA can only be evaluated between separately versioned campaign epochs. It may never mutate the prompt during a frozen cohort.

### 6. Evidence plane

Every task has an append-only remote evidence directory created before launch. It contains:

- immutable task, benchmark, harness, model, workflow, skill, extension, and network hashes;
- sanitized mount, environment-key, process, and negative-isolation inventories;
- complete parent and child trajectories and tool events;
- every model ID, role, request count, token class, duration, cost when available, and provider response metadata;
- every GBrain query/result/write and the IDs actually used;
- task-scoped Claude native memory;
- stdout, stderr, workflow scripts generated by Ultracode, crash records, and UI/session identifiers;
- the one final candidate, declaration, hash, length, and lock timestamp;
- raw submission response and official vulnerable/fixed exit codes; and
- a terminal ledger event that cannot be overwritten by a later retry.

Secrets and personal data are redacted before evidence is pushed to GitHub or supplied to reviewers. Raw private evidence remains backed up outside the agent boundary with a hash manifest.

## Harness behavior

### Superpowers and reasoning sequence

The generic task contract preserves the behavior that solved previously difficult tasks:

1. invoke `using-superpowers` and select only relevant skills;
2. brainstorm with explicit self-questioning before implementation;
3. run bounded parallel reconnaissance to generate independent, source-grounded hypotheses;
4. reconcile hypotheses in the parent rather than majority-voting them;
5. use `systematic-debugging` after a concrete failure or surprising result;
6. use test-driven changes where code is modified;
7. perform adversarial logic and edge-case review; and
8. invoke verification-before-completion before locking one final candidate.

The skills are frozen local copies with hashes. They are generic and contain no task IDs or historical answers.

### Ultracode, workflows, and subagents

Ultracode and dynamic workflows are enabled because they are part of the current extension's useful orchestration surface. They are bounded by the controller:

- at most three concurrent solver children;
- one reconnaissance workflow;
- one conditional debugging workflow after observable failure;
- one final adversarial review;
- fixed per-task request, token, wall-time, and child-spawn ceilings; and
- exact model and role provenance for every child.

Generated workflow scripts are preserved and hashed. Empty, skipped, retried, or failed children are visible; the parent cannot silently relaunch them outside the task budget. A workflow engine warning or limit bypass is not accepted as authority to exceed controller limits.

### Clangd and other plugins

**Performance optimisation:** Maintain an audited maximum-capability registry. Inventory the native extension, plugins, tools, MCP servers/connectors, local analyzers, and documentation routes; enable each useful permissible capability after its audit passes. An entry freezes its ID, version/hash, role, read/write powers, filesystem/network scope, provider/model dependencies, credentials held by the controller, budget accounting, logging, classification, and certification evidence. Unknown capabilities remain unavailable until audited and a new epoch is certified. Useful permissible tools are enabled by default after audit; certification measures useful capability coverage and boundary enforcement, not minimal tool-call counts.

**Leakage boundary:** Parent and children may use audited read-only local source inspection, clangd and GBrain recall/search. Controlled generic language, compiler, debugger, file-format, library API, and tool documentation routes are allowed with request/result audit. The provided vulnerable task archive is permitted evidence. External upstream repositories for the target, patches, target issues/changelogs, CVEs/vulnerability databases, published PoCs, prior solutions, and fixed-side sources remain blocked, including redirects, mirrors, search results, and indirect MCP routes. Do not confuse the supplied vulnerable archive with external target-repository leakage. Broad browser/search/connectors or external reviewers require a scoped useful registry entry; they never bypass this boundary. Host files, personal accounts and credentials remain inaccessible.

### Remote Control and human interaction

Claude Remote Control may remain enabled for observation and reconnection because CyberGym does not prohibit it. After the first model request, humans may view progress, abort for safety, or restore the UI connection. They may not send prompts, choose candidates, edit files, supply evidence, answer model questions, or steer recovery. All control-channel activity is logged.

### Version and auto-update policy

Auto-updates remain enabled unless the benchmark later requires otherwise. This does not permit silent version drift:

- record VS Code, extension, bundled CLI, plugin, skill, workflow, and model versions before every task;
- archive the certified extension/package artifacts where licensing permits;
- if an update activates, stop scheduling new tasks immediately;
- prefer restoring the certified version and continuing the same frozen epoch;
- accepting the update requires synthetic recertification and a new harness epoch; and
- never combine harness epochs in the 1,507-task headline cohort. If the certified version cannot be restored and the update is accepted, close the old epoch as incomplete and restart the clean cohort from task one under the new epoch.

If restoring the prior version is impossible, the cleanest option is a new versioned cohort rather than pretending the system did not change.

## End-to-end task flow

1. The controller selects the next precommitted task ID and creates an empty evidence record.
2. CyberGym generates the Level 1 bundle from the locked revision.
3. The controller builds a fresh task environment and injects only the frozen generic harness.
4. Preflight proves mounts, files, processes, model configuration, memory state, network routes, and extension execution context.
5. VS Code attaches and the controller starts the Claude Code session. The first solver request marks the attempt started.
6. The task contract performs task-local brainstorming, automatic and model-initiated audited GBrain recall, bounded GLM/DeepSeek reconnaissance, implementation, conditional debugging/recovery, and final adversarial review using registered capabilities.
7. Claude writes one final candidate and a declaration. The controller stops the agent, makes outputs immutable, and records the hash.
8. The private submission endpoint is called exactly once for that hash. The official verifier runs outside the agent boundary and records both exit codes.
9. The controller alone writes memory after the true oracle verdict, using provenance/leakage filters. The solver never sees fixed-image output.
10. Evidence is flushed, hashed, backed up, and the ledger receives exactly one terminal result.

## Failure handling

- **Preflight failure before first request:** repair and rerun preflight; no attempt consumed.
- **Workstation or VS Code failure after start:** the remote task continues. Reattach read-only if possible. If the remote agent died, record terminal failure.
- **Provider throttling or quota exhaustion:** do not start tasks when capacity is doubtful. A failure after the first request remains part of the attempt; there is no hidden restart.
- **Child/workflow failure:** surface it to the parent inside the existing budget. No out-of-band replacement child.
- **Unexpected test/crash behavior:** invoke the frozen systematic-debugging path, retaining commands and evidence.
- **Ambiguous submission response:** retain the raw response, do not submit again, and classify conservatively for audit.
- **Memory unavailable:** follow the predeclared fail-open or fail-closed policy selected at certification; never improvise per task.
- **Version change:** stop before the next task and apply the version policy above.
- **Controller or storage failure:** append-only checkpoints permit reconstruction; already-started tasks are never erased from the denominator.

## Certification and go-live gates

Certification uses synthetic vulnerable/fixed toy targets, never a cohort task. It must demonstrate:

1. the full 1,507-task cohort and benchmark hashes are frozen;
2. the exact primary GLM-5.3 Max request and Z.ai Coding Plan entitlement are evidenced;
3. active DeepSeek recon, conditional debugging/recovery and final critic execute through the official gateway at thinking/max, within their allocated budgets, with provider metadata and secret-isolation evidence;
4. `audited_hybrid` GBrain automatic and parent/child initiated read-only retrieval execute, while agent writes fail and controller writes require a true oracle verdict;
5. VS Code plus the Claude Code extension execute inside the proven clean boundary;
6. task-scoped native auto memory starts empty and cannot cross tasks;
7. every enabled useful capability, parent/child local tool, clangd, workflow, review, model request and token/tool event is exercised and reconciled under hard limits, with no undeclared calls;
8. generic documentation and other registered route successes and representative answer-leakage/credential/host denials are logged, including redirected and indirect access;
9. forbidden artifacts, Git history, old task data, controller paths, fixed images, and host interfaces are unreachable;
10. one-final locking, submission, verifier separation, and both exit codes work;
11. crash/reconnect behavior preserves the remote session and append-only evidence;
12. independent aggregation reproduces all counts and hashes; and
13. the certified commit and package hashes match the launch manifest.

A failed gate is a no-go. The system is repaired and recertified before the first official task.

## Campaign phases

Implementation is deliberately decomposed into five reviewable subprojects:

1. **Control and isolation:** benchmark lock, controller, clean containers, private submission/oracle boundary, and negative preflight.
2. **Harness and telemetry:** native VS Code/Claude Code remote execution, bounded Ultracode, skills, clangd, version capture, final lock, and append-only evidence.
3. **Memory and multimodel policy:** task-scoped native memory, deployed GBrain schema/audit path and `audited_hybrid` retrieval, controller oracle writes, and the approved active DeepSeek roles.
4. **Synthetic certification:** toy targets and non-cohort fixtures only. No task from the frozen 1,507-task cohort is exposed to the harness before its one official attempt.
5. **Full campaign, independent audit, and submission:** run all 1,507 tasks in fixed order, aggregate without gaps, independently recompute the score, publish non-secret reproducibility material, and submit the leaderboard record.

Each subproject gets its own implementation checklist and acceptance evidence. No later phase can weaken an earlier boundary without a new design revision and recertification.

## Frozen design decisions

- Use native VS Code plus the Claude Code extension as the visible official harness.
- Run the clean execution context remotely under SunChaser control; never from contaminated `C:\GLM`.
- Use GLM-5.3 Max through the user's Z.ai Coding Plan as the primary solver.
- Use active declared DeepSeek official-API thinking/max recon, conditional debugging/recovery and final critic; the GLM parent selects the one official final.
- Enable Ultracode, workflows, Superpowers, subagents, agent map, clangd, and task-scoped Claude native memory under explicit bounds.
- Keep remote observation/reconnection enabled and human task steering disabled after start.
- Permit only disclosed, audited, allowlisted network routes.
- Use the dedicated CyberGym GBrain in `audited_hybrid` mode, with automatic and parent/child read-only retrieval and controller-only writes after a true oracle verdict.
- Keep GEPA out until the simpler memory loop has reliable, oracle-labelled evidence and a later versioned experiment justifies it.
- Leave auto-updates enabled, but stop on activation and require rollback or a new certified harness epoch.
- Enable useful permissible capabilities after registry audit; block answer leakage, credentials and host escape across every tool/model route.

## Approval boundary

The written specification and plans, and this policy amendment, have been approved. Proceed with their implementation and synthetic certification without repeating design approval. They do not authorise the official 1,507-task launch. Go-live requires a separate recorded approval after the live native harness, maximum-capability registry, active DeepSeek, hybrid GBrain and isolation certification evidence is reviewed.
