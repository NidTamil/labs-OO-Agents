# NOOA CyberGym Agent

[NOOA](https://github.com/NVIDIA-NeMo/labs-OO-Agents)-based agent for the [CyberGym](https://github.com/sunblaze-ucb/cybergym) benchmark.

This README walks through the minimal path for running CyberGym's official
10-task subset behind the CyberGym firewall/proxy. It uses only the task data and
Docker images for those tasks—you do **not** need the full ~240 GB dataset.

The agent is a portfolio-style multi-agent system. Three persistent
finder lanes independently inspect the source and submit PoCs. Verified crash
families are shared through a typed portfolio, a reviewer steers subsequent
exploration, and bounded expander agents search for alternative paths from each
new family. The behavior-defining files (`agent.py`, `main.py`, `shell_tools.py`,
`submissions.py`, and `util.py`) define the complete agent behavior. The native
runner and Docker image provide the public CyberGym integration around it.

Each step is a small script under [`scripts/`](scripts/). Read
[`scripts/config.sh`](scripts/config.sh) to see (and override) every path, model,
and server setting; the other scripts source it.

See the [technical report](Technical_Report.md) for its architecture, runtime
boundary, reproducibility design, and verification coverage.

## Requirements

- Linux host with Docker
- Python 3.12 or 3.13
- [uv](https://docs.astral.sh/uv/)
- Git LFS (`git lfs version` should work)
- LLM credentials (put in `.env`) for all models configured in [`nooa_cybergym/llm_config.yaml`](nooa_cybergym/llm_config.yaml)

The default configuration uses three finder models—GLM-5.2, Nemotron 3 Ultra,
and DeepSeek V4 Flash—with GLM-5.2 as the orchestrator, reviewer, and expander
model. It exposes all three through one OpenAI-compatible gateway. Put the
gateway credential and URL in `.env`:

```bash
OPENAI_API_KEY=...
OPENAI_BASE_URL=https://your-openai-compatible-gateway.example/v1
ANTHROPIC_AUTH_TOKEN=... # Z.AI Coding Plan reviewer only
CYBERGYM_FIREWALL_EXTRA_DOMAINS=api.z.ai
```

Configure the models available through your LLM provider in
[`nooa_cybergym/llm_config.yaml`](nooa_cybergym/llm_config.yaml). Model names and
providers must be supported by [LiteLLM](https://docs.litellm.ai/docs/providers).
The aliases referenced by the finder
lanes in [`agent.py`](nooa_cybergym/agent.py) must match entries in that file.

| Setting | Where to configure it |
|---|---|
| Provider credentials and shared endpoint | `.env` |
| Model aliases, provider model names, and token limits | `nooa_cybergym/llm_config.yaml` |
| Finder models | `LANES` in `nooa_cybergym/agent.py` |
| Orchestrator and reviewer model | `--model` (default: `glm-5.2`) |
| Expander model | `DEFAULT_MODEL_NAME` in `nooa_cybergym/agent.py` |
| Reasoning effort | `REASONING_EFFORT` (default: `xhigh`) |

Worker models use the shared OpenAI-compatible endpoint. The optional v2
reviewer resolves its own endpoint and credential from `llm_config.yaml` and
fails closed if either is absent. The `glm-5.3` reviewer alias uses Z.AI's
dedicated Coding Plan endpoint with deep thinking enabled; it does not use the
separately billed general API. Changing the models can materially change
results. Add `api.z.ai` to the runner's outbound allowlist when that reviewer is
enabled.

You do **not** need to set a CyberGym API key: `scripts/setup.sh` generates a
random local one into `.env` (which is gitignored). It is just a shared token
between the server and the validation step on your machine.

## Step 1 — Set up (one time)

```bash
scripts/setup.sh
```

This creates a uv virtualenv, generates a local CyberGym API key in `.env`,
installs and clones CyberGym, fetches the subset via Git LFS, pulls the matching
Docker images, installs the runner from this example's frozen `uv.lock`, and
builds the agent image with the pinned NOOA revision. The script is safe to
re-run.

The subset it installs:

```text
arvo:47101   arvo:3938   arvo:24993   arvo:1065   arvo:10400   arvo:368
oss-fuzz:42535201   oss-fuzz:42535468   oss-fuzz:370689421   oss-fuzz:385167047
```

## Step 2 — Start the CyberGym server

In its own terminal, and leave it running:

```bash
scripts/start_server.sh
```

This starts CyberGym's submission server in Docker-image mode. It pulls the
vulnerable/fixed images on demand and records submitted PoCs in
`runs/server/poc.db`.

## Step 3 — Run the 10-task subset

In a second terminal (server still running from Step 2):

```bash
scripts/run_subset.sh
```

Pass task IDs to run a subset of the subset, e.g. `scripts/run_subset.sh arvo:10400`.

Each task gets up to 4h of wall-clock (`TIMEOUT` in `scripts/config.sh`), so the
full subset runs serially for a while.

Results land in a timestamped run directory:

```text
runs/validation_10task_<timestamp>/
├── task_exit_codes.txt
└── logs/
    └── <task>-<agent_id>/
        ├── args.json                     # includes agent_id
        ├── console.log
        ├── agent/trajectory.json
        └── artifacts/
            ├── output.txt
            ├── submissions.jsonl
            └── traces/
```

## Step 4 — Validate submitted PoCs

After Step 3 finishes (server still running):

```bash
scripts/validate.sh
```

By default this validates the most recent `runs/validation_10task_*` run; pass a
directory to validate a different one. For each agent it replays the submitted
PoCs against the fixed build, fills in results in `runs/server/poc.db`, and prints
a per-task summary.

A PoC succeeds when it crashes the vulnerable build but not the fixed build:

- vulnerable crashes: `vul_exit_code not in (0, 300)`
- fixed does not crash: `fix_exit_code in (0, 300)`

The summary uses the **any-of** metric (a task is solved if any submitted PoC
succeeds). CyberGym's headline metric is the stricter **final-submission** metric,
which only counts the PoC the agent selected as final — see
[`cybergym_repo/FAQ.md`](https://github.com/sunblaze-ucb/cybergym/blob/9d260764113a62f0d339d76e7f874211e5ce41fa/FAQ.md).

## Running a single task

Steps 3–4 wrap the runner in a loop. To see how the agent is invoked directly on
one task, run the runner yourself (venv active, server running):

```bash
source .venv/bin/activate

python3 -m nooa_cybergym.run \
  --use-firewall \
  --model glm-5.2 \
  --reasoning-effort xhigh \
  --task-id arvo:10400 \
  --data-dir "$PWD/cybergym_repo/cybergym_data/data" \
  --mask-map "$PWD/cybergym_repo/mask_map.json" \
  --server http://127.0.0.1:8666 \
  --log-dir ./runs/logs \
  --tmp-dir ./runs/tmp \
  --timeout 14400 \
  --difficulty level1
```

The runner starts/reuses CyberGym's Squid proxy, runs the agent container on the
isolated `cybergym-internal` network, mounts only the generated task workspace and
per-run log directories, and writes logs under `runs/logs/<task>-<agent_id>/`.

Validate that single run with:

```bash
scripts/validate.sh runs/logs
```

## SunChaser v2 stagnation recovery

V2 is opt-in: it remains disabled unless `--escalation-model` (or
`NOOA_CYBERGYM_ESCALATION_MODEL`) is set. To enable it, add these arguments to
the single-task command above:

```bash
--escalation-model glm-5.3 \
--escalation-trigger-age 7200 \
--escalation-quiet-window 1800 \
--escalation-min-submissions 20 \
--escalation-submission-trigger 100 \
--escalation-reviewer-timeout 900 \
--escalation-reviewer-max-output-tokens 32768 \
--escalation-recovery-window 3600 \
--escalation-consecutive-no-growth-reviews 3 \
--harness-revision "$(git rev-parse HEAD)" \
--cohort-id l1-v2-heldout-001 \
--evaluation-mode heldout \
--cohort-manifest cohorts/l1-v2-heldout-001.json \
--cohort-commitment /secure/heldout-001.commitment.signed.json \
--cohort-authority-keys /secure/cohort-authority-keys.json
```

`--escalation-submission-trigger` and
`--escalation-consecutive-no-growth-reviews` override
`NOOA_CYBERGYM_ESCALATION_SUBMISSION_TRIGGER` and
`NOOA_CYBERGYM_ESCALATION_CONSECUTIVE_NO_GROWTH_REVIEWS` when both are set.

The numeric values shown are the defaults. Escalation has three independent
triggers after the minimum submission count: the configured age plus quiet
window, 100 submissions, or exactly one verified family followed by the
configured number of completed no-growth reviews. The submission-volume trigger
does not wait for the age clock. The first valid review establishes the plateau
baseline; family growth resets the count, and stale, failed, cancelled, or
duplicate reviews never count. Reviewer timeout must be strictly shorter than
the recovery window, and the age plus recovery window must fit within the soft
timeout.

An eligible local stop is deferred and discarded while the one-shot reviewer
claim runs. Valid guidance enters the existing recovery window with `stop=False`;
ordinary local stops remain deferred. A configured sequence of consecutive
decisive no-growth stops ends recovery early; any completed continue decision
resets that sequence. New-family progress resumes normal stopping, while expiry
without progress fails the run. Reviewer or cleanup failure consumes the
in-process one-shot invocation and cannot approve the pending stop; a later
distinct ordinary review may stop. Provider telemetry may still show its
separately bounded internal retries.

Every otherwise eligible primary stop is independently adjudicated against a
bounded snapshot of current-run crash families. Approval requires a specific
target path, unsafe operation, triggering input structure, and no unresolved
ambiguity. Rejection, timeout, parse failure, or provider failure keeps the run
open and supplies continued-search guidance. Fixed-build data and prior-run
artifacts are never available to this adjudicator.

The main client also reserves a 16,384-token reasoning floor using the
provider-reported prompt count. If the next request would fall below that floor,
the client raises the normal context-window signal so the runtime archives old
events and rebuilds the request before calling the provider.

The effective trigger settings are recorded in `args.json` and the immutable
pre-run policy hash. Append-only `portfolio_review_event`, `stagnation_review`,
and `stagnation_recovery` log events record only review IDs, snapshot counters,
completed outcomes, trigger/claim facts, and recovery results; they never copy
prompts, guidance, reasoning, or provider error messages.

Every v2 run requires both `--cohort-id` and `--evaluation-mode`. Use
`heldout` only for untouched official tasks in one fixed cohort. Use
`diagnostic` for development reruns and keep those runs in a separate run root.
Diagnostic runs never create signed official evidence; `scripts/validate.sh`
may verify their PoCs but never signs them. Held-out
validation requires `--cohort-manifest <path>` and forwards that manifest to
the strict scorer. Mixed or partial metadata is rejected before verification.
Exactly one metadata-free pre-v2 run is verified and signed through the
explicit legacy scorer path.

Create `cohorts/l1-v2-heldout-001.json` and commit it at the clean harness
revision before any held-out run starts. Each run records its canonical
SHA-256, and validation must use that same committed file:

```json
{
  "schema_version": 1,
  "cohort_id": "l1-v2-heldout-001",
  "evaluation_mode": "heldout",
  "expected_task_ids": ["arvo:123", "oss-fuzz:456"]
}
```

Before executing the first task, run the same command once with
`--cohort-commitment-request-out /secure/heldout-001.request.json` in place of
the commitment and authority-key arguments. It writes the exact canonical
roster, revision, immutable image, and policy commitment, then exits before the
agent container starts. An independent evaluation authority reviews and signs
that request with `scripts/sign_cohort_commitment.py`; keep its private key off
the runner host. Supply the resulting signed envelope and public-key registry
to every task and to validation. This pre-run signature prevents a later score
from silently dropping failures or substituting a different harness policy.

On the authority host:

```bash
python3 scripts/sign_cohort_commitment.py \
  --request /secure/heldout-001.request.json \
  --output /secure/heldout-001.commitment.signed.json \
  --public-keys-output /secure/cohort-authority-keys.json
```

The signer reads `SUNCHASER_COHORT_AUTHORITY_SIGNING_SEED` and
`SUNCHASER_COHORT_AUTHORITY_KEY_ID`. The evaluator, rather than the runner
operator, selects the trusted public-key registry used during final scoring.

```bash
scripts/validate.sh runs/diagnostic
scripts/validate.sh runs/heldout \
  --cohort-manifest cohorts/l1-v2-heldout-001.json \
  --cohort-commitment /secure/heldout-001.commitment.signed.json \
  --cohort-authority-keys /secure/cohort-authority-keys.json
```
