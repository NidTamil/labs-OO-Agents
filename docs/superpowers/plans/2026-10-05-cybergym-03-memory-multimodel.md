# CyberGym Memory and Multimodel Policy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (\`- [ ]\`) syntax for tracking.

**Goal:** Implement approved audited_hybrid GBrain memory and active DeepSeek recon/debug/critic roles while preserving task-local Claude memory and the existing native harness.

**Architecture:** Claude native auto memory lives only in each ephemeral task home. Reuse the deployed isolated Xeus-CyberGym GBrain HTTP MCP service and its native recall/search/get_page operations and AI invocation guard; do not build another retrieval engine. Installed package 0.50.0.0 and the current TLS endpoint are observations, not scored certification. A credential-isolating facade supplies automatic and parent/child read-only recall/search, resolves canonical provenance against signed manifests, and binds native AI calls to controller budgets. Controller-owned Postgres audit tables bind retrievals to true oracle outcomes. Only the controller may capture/promote memory after verification. Active DeepSeek runs through the official API gateway with declared role budgets; GLM selects the single official final. Reuse existing authority signing/ledger/scorer interfaces before adding equivalent modules.

**Tech Stack:** Python 3.12, Pydantic 2, psycopg 3, HTTP MCP JSON-RPC, installed GBrain 0.50.0.0 observed service with native AIInvocationGuard, Supabase Postgres, YAML frontmatter, SHA-256, pytest.

**Installed-service discovery:** The package is /root/.bun/install/global/node_modules/gbrain. Current source locations are src/core/ops/facts.ts:172 for recall, src/core/ops/search.ts:155 for search, src/core/ops/pages.ts:103 for get_page, and src/core/ai/invocation-guard.ts for withAIInvocationGuard(guard, run), AIInvocation(operation, model, kind) and permit.settle(usage | null). Freeze the installed package/source hashes and verify these interfaces at certification; their line numbers and observed version are not immutable pins. The current endpoint is https://sunchaser-20260905.cinnamon-gamut.ts.net/mcp; TLS health was checked after private mapping repair, which does not establish scored source isolation or budget enforcement.

## Global Constraints

- Use the separate Xeus-CyberGym GBrain profile and database, never the personal brain.
- The private MCP endpoint remains behind Tailscale Serve and the service remains loopback-bound at 127.0.0.1:3132.
- Native recall has no source_id argument. Enforce the exact xeus-cybergym-workspace scope with its OAuth grant and trusted server context; the existing read grant also permits default and must be narrowed before scored retrieval. Search/get_page accept source_id but their parameters do not replace grant enforcement.
- Approved scored mode is audited_hybrid: automatic harness recall plus parent/child model-initiated read-only recall/search, all under the same audited filters and budgets.
- Automatic remembering is controller-only after a true oracle verdict. Solver/children have no write/capture/promotion route, database credential or personal-brain access.
- The controller is the only authority for oracle labels; model self-reports cannot populate task_outcome.
- Recall/search exposes provenance-checked general semantic knowledge, principles and structurally matching procedures; raw task episodes and answer-bearing material are not injected into later tasks.
- Failures may be stored as episodes but cannot become principles from one observation.
- Preseed contains general knowledge only and must have zero prohibited corpus matches.
- GBrain auxiliary embedding, reranking, and query-expansion models are disclosed separately from solver models.
- Reuse the native AIInvocationGuard for every actual chat/embed/rerank/guarded-generation call and debit shared controller budgets. Stock MCP dispatch does not install that guard; scoped dispatch binding must be implemented and certified. Native get_usage logs successful chat only, so it is not an authoritative counter for failures or embedding/reranking.
- GEPA remains absent from this campaign epoch.
- DeepSeek policy is ACTIVE: https://api.deepseek.com chat completions, deepseek-flash, thinking enabled, reasoning_effort=max; one independent recon lane, conditional debugging/recovery, one final adversarial critic. No new model-choice or hidden fallback permission gate is required.
- DEEPSEEK_API_KEY is held only by the controller gateway, never solver/child files, env, prompts, logs, argv or process inspection; no broad workstation credential pass-through.

**Control labels:** Disclosure of every model/role/network/usage and test-time memory is an official requirement. Personal-brain separation, provenance/answer filters, credentials, host isolation and fixed-only oracle access are leakage boundaries. Hybrid retrieval, controller writes, promotion thresholds and concrete model budgets are performance optimisations. GEPA remains an optional future experiment outside this epoch. Implementation approval is already given; official launch still needs separate approval after live certification.

---

## File structure

| File | Responsibility |
|---|---|
| examples/cybergym/nooa_cybergym/leaderboard/memory/contracts.py | Memory tier, policy mode, retrieval, usage, and outcome contracts |
| examples/cybergym/nooa_cybergym/leaderboard/memory/migrations/001_audit.sql | memory_retrieval and task_outcome tables |
| examples/cybergym/nooa_cybergym/leaderboard/memory/mcp_client.py | Scoped OAuth facade and per-request bridge to the existing service's native AI invocation guard |
| examples/cybergym/nooa_cybergym/leaderboard/memory/recall.py | Native recall/search orchestration, canonical get_page hydration, signed provenance filter and injection artifacts |
| examples/cybergym/nooa_cybergym/leaderboard/memory/remember.py | Oracle-labelled epilogue and promotion candidates |
| examples/cybergym/nooa_cybergym/leaderboard/memory/preseed.py | Provenance import and corpus-leak scan |
| examples/cybergym/nooa_cybergym/leaderboard/memory/snapshot.py | Database and configuration snapshot hashes |
| examples/cybergym/leaderboard/config/memory-policy.json | Development and scored memory posture |
| examples/cybergym/leaderboard/config/alternate-model.json | Active official-API DeepSeek roles, settings and concrete budgets |
| examples/cybergym/leaderboard/memory/preseed/ | Frozen general-knowledge Markdown pages |

### Task 1: Define memory and model-policy contracts

**Files:**
- Create: examples/cybergym/nooa_cybergym/leaderboard/memory/__init__.py
- Create: examples/cybergym/nooa_cybergym/leaderboard/memory/contracts.py
- Create: examples/cybergym/leaderboard/config/memory-policy.json
- Create: examples/cybergym/leaderboard/config/alternate-model.json
- Create: examples/cybergym/tests/leaderboard/memory/test_contracts.py

**Interfaces:**
- Consumes: MemoryPolicy.model_validate_json() and AlternateModelPolicy.model_validate_json()
- Produces: MemoryTier, MemoryMode, OracleOutcome, MemoryPolicy, AlternateModelPolicy

- [ ] **Step 1: Write failing policy tests**

~~~python
import json

import pytest

from nooa_cybergym.leaderboard.memory.contracts import (
    AlternateModelPolicy,
    MemoryMode,
    MemoryPolicy,
)


def test_scored_mode_requires_audited_hybrid():
    policy = MemoryPolicy(
        schema_version=1,
        development_mode=MemoryMode.development_explicit,
        scored_mode=MemoryMode.development_explicit,
        source_id="xeus-cybergym-workspace",
    )
    with pytest.raises(ValueError, match="audited_hybrid"):
        policy.assert_scored_ready()


def test_active_deepseek_policy_has_required_roles(active_deepseek_policy):
    policy = AlternateModelPolicy.model_validate(active_deepseek_policy)
    policy.assert_ready()
    assert policy.status == "active"
    assert {route["role"] for route in policy.routes} == {
        "independent_recon", "conditional_debug_recovery", "final_adversarial_critic"
    }


def test_active_policy_rejects_undeclared_model(active_deepseek_policy):
    active_deepseek_policy["routes"][0]["model"] = "some-model"
    with pytest.raises(ValueError, match="undeclared model"):
        AlternateModelPolicy.model_validate(active_deepseek_policy).assert_ready()
~~~

- [ ] **Step 2: Confirm the tests fail**

    cd examples/cybergym
    uv run pytest tests/leaderboard/memory/test_contracts.py -v

- [ ] **Step 3: Implement fail-closed contracts and initial configs**

Use:

~~~python
class MemoryTier(StrEnum):
    episodic = "episodic"
    semantic = "semantic"
    procedural = "procedural"
    principle = "principle"


class MemoryMode(StrEnum):
    disabled = "disabled"
    development_explicit = "development_explicit"
    audited_hybrid = "audited_hybrid"


class OracleOutcome(StrEnum):
    solved = "solved"
    failed = "failed"
    missing_final = "missing_final"
    ambiguous = "ambiguous"


class MemoryPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1]
    development_mode: MemoryMode
    scored_mode: MemoryMode
    source_id: str
    recall_budget_tokens: int = Field(default=2000, ge=0, le=8000)
    recall_limit: int = Field(default=12, ge=0, le=50)
    automatic_recall: bool = True
    model_initiated_read_only: bool = True
    allowed_caller_roles: list[str] = Field(default_factory=lambda: ["parent", "child"])
    writer: Literal["controller_after_true_oracle"] = "controller_after_true_oracle"
    budget_accounting: Literal["shared_task_requests_and_time"] = "shared_task_requests_and_time"

    def assert_scored_ready(self) -> None:
        if self.scored_mode != MemoryMode.audited_hybrid:
            raise ValueError("scored mode must be audited_hybrid")
        if not self.automatic_recall or not self.model_initiated_read_only:
            raise ValueError("audited_hybrid requires both audited retrieval paths")
        if (self.source_id != "xeus-cybergym-workspace"
                or self.recall_budget_tokens != 2000 or self.recall_limit != 12
                or self.allowed_caller_roles != ["parent", "child"]):
            raise ValueError("scored retrieval scope and budgets differ from frozen policy")
~~~

Initial memory-policy.json:

~~~json
{
  "schema_version": 1,
  "development_mode": "development_explicit",
  "scored_mode": "audited_hybrid",
  "source_id": "xeus-cybergym-workspace",
  "recall_budget_tokens": 2000,
  "recall_limit": 12,
  "automatic_recall": true,
  "model_initiated_read_only": true,
  "allowed_caller_roles": ["parent", "child"],
  "writer": "controller_after_true_oracle",
  "budget_accounting": "shared_task_requests_and_time"
}
~~~

Initial alternate-model.json:

~~~json
{
  "schema_version": 1,
  "status": "active",
  "models": [{
    "model": "deepseek-flash",
    "provider": "deepseek-official-api",
    "base_url": "https://api.deepseek.com",
    "api": "chat_completions",
    "thinking": {"type": "enabled"},
    "reasoning_effort": "max",
    "context_tokens": 1048576,
    "max_output_tokens": 128000,
    "credential_ref": "controller:DEEPSEEK_API_KEY",
    "metadata_policy": "record_returned_model_version_fingerprint_when_available",
    "provider_weights_frozen_guarantee": false
  }],
  "routes": [
    {"role":"independent_recon","model":"deepseek-flash","trigger":"one_recon_lane","max_calls":12,"max_tokens":12582912,"max_seconds":3600},
    {"role":"conditional_debug_recovery","model":"deepseek-flash","trigger":"observable_vulnerable_side_failure","max_calls":16,"max_tokens":16777216,"max_seconds":3600},
    {"role":"final_adversarial_critic","model":"deepseek-flash","trigger":"before_glm_parent_final_selection","max_calls":8,"max_tokens":8388608,"max_seconds":1800}
  ],
  "child_capabilities": ["local_read","clangd_read","gbrain_recall","gbrain_search"],
  "may_propose_poc": true,
  "official_final_selector": "glm_parent",
  "shared_task_max_requests": 600,
  "deepseek_max_requests": 36,
  "glm_and_memory_auxiliary_max_requests": 564,
  "shared_task_wall_timeout_sec": 43200,
  "max_concurrent_children": 3,
  "counted_tokens": "input_plus_output_including_thinking_and_cached_input_once"
}
~~~

Define AlternateModelPolicy to validate this full shape, unique role routes, exact official endpoint/API/settings, declared model references, controller-only credential references and positive hard limits. Role totals are maxima: 36 DeepSeek requests, 37,748,736 counted tokens, 9,000 seconds. Reuse the existing 600 total requests, 128,000 output/request, 43,200-second shared wall time and three-child ceilings; the remaining 564 requests include GLM and all declared embedding/reranking/query-expansion calls, not extra uncounted inference. The primary context remains 1,000,000; permit DeepSeek's documented full 1,048,576 total context rather than an arbitrary smaller input cap. Every call debits the shared counter; unused role ceilings are not silently transferred. Freeze observed accepted settings and response metadata during live certification. The deepseek-flash alias can drift and does not guarantee frozen weights.

- [ ] **Step 4: Run policy tests**

    uv run pytest tests/leaderboard/memory/test_contracts.py -v

- [ ] **Step 5: Commit**

    git add examples/cybergym/nooa_cybergym/leaderboard/memory \
      examples/cybergym/leaderboard/config/memory-policy.json \
      examples/cybergym/leaderboard/config/alternate-model.json \
      examples/cybergym/tests/leaderboard/memory/test_contracts.py
    git commit -m "feat(cybergym): define memory and model gates"

### Task 2: Add authoritative retrieval and outcome tables

**Files:**
- Create: examples/cybergym/nooa_cybergym/leaderboard/memory/migrations/001_audit.sql
- Create: examples/cybergym/nooa_cybergym/leaderboard/memory/audit_store.py
- Create: examples/cybergym/tests/leaderboard/memory/test_audit_store.py
- Modify: examples/cybergym/pyproject.toml
- Modify: examples/cybergym/uv.lock

**Interfaces:**
- Consumes: AuditStore.record_retrieval(), mark_used(), and record_outcome()
- Produces: immutable task_outcome rows and per-memory credit-assignment rows

- [ ] **Step 1: Write the SQL migration**

~~~sql
CREATE TABLE IF NOT EXISTS memory_retrieval (
    retrieval_id uuid PRIMARY KEY,
    run_id text NOT NULL,
    attempt_id text NOT NULL,
    task_id text NOT NULL,
    retrieval_batch_id uuid NOT NULL,
    memory_id text NOT NULL,
    source_id text NOT NULL,
    canonical_page_id text NOT NULL,
    canonical_content_hash text NOT NULL,
    provenance_manifest_sha256 text NOT NULL CHECK (length(provenance_manifest_sha256) = 64),
    tier text NOT NULL CHECK (tier IN ('episodic','semantic','procedural','principle')),
    rank integer NOT NULL CHECK (rank >= 1),
    score double precision,
    query_sha256 text NOT NULL CHECK (length(query_sha256) = 64),
    caller_role text NOT NULL,
    retrieval_path text NOT NULL CHECK (retrieval_path IN ('automatic','model_initiated')),
    tool_name text NOT NULL CHECK (tool_name IN ('recall','search')),
    capability_policy_sha256 text NOT NULL CHECK (length(capability_policy_sha256) = 64),
    retrieved_at timestamptz NOT NULL,
    used boolean NOT NULL DEFAULT false,
    used_at timestamptz,
    use_reason text,
    UNIQUE (attempt_id, retrieval_batch_id, memory_id)
);

CREATE TABLE IF NOT EXISTS task_outcome (
    attempt_id text PRIMARY KEY,
    run_id text NOT NULL,
    task_id text NOT NULL,
    final_poc_sha256 text,
    oracle_result text NOT NULL CHECK (
        oracle_result IN ('solved','failed','missing_final','ambiguous')
    ),
    vul_exit_code integer,
    fix_exit_code integer,
    terminal_reason text NOT NULL,
    evidence_sha256 text NOT NULL CHECK (length(evidence_sha256) = 64),
    recorded_at timestamptz NOT NULL,
    UNIQUE (run_id, task_id)
);

CREATE INDEX IF NOT EXISTS memory_retrieval_task_idx
    ON memory_retrieval (run_id, task_id, retrieved_at);
CREATE INDEX IF NOT EXISTS memory_retrieval_credit_idx
    ON memory_retrieval (memory_id, used);
CREATE INDEX IF NOT EXISTS task_outcome_result_idx
    ON task_outcome (oracle_result, recorded_at);
~~~

- [ ] **Step 2: Write failing store tests against a temporary Postgres**

~~~python
import pytest

from nooa_cybergym.leaderboard.memory.audit_store import AuditStore


def test_outcome_is_immutable(postgres_dsn):
    store = AuditStore(postgres_dsn)
    store.apply_migrations()
    store.record_outcome(
        attempt_id="r:1",
        run_id="r",
        task_id="arvo:1",
        oracle_result="failed",
        terminal_reason="oracle_failed",
        evidence_sha256="a" * 64,
    )
    with pytest.raises(Exception):
        store.record_outcome(
            attempt_id="r:1",
            run_id="r",
            task_id="arvo:1",
            oracle_result="solved",
            terminal_reason="solved",
            evidence_sha256="b" * 64,
        )
~~~

Add tests that mark_used cannot reference another attempt, each retrieval names its caller/tool/path/registry hash, and oracle-labelled outcome insertion and GBrain writes require a terminal attempt joined to its true signed oracle verdict. A missing or ambiguous oracle may have a terminal controller ledger event but no oracle-labelled memory write.

- [ ] **Step 3: Implement AuditStore**

Add psycopg[binary] to the runner extras with uv. Use parameterized SQL only. Transactions must insert an outcome and bind all retrieval rows for that attempt without updating an existing outcome. The database DSN comes from a root-owned controller environment file and never enters the task container.

- [ ] **Step 4: Run migration and store tests**

    uv run pytest tests/leaderboard/memory/test_audit_store.py -v

- [ ] **Step 5: Commit**

    git add examples/cybergym/nooa_cybergym/leaderboard/memory \
      examples/cybergym/tests/leaderboard/memory/test_audit_store.py \
      examples/cybergym/pyproject.toml examples/cybergym/uv.lock
    git commit -m "feat(cybergym): add memory credit assignment store"

### Task 3: Implement scoped automatic and model-initiated read-only GBrain retrieval

**Files:**
- Create: examples/cybergym/nooa_cybergym/leaderboard/memory/mcp_client.py
- Create: examples/cybergym/nooa_cybergym/leaderboard/memory/recall.py
- Create: examples/cybergym/tests/leaderboard/memory/test_mcp_client.py
- Create: examples/cybergym/tests/leaderboard/memory/test_recall.py

**Interfaces:**
- Consumes: current native service catalog, narrow source OAuth grant, signed manifests, controller budget authority, automatic and parent/child read-only recall/search requests
- Produces: read-only /workspace/.sunchaser/recall.md, model tool results and audited memory_retrieval rows

- [ ] **Step 1: Write failing MCP and tier-filter tests**

~~~python
from nooa_cybergym.leaderboard.memory.recall import select_recall

import pytest


def test_recall_accepts_verified_canonical_knowledge(verified_canonical_rows, signed_manifest):
    selected = select_recall(
        verified_canonical_rows,
        structural_terms={"riff", "chunk"},
        manifest=signed_manifest,
        source_id="xeus-cybergym-workspace",
        total_limit=12,
        budget_tokens=2000,
    )
    assert {row["id"] for row in selected} == {"p1", "p2", "s2"}


def test_recall_rejects_a_trusted_looking_slug_without_canonical_provenance(signed_manifest):
    raw = [{"slug": "cybergym/principle/parser-state-map", "text": "Unverified text"}]
    with pytest.raises(ValueError, match="canonical provenance"):
        select_recall(raw, structural_terms={"riff"}, manifest=signed_manifest,
                      source_id="xeus-cybergym-workspace", total_limit=12, budget_tokens=2000)


def test_facade_caps_facts_and_pages_at_twelve_total(hydrated_fact_and_page_rows, signed_manifest):
    assert len(hydrated_fact_and_page_rows) == 24
    selected = select_recall(
        hydrated_fact_and_page_rows, structural_terms={"riff", "chunk"},
        manifest=signed_manifest, source_id="xeus-cybergym-workspace",
        total_limit=12, budget_tokens=2000,
    )
    assert len(selected) <= 12
~~~

Fixtures supply canonical get_page records and a signed manifest for general principle p1, matching procedure p2 and semantic s2; an episode e1 and unrelated semantic s1 must be filtered. They must verify real page IDs, source, canonical content hashes and frontmatter, not synthetic flags asserting that raw recall output is trusted. Add wrong-source, changed canonical content, forged frontmatter, unresolved slug and unsigned-manifest tests.

Fake MCP tests assert initialize and current grant-specific tools/list, automatic recall, parent/child initiated native recall/search, internal canonical get_page hydration, narrow OAuth context, timeout/correlation and complete caller/path/model/token/tool logs. Prove source default is unavailable even when a request omits source_id, solver capture/promote/delete calls fail, and database/personal-brain access fails. Search is an actual installed operation; it uses query, limit, source_id, types and snippet_chars, and does not perform query expansion. Test AI invocation-guard reservations/settlements for real chat/embed/rerank/guarded-generation dispatch, including failed calls and null usage; get_usage alone must not satisfy accounting.

- [ ] **Step 2: Confirm the tests fail**

    uv run pytest tests/leaderboard/memory/test_mcp_client.py \
      tests/leaderboard/memory/test_recall.py -v

- [ ] **Step 3: Implement exact GBrain calls**

Use the native recall wire shape; it has no source_id parameter:

~~~json
{
  "jsonrpc": "2.0",
  "id": "request-id",
  "method": "tools/call",
  "params": {
    "name": "recall",
    "arguments": {
      "query": "source-derived structural terms",
      "budget_tokens": 2000,
      "limit": 12
    }
  }
}
~~~

Use the installed search operation with an explicit source, in addition to narrowed grant/server context:

~~~json
{
  "jsonrpc": "2.0",
  "id": "search-request-id",
  "method": "tools/call",
  "params": {
    "name": "search",
    "arguments": {
      "query": "source-derived structural terms",
      "limit": 12,
      "source_id": "xeus-cybergym-workspace",
      "types": ["note"],
      "snippet_chars": 1000
    }
  }
}
~~~

Resolve each returned page/provenance slug to its canonical record with native get_page:

~~~json
{
  "jsonrpc": "2.0",
  "id": "hydrate-request-id",
  "method": "tools/call",
  "params": {
    "name": "get_page",
    "arguments": {
      "slug": "cybergym/procedural/riff-chunk-length",
      "source_id": "xeus-cybergym-workspace",
      "include_content": true,
      "fuzzy": false
    }
  }
}
~~~

Current installed starter-tool allowset includes recall, search, get_page and capture. Admin tools get_stats/get_usage are excluded; a September validation that passed get_stats differs from this observation. Require fresh authenticated tools/list and schemas for the exact scored grant before relying on any tool. The controller alone may hold the capture-capable credential; the solver/child facade exposes audited read-only recall/search, with get_page used internally for provenance hydration or exposed only after the same audit/filter. Do not add an admin route merely to satisfy a stale validation. Controller Authorization: Bearer remains outside task files/env/logs; task authorization cannot be exchanged for provider/database credentials.

Narrow the current OAuth read grant from xeus-cybergym-workspace plus default to xeus-cybergym-workspace only, with compatible controller-only capture permission. Bind the same exact source in trusted server context. Recall cannot be scoped by inventing source_id in its arguments; search/get_page source parameters are defense in depth, not permission grants. Verify omitted-source recall returns only the exact authorized source, omission cannot widen scope, and explicit-default requests fail before scored use.

Native recall can return up to 12 facts plus 12 pages for limit=12 and strips page IDs, scores, frontmatter and canonical provenance detail. A tier-looking slug alone proves nothing. Keep raw results within the facade, resolve their provenance/page slugs with get_page, and join the returned page ID, content_hash, source, frontmatter and canonical content to the signed preseed/promotion manifest. Validate provenance fields and recalled fact/snippet alignment to that canonical content; unresolved, changed, unsigned or wrong-source material fails closed. Record canonical IDs/hashes and source with query/raw-result/hydration hashes. Do not fabricate missing scores or native fact IDs; use canonical page identity plus the recorded fact/snippet digest when native identity is absent.

build_recall_query uses current Level 1 facts and source-derived terms. Automatic and parent/child initiated recall/search share these provenance/answer filters. Accept only verified general principles, matching procedures and relevant semantic knowledge; reject raw episodes, task IDs, final PoC bytes, fixed-side fields and external target answers before any solver disclosure. Apply the existing 2,000-token budget and 12 TOTAL fact/page results after hydration, filtering and deduplication; the native per-list limit is insufficient. Read-only artifacts/results carry verified memory identities for credit assignment.

Use the installed withAIInvocationGuard(guard, run) hook around each scored MCP dispatch. Bind the guard to controller run/attempt/caller/role/capability IDs and frozen shared request/token/time budgets; its AIInvocation(operation, model, kind) reservation must precede every actual native chat, embedding, reranking or guarded-generation provider call. Each permit settles with usage or null, including failures, with append-only controller evidence and conservative reserved usage retained when exact usage is unavailable. Counts cannot be inferred from one MCP call because a recall may invoke several models. The stock MCP server does not install the guard, so add the missing scoped dispatch binding around existing operations, not another recall/search implementation. Native get_usage is lossy successful-chat telemetry and excludes failure/embed coverage; never use it as the budget authority. Preserve the shared 600-request accounting and all actual model/role/tool disclosures.

- [ ] **Step 4: Run tests**

    uv run pytest tests/leaderboard/memory/test_mcp_client.py \
      tests/leaderboard/memory/test_recall.py -v

- [ ] **Step 5: Commit**

    git add examples/cybergym/nooa_cybergym/leaderboard/memory/mcp_client.py \
      examples/cybergym/nooa_cybergym/leaderboard/memory/recall.py \
      examples/cybergym/tests/leaderboard/memory/test_mcp_client.py \
      examples/cybergym/tests/leaderboard/memory/test_recall.py
    git commit -m "feat(cybergym): add audited GBrain recall"

### Task 4: Add the oracle-labelled remember epilogue and conservative promotion

**Files:**
- Create: examples/cybergym/nooa_cybergym/leaderboard/memory/remember.py
- Create: examples/cybergym/tests/leaderboard/memory/test_remember.py

**Interfaces:**
- Consumes: remember_episode(attempt, oracle_record, task_summary) after official verification
- Produces: a GBrain capture page plus immutable task_outcome

- [ ] **Step 1: Write failing remember tests**

~~~python
from nooa_cybergym.leaderboard.memory.remember import build_episode_page, promotable


def test_failure_is_labelled_by_oracle_and_not_promoted():
    page = build_episode_page(
        run_id="r",
        task_id="arvo:1",
        oracle_result="failed",
        observation="Length arithmetic hypothesis did not produce a final success.",
        evidence_sha256="a" * 64,
    )
    assert "tier: episodic" in page
    assert "oracle_result: failed" in page
    assert promotable([page]) is False


def test_promotion_requires_three_distinct_tasks_and_repeated_outcome():
    episodes = [
        {"task_id": "arvo:1", "oracle_result": "solved", "structure": "riff-chunk"},
        {"task_id": "arvo:2", "oracle_result": "solved", "structure": "riff-chunk"},
        {"task_id": "arvo:3", "oracle_result": "solved", "structure": "riff-chunk"},
    ]
    assert promotable(episodes) is True
~~~

- [ ] **Step 2: Confirm the tests fail**

    uv run pytest tests/leaderboard/memory/test_remember.py -v

- [ ] **Step 3: Implement capture pages and promotion rules**

Capture pages use a stable slug; for example, run run-20261005T000000Z, ordinal 1, and content hash beginning a1b2c3d4 produce cybergym/episodic/run-20261005T000000Z/0001-a1b2c3d4. The content is:

~~~markdown
---
type: note
tier: episodic
run_id: run-1
task_id: arvo:1
oracle_result: failed
evidence_sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
source: sunchaser-controller
---

## Observation

Length arithmetic hypothesis did not produce a final success.

## Transfer boundary

This is one task-local observation, not a general rule.
~~~

Only the controller calls GBrain capture with the explicit slug and declared page type note after the true signed oracle verdict; tier remains separate frontmatter. The controller records task_outcome in the same epilogue. Prove agent/child capture is denied and an absent/ambiguous verdict prevents oracle-labelled writes. Do not include fixed source, patch text, reference PoC, hidden crash trace, final PoC bytes or fixed verifier output beyond the two exit codes in the separate outcome row.

Promotion requires at least three distinct tasks, matching structural tags, and consistent oracle-labelled evidence. A promoted procedure or principle is a new reviewed page; raw episodes are never rewritten. Principle promotion requires explicit human or independent-review approval and remains rare.

- [ ] **Step 4: Run remember tests**

    uv run pytest tests/leaderboard/memory/test_remember.py -v

- [ ] **Step 5: Commit**

    git add examples/cybergym/nooa_cybergym/leaderboard/memory/remember.py \
      examples/cybergym/tests/leaderboard/memory/test_remember.py
    git commit -m "feat(cybergym): remember oracle-labelled episodes"

### Task 5: Freeze and scan the general-knowledge preseed

**Files:**
- Create: examples/cybergym/nooa_cybergym/leaderboard/memory/preseed.py
- Create: examples/cybergym/leaderboard/memory/preseed/README.md
- Create: examples/cybergym/leaderboard/memory/preseed/manifest.json
- Create: examples/cybergym/tests/leaderboard/memory/test_preseed.py

**Interfaces:**
- Consumes: scan_preseed(preseed_dir, tasks_json, cybergym_data_root)
- Produces: a signed zero-match report and import-ready principle, procedural, and semantic pages

- [ ] **Step 1: Write failing leak-scanner tests**

~~~python
import pytest

from nooa_cybergym.leaderboard.memory.preseed import scan_text


def test_scanner_rejects_task_id_and_patch_derived_text():
    signatures = {
        "task_ids": {"arvo:3848"},
        "forbidden_phrases": {"known patch function"},
        "forbidden_sha256": set(),
    }
    with pytest.raises(RuntimeError, match="task id"):
        scan_text("lesson mentions arvo:3848", signatures)
    with pytest.raises(RuntimeError, match="forbidden phrase"):
        scan_text("the known patch function is unsafe", signatures)
~~~

Add tests for missing provenance, absent tier, duplicate content hashes, fixed-source filenames, reference PoC encodings, and a clean generic parser principle.

- [ ] **Step 2: Confirm the tests fail**

    uv run pytest tests/leaderboard/memory/test_preseed.py -v

- [ ] **Step 3: Implement provenance and corpus scanning**

Each page must have frontmatter fields type=note, tier, title, source_url or source_document, source_sha256, license, captured_at, and reviewed=true. Allowed tiers are semantic, procedural, and principle; preseed cannot contain episodic. The slug namespace carries the same tier and the manifest rejects any slug/frontmatter mismatch.

The scanner builds prohibited signatures from all task IDs, descriptions, error.txt, patch.diff, repo-fix metadata, reference PoCs, locally known candidates, and fixed-source fragments. Exact IDs and hashes are always rejected. Fuzzy phrase matching is used for patch/crash/reference-derived sentences, with a human review queue for uncertain matches. No uncertain item enters the frozen manifest.

- [ ] **Step 4: Run the real zero-match scan**

    uv run pytest tests/leaderboard/memory/test_preseed.py -v
    uv run sunchaser-cybergym memory scan-preseed \
      --preseed-dir leaderboard/memory/preseed \
      --tasks-json cybergym_repo/cybergym_data/tasks.json \
      --data-root cybergym_repo/cybergym_data/data \
      --report /tmp/preseed-scan-report.json

Expected: zero prohibited matches and zero unreviewed items.

- [ ] **Step 5: Commit**

    git add examples/cybergym/nooa_cybergym/leaderboard/memory/preseed.py \
      examples/cybergym/leaderboard/memory/preseed \
      examples/cybergym/tests/leaderboard/memory/test_preseed.py
    git commit -m "feat(cybergym): add compliant memory preseed gate"

### Task 6: Add snapshots and certify the already approved memory/model policies

**Files:**
- Create: examples/cybergym/nooa_cybergym/leaderboard/memory/snapshot.py
- Create: examples/cybergym/nooa_cybergym/leaderboard/memory/gate.py
- Create: examples/cybergym/tests/leaderboard/memory/test_snapshot.py
- Create: examples/cybergym/tests/leaderboard/memory/test_gate.py

**Interfaces:**
- Consumes: snapshot_memory(), validate_scored_memory_policy(), validate_model_policy()
- Produces: immutable snapshot manifest or a pre-go-live rejection

- [ ] **Step 1: Write failing gate tests**

~~~python
import pytest

from nooa_cybergym.leaderboard.memory.gate import validate_go_live_policies


def test_go_live_rejects_unaudited_memory(active_deepseek_policy):
    with pytest.raises(RuntimeError, match="memory policy"):
        validate_go_live_policies(
            memory={"scored_mode": "development_explicit"},
            alternate=active_deepseek_policy,
        )


def test_go_live_accepts_certified_hybrid_and_active_deepseek(certified_hybrid_policy, active_deepseek_policy):
    validate_go_live_policies(
        memory=certified_hybrid_policy,
        alternate=active_deepseek_policy,
    )
~~~

- [ ] **Step 2: Confirm the tests fail**

    uv run pytest tests/leaderboard/memory/test_snapshot.py \
      tests/leaderboard/memory/test_gate.py -v

- [ ] **Step 3: Implement snapshots and gate**

snapshot_memory records observed package/source hashes, current TLS endpoint, health/version, exact OAuth source scope and trusted-context configuration, authenticated tools/list/schema hashes, native guard binding hash, canonical page IDs/content hashes, signed provenance-manifest hash, controller-obtained page/fact/audit-table counts, schema/retrieval-model/configuration hashes and encrypted backup hash. Obtain controller metadata through existing authorized interfaces; do not assume get_stats/get_usage is exposed by the starter grant. Store no credential values.

validate_go_live_policies requires audited_hybrid, certified automatic and parent/child native read-only recall/search, canonical signed-manifest hydration, the narrowed exact-source grant/context, 12-total/2,000-token post-filter limits, native AI invocation-guard budget binding and controller-after-true-oracle write hashes. No provider, MCP OAuth or database credential enters tasks. A logged read outage in an already started attempt may fail open without memory; unsafe provenance/scope never permits unsafe content. Writes still require a true verdict. Missing service/catalog/guard/scope evidence before start is fail-closed. No outage restarts a task or enables an undeclared fallback.

The active DeepSeek policy requires the exact official endpoint/API/model/thinking/max settings, recon/debug/critic roles, deterministic triggers, concrete request/token/time limits, controller-only credential reference, capability-policy hash and certification hash. Verify no undeclared model route and no secret exposure; exercise approved roles instead of testing that all alternates are impossible. Bind observed provider metadata but disclose alias drift and no frozen-weight guarantee. Separate launch approval is checked by Plan 05 rather than by a new model-choice gate.

- [ ] **Step 4: Run the complete Plan 03 gate**

    uv run pytest tests/leaderboard/memory -v
    uv run sunchaser-cybergym memory verify-service \
      --endpoint https://sunchaser-20260905.cinnamon-gamut.ts.net/mcp \
      --source xeus-cybergym-workspace \
      --required-tools recall,search,get_page,capture
    git diff --check

The verify-service CLI above is a planned interface, not an already executed certification command. It must record current authenticated tools/list/schemas and verify the exact read source excludes default; the facade must deny solver capture. Then exercise native recall/search/get_page hydration, combined 12-result/2,000-token limits, guard-before-provider-call accounting (including failures, embed/rerank and null usage), and controller-only writes after a true oracle. Installed package 0.50.0.0 and repaired TLS health alone cannot pass these gates. Live native integration acceptance is recorded only after Plan 04 runs; official launch remains unauthorised.

- [ ] **Step 5: Commit and request implementation review**

    git add examples/cybergym/nooa_cybergym/leaderboard/memory \
      examples/cybergym/tests/leaderboard/memory \
      examples/cybergym/leaderboard/config \
      examples/cybergym/leaderboard/memory \
      examples/cybergym/pyproject.toml examples/cybergym/uv.lock
    git commit -m "feat(cybergym): gate audited memory and multimodel policy"

The reviewer verifies default/personal-brain and answer-bearing material are unreachable, both native retrieval paths and canonical hydration work for parent/children, unsigned or changed canonical records fail, 12 TOTAL results and 2,000 tokens are enforced after filtering, the native invocation guard accounts for every provider call before dispatch, writes require the true oracle, failures are not over-promoted, auxiliary models are itemized/counted, active DeepSeek roles use the official thinking/max route, and undeclared calls/credential/host access fail. Review the approved policy's implementation without creating another memory engine or repeating design approval.

## Plan 03 acceptance

Accept when the deployed service's current catalog/schemas and narrowed source grant are certified, existing native recall/search/get_page perform verified canonical-manifest retrieval with 12-total/2,000-token facade limits, every native AI call is controller-budgeted through its invocation guard, audit rows bind canonical identities to immutable true oracle outcomes, agent writes fail, task-local memory cannot cross containers, preseed scan has zero prohibited matches, and active DeepSeek/tool usage is logged within budgets without secret exposure or undeclared routes. Package/TLS observations and lossy get_usage telemetry cannot substitute for live certification. Official launch approval remains separate.
