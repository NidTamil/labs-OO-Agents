# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Synthetic boundary tests for the controller-owned GBrain read facade."""

import hashlib
import json
from dataclasses import replace

import pytest
from nooa_cybergym.leaderboard.memory import (
    AllowedPage,
    Caller,
    ManifestAttestation,
    MemoryFacade,
    ReadScopeAttestation,
    UnsafeMemory,
)

SOURCE = "xeus-cybergym-workspace"
CONTENT = "Validate chunk length before advancing the parser cursor."
FRONTMATTER = {
    "type": "note",
    "tier": "principle",
    "title": "Length before cursor",
    "source_document": "synthetic-generic-parser-note",
    "source_sha256": "c" * 64,
    "license": "CC0-1.0",
    "captured_at": "2026-10-05T00:00:00Z",
    "reviewed": True,
}


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def page(*, page_id=1, tier="principle", content=CONTENT, terms=("chunk",), slug_name=None):
    slug = f"cybergym/{tier}/{slug_name or page_id}"
    frontmatter = FRONTMATTER | {"tier": tier}
    allowed = AllowedPage(
        page_id=page_id,
        slug=slug,
        source_id=SOURCE,
        content_hash=digest(content),
        content_sha256=digest(content),
        frontmatter=frontmatter,
        structural_terms=terms,
    )
    canonical = {
        "id": page_id,
        "slug": slug,
        "source_id": SOURCE,
        "content_hash": digest(content),
        "frontmatter": frontmatter,
        "content": content,
    }
    return allowed, canonical


class Transport:
    def __init__(self, *, rows=None, canonicals=None, scope=None):
        self.rows = {"facts": [], "results": []} if rows is None else rows
        self.canonicals = canonicals or {}
        self.scope = scope or ReadScopeAttestation(
            source_ids=frozenset({SOURCE}),
            server_context_source_id=SOURCE,
            tool_names=frozenset({"recall", "search", "get_page"}),
            catalog_sha256="a" * 64,
            native_guard_binding_sha256="b" * 64,
        )
        self.calls = []

    def read_scope(self):
        return self.scope

    def call(self, tool, arguments, *, request_id, timeout_seconds):
        self.calls.append((tool, dict(arguments), request_id, timeout_seconds))
        if tool == "get_page":
            return self.canonicals[arguments["slug"]]
        return self.rows


class Audit:
    def __init__(self):
        self.events = []
        self.accept = True

    def record(self, event):
        if self.accept:
            self.events.append(event)
        return self.accept


def facade(
    *,
    allowed=None,
    transport=None,
    audit=None,
    attestor=None,
    answer_filter=None,
    token_counter=None,
):
    allowed = [page()[0]] if allowed is None else allowed
    signed = b"opaque-authority-signed-manifest"
    if attestor is None:

        def attestor(payload):
            return ManifestAttestation(
                source_id=SOURCE,
                envelope_sha256=hashlib.sha256(payload).hexdigest(),
                signature_key_id="synthetic-authority",
                pages=tuple(allowed),
            )

    audit = audit or Audit()
    transport = transport or Transport()
    return (
        MemoryFacade(
            transport=transport,
            signed_manifest=signed,
            attest_manifest=attestor,
            audit=audit,
            answer_filter=answer_filter or (lambda text: True),
            token_counter=token_counter or (lambda text: len(text.split())),
        ),
        transport,
        audit,
    )


def test_automatic_recall_hydrates_canonical_page_and_audits_before_disclosure():
    allowed, canonical = page()
    transport = Transport(
        rows={
            "facts": [
                {
                    "id": 101,
                    "fact": CONTENT,
                    "context": allowed.slug,
                    "source": "mcp:extract_facts",
                    "provenance": allowed.slug,
                }
            ],
            "results": [],
        },
        canonicals={allowed.slug: canonical},
    )
    memory, transport, audit = facade(allowed=[allowed], transport=transport)
    result = memory.automatic_recall(
        level1_facts=("parser",),
        structural_terms=("chunk",),
        task_id="synthetic-task",
        attempt_id="attempt-1",
        request_id="read-1",
    )
    assert [(item.page_id, item.excerpt) for item in result] == [(1, CONTENT)]
    assert [call[0] for call in transport.calls] == ["recall", "get_page"]
    assert transport.calls[0][1] == {
        "query": "parser chunk",
        "budget_tokens": 2000,
        "limit": 12,
    }
    assert transport.calls[1][1] == {
        "slug": allowed.slug,
        "source_id": SOURCE,
        "include_content": True,
        "fuzzy": False,
    }
    assert [event["event"] for event in audit.events] == ["request", "result"]
    assert audit.events[-1]["selected"][0]["page_id"] == 1
    assert audit.events[-1]["path"] == "automatic"
    assert audit.events[-1]["tool"] == "recall"
    assert audit.events[-1]["query_sha256"] == digest("parser chunk")
    assert CONTENT not in json.dumps(audit.events)


def test_native_recall_fact_and_result_shapes_with_numeric_page_id():
    allowed, canonical = page(page_id=73)
    transport = Transport(
        rows={
            "facts": [
                {
                    "id": 101,
                    "fact": CONTENT,
                    "context": allowed.slug,
                    "source": "mcp:extract_facts",
                    "provenance": allowed.slug,
                }
            ],
            "results": [
                {
                    "slug": allowed.slug,
                    "title": "Length before cursor",
                    "chunk": CONTENT,
                    "evidence": [],
                    "create_safety": "safe",
                    "provenance": allowed.slug,
                }
            ],
        },
        canonicals={allowed.slug: canonical},
        scope=ReadScopeAttestation(
            source_ids=frozenset({SOURCE}),
            server_context_source_id=SOURCE,
            tool_names=frozenset({"recall", "search", "get_page", "capture"}),
            catalog_sha256="a" * 64,
            native_guard_binding_sha256="b" * 64,
        ),
    )
    memory, _, _ = facade(allowed=[allowed], transport=transport)
    selected = memory.automatic_recall(
        level1_facts=("parser",),
        structural_terms=("chunk",),
        task_id="synthetic-task",
        attempt_id="attempt-1",
        request_id="native-recall",
    )
    assert len(selected) == 1
    assert selected[0].page_id == 73
    assert selected[0].excerpt == CONTENT


def test_native_search_bare_array_uses_chunk_text():
    allowed, canonical = page(page_id=74, tier="semantic", terms=("chunk",))
    transport = Transport(
        rows=[{"slug": allowed.slug, "page_id": 74, "chunk_text": CONTENT}],
        canonicals={allowed.slug: canonical},
    )
    memory, _, _ = facade(allowed=[allowed], transport=transport)
    selected = memory.model_tool(
        "search",
        "chunk parser",
        caller=Caller.CHILD,
        structural_terms=("chunk",),
        task_id="synthetic-task",
        attempt_id="attempt-1",
        request_id="native-search",
        model_id="synthetic-model",
    )
    assert [item.page_id for item in selected] == [74]


def test_fact_producer_source_never_substitutes_for_missing_context():
    allowed, canonical = page(page_id=75)
    transport = Transport(
        rows={
            "facts": [
                {
                    "id": 102,
                    "fact": CONTENT,
                    "context": None,
                    "source": allowed.slug,
                    "provenance": allowed.slug,
                }
            ],
            "results": [],
        },
        canonicals={allowed.slug: canonical},
    )
    memory, transport, _ = facade(allowed=[allowed], transport=transport)
    selected = memory.automatic_recall(
        level1_facts=("parser",),
        structural_terms=("chunk",),
        task_id="synthetic-task",
        attempt_id="attempt-1",
        request_id="fact-context",
    )
    assert selected == ()
    assert [name for name, *_ in transport.calls] == ["recall"]


def test_search_page_id_must_match_hydrated_canonical_page():
    allowed, canonical = page(page_id=76)
    transport = Transport(
        rows=[{"slug": allowed.slug, "page_id": 999, "chunk_text": CONTENT}],
        canonicals={allowed.slug: canonical},
    )
    memory, _, _ = facade(allowed=[allowed], transport=transport)
    with pytest.raises(UnsafeMemory, match="canonical provenance"):
        memory.model_tool(
            "search",
            "chunk parser",
            caller=Caller.PARENT,
            structural_terms=("chunk",),
            task_id="synthetic-task",
            attempt_id="attempt-1",
            request_id="search-page-id",
            model_id="synthetic-model",
        )


@pytest.mark.parametrize("caller", [Caller.PARENT, Caller.CHILD])
def test_model_search_uses_native_source_scoped_operation_and_same_filter(caller):
    allowed, canonical = page(tier="procedural", terms=("chunk",))
    transport = Transport(
        rows=[{"slug": allowed.slug, "page_id": allowed.page_id, "chunk_text": CONTENT}],
        canonicals={allowed.slug: canonical},
    )
    memory, transport, audit = facade(allowed=[allowed], transport=transport)
    result = memory.model_tool(
        "search",
        "chunk parser",
        caller=caller,
        structural_terms=("chunk",),
        task_id="synthetic-task",
        attempt_id="attempt-1",
        request_id="read-2",
        model_id="synthetic-model",
    )
    assert [item.page_id for item in result] == [1]
    assert transport.calls[0][1] == {
        "query": "chunk parser",
        "limit": 12,
        "source_id": SOURCE,
        "types": ["note"],
        "snippet_chars": 1000,
    }
    assert audit.events[-1]["caller"] == caller.value
    assert audit.events[-1]["model_id"] == "synthetic-model"


def test_model_tool_refuses_agent_write_before_any_native_call():
    controller_catalog = ReadScopeAttestation(
        source_ids=frozenset({SOURCE}),
        server_context_source_id=SOURCE,
        tool_names=frozenset({"recall", "search", "get_page", "capture"}),
        catalog_sha256="a" * 64,
        native_guard_binding_sha256="b" * 64,
    )
    memory, transport, _ = facade(transport=Transport(scope=controller_catalog))
    with pytest.raises(UnsafeMemory, match="read-only"):
        memory.model_tool(
            "capture",
            "",
            caller=Caller.CHILD,
            structural_terms=("chunk",),
            task_id="synthetic-task",
            attempt_id="attempt-1",
            request_id="write-1",
            model_id="synthetic-model",
        )
    assert transport.calls == []


@pytest.mark.parametrize(
    "scope",
    [
        ReadScopeAttestation(
            source_ids=frozenset({SOURCE, "default"}),
            server_context_source_id=SOURCE,
            tool_names=frozenset({"recall", "search", "get_page"}),
            catalog_sha256="a" * 64,
            native_guard_binding_sha256="b" * 64,
        ),
        ReadScopeAttestation(
            source_ids=frozenset({SOURCE}),
            server_context_source_id="default",
            tool_names=frozenset({"recall", "search", "get_page"}),
            catalog_sha256="a" * 64,
            native_guard_binding_sha256="b" * 64,
        ),
        ReadScopeAttestation(
            source_ids=frozenset({SOURCE}),
            server_context_source_id=SOURCE,
            tool_names=frozenset({"recall", "search", "capture"}),
            catalog_sha256="a" * 64,
            native_guard_binding_sha256="b" * 64,
        ),
    ],
)
def test_unsafe_grant_or_context_fails_before_recall(scope):
    transport = Transport(scope=scope)
    memory, transport, _ = facade(transport=transport)
    with pytest.raises(UnsafeMemory, match="source scope|read-only"):
        memory.automatic_recall(
            level1_facts=("parser",),
            structural_terms=("chunk",),
            task_id="synthetic-task",
            attempt_id="attempt-1",
            request_id="read-3",
        )
    assert transport.calls == []


def test_unsigned_manifest_rejected_before_native_call():
    def reject(_payload):
        raise ValueError("invalid signature")

    with pytest.raises(UnsafeMemory, match="signed manifest"):
        facade(attestor=reject)


@pytest.mark.parametrize(
    "change",
    [
        {"source_id": "default"},
        {"content_hash": "e" * 64},
        {"content": "Changed canonical content."},
        {"frontmatter": FRONTMATTER | {"tier": "episodic"}},
        {"id": "other-page"},
    ],
)
def test_changed_or_wrong_source_canonical_record_fails_closed(change):
    allowed, canonical = page()
    transport = Transport(
        rows={"facts": [], "results": [{"slug": allowed.slug, "chunk": CONTENT}]},
        canonicals={allowed.slug: canonical | change},
    )
    memory, transport, _ = facade(allowed=[allowed], transport=transport)
    with pytest.raises(UnsafeMemory, match="canonical provenance"):
        memory.automatic_recall(
            level1_facts=("parser",),
            structural_terms=("chunk",),
            task_id="synthetic-task",
            attempt_id="attempt-1",
            request_id="read-4",
        )


def test_recall_fact_must_be_verbatim_in_canonical_content():
    allowed, canonical = page()
    transport = Transport(
        rows={
            "facts": [
                {
                    "id": 103,
                    "fact": "An unsupported claim.",
                    "context": allowed.slug,
                    "source": "mcp:extract_facts",
                    "provenance": allowed.slug,
                }
            ],
            "results": [],
        },
        canonicals={allowed.slug: canonical},
    )
    memory, _, _ = facade(allowed=[allowed], transport=transport)
    with pytest.raises(UnsafeMemory, match="canonical provenance"):
        memory.automatic_recall(
            level1_facts=("parser",),
            structural_terms=("chunk",),
            task_id="synthetic-task",
            attempt_id="attempt-1",
            request_id="read-5",
        )


def test_native_ingest_hash_is_independent_of_returned_markdown_hash():
    allowed, canonical = page()
    native_hash = "d" * 64
    allowed = replace(allowed, content_hash=native_hash)
    canonical["content_hash"] = native_hash
    transport = Transport(
        rows={"facts": [], "results": [{"slug": allowed.slug, "chunk": CONTENT}]},
        canonicals={allowed.slug: canonical},
    )
    memory, _, _ = facade(allowed=[allowed], transport=transport)
    selected = memory.automatic_recall(
        level1_facts=("parser",),
        structural_terms=("chunk",),
        task_id="synthetic-task",
        attempt_id="attempt-1",
        request_id="read-hash",
    )
    assert selected[0].content_hash == native_hash


def test_unresolved_slug_fails_closed():
    transport = Transport(
        rows={"facts": [], "results": [{"slug": "cybergym/principle/unknown", "chunk": CONTENT}]}
    )
    memory, _, _ = facade(transport=transport)
    with pytest.raises(UnsafeMemory, match="canonical provenance"):
        memory.automatic_recall(
            level1_facts=("parser",),
            structural_terms=("chunk",),
            task_id="synthetic-task",
            attempt_id="attempt-1",
            request_id="read-6",
        )


def test_filter_drops_episodes_unrelated_semantics_and_answer_bearing_excerpt():
    principle, p = page(page_id=2, terms=("chunk",))
    unrelated, s = page(page_id=3, tier="semantic", terms=("socket",))
    episodic_slug = "cybergym/episodic/e"
    transport = Transport(
        rows={
            "facts": [
                {
                    "id": 104,
                    "fact": "Prior attempt.",
                    "context": episodic_slug,
                    "source": "mcp:extract_facts",
                    "provenance": episodic_slug,
                }
            ],
            "results": [
                {"slug": unrelated.slug, "chunk": CONTENT},
                {"slug": principle.slug, "chunk": CONTENT},
            ],
        },
        canonicals={unrelated.slug: s, principle.slug: p},
    )
    memory, _, _ = facade(
        allowed=[principle, unrelated],
        transport=transport,
        answer_filter=lambda text: "cursor" not in text,
    )
    assert (
        memory.automatic_recall(
            level1_facts=("parser",),
            structural_terms=("chunk",),
            task_id="synthetic-task",
            attempt_id="attempt-1",
            request_id="read-7",
        )
        == ()
    )


def test_post_filter_caps_combined_fact_and_page_count_and_token_budget():
    entries = [page(page_id=i) for i in range(1, 25)]
    rows = {
        "facts": [
            {
                "id": i,
                "fact": CONTENT,
                "context": a.slug,
                "source": "mcp:extract_facts",
                "provenance": a.slug,
            }
            for i, (a, _) in enumerate(entries[:12], 1)
        ],
        "results": [{"slug": a.slug, "chunk": CONTENT} for a, _ in entries[12:]],
    }
    transport = Transport(rows=rows, canonicals={a.slug: c for a, c in entries})
    memory, _, audit = facade(allowed=[a for a, _ in entries], transport=transport)
    selected = memory.automatic_recall(
        level1_facts=("parser",),
        structural_terms=("chunk",),
        task_id="synthetic-task",
        attempt_id="attempt-1",
        request_id="read-8",
    )
    assert len(selected) == 12
    assert sum(item.token_count for item in selected) <= 2000
    assert audit.events[-1]["selected_count"] == 12


def test_token_cap_counts_exposed_identity_and_excerpt_after_filtering():
    long_content = "token " * 1000
    entries = [page(page_id=i, content=long_content) for i in range(1, 4)]
    transport = Transport(
        rows={
            "facts": [],
            "results": [{"slug": allowed.slug, "chunk": long_content} for allowed, _ in entries],
        },
        canonicals={allowed.slug: canonical for allowed, canonical in entries},
    )
    memory, _, audit = facade(allowed=[allowed for allowed, _ in entries], transport=transport)
    selected = memory.automatic_recall(
        level1_facts=("parser",),
        structural_terms=("chunk",),
        task_id="synthetic-task",
        attempt_id="attempt-1",
        request_id="read-budget",
    )
    assert len(selected) == 1
    assert audit.events[-1]["injected_tokens"] == 1002


def test_task_answer_filter_blocks_model_query_before_native_call():
    memory, transport, _ = facade(answer_filter=lambda text: "patch" not in text)
    with pytest.raises(UnsafeMemory, match="query rejected"):
        memory.model_tool(
            "search",
            "patch parser",
            caller=Caller.PARENT,
            structural_terms=("parser",),
            task_id="synthetic-task",
            attempt_id="attempt-1",
            request_id="read-query",
            model_id="synthetic-model",
        )
    assert transport.calls == []


def test_task_answer_filter_blocks_prohibited_signed_slug_from_disclosure():
    allowed, canonical = page(page_id=77, slug_name="prohibited-task-id")
    transport = Transport(
        rows={"facts": [], "results": [{"slug": allowed.slug, "chunk": CONTENT}]},
        canonicals={allowed.slug: canonical},
    )
    memory, _, _ = facade(
        allowed=[allowed],
        transport=transport,
        answer_filter=lambda text: "prohibited-task-id" not in text,
    )
    selected = memory.automatic_recall(
        level1_facts=("parser",),
        structural_terms=("chunk",),
        task_id="synthetic-task",
        attempt_id="attempt-1",
        request_id="read-slug",
    )
    assert selected == ()


def test_token_counter_failure_stops_unsafe_disclosure():
    allowed, canonical = page()
    transport = Transport(
        rows={"facts": [], "results": [{"slug": allowed.slug, "chunk": CONTENT}]},
        canonicals={allowed.slug: canonical},
    )

    def failed_counter(_text):
        raise RuntimeError("synthetic tokenizer outage")

    memory, _, _ = facade(allowed=[allowed], transport=transport, token_counter=failed_counter)
    with pytest.raises(UnsafeMemory, match="token accounting"):
        memory.automatic_recall(
            level1_facts=("parser",),
            structural_terms=("chunk",),
            task_id="synthetic-task",
            attempt_id="attempt-1",
            request_id="read-tokens",
        )


def test_audit_refusal_prevents_disclosure():
    allowed, canonical = page()
    transport = Transport(
        rows={
            "facts": [
                {
                    "id": 105,
                    "fact": CONTENT,
                    "context": allowed.slug,
                    "source": "mcp:extract_facts",
                    "provenance": allowed.slug,
                }
            ],
            "results": [],
        },
        canonicals={allowed.slug: canonical},
    )
    audit = Audit()
    audit.accept = False
    memory, _, _ = facade(transport=transport, audit=audit)
    with pytest.raises(UnsafeMemory, match="audit"):
        memory.automatic_recall(
            level1_facts=("parser",),
            structural_terms=("chunk",),
            task_id="synthetic-task",
            attempt_id="attempt-1",
            request_id="read-9",
        )
