# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Synthetic MCP boundary tests; no live provider or private GBrain data."""

import hashlib
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest
from nooa_cybergym.leaderboard.memory import (
    AllowedPage,
    Caller,
    ManifestAttestation,
    MemoryFacade,
    MemoryUnavailable,
)
from nooa_cybergym.leaderboard.memory_transport import (
    CatalogAttestation,
    ControllerMemoryTransport,
    RuntimeReadEvidence,
    TransportDenied,
)

SOURCE = "xeus-cybergym-workspace"
SIGNED = b"opaque-signed-catalog-envelope"
TOOLS = [
    {
        "name": "recall",
        "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}},
    },
    {
        "name": "search",
        "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}},
    },
    {
        "name": "get_page",
        "inputSchema": {"type": "object", "properties": {"slug": {"type": "string"}}},
    },
    {
        "name": "capture",
        "inputSchema": {"type": "object", "properties": {"slug": {"type": "string"}}},
    },
]


def canonical_hash(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()


def attestation(*, tools=TOOLS):
    return CatalogAttestation(
        envelope_sha256=hashlib.sha256(SIGNED).hexdigest(),
        signature_key_id="synthetic-authority",
        catalog_sha256=canonical_hash(sorted(tools, key=lambda tool: tool["name"])),
        tool_names=frozenset(tool["name"] for tool in tools),
        source_ids=frozenset({SOURCE}),
        server_context_source_id=SOURCE,
        native_guard_binding_sha256="b" * 64,
        server_info_sha256=canonical_hash({"name": "gbrain", "version": "0.50.0.0"}),
        protocol_version="2025-06-18",
    )


class Bridge:
    def __init__(self):
        self.calls = []
        self.notifications = []
        self.tools = TOOLS
        self.evidence = RuntimeReadEvidence(
            source_ids=frozenset({SOURCE}),
            server_context_source_id=SOURCE,
            native_guard_binding_sha256="b" * 64,
            native_guard_bound=True,
        )
        self.tool_result = {
            "content": [{"type": "text", "text": '{"facts":[],"results":[]}'}],
            "isError": False,
        }
        self.tool_results = {}
        self.server_info = {"name": "gbrain", "version": "0.50.0.0"}
        self.protocol_version = "2025-06-18"
        self.error = None

    def read_evidence(self):
        return self.evidence

    def notify(self, message):
        self.notifications.append(message)

    def exchange(self, message, *, timeout_seconds):
        self.calls.append((message, timeout_seconds))
        if self.error:
            raise self.error
        method = message["method"]
        if method == "initialize":
            result = {
                "protocolVersion": self.protocol_version,
                "serverInfo": self.server_info,
                "capabilities": {"tools": {}},
            }
        elif method == "tools/list":
            result = {"tools": self.tools}
        else:
            result = self.tool_results.get(message["params"]["name"], self.tool_result)
        return {"jsonrpc": "2.0", "id": message["id"], "result": result}


def transport(*, bridge=None, verify=None):
    bridge = bridge or Bridge()
    verify = verify or (lambda payload: attestation() if payload == SIGNED else None)
    return ControllerMemoryTransport(
        bridge=bridge, signed_catalog=SIGNED, attest_catalog=verify
    ), bridge


def test_signed_authenticated_catalog_and_native_recall_wire():
    client, bridge = transport()
    scope = client.read_scope()
    assert scope.source_ids == frozenset({SOURCE})
    assert scope.tool_names == frozenset({"recall", "search", "get_page", "capture"})
    assert [message["method"] for message, _ in bridge.calls] == ["initialize", "tools/list"]
    assert bridge.notifications == [{"jsonrpc": "2.0", "method": "notifications/initialized"}]

    result = client.call(
        "recall",
        {"query": "chunk", "budget_tokens": 2000, "limit": 12},
        request_id="read-1",
        timeout_seconds=20.0,
    )
    assert result == {"facts": [], "results": []}
    message, timeout = bridge.calls[-1]
    assert message == {
        "jsonrpc": "2.0",
        "id": "read-1",
        "method": "tools/call",
        "params": {
            "name": "recall",
            "arguments": {"query": "chunk", "budget_tokens": 2000, "limit": 12},
        },
    }
    assert timeout == 20.0


def test_structured_search_decodes_bare_array_and_keeps_exact_source_argument():
    client, bridge = transport()
    client.read_scope()
    bridge.tool_result = {
        "structuredContent": [
            {"slug": "cybergym/principle/1", "page_id": 1, "chunk_text": "Generic note."}
        ],
        "isError": False,
    }
    result = client.call(
        "search",
        {
            "query": "chunk",
            "limit": 12,
            "source_id": SOURCE,
            "types": ["note"],
            "snippet_chars": 1000,
        },
        request_id="read-2",
        timeout_seconds=20.0,
    )
    assert result[0]["page_id"] == 1
    assert bridge.calls[-1][0]["params"]["arguments"]["source_id"] == SOURCE


def test_controller_catalog_capture_never_becomes_a_solver_dispatch():
    client, bridge = transport()
    client.read_scope()
    before = len(bridge.calls)
    with pytest.raises(TransportDenied, match="read-only"):
        client.call("capture", {"slug": "synthetic"}, request_id="write-1", timeout_seconds=20.0)
    assert len(bridge.calls) == before


@pytest.mark.parametrize(
    "change",
    [
        {"source_ids": frozenset({SOURCE, "default"})},
        {"server_context_source_id": "default"},
        {"native_guard_bound": False},
        {"native_guard_binding_sha256": "c" * 64},
    ],
)
def test_runtime_scope_or_guard_mismatch_blocks_before_tool_dispatch(change):
    bridge = Bridge()
    bridge.evidence = replace(bridge.evidence, **change)
    client, _ = transport(bridge=bridge)
    with pytest.raises(TransportDenied, match="scope|guard"):
        client.read_scope()
    assert all(message["method"] != "tools/call" for message, _ in bridge.calls)


def test_observed_catalog_schema_change_fails_signed_digest_check():
    bridge = Bridge()
    bridge.tools = [dict(tool) for tool in TOOLS]
    bridge.tools[0] = {
        **bridge.tools[0],
        "inputSchema": {"type": "object", "additionalProperties": True},
    }
    client, _ = transport(bridge=bridge)
    with pytest.raises(TransportDenied, match="signed catalog"):
        client.read_scope()


def test_catalog_drift_revokes_previously_checked_dispatch():
    client, bridge = transport()
    client.read_scope()
    bridge.tools = [dict(tool) for tool in TOOLS]
    bridge.tools[0] = {
        **bridge.tools[0],
        "inputSchema": {"type": "object", "additionalProperties": True},
    }
    with pytest.raises(TransportDenied, match="signed catalog"):
        client.read_scope()
    before = len(bridge.calls)
    with pytest.raises(TransportDenied, match="catalog has not been checked"):
        client.call(
            "recall",
            {"query": "chunk", "budget_tokens": 2000, "limit": 12},
            request_id="stale-read",
            timeout_seconds=20.0,
        )
    assert len(bridge.calls) == before


def test_server_identity_drift_fails_signed_attestation():
    bridge = Bridge()
    bridge.server_info = {"name": "gbrain", "version": "changed"}
    client, _ = transport(bridge=bridge)
    with pytest.raises(TransportDenied, match="server identity"):
        client.read_scope()


def test_initialize_requests_the_signed_protocol_version():
    bridge = Bridge()
    bridge.protocol_version = "2025-03-26"
    certified = replace(attestation(), protocol_version="2025-03-26")
    client, _ = transport(bridge=bridge, verify=lambda _payload: certified)
    client.read_scope()
    assert bridge.calls[0][0]["params"]["protocolVersion"] == "2025-03-26"


def test_shared_adapter_serializes_catalog_refreshes_for_child_reads():
    class SlowBridge(Bridge):
        def __init__(self):
            super().__init__()
            self.active = 0
            self.max_active = 0
            self.lock = threading.Lock()

        def exchange(self, message, *, timeout_seconds):
            with self.lock:
                self.active += 1
                self.max_active = max(self.max_active, self.active)
            try:
                time.sleep(0.005)
                return super().exchange(message, timeout_seconds=timeout_seconds)
            finally:
                with self.lock:
                    self.active -= 1

    bridge = SlowBridge()
    client, _ = transport(bridge=bridge)
    with ThreadPoolExecutor(max_workers=3) as executor:
        scopes = list(executor.map(lambda _: client.read_scope(), range(3)))
    assert all(scope.source_ids == frozenset({SOURCE}) for scope in scopes)
    assert bridge.max_active == 1
    assert sum(message["method"] == "initialize" for message, _ in bridge.calls) == 1


def test_unsigned_catalog_rejected_before_network():
    bridge = Bridge()
    with pytest.raises(TransportDenied, match="signed catalog"):
        transport(bridge=bridge, verify=lambda _payload: None)
    assert bridge.calls == []


@pytest.mark.parametrize(
    "tool_result",
    [
        {"isError": True, "content": [{"type": "text", "text": "private-error-marker"}]},
        {"isError": 0, "content": [{"type": "text", "text": '{"facts":[],"results":[]}'}]},
        {"content": [{"type": "text", "text": "not-json"}]},
        {"content": [{"type": "text", "text": "{}"}, {"type": "text", "text": "{}"}]},
        {
            "structuredContent": {"facts": [], "results": []},
            "content": [{"type": "text", "text": "{}"}],
        },
        {"structuredContent": {"facts": [], "results": []}, "content": []},
        {"structuredContent": {"pages": []}},
    ],
)
def test_malformed_or_ambiguous_native_response_never_reaches_facade(tool_result):
    client, bridge = transport()
    client.read_scope()
    bridge.tool_result = tool_result
    with pytest.raises(TransportDenied) as error:
        client.call(
            "recall",
            {"query": "chunk", "budget_tokens": 2000, "limit": 12},
            request_id="read-3",
            timeout_seconds=20.0,
        )
    assert "private-error-marker" not in str(error.value)


def test_wrong_source_and_extra_native_arguments_fail_before_dispatch():
    client, bridge = transport()
    client.read_scope()
    before = len(bridge.calls)
    with pytest.raises(TransportDenied):
        client.call(
            "recall",
            {"query": "chunk", "budget_tokens": 2000, "limit": 12, "source_id": "default"},
            request_id="read-4",
            timeout_seconds=20.0,
        )
    with pytest.raises(TransportDenied):
        client.call(
            "search",
            {
                "query": "chunk",
                "limit": 12,
                "source_id": "default",
                "types": ["note"],
                "snippet_chars": 1000,
            },
            request_id="read-5",
            timeout_seconds=20.0,
        )
    assert len(bridge.calls) == before


def test_bridge_exception_is_sanitized_and_not_returned_to_model():
    client, bridge = transport()
    client.read_scope()
    bridge.error = RuntimeError("private-error-marker")
    with pytest.raises(TransportDenied) as error:
        client.call(
            "recall",
            {"query": "chunk", "budget_tokens": 2000, "limit": 12},
            request_id="read-6",
            timeout_seconds=20.0,
        )
    assert "private-error-marker" not in str(error.value)
    assert error.value.__context__ is None


def test_native_transport_hydrates_verified_result_before_model_disclosure():
    content = "Validate a generic chunk length before advancing a cursor."
    slug = "cybergym/principle/1"
    frontmatter = {
        "type": "note",
        "tier": "principle",
        "title": "Length before cursor",
        "source_document": "synthetic-generic-note",
        "source_sha256": "c" * 64,
        "license": "CC0-1.0",
        "captured_at": "2026-10-05T00:00:00Z",
        "reviewed": True,
    }
    allowed = AllowedPage(
        page_id=1,
        slug=slug,
        source_id=SOURCE,
        content_hash="d" * 64,
        content_sha256=hashlib.sha256(content.encode()).hexdigest(),
        frontmatter=frontmatter,
        structural_terms=("chunk",),
    )
    canonical = {
        "id": 1,
        "slug": slug,
        "source_id": SOURCE,
        "content_hash": "d" * 64,
        "frontmatter": frontmatter,
        "content": content,
    }
    bridge = Bridge()
    bridge.tool_results = {
        "recall": {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(
                        {"facts": [], "results": [{"slug": slug, "chunk": content}]}
                    ),
                }
            ],
            "isError": False,
        },
        "get_page": {"structuredContent": canonical, "isError": False},
    }
    client, _ = transport(bridge=bridge)
    signed_manifest = b"opaque-signed-memory-manifest"

    def attest_manifest(payload):
        return ManifestAttestation(
            source_id=SOURCE,
            envelope_sha256=hashlib.sha256(payload).hexdigest(),
            signature_key_id="synthetic-authority",
            pages=(allowed,),
        )

    class Audit:
        def __init__(self):
            self.events = []

        def record(self, event):
            self.events.append(event)
            return True

    audit = Audit()
    memory = MemoryFacade(
        transport=client,
        signed_manifest=signed_manifest,
        attest_manifest=attest_manifest,
        audit=audit,
        answer_filter=lambda _text: True,
        token_counter=lambda text: len(text.split()),
    )
    selected = memory.model_tool(
        "recall",
        "chunk parser",
        caller=Caller.CHILD,
        structural_terms=("chunk",),
        task_id="synthetic-task",
        attempt_id="attempt-1",
        request_id="integrated-read",
        model_id="synthetic-model",
    )
    assert [(item.page_id, item.excerpt) for item in selected] == [(1, content)]
    assert [
        message["params"]["name"]
        for message, _ in bridge.calls
        if message["method"] == "tools/call"
    ] == ["recall", "get_page"]
    assert audit.events[-1]["selected_count"] == 1


def test_malformed_transport_result_is_absent_from_model_response():
    bridge = Bridge()
    bridge.tool_result = {"content": [{"type": "text", "text": "private-error-marker"}]}
    client, _ = transport(bridge=bridge)
    signed_manifest = b"opaque-signed-memory-manifest"

    def attest_manifest(payload):
        return ManifestAttestation(
            source_id=SOURCE,
            envelope_sha256=hashlib.sha256(payload).hexdigest(),
            signature_key_id="synthetic-authority",
            pages=(),
        )

    class Audit:
        def record(self, _event):
            return True

    memory = MemoryFacade(
        transport=client,
        signed_manifest=signed_manifest,
        attest_manifest=attest_manifest,
        audit=Audit(),
        answer_filter=lambda _text: True,
        token_counter=lambda text: len(text.split()),
    )
    with pytest.raises(MemoryUnavailable) as error:
        memory.model_tool(
            "recall",
            "chunk parser",
            caller=Caller.PARENT,
            structural_terms=("chunk",),
            task_id="synthetic-task",
            attempt_id="attempt-1",
            request_id="invalid-result",
            model_id="synthetic-model",
        )
    assert "private-error-marker" not in str(error.value)
