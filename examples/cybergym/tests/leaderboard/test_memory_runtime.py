"""Real authority signatures and the complete HTTP → native transport → facade path."""

import base64
import hashlib
import json
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nooa_cybergym.leaderboard.host_boundary_runtime import AdmittedPeer, GatewayRequest
from nooa_cybergym.leaderboard.memory import SOURCE_ID, Caller
from nooa_cybergym.leaderboard.memory_runtime import (
    MemoryAuthority,
    TrustedMemoryCaller,
    build_memory_gateway,
    build_signed_memory_bundle,
)
from nooa_cybergym.leaderboard.memory_transport import RuntimeReadEvidence, TransportDenied
from xeus_cybergym.canonical import canonical_json
from xeus_cybergym.ledger import Ed25519Signer, Ed25519Verifier, SignedEnvelope

TOOLS = [
    {"name": name, "description": "Native synthetic read", "inputSchema": {"type": "object"}}
    for name in ("recall", "search", "get_page")
]
PEER = AdmittedPeer("container-1", "network-1", "172.30.0.2")


class Audit:
    def __init__(self):
        self.events = []

    def record(self, event):
        self.events.append(dict(event))
        return True


class NativePeer:
    def __init__(self):
        self.calls = []
        self.tools = TOOLS
        self.sources = [SOURCE_ID]
        self.guard = True
        self.results = {"recall": {"facts": [], "results": []}, "search": []}

    def inspection(self):
        return {
            "source_ids": self.sources,
            "server_context_source_id": SOURCE_ID,
            "native_guard_bound": self.guard,
            "native_guard_binding_sha256": "a" * 64,
            "source_tree_sha256": "b" * 64,
            "runtime_sha256": "c" * 64,
            "native_guard_sha256": "d" * 64,
            "backend_identity_sha256": "e" * 64,
            "gbrain_version": "0.50.0.0",
            "profile": "/srv/sunchaser/gbrain-profiles/xeus-cybergym",
            "client_id": "synthetic-oauth",
            "grant_revision": 1,
            "scopes": ["read"],
            "transport": "native-guarded-stdio",
            "session_mode": "read",
            "allowed_operations": ["recall", "search", "get_page"],
        }

    def read_evidence(self):
        return RuntimeReadEvidence(frozenset(self.sources), SOURCE_ID, "a" * 64, self.guard)

    def notify(self, message):
        self.calls.append(message)

    def exchange(self, message, *, timeout_seconds):
        self.calls.append(message)
        if message["method"] == "initialize":
            result = {
                "protocolVersion": "2025-06-18",
                "serverInfo": {"name": "gbrain", "version": "0.50.0.0"},
                "capabilities": {"tools": {}},
            }
        elif message["method"] == "tools/list":
            result = {"tools": self.tools}
        else:
            result = {
                "content": [
                    {"type": "text", "text": json.dumps(self.results[message["params"]["name"]])}
                ]
            }
        return {"jsonrpc": "2.0", "id": message["id"], "result": result}


def authority():
    key = Ed25519PrivateKey.generate()
    keys = {"synthetic-authority": key.public_key()}
    return Ed25519Signer(private_key=key, key_id="synthetic-authority"), Ed25519Verifier(keys), keys


def setup(*, caller=Caller.PARENT, native=None):
    native = native or NativePeer()
    signer, verifier, keys = authority()
    bundle = build_signed_memory_bundle(bridge=native, signer=signer, verifier=verifier)
    audit = Audit()
    context = TrustedMemoryCaller("task-synthetic", "attempt-1", caller, "glm-5.3", ("buffer",))
    handler = build_memory_gateway(
        bridge=native,
        signed_catalog=bundle.signed_catalog,
        signed_manifest=bundle.signed_manifest,
        public_keys=keys,
        audit=audit,
        answer_filter=lambda text: "forbidden" not in text,
        token_counter=lambda text: len(text.split()),
        authorize_peer=lambda peer: peer == PEER,
        resolve_caller=lambda peer, tool_id, name, arguments: (
            context
            if peer == PEER
            and tool_id == "toolu-native-1"
            and arguments == {"query": "buffer bounds"}
            else None
        ),
        task_id="task-synthetic",
        attempt_id="attempt-1",
    )
    return handler, native, audit, bundle, signer, verifier, keys


def request(method="tools/call", params=None, **changes):
    body = {
        "jsonrpc": "2.0",
        "id": "client-1",
        "method": method,
        "params": params
        if params is not None
        else {
            "name": "recall",
            "arguments": {"query": "buffer bounds"},
            "_meta": {"claudecode/toolUseId": "toolu-native-1"},
        },
    }
    return replace(
        GatewayRequest(
            "gbrain-read-gateway",
            "POST",
            "/mcp",
            (("Content-Type", "application/json"),),
            json.dumps(body).encode(),
            PEER,
        ),
        **changes,
    )


def test_discovery_builder_signs_only_observed_catalog_and_empty_readable_allowlist():
    native = NativePeer()
    signer, verifier, keys = authority()
    bundle = build_signed_memory_bundle(bridge=native, signer=signer, verifier=verifier)
    catalog = json.loads(verifier.verify(SignedEnvelope.model_validate_json(bundle.signed_catalog)))
    manifest = json.loads(
        verifier.verify(SignedEnvelope.model_validate_json(bundle.signed_manifest))
    )
    assert catalog["tools"] == sorted(TOOLS, key=lambda tool: tool["name"])
    assert manifest["pages"] == []
    assert manifest["catalog_envelope_sha256"] == hashlib.sha256(bundle.signed_catalog).hexdigest()
    assert [call["method"] for call in native.calls] == [
        "initialize",
        "notifications/initialized",
        "tools/list",
    ]
    assert MemoryAuthority(keys).attest_catalog(bundle.signed_catalog).source_ids == frozenset(
        {SOURCE_ID}
    )


@pytest.mark.parametrize("caller", [Caller.PARENT, Caller.CHILD])
def test_solver_mcp_reads_use_trusted_role_and_real_strict_facade(caller):
    handler, native, audit, *_ = setup(caller=caller)
    response = handler(request())
    assert response.status == 200
    result = json.loads(json.loads(response.body)["result"]["content"][0]["text"])
    assert result["results"] == []
    events = [event for event in audit.events if event.get("event") == "request"]
    assert events[-1]["caller"] == caller.value
    assert events[-1]["task_id"] == "task-synthetic"
    assert native.calls[-1]["params"]["arguments"] == {
        "query": "buffer bounds",
        "budget_tokens": 2000,
        "limit": 12,
    }


def test_automatic_recall_is_controller_only_and_solver_catalog_hides_hydration_and_write():
    handler, native, audit, *_ = setup()
    assert (
        handler.automatic_recall(level1_facts=("buffer parser",), structural_terms=("buffer",))
        == ()
    )
    assert [event for event in audit.events if event.get("event") == "request"][-1][
        "caller"
    ] == "automatic"
    response = handler(request("tools/list", {}))
    assert [tool["name"] for tool in json.loads(response.body)["result"]["tools"]] == [
        "recall",
        "search",
    ]
    for name in ("capture", "get_page", "automatic_recall", "xeus/certify-native-models"):
        before = len(native.calls)
        assert (
            handler(request(params={"name": name, "arguments": {"query": "buffer"}})).status == 403
        )
        assert len(native.calls) == before


def test_native_mcp_initialize_accepts_observed_transport_headers():
    handler, *_ = setup()
    initialization = request(
        "initialize",
        {
            "protocolVersion": "2025-11-25",
            "clientInfo": {"name": "claude", "version": "2.1.289"},
            "capabilities": {},
        },
        headers=(
            ("Content-Type", "application/json"),
            ("Accept-Encoding", "gzip, deflate"),
            ("Mcp-Method", "initialize"),
        ),
    )
    assert handler(initialization).status == 200
    assert handler(request("tools/list", {}, headers=initialization.headers)).status == 200


@pytest.mark.parametrize(
    "change",
    [
        {"peer": AdmittedPeer("unknown", "network-1", "172.30.0.3")},
        {"headers": (("x-agent-role", "parent"),)},
        {"headers": (("Accept-Encoding", "gzip"), ("Authorization", "Bearer hidden"))},
        {"path": "/mcp?source=default"},
        {"body": b'{"jsonrpc":"2.0","id":1,"method":"tools/list","method":"tools/call"}'},
    ],
)
def test_untrusted_identity_routes_or_ambiguous_json_fail_before_native_dispatch(change):
    handler, native, *_ = setup()
    before = len(native.calls)
    assert handler(request(**change)).status in (400, 403)
    assert len(native.calls) == before


def test_catalog_drift_fails_closed_before_memory_retrieval():
    handler, native, *_ = setup()
    native.tools = TOOLS + [{"name": "capture", "inputSchema": {"type": "object"}}]
    response = handler(request())
    assert response.status == 403
    assert all(call["method"] != "tools/call" for call in native.calls)


def test_empty_signed_manifest_blocks_unsigned_native_page_without_disclosing_text():
    handler, native, *_ = setup()
    native.results["recall"] = {
        "facts": [],
        "results": [{"slug": "cybergym/principle/unreviewed", "chunk": "private-marker"}],
    }
    response = handler(request())
    assert response.status == 403
    assert b"private-marker" not in response.body


def test_native_source_scope_mismatch_cannot_be_signed():
    native = NativePeer()
    native.sources.append("default")
    signer, verifier, _ = authority()
    with pytest.raises(TransportDenied):
        build_signed_memory_bundle(bridge=native, signer=signer, verifier=verifier)
    assert native.calls == []


def test_manifest_signature_tampering_or_cross_catalog_binding_rejected():
    _, _, _, bundle, signer, verifier, keys = setup()
    manifest = json.loads(
        verifier.verify(SignedEnvelope.model_validate_json(bundle.signed_manifest))
    )
    envelope = json.loads(bundle.signed_manifest)
    envelope["payload"] = base64.b64encode(
        canonical_json(manifest | {"source_id": "default"})
    ).decode()
    authority = MemoryAuthority(keys)
    with pytest.raises(TransportDenied):
        authority.attest_manifest(
            json.dumps(envelope).encode(),
            catalog_envelope_sha256=hashlib.sha256(bundle.signed_catalog).hexdigest(),
        )
    wrong = (
        signer.sign(canonical_json(manifest | {"catalog_envelope_sha256": "f" * 64}))
        .model_dump_json()
        .encode()
    )
    with pytest.raises(TransportDenied):
        authority.attest_manifest(
            wrong, catalog_envelope_sha256=hashlib.sha256(bundle.signed_catalog).hexdigest()
        )


@pytest.mark.parametrize(
    "params",
    [
        {"name": "recall", "arguments": {"query": "buffer bounds"}},
        {
            "name": "recall",
            "arguments": {"query": "buffer bounds"},
            "_meta": {"claudecode/toolUseId": "unregistered"},
        },
        {
            "name": "recall",
            "arguments": {"query": "changed query"},
            "_meta": {"claudecode/toolUseId": "toolu-native-1"},
        },
    ],
)
def test_native_tool_use_id_and_exact_provider_arguments_are_required_for_reads(params):
    handler, native, *_ = setup()
    before = len(native.calls)
    assert handler(request(params=params)).status == 403
    assert len(native.calls) == before


@pytest.mark.parametrize("protocol", ["2025-06-18", "2025-11-25"])
def test_initialization_needs_no_pending_tool_but_still_requires_admitted_peer(protocol):
    handler, _, *_ = setup()
    params = {
        "protocolVersion": protocol,
        "capabilities": {},
        "clientInfo": {"name": "claude", "version": "synthetic"},
    }
    assert handler(request("initialize", params)).status == 200


def test_extra_native_metadata_is_inert_and_does_not_grant_role():
    handler, *_ = setup()
    params = {
        "name": "recall",
        "arguments": {"query": "buffer bounds"},
        "_meta": {"claudecode/toolUseId": "toolu-native-1", "progressToken": 7, "role": "parent"},
    }
    assert handler(request(params=params)).status == 200


def test_signed_canonical_page_is_hydrated_before_http_disclosure():
    _, native, audit, bundle, signer, verifier, keys = setup()
    content = "Validate buffer length before advancing a cursor."
    content_hash = hashlib.sha256(content.encode()).hexdigest()
    frontmatter = {
        "type": "note",
        "tier": "principle",
        "title": "Buffer length checks",
        "source_document": "synthetic-generic-note",
        "source_sha256": "f" * 64,
        "license": "CC0-1.0",
        "captured_at": "2026-10-05T00:00:00Z",
        "reviewed": True,
    }
    page = {
        "page_id": 1,
        "slug": "cybergym/principle/buffer",
        "source_id": SOURCE_ID,
        "content_hash": content_hash,
        "content_sha256": content_hash,
        "frontmatter": frontmatter,
        "structural_terms": ["buffer"],
    }
    manifest = json.loads(
        verifier.verify(SignedEnvelope.model_validate_json(bundle.signed_manifest))
    )
    signed_manifest = (
        signer.sign(canonical_json(manifest | {"pages": [page]})).model_dump_json().encode()
    )
    native.results["recall"] = {"facts": [], "results": [{"slug": page["slug"], "chunk": content}]}
    native.results["get_page"] = {
        "id": 1,
        "slug": page["slug"],
        "source_id": SOURCE_ID,
        "content_hash": content_hash,
        "content": content,
        "frontmatter": frontmatter,
    }
    context = TrustedMemoryCaller(
        "task-synthetic", "attempt-1", Caller.PARENT, "glm-5.3", ("buffer",)
    )
    handler = build_memory_gateway(
        bridge=native,
        signed_catalog=bundle.signed_catalog,
        signed_manifest=signed_manifest,
        public_keys=keys,
        audit=audit,
        answer_filter=lambda _: True,
        token_counter=lambda text: len(text.split()),
        authorize_peer=lambda peer: peer == PEER,
        resolve_caller=lambda *_: context,
        task_id="task-synthetic",
        attempt_id="attempt-1",
    )
    response = handler(request())
    assert response.status == 200
    rows = json.loads(json.loads(response.body)["result"]["content"][0]["text"])["results"]
    assert [(row["page_id"], row["excerpt"]) for row in rows] == [(1, content)]
    assert native.calls[-1]["params"]["name"] == "get_page"
    assert native.calls[-1]["params"]["arguments"]["source_id"] == SOURCE_ID


def test_discovery_refuses_guard_or_grant_drift_between_observation_and_signing():
    native = NativePeer()
    original = native.inspection
    observations = 0

    def changing():
        nonlocal observations
        observations += 1
        result = original()
        if observations > 1:
            result["grant_revision"] = 2
        return result

    native.inspection = changing
    signer, verifier, _ = authority()
    with pytest.raises(TransportDenied):
        build_signed_memory_bundle(bridge=native, signer=signer, verifier=verifier)


def test_direct_http_read_requires_the_same_native_tool_correlation():
    handler, _, audit, *_ = setup()
    denied = handler(request(path="/search", body=b'{"query":"buffer bounds"}'))
    assert denied.status == 403
    accepted = handler(
        request(path="/search", body=b'{"query":"buffer bounds","tool_use_id":"toolu-native-1"}')
    )
    assert accepted.status == 200
    assert json.loads(accepted.body)["results"] == []
    assert [row for row in audit.events if row["event"] == "memory_native_tool_admitted"][-1][
        "native_tool_use_id"
    ] == "toolu-native-1"
