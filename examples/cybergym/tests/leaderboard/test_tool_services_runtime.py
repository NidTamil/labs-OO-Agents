"""Registered tools preserve native admission, container scope and document policy."""

from __future__ import annotations

import json
import socket
import struct
import threading
from dataclasses import replace
from pathlib import Path

import httpx
import pytest
from nooa_cybergym.leaderboard.documentation_service import VerifiedHTTPSNoRedirectTransport
from nooa_cybergym.leaderboard.host_boundary_runtime import AdmittedPeer, GatewayRequest
from nooa_cybergym.leaderboard.native_tool_runtime import NativeToolCall
from nooa_cybergym.leaderboard.network import NetworkPolicy
from nooa_cybergym.leaderboard.tool_services_runtime import (
    ClangdClient,
    DockerClangdProcess,
    DocumentationReader,
    RegisteredToolGateway,
    ToolServiceDenied,
    sanitize_compile_commands,
)

from .test_documentation_service import _admission


class Audit:
    def __init__(self):
        self.events = []
        self.acknowledge = True

    def record(self, event):
        self.events.append(event)
        return self.acknowledge


PEER = AdmittedPeer("container-a", "network-a", "172.22.0.2")
POLICY = Path(__file__).parents[2] / "leaderboard/config/network-policy.json"


def call(name, args, *, role="child"):
    return NativeToolCall(
        "synthetic-task",
        "attempt-1",
        "request-1",
        "session-1",
        "agent-1" if role == "child" else None,
        role,
        "tool-1",
        name,
        args,
    )


def request(server, method="tools/list", params=None):
    return GatewayRequest(
        "registered-tool-gateway",
        "POST",
        "/mcp/" + server,
        (("Content-Type", "application/json"),),
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}).encode(),
        PEER,
    )


class ClangdFixture:
    container_id = PEER.container_id

    def __init__(self):
        self.calls = []

    def invoke(self, name, args):
        self.calls.append((name, args))
        return [{"name": "vulnerable_source_symbol"}]


def gateway(clangd=None, resolver=None, audit=None, docs=None):
    return RegisteredToolGateway(
        clangd=clangd or ClangdFixture(),
        documentation=docs,
        authorize_peer=lambda peer: peer == PEER,
        resolve_caller=resolver or (lambda peer, tid, name, args: call(name, args)),
        audit=audit or Audit(),
        task_id="synthetic-task",
        attempt_id="attempt-1",
    )


def tool_request(server="clangd", name="hover", args=None, meta=True):
    params = {
        "name": name,
        "arguments": args or {"path": "/workspace/src/a.cc", "line": 0, "character": 4},
    }
    if meta:
        params["_meta"] = {"claudecode/toolUseId": "tool-1"}
    return request(server, "tools/call", params)


def test_roster_and_native_authorized_child_dispatch_are_audited():
    clangd, audit, resolved = ClangdFixture(), Audit(), []

    def resolve(peer, tid, name, args):
        resolved.append((peer, tid, name, args))
        return call(name, args)

    handler = gateway(clangd, resolve, audit)
    tools = json.loads(handler(request("clangd")).body)["result"]["tools"]
    assert {t["name"] for t in tools} == {"document_symbols", "hover", "definition", "references"}
    assert all(t["inputSchema"]["additionalProperties"] is False for t in tools)
    reply = handler(tool_request())
    assert reply.status == 200 and b"vulnerable_source_symbol" in reply.body
    assert resolved[0][1:3] == ("tool-1", "mcp__clangd__hover")
    assert clangd.calls and len(audit.events) == 2
    assert audit.events[0]["role"] == "child"
    assert audit.events[1]["outcome"] == "released"


@pytest.mark.parametrize("server", ["clangd", "documentation"])
def test_pinned_native_latest_mcp_version_initializes_without_tool_grant(server):
    response = gateway()(
        request(
            server,
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "clientInfo": {"name": "claude", "version": "2.1.289"},
                "capabilities": {},
            },
        )
    )
    assert response.status == 200
    assert json.loads(response.body)["result"]["protocolVersion"] == "2025-11-25"


@pytest.mark.parametrize("server", ["clangd", "documentation"])
def test_native_mcp_initialize_accepts_observed_transport_headers(server):
    initialization = replace(
        request(
            server,
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "clientInfo": {"name": "claude", "version": "2.1.289"},
                "capabilities": {},
            },
        ),
        headers=(
            ("Content-Type", "application/json"),
            ("Accept-Encoding", "gzip, deflate"),
            ("Mcp-Method", "initialize"),
        ),
    )
    handler = gateway()
    assert handler(initialization).status == 200
    assert handler(replace(request(server), headers=initialization.headers)).status == 200


@pytest.mark.parametrize("server", ["clangd", "documentation"])
def test_native_mcp_transport_still_rejects_credential_headers(server):
    raw = request(server)
    assert gateway()(
        replace(raw, headers=raw.headers + (("Authorization", "Bearer hidden"),))
    ).status == 403


@pytest.mark.parametrize(
    "mutation",
    ["no-meta", "wrong-role", "wrong-id", "wrong-name", "wrong-args", "extra-arg", "bad-peer"],
)
def test_no_dispatch_without_exact_native_tool_and_arguments(mutation):
    clangd = ClangdFixture()

    def resolve(peer, tid, name, args):
        obj = call(name, args)
        return replace(
            obj,
            **{
                "wrong-role": {"role": "automatic"},
                "wrong-id": {"tool_id": "other"},
                "wrong-name": {"name": "mcp__clangd__references"},
                "wrong-args": {"arguments": {"path": "/workspace/secret"}},
            }.get(mutation, {}),
        )

    req = tool_request(meta=mutation != "no-meta")
    if mutation == "extra-arg":
        req = tool_request(
            args={"path": "/workspace/src/a.cc", "line": 0, "character": 4, "command": "id"}
        )
    if mutation == "bad-peer":
        req = replace(req, peer=replace(PEER, container_id="other"))
    assert gateway(clangd, resolve)(req).status == 403
    assert not clangd.calls


def test_audit_failure_never_dispatches_or_releases_result():
    clangd, audit = ClangdFixture(), Audit()
    audit.acknowledge = False
    assert gateway(clangd, audit=audit)(tool_request()).status == 503
    assert not clangd.calls


def test_result_is_not_released_when_result_audit_fails():
    audit, clangd = Audit(), ClangdFixture()

    def record(event):
        audit.events.append(event)
        return event["event"] != "registered_tool_result"

    audit.record = record
    reply = gateway(clangd, audit=audit)(tool_request())
    assert reply.status == 503 and b"vulnerable_source_symbol" not in reply.body
    assert len(clangd.calls) == 1


def test_duplicate_native_metadata_key_cannot_dispatch():
    clangd = ClangdFixture()
    req = tool_request()
    body = req.body.replace(
        b'"claudecode/toolUseId": "tool-1"',
        b'"claudecode/toolUseId": "tool-1", "claudecode/toolUseId": "tool-2"',
    )
    assert gateway(clangd)(replace(req, body=body)).status == 400
    assert not clangd.calls


def test_native_extra_metadata_is_inert_and_id_still_required():
    req = tool_request()
    body = json.loads(req.body)
    body["params"]["_meta"].update({"progressToken": 42, "role": "parent"})
    audit = Audit()
    assert gateway(audit=audit)(replace(req, body=json.dumps(body).encode())).status == 200
    assert audit.events[0]["role"] == "child"


def test_compile_database_preserves_useful_flags_and_discards_only_output_actions():
    rows = [
        {
            "directory": "/workspace/src",
            "file": "lib/a.cc",
            "arguments": [
                "g++",
                "-Iinclude",
                "-std=c++20",
                "-DDEBUG=1",
                "-pthread",
                "-c",
                "lib/a.cc",
                "-o",
                "a.o",
            ],
        }
    ]
    result = sanitize_compile_commands(rows, ("/workspace/src",))
    assert result[0]["arguments"] == [
        "/usr/bin/clang++",
        "-I",
        "/workspace/src/include",
        "-std=c++20",
        "-DDEBUG=1",
        "-pthread",
        "/workspace/src/lib/a.cc",
    ]


@pytest.mark.parametrize(
    "flags",
    [
        ["-Xclang", "-load", "evil.so"],
        ["-fplugin=evil.so"],
        ["@flags"],
        ["--config=evil"],
        ["-I/home/agent/.claude"],
        ["-isystem", "/etc"],
        ["-fmodules-cache-path=/workspace/output"],
    ],
)
def test_compile_database_rejects_executable_and_external_options(flags):
    rows = [
        {"directory": "/workspace/src", "file": "a.cc", "arguments": ["clang++", *flags, "a.cc"]}
    ]
    with pytest.raises(ToolServiceDenied):
        sanitize_compile_commands(rows, ("/workspace/src",))


class Wire:
    """Real byte socket counterpart, modelling an independent LSP server."""

    def __init__(self, response=None):
        self.client, self.server = socket.socketpair()
        self.received = []
        self.response = (
            response
            if response is not None
            else {"contents": {"kind": "plaintext", "value": "int n"}}
        )
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        stream = self.server.makefile("rb")
        try:
            while True:
                header = stream.readline()
                if not header:
                    break
                length = int(header.decode().split(":")[1])
                assert stream.readline() == b"\r\n"
                msg = json.loads(stream.read(length))
                self.received.append(msg)
                if "id" not in msg:
                    continue
                result = {"capabilities": {}} if msg["method"] == "initialize" else self.response
                data = json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}).encode()
                self.server.sendall(
                    b"Content-Length: " + str(len(data)).encode() + b"\r\n\r\n" + data
                )
        finally:
            stream.close()

    def close(self):
        self.client.close()
        self.server.close()


def test_lsp_framing_open_readonly_requests_and_reference_context():
    wire = Wire()
    reads = []

    def read(path):
        reads.append(path)
        return "int n = 1;\n"

    client = ClangdClient(
        wire.client, read_source=read, source_roots=("/workspace/src",), container_id="container-a"
    )
    try:
        result = client.invoke("hover", {"path": "/workspace/src/a.cc", "line": 0, "character": 4})
        assert result["contents"]["value"] == "int n"
        client.invoke("references", {"path": "/workspace/src/a.cc", "line": 0, "character": 4})
        methods = [m["method"] for m in wire.received]
        assert methods[:3] == ["initialize", "initialized", "textDocument/didOpen"]
        assert "textDocument/hover" in methods
        assert wire.received[-1]["params"]["context"] == {"includeDeclaration": True}
        assert reads == ["/workspace/src/a.cc", "/workspace/src/a.cc"]
    finally:
        wire.close()


@pytest.mark.parametrize(
    "args",
    [
        {"path": "/etc/passwd", "line": 0, "character": 0},
        {"path": "/workspace/src/../secret", "line": 0, "character": 0},
        {"path": "/workspace/src/a.cc", "line": -1, "character": 0},
        {"path": "/workspace/src/a.cc", "line": True, "character": 0},
        {"path": "/workspace/src/a.cc", "line": 0, "character": 0, "command": "id"},
    ],
)
def test_clangd_refuses_unbounded_source_and_operations_before_read(args):
    wire = Wire()
    client = ClangdClient(
        wire.client,
        read_source=lambda _: pytest.fail("read forbidden"),
        source_roots=("/workspace/src",),
        container_id="container-a",
    )
    try:
        with pytest.raises(ToolServiceDenied):
            client.invoke("hover", args)
    finally:
        wire.close()


def test_lsp_result_cannot_introduce_external_source_locations():
    wire = Wire(response=[{"uri": "file:///home/agent/.claude/settings.json", "range": {}}])
    client = ClangdClient(
        wire.client,
        read_source=lambda _: "int n;",
        source_roots=("/workspace/src",),
        container_id="container-a",
    )
    try:
        with pytest.raises(ToolServiceDenied):
            client.invoke("definition", {"path": "/workspace/src/a.cc", "line": 0, "character": 4})
    finally:
        wire.close()


def test_real_docker_multiplex_frames_and_fixed_agent_invocation():
    left, right = socket.socketpair()
    created = []

    class API:
        def exec_create(self, *args, **kwargs):
            created.append((args, kwargs))
            return {"Id": "exec-1"}

        def exec_start(self, identity, **kwargs):
            assert kwargs == {"socket": True, "tty": False}
            return left

    process = DockerClangdProcess(
        API(), container_id="container-a", source_roots=("/workspace/src",)
    )
    try:
        assert created[0][1]["user"] == "agent"
        command = created[0][1]["cmd"]
        assert command[:4] == ["/usr/bin/python3", "-I", "-S", "-c"]
        assert "--enable-config=false" in command[4]
        assert "--query-driver" not in command[4]
        compile(command[4], "<controller-clangd-launcher>", "exec")
        assert right.recv(6) == struct.pack(">I", 2) + b"[]"
        right.sendall(
            struct.pack(">BxxxI", 2, 4) + b"log\n" + struct.pack(">BxxxI", 1, 5) + b"hello"
        )
        assert process.recv(5) == b"hello"
        process.sendall(b"input")
        assert right.recv(5) == b"input"
    finally:
        process.close()
        right.close()


def docs_fixture(upstream, *, resolver=None, admission_transform=lambda x: x):
    audit = Audit()
    admission = admission_transform(_admission(audit))
    transport = VerifiedHTTPSNoRedirectTransport(
        transport=httpx.MockTransport(upstream),
        resolver=resolver
        or (
            lambda host, port: [
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443))
            ]
        ),
    )
    return DocumentationReader(
        policy=NetworkPolicy.load(POLICY),
        transport=transport,
        resolve_admission=lambda native, route: admission,
        audit=audit,
    ), audit


def test_docs_real_service_preserves_capability_policy_and_native_identity():
    outbound = []

    def upstream(req):
        outbound.append(req)
        return httpx.Response(
            200, text="Generic compiler reference", headers={"Content-Type": "text/plain"}
        )

    docs, audit = docs_fixture(upstream)
    args = {"route": "compiler", "url": "https://clang.llvm.org/docs/UsersManual.html"}
    reply = gateway(docs=docs)(tool_request("documentation", "fetch", args))
    assert reply.status == 200 and b"Generic compiler reference" in reply.body
    assert len(outbound) == 1 and any(
        getattr(e, "outcome", None) == "released" for e in audit.events
    )


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/secret",
        "https://github.com/project/fix",
        "https://clang.llvm.org/docs/CVE-2025-1234.html",
    ],
)
def test_docs_disallows_private_target_and_answer_urls_before_network(url):
    docs, _ = docs_fixture(lambda req: pytest.fail("forbidden fetch"))
    args = {"route": "compiler", "url": url}
    assert gateway(docs=docs)(tool_request("documentation", "fetch", args)).status == 403


def test_docs_rejects_capability_from_other_native_request():
    docs, _ = docs_fixture(
        lambda req: pytest.fail("forbidden fetch"),
        admission_transform=lambda a: replace(a, request=replace(a.request, request_id="other")),
    )
    args = {"route": "compiler", "url": "https://clang.llvm.org/docs/UsersManual.html"}
    assert gateway(docs=docs)(tool_request("documentation", "fetch", args)).status == 403
