# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Native-authorized registered MCP tools backed by container LSP and checked HTTPS."""

from __future__ import annotations

import asyncio
import hashlib
import json
import posixpath
import re
import shlex
import socket
import struct
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from urllib.parse import quote, unquote, urlencode, urlsplit

from .documentation_service import (
    DocumentationAdmission,
    DocumentationHTTPService,
    VerifiedHTTPSNoRedirectTransport,
)
from .host_boundary_runtime import AdmittedPeer, GatewayReply, GatewayRequest
from .native_tool_runtime import NativeToolCall
from .network import NetworkPolicy

_MAX_FRAME = 4 * 1024 * 1024
_MAX_SOURCE = 1024 * 1024
_METHODS = {
    "document_symbols": "textDocument/documentSymbol",
    "hover": "textDocument/hover",
    "definition": "textDocument/definition",
    "references": "textDocument/references",
}
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")


class ToolServiceDenied(PermissionError):
    """The request or response is outside the frozen read-only tool surface."""


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _decode(value):
    result = json.loads(value, object_pairs_hook=_pairs)
    _json(result)
    return result


def _path(value, roots):
    if (
        type(value) is not str
        or not value.startswith("/")
        or len(value) > 4096
        or any(ord(c) < 32 for c in value)
        or "\\" in value
        or "%" in value
        or posixpath.normpath(value) != value
        or "//" in value
        or not any(value.startswith(root + "/") for root in roots)
    ):
        raise ToolServiceDenied("source path outside frozen task roots")
    return value


def _roots(values):
    result = tuple(values)
    if (
        not result
        or len(set(result)) != len(result)
        or any(
            type(v) is not str
            or not v.startswith("/workspace/")
            or posixpath.normpath(v) != v
            or any(ord(c) < 32 for c in v)
            or "\\" in v
            or "%" in v
            for v in result
        )
    ):
        raise ValueError("explicit normalized task-container source roots required")
    return result


def _validate_tool(name, args):
    if name not in _METHODS or type(args) is not dict:
        raise ToolServiceDenied("unknown read-only clangd operation")
    expected = {"path"} if name == "document_symbols" else {"path", "line", "character"}
    if set(args) != expected or type(args["path"]) is not str:
        raise ToolServiceDenied("invalid clangd arguments")
    for field in expected - {"path"}:
        if type(args[field]) is not int or not 0 <= args[field] <= 1_000_000:
            raise ToolServiceDenied("invalid LSP position")


def sanitize_compile_commands(
    records: Sequence[Mapping], source_roots: Sequence[str]
) -> list[dict]:
    """Keep useful compile flags while excluding plugins, drivers and response files.

    Input is controller-observed task compilation data. It is never executed. A
    rejected database must be reviewed; unsafe flags are not silently stripped.
    The returned canonical database is copied into a private clangd directory.
    """
    roots = _roots(source_roots)
    if len(records) > 20000:
        raise ToolServiceDenied("compile database exceeds bound")
    result = []
    include_roots = (*roots, "/usr/include", "/usr/local/include")
    for row in records:
        if type(row) is not dict or set(row) - {
            "directory",
            "file",
            "arguments",
            "command",
            "output",
        }:
            raise ToolServiceDenied("unsupported compilation database row")
        directory = row.get("directory")
        if directory not in roots:
            _path(directory, roots)
        source = row.get("file")
        if type(source) is not str:
            raise ToolServiceDenied("source path missing")
        source = _path(posixpath.normpath(posixpath.join(directory, source)), roots)
        if ("arguments" in row) == ("command" in row):
            raise ToolServiceDenied("one compilation command representation required")
        argv = row.get("arguments") if "arguments" in row else shlex.split(row["command"])
        if (
            type(argv) is not list
            or not argv
            or len(argv) > 512
            or any(
                type(v) is not str or not v or len(v) > 4096 or any(ord(c) < 32 for c in v)
                for v in argv
            )
            or posixpath.basename(argv[0]) not in {"cc", "c++", "gcc", "g++", "clang", "clang++"}
        ):
            raise ToolServiceDenied("compilation driver or arguments denied")
        safe = [
            "/usr/bin/clang++"
            if posixpath.basename(argv[0]) in {"c++", "g++", "clang++"}
            else "/usr/bin/clang"
        ]
        i = 1
        while i < len(argv):
            arg = argv[i]
            if arg in {"-c", "-S", "-E"}:
                i += 1
                continue
            if arg == "-o":
                if i + 1 >= len(argv):
                    raise ToolServiceDenied("missing compile output")
                i += 2
                continue
            if arg == "-x":
                if i + 1 >= len(argv) or argv[i + 1] not in {
                    "c",
                    "c++",
                    "objective-c",
                    "objective-c++",
                }:
                    raise ToolServiceDenied("unknown source language")
                safe.extend(argv[i : i + 2])
                i += 2
                continue
            if arg in {"-I", "-isystem", "-iquote", "-include"} or arg.startswith("-I"):
                separate = arg in {"-I", "-isystem", "-iquote", "-include"}
                if separate and i + 1 >= len(argv):
                    raise ToolServiceDenied("missing include path")
                value = argv[i + 1] if separate else arg[2:]
                target = posixpath.normpath(posixpath.join(directory, value))
                if target not in include_roots:
                    _path(target, include_roots)
                safe.extend([arg if separate else "-I", target])
                i += 2 if separate else 1
                continue
            if (
                re.fullmatch(r"-std=[A-Za-z0-9+._-]+", arg)
                or re.fullmatch(r"-[DU][A-Za-z_][A-Za-z0-9_]*(=.*)?", arg)
                or re.fullmatch(r"-O[0-3sgz]", arg)
                or arg
                in {
                    "-g",
                    "-pthread",
                    "-fPIC",
                    "-fpic",
                    "-fno-exceptions",
                    "-fno-rtti",
                    "-ffreestanding",
                    "-nostdinc",
                    "-nostdinc++",
                    "-fms-extensions",
                    "-fms-compatibility",
                }
                or re.fullmatch(r"-W(?:no-)?[a-z][a-z0-9-]*", arg)
            ):
                safe.append(arg)
                i += 1
                continue
            if (
                not arg.startswith("-")
                and posixpath.normpath(posixpath.join(directory, arg)) == source
            ):
                i += 1
                continue
            raise ToolServiceDenied("compile flag outside audited allowlist")
        safe.append(source)
        result.append({"directory": directory, "file": source, "arguments": safe})
    if len(_json(result)) > _MAX_FRAME:
        raise ToolServiceDenied("compilation database exceeds byte limit")
    return result


# No shell, query driver, project .clangd, plugin or source-provided executable.
# The compilation database is the validated immutable snapshot supplied by the controller.
_LAUNCH = """import json,os,struct,tempfile
def exact(n):
 result=b""
 while len(result)<n:
  data=os.read(0,n-len(result))
  if not data: raise EOFError("missing frozen compiler database")
  result+=data
 return result
length=struct.unpack(">I",exact(4))[0]
if not 0<length<=4194304: raise ValueError("compiler database exceeds bound")
database=json.loads(exact(length))
d=tempfile.mkdtemp(prefix="xeus-clangd-",dir="/tmp")
os.chmod(d,0o700)
with open(d+"/compile_commands.json","x",encoding="utf-8") as f: json.dump(database,f)
os.execve("/usr/bin/clangd",["/usr/bin/clangd","--enable-config=false","--background-index=false","--clang-tidy=false","--pch-storage=memory","--log=error","--compile-commands-dir="+d],{"PATH":"/usr/bin:/bin","HOME":d,"LANG":"C.UTF-8","TMPDIR":d})
"""
_READ = """import os,stat,sys
parts=sys.argv[1].split("/")[1:]
fd=os.open("/",os.O_RDONLY|os.O_DIRECTORY)
try:
 for part in parts[:-1]:
  nextfd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=nextfd
 f=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
 try:
  if not stat.S_ISREG(os.fstat(f).st_mode): raise ValueError("not a regular source")
  data=b""
  while True:
   chunk=os.read(f,min(65536,1048577-len(data)))
   if not chunk: break
   data+=chunk
   if len(data)>1048576: raise ValueError("source exceeds bound")
  data.decode("utf-8");sys.stdout.buffer.write(data)
 finally: os.close(f)
finally: os.close(fd)
"""


class DockerClangdProcess:
    """Duplex Docker exec socket; stdin is raw, stdout is Docker-multiplexed."""

    def __init__(self, api, *, container_id: str, source_roots: Sequence[str], compile_commands=()):
        if type(container_id) is not str or not _ID.fullmatch(container_id):
            raise ValueError("frozen task container identity required")
        self.container_id, self.source_roots = container_id, _roots(source_roots)
        self._api, self._pending = api, bytearray()
        database = sanitize_compile_commands(compile_commands, self.source_roots)
        self.compile_database_sha256 = hashlib.sha256(_json(database)).hexdigest()
        created = api.exec_create(
            container_id,
            cmd=["/usr/bin/python3", "-I", "-S", "-c", _LAUNCH],
            user="agent",
            stdin=True,
            stdout=True,
            stderr=True,
            tty=False,
            workdir=self.source_roots[0],
            environment={"PATH": "/usr/bin:/bin"},
        )
        self.exec_id = created["Id"]
        self._handle = api.exec_start(self.exec_id, socket=True, tty=False)
        self._socket = getattr(self._handle, "_sock", self._handle)
        self.settimeout(20)
        encoded = _json(database)
        self.sendall(struct.pack(">I", len(encoded)) + encoded)

    def sendall(self, data):
        self._socket.sendall(data)

    def settimeout(self, seconds):
        self._socket.settimeout(seconds)
        self._deadline = time.monotonic() + seconds

    def _exact(self, size):
        data = bytearray()
        while len(data) < size:
            remaining = self._deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Docker exec receive deadline exceeded")
            self._socket.settimeout(remaining)
            chunk = self._socket.recv(size - len(data))
            if not chunk:
                raise EOFError("clangd exec closed")
            data.extend(chunk)
        return bytes(data)

    def recv(self, size):
        skipped, frames = 0, 0
        while not self._pending:
            frames += 1
            if frames > 1000:
                raise ToolServiceDenied("Docker exec frame count exceeded bound")
            header = self._exact(8)
            stream, length = struct.unpack(">BxxxI", header)
            if stream not in (1, 2) or header[1:4] != b"\0\0\0" or length > _MAX_FRAME:
                raise ToolServiceDenied("invalid Docker exec frame")
            payload = self._exact(length)
            if stream == 1:
                self._pending.extend(payload)
            else:
                skipped += length
                if skipped > _MAX_FRAME:
                    raise ToolServiceDenied("clangd stderr exceeded limit")
        result = bytes(self._pending[:size])
        del self._pending[:size]
        return result

    def read_source(self, path):
        path = _path(path, self.source_roots)
        result = self._api.exec_create(
            self.container_id,
            cmd=["/usr/bin/python3", "-I", "-S", "-c", _READ, path],
            user="agent",
            stdin=False,
            stdout=True,
            stderr=False,
            tty=False,
            workdir=self.source_roots[0],
            environment={"PATH": "/usr/bin:/bin"},
        )
        data = self._api.exec_start(result["Id"], stream=False, tty=False)
        inspected = self._api.exec_inspect(result["Id"])
        if (
            inspected.get("ExitCode") != 0
            or inspected.get("Running") is not False
            or type(data) is not bytes
            or len(data) > _MAX_SOURCE
        ):
            raise ToolServiceDenied("source file unavailable")
        return data.decode("utf-8")

    def close(self):
        try:
            self._socket.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        self._handle.close()


class ClangdClient:
    """Serial bounded LSP session exposing only four read operations."""

    def __init__(
        self,
        channel,
        *,
        read_source: Callable[[str], str],
        source_roots: Sequence[str],
        container_id: str,
        timeout_seconds=20,
    ):
        if not callable(read_source) or not 0 < timeout_seconds <= 60:
            raise ValueError("bounded source reader and timeout required")
        self.container_id, self.source_roots = container_id, _roots(source_roots)
        self._channel, self._read = channel, read_source
        self._timeout, self._sequence, self._started = timeout_seconds, 0, False
        self._buffer, self._lock, self._opened = bytearray(), threading.RLock(), {}
        self._broken = False
        self.compile_database_sha256 = getattr(channel, "compile_database_sha256", None)

    @classmethod
    def for_docker(cls, api, *, container_id, source_roots, compile_commands=()):
        process = DockerClangdProcess(
            api,
            container_id=container_id,
            source_roots=source_roots,
            compile_commands=compile_commands,
        )
        return cls(
            process,
            read_source=process.read_source,
            source_roots=source_roots,
            container_id=container_id,
        )

    def _send(self, message):
        payload = _json(message)
        if len(payload) > _MAX_FRAME:
            raise ToolServiceDenied("LSP request exceeded bound")
        self._channel.sendall(
            b"Content-Length: " + str(len(payload)).encode() + b"\r\n\r\n" + payload
        )

    def _receive(self, deadline):
        while b"\r\n\r\n" not in self._buffer:
            if len(self._buffer) > 8192:
                raise ToolServiceDenied("LSP header exceeded bound")
            self._more(deadline)
        offset = self._buffer.index(b"\r\n\r\n")
        headers = bytes(self._buffer[:offset]).decode("ascii").split("\r\n")
        parsed = {}
        for header in headers:
            name, value = header.split(":", 1)
            name = name.lower()
            if name in parsed or name not in {"content-length", "content-type"}:
                raise ToolServiceDenied("invalid LSP header")
            parsed[name] = value.strip()
        length = int(parsed["content-length"])
        if not 0 < length <= _MAX_FRAME:
            raise ToolServiceDenied("invalid LSP body length")
        offset += 4
        while len(self._buffer) < offset + length:
            self._more(deadline)
        body = bytes(self._buffer[offset : offset + length])
        del self._buffer[: offset + length]
        return _decode(body)

    def _more(self, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("LSP deadline exceeded")
        self._channel.settimeout(remaining)
        chunk = self._channel.recv(65536)
        if not chunk:
            raise EOFError("LSP process closed")
        self._buffer.extend(chunk)

    def _request(self, method, params):
        self._sequence += 1
        identity = self._sequence
        self._send({"jsonrpc": "2.0", "id": identity, "method": method, "params": params})
        deadline = time.monotonic() + self._timeout
        for _ in range(1000):
            message = self._receive(deadline)
            if type(message) is not dict or message.get("jsonrpc") != "2.0":
                raise ToolServiceDenied("invalid LSP response")
            if "id" not in message and message.get("method") in {
                "textDocument/publishDiagnostics",
                "window/logMessage",
                "$/progress",
                "window/showMessage",
            }:
                continue
            if (
                message.get("id") != identity
                or "method" in message
                or "error" in message
                or "result" not in message
            ):
                raise ToolServiceDenied("unexpected LSP reply")
            return message["result"]
        raise ToolServiceDenied("LSP notifications exceeded bound")

    def _check_result(self, value, depth=0):
        if depth > 32:
            raise ToolServiceDenied("LSP result nesting exceeded bound")
        if isinstance(value, dict):
            for key, item in value.items():
                if key in {"uri", "targetUri"}:
                    if type(item) is not str:
                        raise ToolServiceDenied("invalid LSP location")
                    parsed = urlsplit(item)
                    if parsed.scheme != "file" or parsed.netloc or parsed.query or parsed.fragment:
                        raise ToolServiceDenied("external LSP location denied")
                    _path(unquote(parsed.path), self.source_roots)
                self._check_result(item, depth + 1)
        elif isinstance(value, list):
            for item in value:
                self._check_result(item, depth + 1)

    def invoke(self, name, args):
        _validate_tool(name, args)
        path = _path(args["path"], self.source_roots)
        with self._lock:
            if self._broken:
                raise ToolServiceDenied("LSP session unavailable")
            content = self._read(path)
            if type(content) is not str or len(content.encode("utf-8")) > _MAX_SOURCE:
                raise ToolServiceDenied("source text exceeds bound")
            if name != "document_symbols":
                lines = content.split("\n")
                if (
                    args["line"] >= len(lines)
                    or args["character"] > len(lines[args["line"]].encode("utf-16-le")) // 2
                ):
                    raise ToolServiceDenied("position outside source text")
            try:
                if not self._started:
                    self._request(
                        "initialize",
                        {
                            "processId": None,
                            "rootUri": "file://" + quote(self.source_roots[0]),
                            "capabilities": {
                                "general": {"positionEncodings": ["utf-16"]},
                                "textDocument": {
                                    "documentSymbol": {"hierarchicalDocumentSymbolSupport": True}
                                },
                            },
                            "initializationOptions": {"clangdFileStatus": False},
                        },
                    )
                    self._send({"jsonrpc": "2.0", "method": "initialized", "params": {}})
                    self._started = True
                uri = "file://" + quote(path)
                version = self._opened.get(path, 0) + 1
                if version == 1:
                    self._send(
                        {
                            "jsonrpc": "2.0",
                            "method": "textDocument/didOpen",
                            "params": {
                                "textDocument": {
                                    "uri": uri,
                                    "languageId": "c" if path.endswith(".c") else "cpp",
                                    "version": version,
                                    "text": content,
                                }
                            },
                        }
                    )
                else:
                    self._send(
                        {
                            "jsonrpc": "2.0",
                            "method": "textDocument/didChange",
                            "params": {
                                "textDocument": {"uri": uri, "version": version},
                                "contentChanges": [{"text": content}],
                            },
                        }
                    )
                self._opened[path] = version
                params = {"textDocument": {"uri": uri}}
                if name != "document_symbols":
                    params["position"] = {"line": args["line"], "character": args["character"]}
                if name == "references":
                    params["context"] = {"includeDeclaration": True}
                result = self._request(_METHODS[name], params)
                self._check_result(result)
                return result
            except Exception:
                self._broken = True
                self._channel.close()
                raise

    def close(self):
        with self._lock:
            try:
                if self._started and not self._broken:
                    self._request("shutdown", None)
                    self._send({"jsonrpc": "2.0", "method": "exit", "params": {}})
            finally:
                self._broken = True
                self._channel.close()


class DocumentationReader:
    """Bind native controller identity to the existing audited documentation ASGI service."""

    def __init__(
        self,
        *,
        policy: NetworkPolicy,
        transport: VerifiedHTTPSNoRedirectTransport,
        resolve_admission: Callable[[NativeToolCall, str], DocumentationAdmission | None],
        audit,
    ):
        if (
            type(policy) is not NetworkPolicy
            or type(transport) is not VerifiedHTTPSNoRedirectTransport
            or not callable(resolve_admission)
        ):
            raise TypeError(
                "frozen documentation policy, transport and capability resolver required"
            )
        self._policy, self._transport, self._resolve, self._audit = (
            policy,
            transport,
            resolve_admission,
            audit,
        )

    def invoke(self, native, args):
        if (
            type(args) is not dict
            or set(args) != {"route", "url"}
            or args["route"] not in {"compiler", "python"}
            or type(args["url"]) is not str
        ):
            raise ToolServiceDenied("unknown documentation operation")
        route = "documentation/" + args["route"] + "/reference-v1"
        admission = self._resolve(native, route)
        if (
            type(admission) is not DocumentationAdmission
            or admission.request.task_id != native.task_id
            or admission.request.attempt_id != native.attempt_id
            or admission.request.request_id != native.request_id
            or admission.authorizer.trusted_role.value != native.role
            or admission.request.routes != (route,)
        ):
            raise ToolServiceDenied("documentation capability does not match native invocation")
        service = DocumentationHTTPService(
            self._policy, self._transport, lambda scope: admission, self._audit
        )
        sent = []

        async def send(message):
            sent.append(message)

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        asyncio.run(
            service(
                {
                    "type": "http",
                    "method": "GET",
                    "path": "/v1/" + route,
                    "query_string": urlencode({"url": args["url"]}).encode(),
                    "headers": [],
                },
                receive,
                send,
            )
        )
        if len(sent) != 2 or sent[0].get("status") != 200:
            raise ToolServiceDenied("documentation fetch denied or unavailable")
        return {"route": args["route"], "url": args["url"], "text": sent[1]["body"].decode("utf-8")}


def _schema(server):
    if server == "documentation":
        return [
            {
                "name": "fetch",
                "description": "Read allowed generic compiler or Python reference documentation.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "route": {"type": "string", "enum": ["compiler", "python"]},
                        "url": {"type": "string", "maxLength": 4096},
                    },
                    "required": ["route", "url"],
                    "additionalProperties": False,
                },
                "annotations": {"readOnlyHint": True, "destructiveHint": False},
            }
        ]
    tools = []
    for name in _METHODS:
        properties = {
            "path": {
                "type": "string",
                "description": "Absolute path under the supplied task source root.",
            }
        }
        if name != "document_symbols":
            properties.update(
                {
                    key: {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Zero-based UTF-16 LSP position.",
                    }
                    for key in ("line", "character")
                }
            )
        tools.append(
            {
                "name": name,
                "description": "Inspect supplied source through container clangd.",
                "inputSchema": {
                    "type": "object",
                    "properties": properties,
                    "required": list(properties),
                    "additionalProperties": False,
                },
                "annotations": {"readOnlyHint": True, "destructiveHint": False},
            }
        )
    return tools


class RegisteredToolGateway:
    """GatewayRequest -> GatewayReply MCP adapter with controller-only native grants."""

    def __init__(
        self,
        *,
        clangd: ClangdClient,
        documentation: DocumentationReader | None,
        authorize_peer: Callable[[AdmittedPeer], bool],
        resolve_caller: Callable[[AdmittedPeer, str, str, Mapping], NativeToolCall | None],
        audit,
        task_id: str,
        attempt_id: str,
    ):
        if (
            not callable(authorize_peer)
            or not callable(resolve_caller)
            or not callable(getattr(audit, "record", None))
        ):
            raise TypeError("controller authority and durable audit required")
        self._clangd, self._docs = clangd, documentation
        self._peer, self._resolve, self._audit = authorize_peer, resolve_caller, audit
        self._task, self._attempt = task_id, attempt_id

    @staticmethod
    def _reply(status, payload):
        return GatewayReply(status, _json(payload), headers=(("Cache-Control", "no-store"),))

    def __call__(self, request: GatewayRequest) -> GatewayReply:
        try:
            if (
                request.endpoint != "registered-tool-gateway"
                or request.method != "POST"
                or request.path not in {"/mcp/clangd", "/mcp/documentation"}
                or type(request.body) is not bytes
                or len(request.body) > 65536
                or self._peer(request.peer) is not True
                or request.peer.container_id != self._clangd.container_id
                or (request.disconnected is not None and request.disconnected.is_set())
            ):
                raise ToolServiceDenied()
            headers = {}
            for key, value in request.headers:
                key = key.lower()
                if (
                    key in headers
                    or key
                    not in {
                        "host",
                        "content-type",
                        "content-length",
                        "accept",
                        "accept-encoding",
                        "user-agent",
                        "connection",
                        "mcp-method",
                        "mcp-protocol-version",
                        "mcp-session-id",
                    }
                    or any(c in value for c in "\r\n\x00")
                ):
                    raise ToolServiceDenied()
                headers[key] = value
            if (
                headers.get("content-type", "application/json").split(";")[0].strip().lower()
                != "application/json"
            ):
                raise ValueError()
            body = _decode(request.body)
            if (
                type(body) is not dict
                or set(body) - {"jsonrpc", "id", "method", "params"}
                or body.get("jsonrpc") != "2.0"
            ):
                raise ValueError()
            method, params = body.get("method"), body.get("params", {})
            if type(params) is not dict:
                raise ValueError()
            if method == "notifications/initialized" and "id" not in body and not params:
                return GatewayReply(202, b"")
            if type(body.get("id")) not in {str, int} or len(str(body["id"])) > 128:
                raise ValueError()
            server = request.path.rsplit("/", 1)[1]
            if method == "initialize":
                if set(params) != {"protocolVersion", "clientInfo", "capabilities"} or params[
                    "protocolVersion"
                ] not in {"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}:
                    raise ValueError()
                result = {
                    "protocolVersion": params["protocolVersion"],
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": server, "version": "xeus-registered-1"},
                }
            elif method == "tools/list" and not params:
                result = {"tools": _schema(server)}
            elif method == "ping" and not params:
                result = {}
            elif method == "tools/call":
                result = self._call(request.peer, server, params)
            else:
                raise ToolServiceDenied()
            return self._reply(200, {"jsonrpc": "2.0", "id": body["id"], "result": result})
        except PermissionError:
            return self._reply(403, {"error": "registered tool denied"})
        except (ValueError, TypeError):
            return self._reply(400, {"error": "invalid registered tool request"})
        except Exception:
            return self._reply(503, {"error": "registered tool unavailable"})

    def _call(self, peer, server, params):
        if (
            set(params) != {"name", "arguments", "_meta"}
            or type(params["_meta"]) is not dict
            or "claudecode/toolUseId" not in params["_meta"]
        ):
            raise ToolServiceDenied()
        name, args, identity = (
            params["name"],
            params["arguments"],
            params["_meta"]["claudecode/toolUseId"],
        )
        if (
            type(identity) is not str
            or not _ID.fullmatch(identity)
            or type(name) is not str
            or type(args) is not dict
        ):
            raise ToolServiceDenied()
        if server == "clangd":
            _validate_tool(name, args)
        elif (
            name != "fetch"
            or set(args) != {"route", "url"}
            or args["route"] not in {"compiler", "python"}
            or type(args["url"]) is not str
            or not 0 < len(args["url"]) <= 4096
        ):
            raise ToolServiceDenied()
        native_name = "mcp__" + server + "__" + name
        native = self._resolve(peer, identity, native_name, dict(args))
        if (
            type(native) is not NativeToolCall
            or native.task_id != self._task
            or native.attempt_id != self._attempt
            or native.role not in {"parent", "child"}
            or native.tool_id != identity
            or native.name != native_name
            or dict(native.arguments) != args
        ):
            raise ToolServiceDenied()
        event = {
            "event": "registered_tool_request",
            "task_id": self._task,
            "attempt_id": self._attempt,
            "request_id": native.request_id,
            "tool_use_id": identity,
            "native_tool": native_name,
            "role": native.role,
            "container_id": peer.container_id,
            "arguments_sha256": hashlib.sha256(_json(args)).hexdigest(),
        }
        if self._audit.record(event) is not True:
            raise RuntimeError("request audit unavailable")
        try:
            if server == "clangd":
                value = self._clangd.invoke(name, args)
            else:
                if self._docs is None:
                    raise ToolServiceDenied("documentation service unavailable")
                value = self._docs.invoke(native, args)
            encoded = _json(value)
            if len(encoded) > _MAX_FRAME:
                raise ToolServiceDenied("tool result exceeds bound")
        except Exception:
            self._audit.record(
                {
                    **event,
                    "event": "registered_tool_result",
                    "outcome": "failed",
                    "result_sha256": None,
                }
            )
            raise
        if (
            self._audit.record(
                {
                    **event,
                    "event": "registered_tool_result",
                    "outcome": "released",
                    "result_sha256": hashlib.sha256(encoded).hexdigest(),
                    "bytes_released": len(encoded),
                }
            )
            is not True
        ):
            raise RuntimeError("result audit unavailable")
        return {"content": [{"type": "text", "text": encoded.decode()}], "isError": False}
