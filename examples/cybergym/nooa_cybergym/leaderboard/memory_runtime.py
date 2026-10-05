"""Signed native GBrain discovery and the controller's read-only HTTP/MCP route."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from xeus_cybergym.canonical import canonical_json
from xeus_cybergym.ledger import Ed25519Verifier, SignedEnvelope

from .host_boundary_runtime import AdmittedPeer, GatewayReply, GatewayRequest
from .memory import (
    READ_TOOLS,
    SOURCE_ID,
    AllowedPage,
    AuditSink,
    Caller,
    ManifestAttestation,
    MemoryFacade,
    MemoryUnavailable,
    UnsafeMemory,
)
from .memory_transport import (
    CatalogAttestation,
    ControllerMcpBridge,
    ControllerMemoryTransport,
    RuntimeReadEvidence,
    TransportDenied,
)

_PROFILE = "/srv/sunchaser/gbrain-profiles/xeus-cybergym"
_HASH = re.compile(r"[a-f0-9]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
_META_HASHES = (
    "source_tree_sha256",
    "runtime_sha256",
    "native_guard_sha256",
    "backend_identity_sha256",
)
_META_FIELDS = (*_META_HASHES, "gbrain_version", "profile", "client_id", "grant_revision")
_CATALOG_FIELDS = frozenset(
    {
        "schema_version",
        "artifact_kind",
        "observed_at",
        "source_ids",
        "server_context_source_id",
        "native_guard_binding_sha256",
        "tools",
        "tool_names",
        "catalog_sha256",
        "server_info",
        "server_info_sha256",
        "protocol_version",
        "backend",
    }
)
_MANIFEST_FIELDS = frozenset(
    {
        "schema_version",
        "artifact_kind",
        "created_at",
        "source_id",
        "catalog_envelope_sha256",
        "pages",
    }
)
_SOLVER_TOOLS = [
    {
        "name": name,
        "description": "Read reviewed generic CyberGym memory with audited provenance.",
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string", "minLength": 1, "maxLength": 1000}},
            "required": ["query"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False},
    }
    for name in ("recall", "search")
]


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and _HASH.fullmatch(value) is not None


def _canonical(value: Any) -> bytes:
    # Native canonical_json is also used for lists in the existing signing API.
    return canonical_json(value)


def _scope(bridge) -> dict:
    observed = bridge.inspection()
    current = bridge.read_evidence()
    if (
        not isinstance(observed, dict)
        or type(current) is not RuntimeReadEvidence
        or observed.get("source_ids") != [SOURCE_ID]
        or current.source_ids != frozenset({SOURCE_ID})
        or current.server_context_source_id != SOURCE_ID
        or observed.get("server_context_source_id") != SOURCE_ID
        or observed.get("scopes") != ["read"]
        or observed.get("session_mode") != "read"
        or observed.get("transport") != "native-guarded-stdio"
        or set(observed.get("allowed_operations", [])) != READ_TOOLS
        or current.native_guard_bound is not True
        or observed.get("native_guard_bound") is not True
        or current.native_guard_binding_sha256 != observed.get("native_guard_binding_sha256")
        or not _is_digest(current.native_guard_binding_sha256)
        or observed.get("profile") != _PROFILE
        or any(not _is_digest(observed.get(name)) for name in _META_HASHES)
        or not isinstance(observed.get("client_id"), str)
        or not observed["client_id"]
        or type(observed.get("grant_revision")) is not int
        or observed["grant_revision"] < 1
    ):
        raise TransportDenied("authenticated discovery scope or native guard is invalid")
    return {key: observed[key] for key in _META_FIELDS} | {
        "native_guard_binding_sha256": current.native_guard_binding_sha256
    }


@dataclass(frozen=True, slots=True)
class SignedMemoryBundle:
    signed_catalog: bytes
    signed_manifest: bytes


def build_signed_memory_bundle(*, bridge, signer, verifier) -> SignedMemoryBundle:
    """Discover an authenticated native session and sign an initially empty allowlist.

    Empty ``pages`` is a deny-all publication policy, not a claim that the source
    database is empty. No catalog, backend hash, credential scope or page is
    supplied by client assertion. The existing Xeus signer/verifier own signing.
    """
    try:
        before = _scope(bridge)

        def exchange(method, params):
            request_id = uuid4().hex
            reply = bridge.exchange(
                {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params},
                timeout_seconds=30,
            )
            if (
                not isinstance(reply, Mapping)
                or reply.get("jsonrpc") != "2.0"
                or reply.get("id") != request_id
                or "error" in reply
                or not isinstance(reply.get("result"), dict)
            ):
                raise ValueError()
            return reply["result"]

        initialized = exchange(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "xeus-cybergym-memory-certifier", "version": "1"},
            },
        )
        server = initialized.get("serverInfo")
        if (
            initialized.get("protocolVersion") != "2025-06-18"
            or not isinstance(server, dict)
            or server.get("name") != "gbrain"
            or server.get("version") != before["gbrain_version"]
            or not isinstance(initialized.get("capabilities"), dict)
        ):
            raise ValueError()
        bridge.notify({"jsonrpc": "2.0", "method": "notifications/initialized"})
        tools, seen, cursor = [], set(), None
        for _ in range(16):
            page = exchange("tools/list", {} if cursor is None else {"cursor": cursor})
            if not isinstance(page.get("tools"), list):
                raise ValueError()
            tools.extend(page["tools"])
            cursor = page.get("nextCursor")
            if cursor is None:
                break
            if not isinstance(cursor, str) or not cursor or cursor in seen:
                raise ValueError()
            seen.add(cursor)
        else:
            raise ValueError()
        if (
            any(
                not isinstance(tool, dict) or not isinstance(tool.get("inputSchema"), dict)
                for tool in tools
            )
            or len(tools) != 3
            or {tool.get("name") for tool in tools} != READ_TOOLS
        ):
            raise ValueError()
        tools = sorted(tools, key=lambda tool: tool["name"])
        if _scope(bridge) != before:
            raise ValueError()
        now = datetime.now(UTC).isoformat()
        catalog = {
            "schema_version": 1,
            "artifact_kind": "memory_catalog",
            "observed_at": now,
            "source_ids": [SOURCE_ID],
            "server_context_source_id": SOURCE_ID,
            "native_guard_binding_sha256": before["native_guard_binding_sha256"],
            "backend": {key: before[key] for key in _META_FIELDS},
            "tools": tools,
            "tool_names": sorted(READ_TOOLS),
            "catalog_sha256": _sha(_canonical(tools)),
            "server_info": server,
            "server_info_sha256": _sha(_canonical(server)),
            "protocol_version": initialized["protocolVersion"],
        }

        def sign(payload):
            encoded = _canonical(payload)
            envelope = signer.sign(encoded)
            if verifier.verify(envelope) != encoded:
                raise ValueError()
            return _canonical(envelope)

        signed_catalog = sign(catalog)
        signed_manifest = sign(
            {
                "schema_version": 1,
                "artifact_kind": "memory_manifest",
                "created_at": now,
                "source_id": SOURCE_ID,
                "catalog_envelope_sha256": _sha(signed_catalog),
                "pages": [],
            }
        )
        return SignedMemoryBundle(signed_catalog, signed_manifest)
    except Exception:
        raise TransportDenied(
            "authenticated native discovery or authority signing failed"
        ) from None


class MemoryAuthority:
    """Verify native Xeus envelopes and convert their exact payloads to facade contracts."""

    def __init__(self, public_keys: Mapping[str, Any]):
        if not public_keys:
            raise ValueError("trusted Xeus public-key registry required")
        self._verifier = Ed25519Verifier(public_keys)

    def _verify(self, envelope: bytes, kind: str):
        if type(envelope) is not bytes or not 0 < len(envelope) <= 4 * 1024 * 1024:
            raise ValueError()
        parsed = SignedEnvelope.model_validate_json(envelope)
        raw = self._verifier.verify(parsed)
        payload = json.loads(raw)
        if (
            not isinstance(payload, dict)
            or payload.get("artifact_kind") != kind
            or type(payload.get("schema_version")) is not int
            or payload["schema_version"] != 1
            or _canonical(payload) != raw
        ):
            raise ValueError()
        return payload, parsed.key_id

    def attest_catalog(self, envelope: bytes) -> CatalogAttestation:
        try:
            payload, key_id = self._verify(envelope, "memory_catalog")
            tools, backend = payload["tools"], payload["backend"]
            if (
                set(payload) != _CATALOG_FIELDS
                or payload["source_ids"] != [SOURCE_ID]
                or payload["server_context_source_id"] != SOURCE_ID
                or payload["tool_names"] != sorted(READ_TOOLS)
                or len(tools) != 3
                or {tool["name"] for tool in tools} != READ_TOOLS
                or any(not isinstance(tool.get("inputSchema"), dict) for tool in tools)
                or tools != sorted(tools, key=lambda tool: tool["name"])
                or _sha(_canonical(tools)) != payload["catalog_sha256"]
                or _sha(_canonical(payload["server_info"])) != payload["server_info_sha256"]
                or set(backend) != set(_META_FIELDS)
                or backend["profile"] != _PROFILE
                or any(not _is_digest(backend[name]) for name in _META_HASHES)
                or payload["server_info"].get("name") != "gbrain"
                or payload["server_info"].get("version") != backend["gbrain_version"]
                or payload["protocol_version"] != "2025-06-18"
            ):
                raise ValueError()
            return CatalogAttestation(
                _sha(envelope),
                key_id,
                payload["catalog_sha256"],
                frozenset(payload["tool_names"]),
                frozenset(payload["source_ids"]),
                payload["server_context_source_id"],
                payload["native_guard_binding_sha256"],
                payload["server_info_sha256"],
                payload["protocol_version"],
            )
        except Exception:
            raise TransportDenied("signed native memory catalog verification failed") from None

    def attest_manifest(
        self, envelope: bytes, *, catalog_envelope_sha256: str
    ) -> ManifestAttestation:
        try:
            payload, key_id = self._verify(envelope, "memory_manifest")
            if (
                set(payload) != _MANIFEST_FIELDS
                or payload["source_id"] != SOURCE_ID
                or not _is_digest(catalog_envelope_sha256)
                or payload["catalog_envelope_sha256"] != catalog_envelope_sha256
                or not isinstance(payload["pages"], list)
            ):
                raise ValueError()
            pages = tuple(
                AllowedPage(**(page | {"structural_terms": tuple(page["structural_terms"])}))
                for page in payload["pages"]
            )
            return ManifestAttestation(SOURCE_ID, _sha(envelope), key_id, pages)
        except Exception:
            raise TransportDenied("signed native memory manifest verification failed") from None


@dataclass(frozen=True, slots=True)
class TrustedMemoryCaller:
    task_id: str
    attempt_id: str
    caller: Caller
    model_id: str
    structural_terms: tuple[str, ...]

    def __post_init__(self):
        if (
            any(
                not isinstance(value, str) or not _ID.fullmatch(value)
                for value in (self.task_id, self.attempt_id, self.model_id)
            )
            or type(self.caller) is not Caller
            or self.caller not in (Caller.PARENT, Caller.CHILD)
            or not isinstance(self.structural_terms, tuple)
            or any(not isinstance(term, str) or not term.strip() for term in self.structural_terms)
        ):
            raise ValueError("verified native memory caller identity required")


def _unique(pairs):
    parsed = {}
    for key, value in pairs:
        if key in parsed:
            raise ValueError("duplicate field")
        parsed[key] = value
    return parsed


class MemoryGatewayHandler:
    """Stateless MCP over HTTP with server-derived task/parent/child authority."""

    def __init__(
        self,
        *,
        facade: MemoryFacade,
        authorize_peer: Callable[[AdmittedPeer], bool],
        resolve_caller: Callable[
            [AdmittedPeer, str, str, Mapping[str, object]], TrustedMemoryCaller | None
        ],
        audit: AuditSink,
        task_id: str,
        attempt_id: str,
    ):
        if (
            not isinstance(facade, MemoryFacade)
            or not callable(resolve_caller)
            or not callable(authorize_peer)
        ):
            raise TypeError("strict memory facade and verified native caller resolver required")
        if any(
            not isinstance(value, str) or not _ID.fullmatch(value)
            for value in (task_id, attempt_id)
        ):
            raise ValueError("frozen task identity required")
        self._facade, self._resolve, self._audit = facade, resolve_caller, audit
        self._authorize_peer = authorize_peer
        self._task, self._attempt = task_id, attempt_id

    def automatic_recall(self, *, level1_facts: Sequence[str], structural_terms: Sequence[str]):
        """Controller hook only; this operation has no HTTP/MCP route."""
        return self._facade.automatic_recall(
            level1_facts=level1_facts,
            structural_terms=structural_terms,
            task_id=self._task,
            attempt_id=self._attempt,
            request_id="memory-auto-" + uuid4().hex,
        )

    @staticmethod
    def _reply(status, payload):
        return GatewayReply(status, _canonical(payload), headers=(("Cache-Control", "no-store"),))

    def __call__(self, request: GatewayRequest) -> GatewayReply:
        request_id = "memory-http-" + uuid4().hex
        try:
            if (
                request.endpoint != "gbrain-read-gateway"
                or request.method != "POST"
                or request.path not in {"/mcp", "/recall", "/search"}
                or type(request.body) is not bytes
                or len(request.body) > 65536
                or (request.disconnected is not None and request.disconnected.is_set())
            ):
                raise PermissionError()
            if self._authorize_peer(request.peer) is not True:
                raise PermissionError()
            headers = {}
            allowed_headers = {
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
            for name, value in request.headers:
                name = name.lower()
                if (
                    name not in allowed_headers
                    or name in headers
                    or any(char in value for char in "\r\n\x00")
                ):
                    raise PermissionError()
                headers[name] = value
            if (
                headers.get("content-type", "application/json").split(";", 1)[0].strip().lower()
                != "application/json"
            ):
                raise ValueError()
            body = json.loads(
                request.body,
                object_pairs_hook=_unique,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
            )
            if not isinstance(body, dict):
                raise ValueError()
            if (
                self._audit.record(
                    {
                        "event": "memory_http_admitted",
                        "request_id": request_id,
                        "task_id": self._task,
                        "attempt_id": self._attempt,
                        "path": request.path,
                    }
                )
                is not True
            ):
                raise RuntimeError()
            if request.path == "/mcp":
                if (
                    set(body) - {"jsonrpc", "id", "method", "params"}
                    or body.get("jsonrpc") != "2.0"
                    or not isinstance(body.get("method"), str)
                ):
                    raise ValueError()
                method, rpc_id = body["method"], body.get("id")
                if (
                    method == "notifications/initialized"
                    and "id" not in body
                    and not body.get("params")
                ):
                    return GatewayReply(202, b"")
                if type(rpc_id) not in (str, int) or (
                    isinstance(rpc_id, str) and len(rpc_id) > 128
                ):
                    raise ValueError()
                params = body.get("params", {})
                if not isinstance(params, dict):
                    raise ValueError()
                if method == "initialize":
                    if set(params) != {"protocolVersion", "clientInfo", "capabilities"} or params[
                        "protocolVersion"
                    ] not in {"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}:
                        raise ValueError()
                    result = {
                        "protocolVersion": params["protocolVersion"],
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "gbrain", "version": "xeus-read-facade-1"},
                    }
                elif method == "tools/list":
                    if params:
                        raise PermissionError()
                    result = {"tools": _SOLVER_TOOLS}
                elif method == "ping":
                    if params:
                        raise PermissionError()
                    result = {}
                elif method == "tools/call":
                    if (
                        set(params) != {"name", "arguments", "_meta"}
                        or not isinstance(params["_meta"], dict)
                        or "claudecode/toolUseId" not in params["_meta"]
                    ):
                        raise PermissionError()
                    data = self._read(
                        params["name"],
                        params["arguments"],
                        params["_meta"]["claudecode/toolUseId"],
                        request.peer,
                        request_id,
                    )
                    result = {
                        "content": [{"type": "text", "text": _canonical(data).decode()}],
                        "isError": False,
                    }
                else:
                    raise PermissionError()
                return self._reply(200, {"jsonrpc": "2.0", "id": rpc_id, "result": result})
            if set(body) != {"query", "tool_use_id"}:
                raise PermissionError()
            return self._reply(
                200,
                self._read(
                    request.path[1:],
                    {"query": body["query"]},
                    body["tool_use_id"],
                    request.peer,
                    request_id,
                ),
            )
        except (PermissionError, UnsafeMemory, TransportDenied):
            return self._reply(403, {"error": "memory route denied"})
        except (ValueError, TypeError):
            return self._reply(400, {"error": "invalid memory request"})
        except MemoryUnavailable:
            return self._reply(503, {"error": "memory unavailable"})
        except Exception:
            return self._reply(503, {"error": "memory unavailable"})

    def _read(self, name, arguments, tool_use_id, peer, request_id):
        if (
            name not in {"recall", "search"}
            or not isinstance(arguments, dict)
            or set(arguments) != {"query"}
            or not isinstance(arguments["query"], str)
            or not 0 < len(arguments["query"].strip()) <= 1000
            or not isinstance(tool_use_id, str)
            or not _ID.fullmatch(tool_use_id)
        ):
            raise PermissionError()
        caller = self._resolve(peer, tool_use_id, name, dict(arguments))
        if (
            type(caller) is not TrustedMemoryCaller
            or caller.task_id != self._task
            or caller.attempt_id != self._attempt
        ):
            raise PermissionError()
        if (
            self._audit.record(
                {
                    "event": "memory_native_tool_admitted",
                    "request_id": request_id,
                    "native_tool_use_id": tool_use_id,
                    "tool": name,
                    "task_id": self._task,
                    "attempt_id": self._attempt,
                    "caller": caller.caller.value,
                    "model_id": caller.model_id,
                }
            )
            is not True
        ):
            raise RuntimeError()
        selections = self._facade.model_tool(
            name,
            arguments["query"],
            caller=caller.caller,
            structural_terms=caller.structural_terms,
            task_id=self._task,
            attempt_id=self._attempt,
            request_id=request_id,
            model_id=caller.model_id,
        )
        return {"source_id": SOURCE_ID, "results": [asdict(selection) for selection in selections]}


def build_memory_gateway(
    *,
    bridge: ControllerMcpBridge,
    signed_catalog: bytes,
    signed_manifest: bytes,
    public_keys: Mapping[str, Any],
    audit: AuditSink,
    answer_filter: Callable[[str], bool],
    token_counter: Callable[[str], int],
    authorize_peer: Callable[[AdmittedPeer], bool],
    resolve_caller: Callable[
        [AdmittedPeer, str, str, Mapping[str, object]], TrustedMemoryCaller | None
    ],
    task_id: str,
    attempt_id: str,
) -> MemoryGatewayHandler:
    """Wire the existing authority, strict native transport and provenance facade."""
    authority = MemoryAuthority(public_keys)
    transport = ControllerMemoryTransport(
        bridge=bridge, signed_catalog=signed_catalog, attest_catalog=authority.attest_catalog
    )
    facade = MemoryFacade(
        transport=transport,
        signed_manifest=signed_manifest,
        attest_manifest=lambda envelope: authority.attest_manifest(
            envelope, catalog_envelope_sha256=_sha(signed_catalog)
        ),
        audit=audit,
        answer_filter=answer_filter,
        token_counter=token_counter,
    )
    return MemoryGatewayHandler(
        facade=facade,
        authorize_peer=authorize_peer,
        resolve_caller=resolve_caller,
        audit=audit,
        task_id=task_id,
        attempt_id=attempt_id,
    )
