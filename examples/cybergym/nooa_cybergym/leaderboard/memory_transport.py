# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Controller-held MCP adapter for the dedicated CyberGym GBrain read facade.

This adapter validates the current authenticated tools/list against a catalog
attested by the existing Xeus signing authority. It permits only the three
native read operations and decodes one unambiguous MCP result. The injected
bridge owns OAuth and must install GBrain's native AI invocation guard before
provider dispatch. This module neither loads credentials nor claims that the
deployed service currently supplies the required grant and guard evidence.
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol
from uuid import uuid4

from nooa_cybergym.leaderboard.memory import READ_TOOLS, SOURCE_ID, ReadScopeAttestation


class TransportDenied(RuntimeError):
    """A request was denied without exposing native error or credential text."""


def _digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


@dataclass(frozen=True, slots=True)
class CatalogAttestation:
    """Output of controller Xeus signature verification, not a signature format."""

    envelope_sha256: str
    signature_key_id: str
    catalog_sha256: str
    tool_names: frozenset[str]
    source_ids: frozenset[str]
    server_context_source_id: str
    native_guard_binding_sha256: str
    server_info_sha256: str
    protocol_version: str

    def __post_init__(self) -> None:
        if (
            not _digest(self.envelope_sha256)
            or not _digest(self.catalog_sha256)
            or not _digest(self.native_guard_binding_sha256)
            or not _digest(self.server_info_sha256)
            or not isinstance(self.protocol_version, str)
            or not self.protocol_version.strip()
            or not isinstance(self.signature_key_id, str)
            or not self.signature_key_id.strip()
            or not isinstance(self.tool_names, frozenset)
            or not isinstance(self.source_ids, frozenset)
        ):
            raise ValueError("invalid signed catalog attestation")


@dataclass(frozen=True, slots=True)
class RuntimeReadEvidence:
    """Authenticated grant/context and installed native guard bridge evidence.

    A production bridge must derive this from the actual scored credential and
    server dispatch. Static client configuration cannot certify it.
    """

    source_ids: frozenset[str]
    server_context_source_id: str
    native_guard_binding_sha256: str
    native_guard_bound: bool


class ControllerMcpBridge(Protocol):
    """Secret-bearing session and native guarded dispatch, held by controller."""

    def read_evidence(self) -> RuntimeReadEvidence: ...

    def exchange(self, message: Mapping[str, object], *, timeout_seconds: float) -> object: ...

    def notify(self, message: Mapping[str, object]) -> None: ...


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON field")
        value[key] = item
    return value


class ControllerMemoryTransport:
    """Strict decoded transport consumed by ``MemoryFacade`` only.

    The controller injects a bridge with authenticated MCP session management,
    true OAuth source introspection and native guard admission/settlement. Until
    that bridge is live-certified, read_scope fails closed when its runtime
    evidence is missing or differs from the signed catalog.
    """

    def __init__(
        self,
        *,
        bridge: ControllerMcpBridge,
        signed_catalog: bytes,
        attest_catalog: Callable[[bytes], CatalogAttestation],
    ) -> None:
        if (
            not isinstance(signed_catalog, bytes)
            or not signed_catalog
            or not callable(attest_catalog)
            or not all(
                callable(getattr(bridge, name, None))
                for name in ("exchange", "notify", "read_evidence")
            )
        ):
            raise TransportDenied("signed catalog and controller MCP bridge required")
        valid = False
        try:
            attested = attest_catalog(signed_catalog)
            valid = not (
                type(attested) is not CatalogAttestation
                or attested.envelope_sha256 != _sha256(signed_catalog)
                or attested.source_ids != frozenset({SOURCE_ID})
                or attested.server_context_source_id != SOURCE_ID
                or not READ_TOOLS <= attested.tool_names
                or attested.tool_names - READ_TOOLS - {"capture"}
            )
        except Exception:
            pass
        if not valid:
            raise TransportDenied("signed catalog verification failed")
        self._bridge = bridge
        self._attested = attested
        self._initialized = False
        self._catalog_checked = False
        self._lock = threading.RLock()

    def __repr__(self) -> str:
        return "<ControllerMemoryTransport controller-held MCP state>"

    def _evidence(self) -> RuntimeReadEvidence:
        current = None
        try:
            current = self._bridge.read_evidence()
        except Exception:
            pass
        if current is None:
            raise TransportDenied("runtime source scope or guard evidence unavailable")
        if type(current) is not RuntimeReadEvidence:
            raise TransportDenied("runtime source scope or guard evidence invalid")
        if (
            current.source_ids != frozenset({SOURCE_ID})
            or current.source_ids != self._attested.source_ids
            or current.server_context_source_id != SOURCE_ID
            or current.server_context_source_id != self._attested.server_context_source_id
        ):
            raise TransportDenied("runtime source scope differs from signed catalog")
        if (
            current.native_guard_bound is not True
            or current.native_guard_binding_sha256 != self._attested.native_guard_binding_sha256
        ):
            raise TransportDenied("native guard binding is unavailable or changed")
        return current

    def _exchange(self, method: str, params: Mapping[str, object], *, timeout_seconds: float):
        request_id = uuid4().hex
        message = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": dict(params),
        }
        return self._send(message, timeout_seconds=timeout_seconds)

    def _send(self, message: Mapping[str, object], *, timeout_seconds: float):
        reply = None
        try:
            reply = self._bridge.exchange(message, timeout_seconds=timeout_seconds)
        except Exception:
            pass
        if reply is None:
            raise TransportDenied("native MCP bridge unavailable")
        if (
            not isinstance(reply, Mapping)
            or reply.get("jsonrpc") != "2.0"
            or reply.get("id") != message["id"]
            or "error" in reply
            or not isinstance(reply.get("result"), Mapping)
        ):
            raise TransportDenied("native MCP response invalid")
        return reply["result"]

    def _initialize(self) -> None:
        if self._initialized:
            return
        result = self._exchange(
            "initialize",
            {
                "protocolVersion": self._attested.protocol_version,
                "capabilities": {},
                "clientInfo": {"name": "xeus-cybergym-memory", "version": "1"},
            },
            timeout_seconds=10.0,
        )
        if not isinstance(result.get("serverInfo"), Mapping) or not isinstance(
            result.get("capabilities"), Mapping
        ):
            raise TransportDenied("native MCP initialization invalid")
        try:
            server_info_sha256 = _sha256(_canonical(dict(result["serverInfo"])))
        except (TypeError, ValueError):
            server_info_sha256 = None
        if (
            result.get("protocolVersion") != self._attested.protocol_version
            or server_info_sha256 != self._attested.server_info_sha256
        ):
            raise TransportDenied("native MCP server identity differs from signed catalog")
        notified = False
        try:
            self._bridge.notify({"jsonrpc": "2.0", "method": "notifications/initialized"})
            notified = True
        except Exception:
            pass
        if not notified:
            raise TransportDenied("native MCP initialization unavailable")
        self._initialized = True

    def _list_tools(self) -> list[dict[str, object]]:
        tools: list[dict[str, object]] = []
        cursor: str | None = None
        seen_cursors: set[str] = set()
        for _ in range(16):
            params: dict[str, object] = {} if cursor is None else {"cursor": cursor}
            result = self._exchange("tools/list", params, timeout_seconds=10.0)
            page = result.get("tools")
            if not isinstance(page, list):
                raise TransportDenied("authenticated tool catalog invalid")
            for tool in page:
                if (
                    not isinstance(tool, Mapping)
                    or not isinstance(tool.get("name"), str)
                    or not tool["name"]
                    or not isinstance(tool.get("inputSchema"), Mapping)
                ):
                    raise TransportDenied("authenticated tool schema invalid")
                tools.append(dict(tool))
            next_cursor = result.get("nextCursor")
            if next_cursor is None:
                return tools
            if not isinstance(next_cursor, str) or not next_cursor or next_cursor in seen_cursors:
                raise TransportDenied("authenticated tool catalog pagination invalid")
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        raise TransportDenied("authenticated tool catalog pagination exceeded")

    def read_scope(self) -> ReadScopeAttestation:
        with self._lock:
            return self._read_scope_locked()

    def _read_scope_locked(self) -> ReadScopeAttestation:
        self._catalog_checked = False
        self._evidence()
        self._initialize()
        tools = self._list_tools()
        names = [tool["name"] for tool in tools]
        if len(names) != len(set(names)):
            raise TransportDenied("authenticated tool catalog contains duplicates")
        catalog_sha256 = None
        try:
            catalog_sha256 = _sha256(_canonical(sorted(tools, key=lambda tool: tool["name"])))
        except (TypeError, ValueError):
            pass
        if catalog_sha256 is None:
            raise TransportDenied("authenticated tool catalog invalid")
        if (
            catalog_sha256 != self._attested.catalog_sha256
            or frozenset(names) != self._attested.tool_names
        ):
            raise TransportDenied("authenticated tool catalog differs from signed catalog")
        self._catalog_checked = True
        return ReadScopeAttestation(
            source_ids=self._attested.source_ids,
            server_context_source_id=self._attested.server_context_source_id,
            tool_names=self._attested.tool_names,
            catalog_sha256=catalog_sha256,
            native_guard_binding_sha256=self._attested.native_guard_binding_sha256,
        )

    @staticmethod
    def _validate_arguments(tool: str, arguments: Mapping[str, object]) -> None:
        if tool not in READ_TOOLS:
            raise TransportDenied("model memory dispatch is read-only")
        if not isinstance(arguments, Mapping):
            raise TransportDenied("native read arguments invalid")
        keys = set(arguments)
        query = arguments.get("query")
        if tool == "recall":
            valid = (
                keys == {"query", "budget_tokens", "limit"}
                and isinstance(query, str)
                and bool(query.strip())
                and len(query) <= 1000
                and type(arguments["budget_tokens"]) is int
                and arguments["budget_tokens"] == 2000
                and type(arguments["limit"]) is int
                and arguments["limit"] == 12
            )
        elif tool == "search":
            valid = (
                keys == {"query", "limit", "source_id", "types", "snippet_chars"}
                and isinstance(query, str)
                and bool(query.strip())
                and len(query) <= 1000
                and type(arguments["limit"]) is int
                and arguments["limit"] == 12
                and arguments["source_id"] == SOURCE_ID
                and arguments["types"] == ["note"]
                and type(arguments["snippet_chars"]) is int
                and arguments["snippet_chars"] == 1000
            )
        else:
            slug = arguments.get("slug")
            valid = (
                keys == {"slug", "source_id", "include_content", "fuzzy"}
                and isinstance(slug, str)
                and slug.startswith("cybergym/")
                and ".." not in slug.split("/")
                and arguments["source_id"] == SOURCE_ID
                and arguments["include_content"] is True
                and arguments["fuzzy"] is False
            )
        if not valid:
            raise TransportDenied("native read arguments outside signed scope")

    @staticmethod
    def _decode_result(result: Mapping[str, object], tool: str):
        if "isError" in result and result["isError"] is not False:
            raise TransportDenied("native read failed")
        has_structured = "structuredContent" in result
        has_content = "content" in result
        if has_structured == has_content:
            raise TransportDenied("native read result is ambiguous")
        if has_structured:
            data = result["structuredContent"]
        else:
            content = result.get("content")
            if (
                not isinstance(content, list)
                or len(content) != 1
                or not isinstance(content[0], Mapping)
                or content[0].get("type") != "text"
                or not isinstance(content[0].get("text"), str)
            ):
                raise TransportDenied("native read text result invalid")
            data = None
            decoded = False
            try:
                data = json.loads(
                    content[0]["text"],
                    object_pairs_hook=_unique_pairs,
                    parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
                )
                decoded = True
            except (TypeError, ValueError):
                pass
            if not decoded:
                raise TransportDenied("native read JSON result invalid")
        if tool == "recall":
            if (
                not isinstance(data, Mapping)
                or not isinstance(data.get("facts"), list)
                or not isinstance(data.get("results"), list)
            ):
                raise TransportDenied("native recall result shape invalid")
        elif tool == "search":
            if not isinstance(data, list):
                raise TransportDenied("native search result shape invalid")
        elif not isinstance(data, Mapping) or type(data.get("id")) is not int:
            raise TransportDenied("native canonical page shape invalid")
        return data

    def call(
        self,
        tool: str,
        arguments: Mapping[str, object],
        *,
        request_id: str,
        timeout_seconds: float,
    ) -> Mapping[str, object] | list[object]:
        with self._lock:
            return self._call_locked(
                tool, arguments, request_id=request_id, timeout_seconds=timeout_seconds
            )

    def _call_locked(
        self,
        tool: str,
        arguments: Mapping[str, object],
        *,
        request_id: str,
        timeout_seconds: float,
    ) -> Mapping[str, object] | list[object]:
        self._validate_arguments(tool, arguments)
        if not self._catalog_checked:
            raise TransportDenied("signed catalog has not been checked")
        self._evidence()
        if (
            not isinstance(request_id, str)
            or not request_id
            or type(timeout_seconds) not in (int, float)
            or not 0 < timeout_seconds <= 60
        ):
            raise TransportDenied("native read correlation or timeout invalid")
        message = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": tool, "arguments": dict(arguments)},
        }
        result = self._send(message, timeout_seconds=float(timeout_seconds))
        return self._decode_result(result, tool)
