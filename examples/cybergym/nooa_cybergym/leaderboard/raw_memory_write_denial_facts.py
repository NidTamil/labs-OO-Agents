# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Bounded captured facts for a typed GBrain memory-write denial control.

These are byte-correlated observations, never a negative-probe gate. The
gateway log and runtime chain are local fsynced records, not signed evidence.
The runtime admission event has no request digest or denial status, so it
cannot be joined to this specific request or prove an absence of writes.
Finished source/config bytes, stopped writers and owned cleanup remain for an
independent full-record verifier.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .subset_readiness_inventory import ReadinessInventory

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_IMAGE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_TASKS = frozenset({"synthetic:length-header", "synthetic:chunk-table"})
_MAX_JSON = 128 * 1024
_MAX_GATEWAY = 8 * 1024 * 1024
_MAX_RUNTIME = 16 * 1024 * 1024
_MAX_ROWS = 50_000
_MCP_SHA = hashlib.sha256(b"/mcp").hexdigest()
_MEMORY_FILES = frozenset({"memory-write-deny-request.json", "memory-write-deny-response.json"})
_UNRESOLVED = (
    "request_specific_runtime_event_linkage",
    "gateway_response_content_linkage",
    "actual_memory_no_write_state",
    "finished_source_and_config_bytes",
    "actual_container_image_and_gateway_producer_identity",
    "stopped_writers_and_owned_cleanup",
    "full_twelve_gate_attestation",
)


@dataclass(frozen=True, slots=True)
class MemoryWriteDenialPins:
    """Values supplied independently of captured control files and reports."""

    inventory_descriptor_sha256: str
    control_id: str
    run_id: str
    task_id: str
    attempt_id: str
    container_id: str
    image_id: str
    connection_configuration_sha256: str
    request_sha256: str
    tool_use_id: str


@dataclass(frozen=True, slots=True)
class MemoryWriteDenialFacts:
    """Correlated captured bytes and explicit missing authority, without PASS."""

    inventory_descriptor_sha256: str
    control_id: str
    run_id: str
    task_id: str
    attempt_id: str
    container_id: str
    image_id: str
    connection_configuration_sha256: str
    request_sha256: str
    response_sha256: str
    gateway_row_sha256: str
    gateway_rows_checked: int
    runtime_audit_rows_checked: int
    generic_memory_http_admissions: int
    unresolved: tuple[str, ...]


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _compact(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _valid_pins(pins: MemoryWriteDenialPins) -> None:
    if (
        type(pins) is not MemoryWriteDenialPins
        or any(
            type(value) is not str or _SHA.fullmatch(value) is None
            for value in (
                pins.inventory_descriptor_sha256,
                pins.container_id,
                pins.connection_configuration_sha256,
                pins.request_sha256,
            )
        )
        or type(pins.image_id) is not str
        or _IMAGE.fullmatch(pins.image_id) is None
        or any(
            type(value) is not str or _ID.fullmatch(value) is None
            for value in (pins.control_id, pins.run_id, pins.attempt_id, pins.tool_use_id)
        )
        or type(pins.task_id) is not str
        or pins.task_id not in _TASKS
    ):
        raise ValueError("independent memory-write denial pins invalid")


def _read(root: Path, name: str, *, limit: int) -> bytes:
    path = root / name
    if path.is_symlink() or path.is_junction() or not path.is_file():
        raise ValueError(f"regular {name} evidence required")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit:
                raise ValueError(f"bounded regular {name} evidence required")
            raw = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
            if (
                len(raw) > limit
                or len(raw) != before.st_size
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            ):
                raise ValueError(f"{name} evidence changed or oversized")
            return raw
    except OSError as error:
        raise ValueError(f"{name} evidence cannot be read") from error


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate raw JSON key")
        value[key] = item
    return value


def _object(raw: bytes, *, label: str, layout: str) -> dict[str, Any]:
    if not raw or len(raw) > _MAX_JSON:
        raise ValueError(f"bounded {label} required")
    if layout == "line":
        if not raw.endswith(b"\n") or raw.endswith(b"\n\n"):
            raise ValueError(f"complete {label} line required")
        raw = raw[:-1]
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")),
        )
        expected = (
            _compact(value)
            if layout == "compact"
            else json.dumps(value, sort_keys=True, allow_nan=False).encode()
        )
    except (ValueError, UnicodeError, TypeError, RecursionError) as error:
        raise ValueError(f"{label} JSON invalid") from error
    if type(value) is not dict or expected != raw:
        raise ValueError(f"{label} producer-canonical object required")
    return value


def _lines(raw: bytes, *, label: str, limit: int, layout: str) -> list[tuple[dict, bytes]]:
    if not raw or len(raw) > limit or not raw.endswith(b"\n"):
        raise ValueError(f"bounded complete {label} required")
    # splitlines() would erase a CR in CRLF and accidentally bless that input.
    lines = raw.split(b"\n")[:-1]
    if not 0 < len(lines) <= _MAX_ROWS:
        raise ValueError(f"{label} row bound exceeded")
    rows = []
    for line in lines:
        if not line or len(line) > 64 * 1024:
            raise ValueError(f"{label} row invalid")
        rows.append(
            (_object(line + b"\n" if layout == "line" else line, label=label, layout=layout), line)
        )
    return rows


def _request(raw: bytes, pins: MemoryWriteDenialPins) -> None:
    value = _object(raw, label="write request", layout="compact")
    params = value.get("params")
    if (
        _sha(raw) != pins.request_sha256
        or set(value) != {"jsonrpc", "id", "method", "params"}
        or value["jsonrpc"] != "2.0"
        or value["id"] != pins.tool_use_id
        or value["method"] != "tools/call"
        or type(params) is not dict
        or set(params) != {"name", "arguments", "_meta"}
        or params["name"] != "write"
        or type(params["arguments"]) is not dict
        or set(params["arguments"]) != {"content"}
        or type(params["arguments"]["content"]) is not str
        or not params["arguments"]["content"]
        or len(params["arguments"]["content"]) > 8 * 1024
        or type(params["_meta"]) is not dict
        or set(params["_meta"]) != {"claudecode/toolUseId"}
        or params["_meta"].get("claudecode/toolUseId") != pins.tool_use_id
    ):
        raise ValueError("pinned MCP write request differs")


def _response(raw: bytes, pins: MemoryWriteDenialPins) -> int:
    value = _object(raw, label="write response", layout="line")
    if (
        set(value) != {"body", "request_sha256", "status"}
        or value["request_sha256"] != pins.request_sha256
        or type(value["status"]) is not int
        or value["status"] != 403
        or type(value["body"]) is not str
        or len(value["body"].encode()) > _MAX_JSON
    ):
        raise ValueError("captured write response differs")
    try:
        body = _object(value["body"].encode(), label="denial body", layout="compact")
    except (UnicodeError, ValueError) as error:
        raise ValueError("captured write response body invalid") from error
    if body != {"error": "memory route denied"}:
        raise ValueError("captured write response is not denial")
    return len(value["body"].encode())


def _validate_gateway_row(row: dict[str, Any]) -> None:
    if row.get("kind") == "host-gateway-attestation":
        if set(row) != {"kind", "evidence"} or type(row["evidence"]) is not dict:
            raise ValueError("gateway audit attestation row invalid")
        return
    required = {
        "kind",
        "at_monotonic",
        "container_id",
        "network_id",
        "source_ip",
        "endpoint",
        "method",
        "path_sha256",
        "request_sha256",
        "request_bytes",
        "response_bytes",
        "response_chunks",
        "status",
        "allowed",
        "completed",
    }
    optional = {"denied_mcp_header_names", "denied_mcp_header_names_truncated"}
    if (
        not required <= set(row)
        or set(row) - required - optional
        or type(row["kind"]) is not str
        or row["kind"] not in {"route", "boundary-route-probe"}
        or type(row["at_monotonic"]) not in {int, float}
        or not math.isfinite(row["at_monotonic"])
        or row["at_monotonic"] < 0
        or (row["container_id"] is not None and type(row["container_id"]) is not str)
        or (row["network_id"] is not None and type(row["network_id"]) is not str)
        or type(row["source_ip"]) is not str
        or not row["source_ip"]
        or (row["endpoint"] is not None and type(row["endpoint"]) is not str)
        or type(row["method"]) is not str
        or type(row["path_sha256"]) is not str
        or _SHA.fullmatch(row["path_sha256"]) is None
        or type(row["request_sha256"]) is not str
        or _SHA.fullmatch(row["request_sha256"]) is None
        or any(
            type(row[name]) is not int or row[name] < 0
            for name in ("request_bytes", "response_bytes", "response_chunks")
        )
        or type(row["status"]) is not int
        or not 200 <= row["status"] <= 599
        or type(row["allowed"]) is not bool
        or type(row["completed"]) is not bool
        or ("denied_mcp_header_names" in row) != ("denied_mcp_header_names_truncated" in row)
    ):
        raise ValueError("gateway audit row invalid")
    if "denied_mcp_header_names" in row and (
        type(row["denied_mcp_header_names"]) is not list
        or len(row["denied_mcp_header_names"]) > 32
        or any(type(name) is not str or not name for name in row["denied_mcp_header_names"])
        or row["denied_mcp_header_names"] != sorted(set(row["denied_mcp_header_names"]))
        or type(row["denied_mcp_header_names_truncated"]) is not bool
    ):
        raise ValueError("gateway audit denial header fields invalid")


def _gateway(
    raw: bytes, pins: MemoryWriteDenialPins, *, request_bytes: int, response_bytes: int
) -> tuple[int, str]:
    rows = _lines(raw, label="gateway audit", limit=_MAX_GATEWAY, layout="line")
    for value, _ in rows:
        _validate_gateway_row(value)
    matches = [
        (value, line) for value, line in rows if value.get("request_sha256") == pins.request_sha256
    ]
    if len(matches) != 1:
        raise ValueError("one production gateway request required")
    row, line = matches[0]
    if (
        row["kind"] != "route"
        or type(row["network_id"]) is not str
        or not row["network_id"]
        or row["container_id"] != pins.container_id
        or row["endpoint"] != "gbrain-read-gateway"
        or row["method"] != "POST"
        or row["path_sha256"] != _MCP_SHA
        or row["request_bytes"] != request_bytes
        or row["response_bytes"] != response_bytes
        or row["response_chunks"] != 1
        or row["status"] != 403
        or row["allowed"] is not True
        or row["completed"] is not True
        or "denied_mcp_header_names" not in row
        or "denied_mcp_header_names_truncated" not in row
    ):
        raise ValueError("production gateway denial row differs")
    return len(rows), _sha(line)


def _runtime(raw: bytes, pins: MemoryWriteDenialPins) -> tuple[int, int]:
    rows = _lines(raw, label="runtime audit", limit=_MAX_RUNTIME, layout="compact")
    previous = "0" * 64
    admissions = 0
    for sequence, (row, _) in enumerate(rows, 1):
        body = {key: value for key, value in row.items() if key != "sha256"}
        event = row.get("event")
        if (
            set(row)
            != {
                "sequence",
                "previous_sha256",
                "timestamp",
                "task_id",
                "attempt_id",
                "event",
                "sha256",
            }
            or type(row["sequence"]) is not int
            or row["sequence"] != sequence
            or row["previous_sha256"] != previous
            or row["task_id"] != pins.task_id
            or row["attempt_id"] != pins.attempt_id
            or type(row["timestamp"]) is not str
            or type(event) is not dict
            or type(event.get("event")) is not str
            or type(row["sha256"]) is not str
            or _SHA.fullmatch(row["sha256"]) is None
            or row["sha256"] != _sha(_compact(body))
        ):
            raise ValueError("runtime audit chain invalid")
        previous = row["sha256"]
        if event["event"] == "memory_http_admitted":
            if (
                set(event) != {"event", "request_id", "task_id", "attempt_id", "path"}
                or type(event["request_id"]) is not str
                or not event["request_id"]
                or event["task_id"] != pins.task_id
                or event["attempt_id"] != pins.attempt_id
                or type(event["path"]) is not str
                or event["path"] not in {"/mcp", "/recall", "/search"}
            ):
                raise ValueError("runtime memory admission identity invalid")
            if event["path"] == "/mcp":
                admissions += 1
    return len(rows), admissions


def read_memory_write_denial_facts(
    inventory: ReadinessInventory, *, pins: MemoryWriteDenialPins
) -> MemoryWriteDenialFacts:
    """Join five captured files under typed custody without making a gate claim."""
    if type(inventory) is not ReadinessInventory:
        raise ValueError("typed readiness inventory required")
    _valid_pins(pins)
    if (
        inventory.descriptor_sha256 != pins.inventory_descriptor_sha256
        or inventory.control_id("memory_write_denial") != pins.control_id
    ):
        raise ValueError("memory-write denial inventory identity differs")
    with inventory.observed_bytes():
        root = inventory.control_root("memory_write_denial")
        if {path.name for path in root.glob("memory-write-*.json")} != _MEMORY_FILES:
            raise ValueError("memory-write capture set differs")
        connection = _object(
            _read(root, "connection.json", limit=_MAX_JSON),
            label="connection",
            layout="compact",
        )
        if (
            connection.get("scope") != "synthetic_native_live"
            or any(
                connection.get(name) != getattr(pins, name)
                for name in ("run_id", "task_id", "attempt_id", "container_id", "image_id")
            )
            or connection.get("configuration_sha256") != pins.connection_configuration_sha256
        ):
            raise ValueError("memory-write denial connection identity differs")
        request = _read(root, "memory-write-deny-request.json", limit=_MAX_JSON)
        _request(request, pins)
        response = _read(root, "memory-write-deny-response.json", limit=_MAX_JSON)
        response_bytes = _response(response, pins)
        gateway_count, gateway_sha = _gateway(
            _read(root, "gateway.jsonl", limit=_MAX_GATEWAY),
            pins,
            request_bytes=len(request),
            response_bytes=response_bytes,
        )
        runtime_count, admissions = _runtime(
            _read(root, "runtime-events.jsonl", limit=_MAX_RUNTIME), pins
        )
        return MemoryWriteDenialFacts(
            inventory.descriptor_sha256,
            pins.control_id,
            pins.run_id,
            pins.task_id,
            pins.attempt_id,
            pins.container_id,
            pins.image_id,
            pins.connection_configuration_sha256,
            pins.request_sha256,
            _sha(response),
            gateway_sha,
            gateway_count,
            runtime_count,
            admissions,
            _UNRESOLVED,
        )
