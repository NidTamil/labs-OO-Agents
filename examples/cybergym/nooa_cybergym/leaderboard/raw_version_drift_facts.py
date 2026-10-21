# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Bounded, read-only facts from a provider-free version-drift control.

This reader does not emit a gate result. Existing calibration artifacts can
correlate one container/launch and show an incompatibility line in a captured
log. They cannot authenticate the workstation client, remote server, extension
or log producer; bind the finished source/config; prove a stopped gateway
writer and absent launch reservation; or prove owned local *and remote*
cleanup. A future producer must record those observations under versioned,
role-correct signatures and a stopped-writer journal. This reader deliberately
returns those unresolved contracts even when all currently available facts
agree. A control report's ``provider_dispatched: false`` is never authority.
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
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}\Z")
_FIXTURES = frozenset({"synthetic:length-header", "synthetic:chunk-table"})
_REJECTION = re.compile(
    r"Extension is not compatible with Code (?P<client>[0-9]+(?:\.[0-9]+){1,3})\. "
    r"Extension requires: (?P<engine>[0-9]+(?:\.[0-9]+){1,3})\."
)
_MAX_JSON = 128 * 1024
_MAX_LOG = 2 * 1024 * 1024
_MAX_AUDIT = 8 * 1024 * 1024
_MAX_AUDIT_ROWS = 50_000
_NO_LAUNCH_PATHS = (
    "/native-launch/reserve",
    "/native-launch/events",
    "/v1/messages",
    "/v1/messages?beta=true",
)
_NO_LAUNCH_HASHES = frozenset(
    hashlib.sha256(path.encode()).hexdigest() for path in _NO_LAUNCH_PATHS
)
_UNRESOLVED = (
    "source_and_config_observation",
    "authenticated_client_server_and_extension_observation",
    "gateway_writer_and_owned_cleanup_closure",
    "authoritative_native_reservation_absence",
)


@dataclass(frozen=True, slots=True)
class VersionDriftPins:
    """Pins supplied independently of the control's report or inventoried files."""

    inventory_descriptor_sha256: str
    source_sha256: str
    config_sha256: str
    image_id: str
    manifest_sha256: str
    binary_sha256: str
    task_id: str
    run_id: str
    launch_id: str
    container_id: str
    client_version: str
    launcher_engine: str


@dataclass(frozen=True, slots=True)
class VersionDriftFacts:
    """Correlated captured facts, with explicit unmet producer contracts."""

    inventory_descriptor_sha256: str
    task_id: str
    run_id: str
    launch_id: str
    container_id: str
    image_id: str
    manifest_sha256: str
    gateway_rows_checked: int
    rejection_line_sha256: str
    unresolved: tuple[str, ...]


def _valid_pins(pins: VersionDriftPins) -> None:
    if (
        type(pins) is not VersionDriftPins
        or any(
            type(value) is not str or _SHA.fullmatch(value) is None
            for value in (
                pins.inventory_descriptor_sha256,
                pins.source_sha256,
                pins.config_sha256,
                pins.manifest_sha256,
                pins.binary_sha256,
                pins.container_id,
            )
        )
        or type(pins.image_id) is not str
        or _IMAGE.fullmatch(pins.image_id) is None
        or any(
            type(value) is not str or _ID.fullmatch(value) is None
            for value in (pins.run_id, pins.launch_id)
        )
        or any(
            type(value) is not str or _VERSION.fullmatch(value) is None
            for value in (pins.client_version, pins.launcher_engine)
        )
        or pins.client_version == pins.launcher_engine
        or type(pins.task_id) is not str
        or pins.task_id not in _FIXTURES
    ):
        raise ValueError("independent version-drift pins invalid")


def _read(root: Path, name: str, *, limit: int) -> bytes:
    path = root / name
    if path.is_symlink() or path.is_junction() or not path.is_file():
        raise ValueError(f"regular {name} evidence required")
    # The inventory's before/after full-root hashes supply byte custody.
    # A future platform backend must supply held file handles for live proof.
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or not 0 <= before.st_size <= limit:
                raise ValueError(f"bounded regular {name} evidence required")
            raw = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
            if (
                len(raw) > limit
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                or len(raw) != before.st_size
            ):
                raise ValueError(f"{name} evidence changed or oversized")
            return raw
    except OSError as error:
        raise ValueError(f"{name} evidence cannot be read") from error


def _strict_object(raw: bytes, *, label: str) -> dict[str, Any]:
    if not raw or len(raw) > _MAX_JSON:
        raise ValueError(f"bounded {label} required")

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate {label} key")
            value[key] = item
        return value

    try:
        value = json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: None)
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode()
    except (ValueError, TypeError, UnicodeError) as error:
        raise ValueError(f"{label} invalid") from error
    if type(value) is not dict or encoded != raw:
        raise ValueError(f"canonical {label} object required")
    return value


def _rejection_digest(raw: bytes, pins: VersionDriftPins) -> str:
    if not raw or len(raw) > _MAX_LOG or b"\x00" in raw:
        raise ValueError("bounded remote incompatibility log required")
    try:
        log = raw.decode("utf-8")
    except UnicodeError as error:
        raise ValueError("remote incompatibility log invalid") from error
    matches = []
    for line in log.splitlines():
        if len(line) > 16_384:
            raise ValueError("remote incompatibility log line oversized")
        matches.extend(_REJECTION.finditer(line))
    if len(matches) != 1:
        raise ValueError("one actual incompatibility line required")
    match = matches[0]
    if (
        match.group("client") != pins.client_version
        or match.group("engine") != pins.launcher_engine
    ):
        raise ValueError("incompatibility version differs from independent pins")
    return hashlib.sha256(match.group().encode()).hexdigest()


def _gateway_rows(raw: bytes, *, container_id: str) -> int:
    if len(raw) > _MAX_AUDIT or (raw and not raw.endswith(b"\n")):
        raise ValueError("bounded complete gateway audit lines required")
    rows = raw.splitlines()
    if len(rows) > _MAX_AUDIT_ROWS:
        raise ValueError("gateway audit row bound exceeded")

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("gateway audit duplicate key")
            value[key] = item
        return value

    for line in rows:
        if not line or len(line) > 64 * 1024:
            raise ValueError("gateway audit row invalid")
        try:
            value = json.loads(
                line,
                object_pairs_hook=unique,
                parse_constant=lambda _: (_ for _ in ()).throw(
                    ValueError("nonfinite audit number")
                ),
            )
        except (ValueError, UnicodeError) as error:
            raise ValueError("gateway audit row invalid") from error
        if type(value) is not dict or value.get("kind") not in {
            "route",
            "boundary-route-probe",
            "host-gateway-attestation",
        }:
            raise ValueError("gateway audit schema unsupported")
        if value["kind"] == "host-gateway-attestation":
            if set(value) != {"kind", "evidence"} or type(value["evidence"]) is not dict:
                raise ValueError("gateway audit attestation row malformed")
            continue
        endpoint, method, path_sha256 = (
            value.get("endpoint"),
            value.get("method"),
            value.get("path_sha256"),
        )
        if (
            (endpoint is not None and type(endpoint) is not str)
            or type(method) is not str
            or type(path_sha256) is not str
            or _SHA.fullmatch(path_sha256) is None
            or value.get("container_id") not in {None, container_id}
            or type(value.get("at_monotonic")) not in {int, float}
            or not math.isfinite(value["at_monotonic"])
            or type(value.get("source_ip")) is not str
            or not value["source_ip"]
            or type(value.get("request_sha256")) is not str
            or _SHA.fullmatch(value["request_sha256"]) is None
            or any(
                type(value.get(field)) is not int or value[field] < 0
                for field in ("request_bytes", "response_bytes", "response_chunks")
            )
            or type(value.get("status")) is not int
            or not 200 <= value["status"] <= 599
            or type(value.get("allowed")) is not bool
            or type(value.get("completed")) is not bool
        ):
            raise ValueError("gateway audit identity or route malformed")
        if endpoint == "model-gateway" or path_sha256 in _NO_LAUNCH_HASHES:
            raise ValueError("model or native launch dispatch present in gateway audit")
    return len(rows)


def read_version_drift_facts(
    inventory: ReadinessInventory, *, pins: VersionDriftPins
) -> VersionDriftFacts:
    """Correlate available raw facts under typed byte custody; never pass a gate.

    The current producer does not record enough authority for a complete drift
    control. In particular, an empty gateway file is only an empty *file* until
    a stopped writer and independent native reservation journal are proven.
    """
    if type(inventory) is not ReadinessInventory:
        raise ValueError("typed readiness inventory required")
    _valid_pins(pins)
    # The independently pinned descriptor transitively binds the exact typed
    # control ID and all of its bytes, not merely the version_drift kind.
    if inventory.descriptor_sha256 != pins.inventory_descriptor_sha256:
        raise ValueError("version-drift inventory identity differs")
    with inventory.observed_bytes():
        root = inventory.control_root("version_drift")
        connection = _strict_object(
            _read(root, "connection.json", limit=_MAX_JSON), label="connection"
        )
        marker = _strict_object(
            _read(root, "calibration.json", limit=_MAX_JSON), label="calibration"
        )
        if (
            connection.get("scope") != "native_schema_discovery_no_provider"
            or marker.get("schema_version") != 1
            or marker.get("scope") != "native_schema_discovery_no_provider"
            or connection.get("provider_dispatched") is not False
            or marker.get("provider_dispatched") is not False
            or marker.get("benchmark_eligible") is not False
        ):
            raise ValueError("version-drift calibration schema invalid")
        if (
            any(
                connection.get(key) != getattr(pins, key)
                for key in ("run_id", "launch_id", "container_id", "image_id")
            )
            or any(
                marker.get(key) != getattr(pins, key)
                for key in ("run_id", "launch_id", "manifest_sha256", "image_id", "binary_sha256")
            )
            or marker.get("task_id") != pins.task_id
            or type(marker.get("peer")) is not dict
            or marker["peer"].get("container_id") != pins.container_id
        ):
            raise ValueError("version-drift calibration identity differs")
        line_sha = _rejection_digest(_read(root, "remote-agent.log", limit=_MAX_LOG), pins)
        row_count = _gateway_rows(
            _read(root, "gateway.jsonl", limit=_MAX_AUDIT), container_id=pins.container_id
        )
        return VersionDriftFacts(
            pins.inventory_descriptor_sha256,
            pins.task_id,
            pins.run_id,
            pins.launch_id,
            pins.container_id,
            pins.image_id,
            pins.manifest_sha256,
            row_count,
            line_sha,
            _UNRESOLVED,
        )
