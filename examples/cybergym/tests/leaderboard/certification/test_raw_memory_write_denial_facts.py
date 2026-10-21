# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""A captured memory write denial is a raw fact, never a gate verdict."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import replace
from pathlib import Path

import pytest
from nooa_cybergym.leaderboard.raw_memory_write_denial_facts import (
    MemoryWriteDenialPins,
    read_memory_write_denial_facts,
)
from nooa_cybergym.leaderboard.raw_pair_manifest import build_raw_pair_manifest
from nooa_cybergym.leaderboard.subset_readiness_inventory import (
    load_subset_readiness_inventory,
)

_TASK = "synthetic:chunk-table"
_RUN = "memory-deny-run"
_ATTEMPT = "attempt-one"
_CONTAINER = "a" * 64
_IMAGE = "sha256:" + "b" * 64
_CONFIG = "c" * 64
_TOOL_USE_ID = "deny-write-one"
_CONTROLS = (
    "primary_takeover",
    "interruption_reconnection",
    "timeout_failure",
    "version_drift",
    "memory_write_denial",
)


def _compact(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _files(root: Path) -> list[dict[str, str | int]]:
    return [
        {
            "path": path.relative_to(root).as_posix(),
            "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        for path in sorted(root.rglob("*"))
        if path.is_file()
    ]


def _request() -> bytes:
    return _compact(
        {
            "jsonrpc": "2.0",
            "id": _TOOL_USE_ID,
            "method": "tools/call",
            "params": {
                "name": "write",
                "arguments": {"content": "synthetic-denial-probe"},
                "_meta": {"claudecode/toolUseId": _TOOL_USE_ID},
            },
        }
    )


def _runtime_rows() -> bytes:
    body = {
        "sequence": 1,
        "previous_sha256": "0" * 64,
        "timestamp": "2026-10-21T00:00:00+00:00",
        "task_id": _TASK,
        "attempt_id": _ATTEMPT,
        "event": {
            "event": "memory_http_admitted",
            "request_id": "memory-http-one",
            "task_id": _TASK,
            "attempt_id": _ATTEMPT,
            "path": "/mcp",
        },
    }
    digest = hashlib.sha256(_compact(body)).hexdigest()
    return _compact({**body, "sha256": digest}) + b"\n"


def _control_files() -> dict[str, bytes]:
    request = _request()
    request_sha = hashlib.sha256(request).hexdigest()
    body = _compact({"error": "memory route denied"}).decode()
    response = (
        json.dumps(
            {"status": 403, "body": body, "request_sha256": request_sha}, sort_keys=True
        ).encode()
        + b"\n"
    )
    gateway = {
        "kind": "route",
        "at_monotonic": 1.5,
        "container_id": _CONTAINER,
        "network_id": "network-one",
        "source_ip": "127.0.0.1",
        "endpoint": "gbrain-read-gateway",
        "method": "POST",
        "path_sha256": hashlib.sha256(b"/mcp").hexdigest(),
        "request_sha256": request_sha,
        "request_bytes": len(request),
        "response_bytes": len(body.encode()),
        "response_chunks": 1,
        "status": 403,
        "allowed": True,
        "completed": True,
        "denied_mcp_header_names": ["content-type"],
        "denied_mcp_header_names_truncated": False,
    }
    return {
        "connection.json": _compact(
            {
                "scope": "synthetic_native_live",
                "run_id": _RUN,
                "task_id": _TASK,
                "attempt_id": _ATTEMPT,
                "container_id": _CONTAINER,
                "image_id": _IMAGE,
                "configuration_sha256": _CONFIG,
            }
        ),
        "memory-write-deny-request.json": request,
        "memory-write-deny-response.json": response,
        "gateway.jsonl": json.dumps(gateway, sort_keys=True).encode() + b"\n",
        "runtime-events.jsonl": _runtime_rows(),
    }


def _bundle(tmp_path: Path, *, mutate=None):
    repetitions = []
    manifests = {}
    for run_id in ("repeat-one", "repeat-two"):
        root = tmp_path / run_id
        root.mkdir()
        fixtures = {}
        for index, task in enumerate(("synthetic:length-header", _TASK)):
            fixture_root = root / f"fixture-{index}"
            fixture_root.mkdir()
            (fixture_root / "result.json").write_bytes(_compact({"run_id": run_id}))
            fixtures[task] = fixture_root
        manifest = _compact(build_raw_pair_manifest(run_id, fixtures))
        manifests[run_id] = manifest
        repetitions.append(
            {
                "run_id": run_id,
                "root": str(root),
                "pair_manifest_sha256": hashlib.sha256(manifest).hexdigest(),
                "fixtures": {task: str(path) for task, path in fixtures.items()},
                "files": _files(root),
            }
        )
    controls = []
    for kind in _CONTROLS:
        root = tmp_path / kind
        root.mkdir()
        files = _control_files() if kind == "memory_write_denial" else {"control.json": b"{}"}
        if kind == "memory_write_denial" and mutate is not None:
            mutate(files)
        for name, raw in files.items():
            (root / name).write_bytes(raw)
        controls.append(
            {
                "kind": kind,
                "control_id": f"control-{kind}",
                "root": str(root),
                "files": _files(root),
            }
        )
    descriptor = _compact(
        {
            "schema_version": 1,
            "scope": "subset_raw_readiness_inventory",
            "repetitions": repetitions,
            "controls": controls,
        }
    )
    inventory = load_subset_readiness_inventory(
        descriptor,
        expected_sha256=hashlib.sha256(descriptor).hexdigest(),
        pair_manifests=manifests,
        deadline_monotonic=time.monotonic() + 60,
    )
    pins = MemoryWriteDenialPins(
        inventory_descriptor_sha256=inventory.descriptor_sha256,
        control_id="control-memory_write_denial",
        run_id=_RUN,
        task_id=_TASK,
        attempt_id=_ATTEMPT,
        container_id=_CONTAINER,
        image_id=_IMAGE,
        connection_configuration_sha256=_CONFIG,
        request_sha256=hashlib.sha256(_request()).hexdigest(),
        tool_use_id=_TOOL_USE_ID,
    )
    return inventory, pins


def _rebind_request(files: dict[str, bytes], request: dict) -> str:
    """Keep all captured transport digests aligned while changing write intent."""
    raw = _compact(request)
    digest = hashlib.sha256(raw).hexdigest()
    files["memory-write-deny-request.json"] = raw
    response = json.loads(files["memory-write-deny-response.json"])
    response["request_sha256"] = digest
    files["memory-write-deny-response.json"] = json.dumps(response, sort_keys=True).encode() + b"\n"
    gateway = json.loads(files["gateway.jsonl"])
    gateway["request_sha256"] = digest
    gateway["request_bytes"] = len(raw)
    files["gateway.jsonl"] = json.dumps(gateway, sort_keys=True).encode() + b"\n"
    return digest


def test_correlates_captured_write_denial_without_claiming_a_gate(tmp_path):
    inventory, pins = _bundle(tmp_path)

    facts = read_memory_write_denial_facts(inventory, pins=pins)

    assert facts.control_id == "control-memory_write_denial"
    assert facts.request_sha256 == hashlib.sha256(_request()).hexdigest()
    assert facts.gateway_rows_checked == 1
    assert facts.runtime_audit_rows_checked == 1
    assert facts.generic_memory_http_admissions == 1
    assert "request_specific_runtime_event_linkage" in facts.unresolved
    assert "gateway_response_content_linkage" in facts.unresolved
    assert "actual_memory_no_write_state" in facts.unresolved
    assert "finished_source_and_config_bytes" in facts.unresolved
    assert "stopped_writers_and_owned_cleanup" in facts.unresolved
    assert not hasattr(facts, "passed")
    assert not hasattr(facts, "verified")


def test_unrelated_malformed_gateway_row_cannot_hide_inside_complete_audit(tmp_path):
    def mutate(files):
        files["gateway.jsonl"] += json.dumps({"kind": "route"}, sort_keys=True).encode() + b"\n"

    inventory, pins = _bundle(tmp_path, mutate=mutate)
    with pytest.raises(ValueError, match="gateway audit"):
        read_memory_write_denial_facts(inventory, pins=pins)


def test_other_mcp_tool_cannot_be_relabelled_as_write_denial(tmp_path):
    changed = None

    def mutate(files):
        nonlocal changed
        request = json.loads(files["memory-write-deny-request.json"])
        request["params"]["name"] = "recall"
        changed = _rebind_request(files, request)

    inventory, pins = _bundle(tmp_path, mutate=mutate)
    with pytest.raises(ValueError, match="MCP write request"):
        read_memory_write_denial_facts(inventory, pins=replace(pins, request_sha256=changed))


def test_malformed_write_without_content_is_not_a_real_write_attempt(tmp_path):
    changed = None

    def mutate(files):
        nonlocal changed
        request = json.loads(files["memory-write-deny-request.json"])
        request["params"]["arguments"] = {}
        changed = _rebind_request(files, request)

    inventory, pins = _bundle(tmp_path, mutate=mutate)
    with pytest.raises(ValueError, match="MCP write request"):
        read_memory_write_denial_facts(inventory, pins=replace(pins, request_sha256=changed))


@pytest.mark.parametrize("field,value", [("status", 200), ("body", '{"error":"other"}')])
def test_captured_response_must_be_the_same_403_denial(tmp_path, field, value):
    def mutate(files):
        response = json.loads(files["memory-write-deny-response.json"])
        response[field] = value
        files["memory-write-deny-response.json"] = (
            json.dumps(response, sort_keys=True).encode() + b"\n"
        )

    inventory, pins = _bundle(tmp_path, mutate=mutate)
    with pytest.raises(ValueError, match="captured write response"):
        read_memory_write_denial_facts(inventory, pins=pins)


def test_duplicate_gateway_rows_for_one_request_are_rejected(tmp_path):
    def mutate(files):
        files["gateway.jsonl"] *= 2

    inventory, pins = _bundle(tmp_path, mutate=mutate)
    with pytest.raises(ValueError, match="one production gateway request"):
        read_memory_write_denial_facts(inventory, pins=pins)


@pytest.mark.parametrize(
    "field,value",
    [
        ("container_id", "9" * 64),
        ("endpoint", "registered-tool-gateway"),
        ("allowed", False),
        ("completed", False),
    ],
)
def test_matching_gateway_row_requires_exact_production_route(tmp_path, field, value):
    def mutate(files):
        row = json.loads(files["gateway.jsonl"])
        row[field] = value
        files["gateway.jsonl"] = json.dumps(row, sort_keys=True).encode() + b"\n"

    inventory, pins = _bundle(tmp_path, mutate=mutate)
    with pytest.raises(ValueError, match="gateway denial row"):
        read_memory_write_denial_facts(inventory, pins=pins)


def test_matched_403_gateway_row_requires_produced_denial_header_fields(tmp_path):
    def mutate(files):
        row = json.loads(files["gateway.jsonl"])
        del row["denied_mcp_header_names"]
        del row["denied_mcp_header_names_truncated"]
        files["gateway.jsonl"] = json.dumps(row, sort_keys=True).encode() + b"\n"

    inventory, pins = _bundle(tmp_path, mutate=mutate)
    with pytest.raises(ValueError, match="gateway denial row"):
        read_memory_write_denial_facts(inventory, pins=pins)


@pytest.mark.parametrize(
    "field,value", [("task_id", "synthetic:length-header"), ("attempt_id", "other-attempt")]
)
def test_runtime_chain_wrong_identity_is_rejected_even_with_valid_digest(tmp_path, field, value):
    def mutate(files):
        row = json.loads(files["runtime-events.jsonl"])
        row[field] = value
        body = {key: item for key, item in row.items() if key != "sha256"}
        row["sha256"] = hashlib.sha256(_compact(body)).hexdigest()
        files["runtime-events.jsonl"] = _compact(row) + b"\n"

    inventory, pins = _bundle(tmp_path, mutate=mutate)
    with pytest.raises(ValueError, match="runtime audit chain"):
        read_memory_write_denial_facts(inventory, pins=pins)


def test_runtime_hash_link_must_be_intact(tmp_path):
    def mutate(files):
        row = json.loads(files["runtime-events.jsonl"])
        row["previous_sha256"] = "f" * 64
        files["runtime-events.jsonl"] = _compact(row) + b"\n"

    inventory, pins = _bundle(tmp_path, mutate=mutate)
    with pytest.raises(ValueError, match="runtime audit chain"):
        read_memory_write_denial_facts(inventory, pins=pins)


@pytest.mark.parametrize(
    "field,value",
    [("task_id", "synthetic:length-header"), ("attempt_id", "other-attempt"), ("request_id", None)],
)
def test_nested_memory_admission_needs_its_own_identity(tmp_path, field, value):
    def mutate(files):
        row = json.loads(files["runtime-events.jsonl"])
        if value is None:
            del row["event"][field]
        else:
            row["event"][field] = value
        body = {key: item for key, item in row.items() if key != "sha256"}
        row["sha256"] = hashlib.sha256(_compact(body)).hexdigest()
        files["runtime-events.jsonl"] = _compact(row) + b"\n"

    inventory, pins = _bundle(tmp_path, mutate=mutate)
    with pytest.raises(ValueError, match="memory admission"):
        read_memory_write_denial_facts(inventory, pins=pins)


def test_truncated_runtime_row_is_not_a_complete_chain(tmp_path):
    def mutate(files):
        files["runtime-events.jsonl"] = files["runtime-events.jsonl"].rstrip(b"\n")

    inventory, pins = _bundle(tmp_path, mutate=mutate)
    with pytest.raises(ValueError, match="bounded complete runtime audit"):
        read_memory_write_denial_facts(inventory, pins=pins)


def test_noncanonical_crlf_gateway_audit_is_rejected(tmp_path):
    def mutate(files):
        files["gateway.jsonl"] = files["gateway.jsonl"].replace(b"\n", b"\r\n")

    inventory, pins = _bundle(tmp_path, mutate=mutate)
    with pytest.raises(ValueError, match="gateway audit"):
        read_memory_write_denial_facts(inventory, pins=pins)


def test_malformed_gateway_header_array_is_rejected_as_evidence(tmp_path):
    def mutate(files):
        row = json.loads(files["gateway.jsonl"])
        row["denied_mcp_header_names"] = [["content-type"]]
        files["gateway.jsonl"] = json.dumps(row, sort_keys=True).encode() + b"\n"

    inventory, pins = _bundle(tmp_path, mutate=mutate)
    with pytest.raises(ValueError, match="gateway audit"):
        read_memory_write_denial_facts(inventory, pins=pins)


def test_unhashable_gateway_kind_fails_closed(tmp_path):
    def mutate(files):
        row = json.loads(files["gateway.jsonl"])
        row["kind"] = []
        files["gateway.jsonl"] = json.dumps(row, sort_keys=True).encode() + b"\n"

    inventory, pins = _bundle(tmp_path, mutate=mutate)
    with pytest.raises(ValueError, match="gateway audit"):
        read_memory_write_denial_facts(inventory, pins=pins)


def test_duplicate_runtime_json_keys_cannot_hide_an_event(tmp_path):
    def mutate(files):
        files["runtime-events.jsonl"] = files["runtime-events.jsonl"].replace(
            b'{"attempt_id":', b'{"sequence":1,"attempt_id":', 1
        )

    inventory, pins = _bundle(tmp_path, mutate=mutate)
    with pytest.raises(ValueError, match="runtime audit JSON"):
        read_memory_write_denial_facts(inventory, pins=pins)


def test_typed_control_id_is_independently_pinned(tmp_path):
    inventory, pins = _bundle(tmp_path)
    with pytest.raises(ValueError, match="inventory identity"):
        read_memory_write_denial_facts(inventory, pins=replace(pins, control_id="other-control"))


def test_malformed_task_pin_fails_closed(tmp_path):
    inventory, pins = _bundle(tmp_path)
    with pytest.raises(ValueError, match="pins invalid"):
        read_memory_write_denial_facts(inventory, pins=replace(pins, task_id=[]))


def test_mutated_capture_after_inventory_is_rejected(tmp_path):
    inventory, pins = _bundle(tmp_path)
    path = inventory.control_root("memory_write_denial") / "memory-write-deny-response.json"
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(ValueError, match="control bytes changed"):
        read_memory_write_denial_facts(inventory, pins=pins)
