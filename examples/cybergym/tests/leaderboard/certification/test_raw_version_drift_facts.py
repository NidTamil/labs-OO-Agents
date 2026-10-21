# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Version-drift raw projections remain facts, not a twelve-gate result."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import replace
from pathlib import Path

import pytest
from nooa_cybergym.leaderboard.raw_pair_manifest import build_raw_pair_manifest
from nooa_cybergym.leaderboard.raw_version_drift_facts import (
    VersionDriftPins,
    read_version_drift_facts,
)
from nooa_cybergym.leaderboard.subset_readiness_inventory import (
    load_subset_readiness_inventory,
)

_FIXTURES = ("synthetic:length-header", "synthetic:chunk-table")
_CONTROLS = (
    "primary_takeover",
    "interruption_reconnection",
    "timeout_failure",
    "version_drift",
    "memory_write_denial",
)
_CONTAINER = "a" * 64
_IMAGE = "sha256:" + "b" * 64
_MANIFEST = "c" * 64
_BINARY = "d" * 64
_REJECTION = "Extension is not compatible with Code 1.141.0. Extension requires: 1.140.0."


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _files(root: Path):
    return [
        {
            "path": path.relative_to(root).as_posix(),
            "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        for path in sorted(root.rglob("*"))
        if path.is_file()
    ]


def _pins(inventory):
    return VersionDriftPins(
        inventory_descriptor_sha256=inventory.descriptor_sha256,
        source_sha256="e" * 64,
        config_sha256="f" * 64,
        image_id=_IMAGE,
        manifest_sha256=_MANIFEST,
        binary_sha256=_BINARY,
        task_id="synthetic:length-header",
        run_id="drift-run",
        launch_id="drift-launch",
        container_id=_CONTAINER,
        client_version="1.141.0",
        launcher_engine="1.140.0",
    )


def _bundle(
    tmp_path: Path,
    *,
    gateway_rows=(),
    gateway_raw=None,
    log_line=_REJECTION,
    marker_image=_IMAGE,
    marker_task="synthetic:length-header",
):
    repetitions = []
    manifests = {}
    for run_id in ("repeat-one", "repeat-two"):
        root = tmp_path / run_id
        root.mkdir()
        fixtures = {}
        for index, fixture in enumerate(_FIXTURES):
            fixture_root = root / f"fixture-{index}"
            fixture_root.mkdir()
            (fixture_root / "result.json").write_bytes(_json({"run_id": run_id}))
            fixtures[fixture] = fixture_root
        manifest = _json(build_raw_pair_manifest(run_id, fixtures))
        manifests[run_id] = manifest
        repetitions.append(
            {
                "run_id": run_id,
                "root": str(root),
                "pair_manifest_sha256": hashlib.sha256(manifest).hexdigest(),
                "fixtures": {key: str(value) for key, value in fixtures.items()},
                "files": _files(root),
            }
        )
    controls = []
    for kind in _CONTROLS:
        root = tmp_path / kind
        root.mkdir()
        if kind == "version_drift":
            connection = {
                "scope": "native_schema_discovery_no_provider",
                "provider_dispatched": False,
                "image_id": _IMAGE,
                "container_id": _CONTAINER,
                "ssh_host_port": 12345,
                "known_hosts": str(root / "known_hosts"),
                "workspace": "/workspace",
                "run_id": "drift-run",
                "launch_id": "drift-launch",
            }
            marker = {
                "schema_version": 1,
                "scope": "native_schema_discovery_no_provider",
                "provider_dispatched": False,
                "benchmark_eligible": False,
                "task_id": marker_task,
                "run_id": "drift-run",
                "launch_id": "drift-launch",
                "manifest_sha256": _MANIFEST,
                "image_id": marker_image,
                "binary_sha256": _BINARY,
                "peer": {"container_id": _CONTAINER},
            }
            (root / "connection.json").write_bytes(_json(connection))
            (root / "calibration.json").write_bytes(_json(marker))
            (root / "remote-agent.log").write_text(log_line + "\n", encoding="utf-8")
            (root / "gateway.jsonl").write_bytes(
                gateway_raw
                if gateway_raw is not None
                else b"".join(
                    json.dumps(row, sort_keys=True).encode() + b"\n" for row in gateway_rows
                )
            )
        else:
            (root / "control.json").write_bytes(_json({"control_id": kind}))
        controls.append(
            {
                "kind": kind,
                "control_id": f"control-{kind}",
                "root": str(root),
                "files": _files(root),
            }
        )
    descriptor = _json(
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
    return inventory


def _gateway_row(endpoint="registered-tool-gateway", path="/health"):
    return {
        "kind": "route",
        "at_monotonic": 1.0,
        "container_id": _CONTAINER,
        "network_id": "network-one",
        "source_ip": "127.0.0.1",
        "endpoint": endpoint,
        "method": "POST",
        "path_sha256": hashlib.sha256(path.encode()).hexdigest(),
        "request_sha256": hashlib.sha256(b"").hexdigest(),
        "request_bytes": 0,
        "response_bytes": 0,
        "response_chunks": 0,
        "status": 200,
        "allowed": True,
        "completed": True,
    }


def test_reads_bounded_identity_and_incompatibility_facts_without_gate_pass(tmp_path):
    inventory = _bundle(tmp_path, gateway_rows=(_gateway_row(),))

    facts = read_version_drift_facts(inventory, pins=_pins(inventory))

    assert facts.task_id == "synthetic:length-header"
    assert facts.inventory_descriptor_sha256 == inventory.descriptor_sha256
    assert (facts.run_id, facts.launch_id, facts.container_id) == (
        "drift-run",
        "drift-launch",
        _CONTAINER,
    )
    assert facts.gateway_rows_checked == 1
    assert facts.rejection_line_sha256 == hashlib.sha256(_REJECTION.encode()).hexdigest()
    assert "source_and_config_observation" in facts.unresolved
    assert "authenticated_client_server_and_extension_observation" in facts.unresolved
    assert "gateway_writer_and_owned_cleanup_closure" in facts.unresolved
    assert not hasattr(facts, "passed")
    assert not hasattr(facts, "verified")


def test_setup_timeout_without_real_incompatibility_is_rejected(tmp_path):
    inventory = _bundle(tmp_path, log_line="native calibration boundary failed or timed out")
    with pytest.raises(ValueError, match="incompatibility"):
        read_version_drift_facts(inventory, pins=_pins(inventory))


@pytest.mark.parametrize(
    "endpoint,path",
    [
        ("model-gateway", "/v1/messages"),
        ("registered-tool-gateway", "/native-launch/reserve"),
        ("registered-tool-gateway", "/native-launch/events"),
    ],
)
def test_any_model_or_launch_dispatch_record_rejects_pause(tmp_path, endpoint, path):
    inventory = _bundle(tmp_path, gateway_rows=(_gateway_row(endpoint, path),))
    with pytest.raises(ValueError, match="dispatch"):
        read_version_drift_facts(inventory, pins=_pins(inventory))


def test_swapped_calibration_image_fails_identity_join(tmp_path):
    inventory = _bundle(tmp_path, marker_image="sha256:" + "9" * 64)
    with pytest.raises(ValueError, match="identity"):
        read_version_drift_facts(inventory, pins=_pins(inventory))


def test_swapped_control_task_fails_identity_join(tmp_path):
    inventory = _bundle(tmp_path, marker_task="synthetic:chunk-table")
    with pytest.raises(ValueError, match="identity"):
        read_version_drift_facts(inventory, pins=_pins(inventory))


def test_duplicate_gateway_keys_cannot_hide_model_route(tmp_path):
    raw = b'{"kind":"route","kind":"host-gateway-attestation","endpoint":"model-gateway"}\n'
    inventory = _bundle(tmp_path, gateway_raw=raw)
    with pytest.raises(ValueError, match="gateway audit"):
        read_version_drift_facts(inventory, pins=_pins(inventory))


def test_attestation_row_cannot_carry_a_suppressed_route(tmp_path):
    inventory = _bundle(
        tmp_path,
        gateway_rows=({"kind": "host-gateway-attestation", "endpoint": "model-gateway"},),
    )
    with pytest.raises(ValueError, match="gateway audit"):
        read_version_drift_facts(inventory, pins=_pins(inventory))


def test_incomplete_gateway_route_row_does_not_count_as_negative_dispatch(tmp_path):
    incomplete = _gateway_row()
    del incomplete["completed"]
    inventory = _bundle(tmp_path, gateway_rows=(incomplete,))
    with pytest.raises(ValueError, match="gateway audit"):
        read_version_drift_facts(inventory, pins=_pins(inventory))


def test_substituted_typed_control_inventory_is_rejected(tmp_path):
    inventory = _bundle(tmp_path)
    wrong = replace(_pins(inventory), inventory_descriptor_sha256="0" * 64)
    with pytest.raises(ValueError, match="inventory"):
        read_version_drift_facts(inventory, pins=wrong)
