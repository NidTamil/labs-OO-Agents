# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Freeze actual observed schemas without approving unknown native builtins."""

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest
from nooa_cybergym.leaderboard.capabilities import Role
from nooa_cybergym.leaderboard.capability_inventory import (
    ObservedService,
    default_native_capability_specs,
    freeze_inventory,
    load_captured_native_schemas,
    load_frozen_bindings,
    main,
    write_inventory,
)
from nooa_cybergym.leaderboard.capability_runtime import ArtifactPin
from nooa_cybergym.leaderboard.network import NetworkPolicy


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def pin(path, content):
    path.write_bytes(content)
    return ArtifactPin(path.name, path, hashlib.sha256(content).hexdigest())


def setup(tmp_path):
    # Deliberately incomplete synthetic schemas are unit fixtures, never live observations.
    names = {
        s.native_name
        for s in default_native_capability_specs(
            gbrain_provider_ids=("openai", "voyage"),
            gbrain_model_ids=("openai:embed", "voyage:rerank"),
        )
        if not s.native_name.startswith("advisory__")
    }
    tools = [
        {"name": name, "input_schema": {"type": "object", "properties": {}}}
        for name in sorted(names)
    ]
    tools.append(
        {
            "name": "WebFetch",
            "input_schema": {"type": "object", "properties": {"url": {"type": "string"}}},
        }
    )
    report = {
        "schema_version": 1,
        "scope": "native_schema_discovery_no_provider",
        "provider_dispatched": False,
        "task_id": "synthetic:length-header",
        "image_id": "sha256:" + "1" * 64,
        "binary_sha256": hashlib.sha256(b"actual synthetic component fixture").hexdigest(),
        "request_sha256": "3" * 64,
        "tools": tools,
    }
    capture = pin(tmp_path / "capture.json", canonical(report))
    service = pin(tmp_path / "service.bin", b"actual synthetic component fixture")
    adapter = pin(tmp_path / "adapter.py", b"actual synthetic adapter fixture")
    services = {
        name: ObservedService(name, "synthetic-1", (service,), name + "-adapter", "1", (adapter,))
        for name in (
            "native",
            "gbrain",
            "clangd",
            "documentation",
            "advisor",
            "finalizer",
            "vulnerable",
            "advisory",
            "claude-vscode",
        )
    }
    evidence = pin(
        tmp_path / "junit.xml",
        b'<testsuite tests="2" failures="0" errors="0"><testcase name="one"/><testcase name="two"/></testsuite>',
    )
    policy = NetworkPolicy.load(
        Path(__file__).parents[2] / "leaderboard/config/network-policy.json"
    )
    return capture, services, evidence, policy


def frozen(tmp_path):
    capture, services, evidence, policy = setup(tmp_path)
    return freeze_inventory(
        calibration=capture,
        services=services,
        component_evidence=(evidence,),
        network_policy=policy,
        gbrain_provider_ids=("openai", "voyage"),
        gbrain_model_ids=("openai:embed", "voyage:rerank"),
    )


def test_freeze_uses_observed_schemas_and_reports_unknown_without_approving(tmp_path):
    inventory = frozen(tmp_path)
    assert inventory.unsupported[0]["name"] == "WebFetch"
    assert inventory.unsupported[0]["disposition"] == "denied_leakage_boundary"
    assert inventory.unsupported[0]["control_label"] == "leakage boundary"
    assert "WebFetch" not in inventory.parent_tools
    assert {"Read", "Grep", "Glob", "Bash", "Write", "Edit", "Agent"} <= set(inventory.parent_tools)
    assert {"Read", "mcp__gbrain__recall", "mcp__clangd__hover"} <= set(inventory.child_tools)
    glob = next(b for b in inventory.bundle.bindings if b.native_name == "Glob")
    glob_entry = next(
        e for e in inventory.bundle.registry.entries if e.capability_id == glob.capability_id
    )
    assert "/usr/lib" in glob_entry.path_scopes
    assert not {"Bash", "Write", "Agent", "mcp__finalizer__select_final"} & set(
        inventory.child_tools
    )
    assert len(inventory.bundle.registry.entries) == 33
    outputs = write_inventory(tmp_path / "frozen", inventory)
    loaded = load_frozen_bindings(outputs["bindings_path"], inventory.bundle.registry)
    assert loaded == inventory.bundle.bindings
    assert json.loads(outputs["inventory_path"].read_bytes())["provider_dispatched"] is False


def test_missing_legacy_read_tools_are_not_invented(tmp_path):
    capture, services, evidence, policy = setup(tmp_path)
    value = json.loads(capture.path.read_bytes())
    value["tools"] = [
        tool for tool in value["tools"] if tool["name"] not in {"Grep", "Glob"}
    ]
    actual = pin(tmp_path / "observed-current-native.json", canonical(value))
    inventory = freeze_inventory(
        calibration=actual,
        services=services,
        component_evidence=(evidence,),
        network_policy=policy,
        gbrain_provider_ids=("openai", "voyage"),
        gbrain_model_ids=("openai:embed", "voyage:rerank"),
    )
    assert "Read" in inventory.parent_tools
    assert "Read" in inventory.child_tools
    assert "Grep" not in inventory.parent_tools
    assert "Glob" not in inventory.child_tools


def test_rejected_synthetic_child_request_can_freeze_actual_read_schemas(tmp_path):
    capture, services, evidence, policy = setup(tmp_path)
    parent = json.loads(capture.path.read_bytes())
    parent["tools"] = [t for t in parent["tools"] if t["name"] not in {"Grep", "Glob"}]
    parent_pin = pin(tmp_path / "parent-observed.json", canonical(parent))
    discovered = [
        {"name": name, "description": name + " read", "input_schema": {"type": "object", "properties": {"pattern": {"type": "string"}}}}
        for name in ("Grep", "Glob")
    ]
    database = tmp_path / "synthetic-child.sqlite"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE identity (id INTEGER PRIMARY KEY, value BLOB NOT NULL)")
        connection.execute("CREATE TABLE child_schema_discovery (id INTEGER PRIMARY KEY, request_sha256 TEXT NOT NULL, schemas BLOB NOT NULL)")
        connection.execute(
            "INSERT INTO identity VALUES(1,?)",
            (canonical({"task_id": "synthetic:length-header", "run_id": "synthetic-live-1", "captured_schemas": {tool["name"]: hashlib.sha256(canonical(tool)).hexdigest() for tool in parent["tools"]}}),),
        )
        connection.execute("INSERT INTO child_schema_discovery VALUES(1,?,?)", ("a" * 64, canonical(discovered)))
    child_pin = ArtifactPin("rejected-child-schema-db", database, hashlib.sha256(database.read_bytes()).hexdigest())
    inventory = freeze_inventory(
        calibration=parent_pin,
        child_calibration=child_pin,
        services=services,
        component_evidence=(evidence,),
        network_policy=policy,
        gbrain_provider_ids=("openai", "voyage"),
        gbrain_model_ids=("openai:embed", "voyage:rerank"),
    )
    assert {"Grep", "Glob"} <= set(inventory.child_tools)
    outputs = write_inventory(tmp_path / "child-frozen", inventory)
    assert {"Grep", "Glob"} <= set(
        load_captured_native_schemas(outputs["bindings_path"], inventory.bundle.registry)
    )
    with sqlite3.connect(database) as connection:
        connection.execute("UPDATE child_schema_discovery SET request_sha256=?", ("b" * 64,))
    with pytest.raises(ValueError, match="changed"):
        load_frozen_bindings(outputs["bindings_path"], inventory.bundle.registry)


def test_observed_vscode_diagnostics_are_added_with_readonly_roles(tmp_path):
    capture, services, evidence, policy = setup(tmp_path)
    value = json.loads(capture.path.read_bytes())
    value["tools"].append(
        {
            "name": "mcp__claude-vscode__getDiagnostics",
            "input_schema": {
                "type": "object",
                "properties": {"uri": {"type": "string"}},
            },
        }
    )
    actual = pin(tmp_path / "observed-diagnostics.json", canonical(value))
    inventory = freeze_inventory(
        calibration=actual,
        services=services,
        component_evidence=(evidence,),
        network_policy=policy,
        gbrain_provider_ids=("openai", "voyage"),
        gbrain_model_ids=("openai:embed", "voyage:rerank"),
    )
    assert "mcp__claude-vscode__getDiagnostics" in inventory.parent_tools
    assert "mcp__claude-vscode__getDiagnostics" in inventory.child_tools


@pytest.mark.parametrize("change", ["scope", "provider", "missing", "duplicate"])
def test_capture_must_be_actual_unambiguous_no_provider_discovery(tmp_path, change):
    capture, services, evidence, policy = setup(tmp_path)
    value = json.loads(capture.path.read_bytes())
    if change == "scope":
        value["task_id"] = "oss-fuzz:official"
    elif change == "provider":
        value["provider_dispatched"] = True
    elif change == "missing":
        value["tools"] = [t for t in value["tools"] if t["name"] != "Read"]
    else:
        value["tools"].append(value["tools"][0])
    altered = pin(tmp_path / "altered.json", canonical(value))
    with pytest.raises(ValueError):
        freeze_inventory(
            calibration=altered,
            services=services,
            component_evidence=(evidence,),
            network_policy=policy,
            gbrain_provider_ids=("openai",),
            gbrain_model_ids=("openai:embed",),
        )


@pytest.mark.parametrize(
    "change", ["schema", "identity", "scopes", "route", "registry", "noncanonical", "duplicate-key"]
)
def test_bindings_loader_rejects_config_drift_even_when_json_is_wellformed(tmp_path, change):
    inventory = frozen(tmp_path)
    outputs = write_inventory(tmp_path / "frozen", inventory)
    value = json.loads(outputs["bindings_path"].read_bytes())
    row = value["bindings"][0]
    if change == "schema":
        row["schema_json"] = "{}"
    elif change == "identity":
        row["identity"]["adapter_digest"] = "f" * 64
    elif change == "scopes":
        row["data_scopes"] = ["host-files"]
    elif change == "route":
        row["routes"] = ["direct-internet"]
    elif change == "registry":
        value["registry_sha256"] = "f" * 64
    raw = canonical(value)
    if change == "noncanonical":
        raw = json.dumps(value, indent=2).encode()
    if change == "duplicate-key":
        raw = raw.replace(b'"schema_version":1', b'"schema_version":1,"schema_version":1', 1)
    changed = tmp_path / "modified.json"
    changed.write_bytes(raw)
    with pytest.raises(ValueError):
        load_frozen_bindings(changed, inventory.bundle.registry)


def test_default_specs_declare_real_model_and_full_task_execution_dependencies():
    specs = default_native_capability_specs(
        gbrain_provider_ids=("openai", "voyage"), gbrain_model_ids=("openai:embed", "voyage:rerank")
    )
    lookup = {(s.native_name, s.variant): s for s in specs}
    assert lookup[("mcp__gbrain__recall", "")].data_scopes == ("xeus-cybergym-workspace",)
    assert lookup[("Agent", "cybergym-debug")].model_ids == ("glm-5.3",)
    assert lookup[("mcp__advisor__critic", "")].model_ids == ("deepseek-flash",)
    assert lookup[("mcp__documentation__fetch", "compiler")].routes == (
        "documentation/compiler/reference-v1",
    )
    assert lookup[("Bash", "")].roles == (Role.PARENT,)
    assert "isolated-task-container" in lookup[("Bash", "")].data_scopes


def test_optional_audited_native_task_tools_require_actual_advertised_schemas(tmp_path):
    capture, services, evidence, policy = setup(tmp_path)
    value = json.loads(capture.path.read_bytes())
    task_names = {"TodoWrite", "TaskCreate", "TaskGet", "TaskUpdate", "TaskList", "TaskStop"}
    for name in sorted(task_names):
        value["tools"].append({"name": name, "input_schema": {"type": "object", "properties": {}}})
    altered = pin(tmp_path / "task-capture.json", canonical(value))
    inventory = freeze_inventory(
        calibration=altered,
        services=services,
        component_evidence=(evidence,),
        network_policy=policy,
        gbrain_provider_ids=("openai",),
        gbrain_model_ids=("openai:embed",),
    )
    assert task_names <= set(inventory.parent_tools)
    assert not task_names & set(inventory.child_tools)
    assert len(inventory.bundle.registry.entries) == 39
    baseline = default_native_capability_specs(
        gbrain_provider_ids=("openai",), gbrain_model_ids=("openai:embed",)
    )
    assert not task_names & {s.native_name for s in baseline}


def test_pinned_service_file_change_invalidates_bindings(tmp_path):
    inventory = frozen(tmp_path)
    outputs = write_inventory(tmp_path / "frozen", inventory)
    (tmp_path / "service.bin").write_bytes(b"changed runtime")
    with pytest.raises(ValueError):
        load_frozen_bindings(outputs["bindings_path"], inventory.bundle.registry)


def test_inventory_json_cli_freezes_exact_pinned_inputs(tmp_path, capsys):
    capture, services, evidence, policy = setup(tmp_path)

    def encode_pin(p):
        return {"name": p.name, "path": str(p.path), "sha256": p.sha256}

    policy_pin = pin(tmp_path / "network-policy.json", policy.canonical_json.encode())
    config = {
        "schema_version": 1,
        "calibration": encode_pin(capture),
        "component_evidence": [encode_pin(evidence)],
        "network_policy": encode_pin(policy_pin),
        "gbrain_provider_ids": ["openai"],
        "gbrain_model_ids": ["openai:embed"],
        "services": {
            name: {
                "service_id": s.service_id,
                "service_version": s.service_version,
                "service_files": [encode_pin(p) for p in s.service_files],
                "adapter_id": s.adapter_id,
                "adapter_version": s.adapter_version,
                "adapter_files": [encode_pin(p) for p in s.adapter_files],
            }
            for name, s in services.items()
        },
    }
    config_path = tmp_path / "freeze-config.json"
    config_path.write_bytes(canonical(config))
    main(["--config", str(config_path), "--output-directory", str(tmp_path / "cli-output")])
    result = json.loads(capsys.readouterr().out)
    from nooa_cybergym.leaderboard.capabilities import CapabilityRegistry

    registry = CapabilityRegistry.load(
        Path(result["registry_path"]), expected_sha256=result["registry_sha256"]
    )
    assert len(load_frozen_bindings(Path(result["bindings_path"]), registry)) == 33


def test_advisory_declared_schemas_match_existing_bounded_protocol():
    from nooa_cybergym.leaderboard.advisory_tools_runtime import ADVISORY_ACTION_SCHEMAS

    schemas = {s["name"]: s["input_schema"] for s in ADVISORY_ACTION_SCHEMAS}
    assert set(schemas) == {"local_read", "clangd_read", "gbrain_recall", "gbrain_search"}
    assert schemas["local_read"]["properties"]["operation"]["enum"] == ["read", "list", "search"]
    assert schemas["local_read"]["properties"]["max_lines"]["maximum"] == 2000
    assert schemas["local_read"]["properties"]["max_results"]["maximum"] == 200
    assert schemas["clangd_read"]["properties"]["line"]["minimum"] == 0
    assert schemas["clangd_read"]["properties"]["line"]["maximum"] == 1000000
    assert schemas["gbrain_recall"]["properties"]["query"]["maxLength"] == 1000
    assert all(s["additionalProperties"] is False for s in schemas.values())
