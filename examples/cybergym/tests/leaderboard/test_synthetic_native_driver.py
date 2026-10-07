# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""The live controller must reject official IDs before it stages or launches."""

import sqlite3
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nooa_cybergym.leaderboard.container import build_container_kwargs
from nooa_cybergym.leaderboard.runtime_config import load_runtime_config
from nooa_cybergym.leaderboard.synthetic_native_driver import (
    _memory_guard_binding,
    _PostOracleMemoryBudget,
    _quiesce_and_stop,
    _recipe,
    _stopped_tool_dispositions,
    _verified_primary_provider,
    validate_request,
)
from xeus_cybergym.canonical import canonical_json
from xeus_cybergym.ledger import Ed25519Signer, Ed25519Verifier, SignatureVerificationError

from .test_runtime_config import prepared  # noqa: F401 - register the fixture


def test_vulnerable_recipe_runs_binary_from_output_bind_mount(tmp_path):
    recipe = _recipe()
    binary = recipe.test_argv[0]
    assert binary.startswith("/workspace/output/")
    assert recipe.build_argv[recipe.build_argv.index("-o") + 1] == binary
    workspace = tmp_path / "workspace"
    output = workspace / "output"
    output.mkdir(parents=True)
    kwargs = build_container_kwargs(
        image="sha256:fixture",
        workspace=workspace,
        output=output,
        network="isolated",
        ssh_port=38377,
    )
    assert kwargs["volumes"][str(output.resolve())] == {
        "bind": "/workspace/output",
        "mode": "rw",
    }
    assert "/workspace/output" not in kwargs["tmpfs"]


def test_driver_rejects_official_task_before_creating_workspace(prepared):  # noqa: F811
    raw, save, _ = prepared
    config = load_runtime_config(save())
    with pytest.raises(ValueError, match="synthetic fixture"):
        validate_request(config, run_id=config.run_ids[0], task_id="arvo:1065")
    assert list(Path(raw["staging_root"]).iterdir()) == []


def test_provider_dispatch_requires_completed_glm_response_with_usage(tmp_path):
    path = tmp_path / "model-requests.jsonl"
    path.write_text('{"event":"request_terminal","role":"deepseek","outcome":"completed"}\n')
    assert _verified_primary_provider(path) is False
    with path.open("a") as stream:
        stream.write('{"event":"request_terminal","role":"primary","outcome":"provider_error","returned_model":"glm-5.3"}\n')
    assert _verified_primary_provider(path) is False
    with path.open("a") as stream:
        stream.write('{"event":"request_terminal","role":"primary","outcome":"completed","usage_status":"observed","returned_model":"glm-5.3","provider_request_id":"msg-1"}\n')
    assert _verified_primary_provider(path) is True


def test_quiesce_clangd_services_while_container_is_still_running():
    events = []

    class Services:
        def close(self):
            events.append("services.close")
            assert container.status == "running"

    class Container:
        status = "running"

        def stop(self, *, timeout):
            assert timeout == 10
            events.append("container.stop")
            self.status = "exited"

        def reload(self):
            events.append("container.reload")

    container = Container()
    _quiesce_and_stop(Services(), container)
    assert events == ["services.close", "container.stop", "container.reload"]


def test_post_oracle_capture_continues_accounting_with_a_strict_auxiliary_cap():
    class Audit:
        events = []

        def record(self, event):
            self.events.append(event)
            return True

    audit = Audit()
    budget = _PostOracleMemoryBudget(
        audit,
        prior_requests=52,
        prior_auxiliary_requests=49,
        remaining_seconds=120,
    )
    assert 0 < budget.remaining_seconds() <= 120
    assert [budget.reserve_request() for _ in range(4)] == [53, 54, 55, 56]
    with pytest.raises(PermissionError, match="post-oracle memory budget"):
        budget.reserve_request()
    assert [event["event"] for event in audit.events] == [
        "post_oracle_memory_model_reserved",
        "post_oracle_memory_model_reserved",
        "post_oracle_memory_model_reserved",
        "post_oracle_memory_model_reserved",
        "post_oracle_memory_model_denied",
    ]

    full = _PostOracleMemoryBudget(
        audit,
        prior_requests=600,
        prior_auxiliary_requests=563,
        remaining_seconds=120,
    )
    with pytest.raises(PermissionError, match="post-oracle memory budget"):
        full.reserve_request()


def test_writer_guard_is_pinned_by_signed_read_catalog(tmp_path):
    key = Ed25519PrivateKey.generate()
    signer = Ed25519Signer(private_key=key, key_id="memory-test")
    verifier = Ed25519Verifier({"memory-test": key.public_key()})
    catalog = {
        "schema_version": 1,
        "artifact_kind": "memory_catalog",
        "source_ids": ["xeus-cybergym-workspace"],
        "server_context_source_id": "xeus-cybergym-workspace",
        "native_guard_binding_sha256": "a" * 64,
    }
    path = tmp_path / "catalog.json"
    path.write_bytes(canonical_json(signer.sign(canonical_json(catalog)).model_dump()))
    assert _memory_guard_binding(path, verifier) == "a" * 64
    path.write_bytes(path.read_bytes().replace(b"memory-test", b"wrong-id"))
    with pytest.raises(SignatureVerificationError):
        _memory_guard_binding(path, verifier)


def test_stopped_tool_dispositions_reconcile_denials_and_interrupted_calls(tmp_path):
    hooks = sqlite3.connect(tmp_path / "native-hooks.sqlite")
    hooks.execute("create table sessions(id text primary key, closed integer)")
    hooks.execute("create table tools(id text primary key, name text, closed integer)")
    hooks.execute("insert into sessions values('session-a',0)")
    hooks.executemany(
        "insert into tools values(?,?,0)",
        [
            ("tool-denied", "Bash"),
            ("tool-observed", "Bash"),
            ("tool-read", "Read"),
            ("tool-final", "mcp__finalizer__select_final"),
        ],
    )
    hooks.commit()
    hooks.close()
    native = sqlite3.connect(tmp_path / "native-tools.sqlite")
    native.execute("create table tools(id text primary key, name text, status text)")
    native.executemany(
        "insert into tools values(?,?,?)",
        [
            ("tool-denied", "Bash", "denied"),
            ("tool-observed", "Bash", "observed"),
            ("tool-read", "Read", "allowed"),
            ("tool-final", "mcp__finalizer__select_final", "dispatched"),
        ],
    )
    native.commit()
    native.close()
    assert _stopped_tool_dispositions(tmp_path, final_declared=True) == {
        "policy_denied_without_post_hook": 1,
        "provider_tool_unadmitted_at_controller_stop": 1,
        "interrupted_tools_at_controller_stop": 1,
        "declared_finalizer_stopped_before_post_hook": 1,
        "sessions_closed_by_controller_stop": 1,
    }
