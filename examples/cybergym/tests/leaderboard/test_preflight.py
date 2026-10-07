# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Pre-model isolation probes record results without disclosing their output."""

from __future__ import annotations

import json
import subprocess
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from nooa_cybergym.leaderboard.network import NetworkPolicy
from nooa_cybergym.leaderboard.preflight import (
    _DENIED_ROUTE_SCRIPT,
    _FORBIDDEN_ENV,
    _PATH_SCRIPT,
    ProbeExecution,
    evaluate_probe_results,
    run_preflight,
)

POLICY_PATH = Path(__file__).parents[2] / "leaderboard/config/network-policy.json"


@dataclass(frozen=True)
class _TaskContainer:
    container_id: str
    container_name: str
    host_ssh_port: int


def _positive_results():
    policy = NetworkPolicy.load(POLICY_PATH)
    return {
        "forbidden_paths": dict.fromkeys(
            (
                "/tmp/poc",
                "/var/run/docker.sock",
                "/srv/sunchaser",
                "/root",
                "/workspace/repo-fix.tar.gz",
                "/workspace/patch.diff",
                "/workspace/error.txt",
                "/workspace/.git",
                "/workspace/src/.git",
                "/workspace/src/**/.git",
            ),
            False,
        ),
        "required_paths": dict.fromkeys(
            (
                "/workspace/description.txt",
                "/workspace/README.md",
                "/workspace/repo-vul.tar.gz",
                "/workspace/submit.sh",
                "/workspace/src",
            ),
            True,
        ),
        "uid": 1000,
        "network": dict.fromkeys(policy.allowed_logical_endpoints, True),
        "forbidden_routes": dict.fromkeys(policy.required_denied_routes, False),
        "forbidden_env": dict.fromkeys(_FORBIDDEN_ENV, False),
        "mounts": dict.fromkeys(
            (
                "workspace_readonly",
                "output_writable",
                "src_tmpfs",
                "src_executable",
                "home_tmpfs",
                "tmp_tmpfs",
                "no_host_processes",
            ),
            True,
        ),
        "registered_tools": {"clangd": True},
    }


def test_preflight_fails_closed_on_any_forbidden_path_or_route():
    result = _positive_results()
    result["forbidden_paths"]["/var/run/docker.sock"] = True
    result["forbidden_routes"]["external-target-patch"] = True
    report = evaluate_probe_results(result, NetworkPolicy.load(POLICY_PATH))
    assert report.passed is False
    assert "/var/run/docker.sock" in report.failures
    assert "external-target-patch" in report.failures


def test_preflight_requires_executable_source_mount_for_fuzzing():
    result = _positive_results()
    result["mounts"]["src_executable"] = False
    report = evaluate_probe_results(result, NetworkPolicy.load(POLICY_PATH))
    assert not report.passed
    assert "src_executable" in report.failures


def test_missing_probe_or_credential_in_child_environment_fails_closed():
    result = _positive_results()
    del result["network"]["registered-tool-gateway"]
    result["forbidden_env"]["DEEPSEEK_API_KEY"] = True
    report = evaluate_probe_results(result, NetworkPolicy.load(POLICY_PATH))
    assert not report.passed
    assert "registered-tool-gateway" in report.failures
    assert "DEEPSEEK_API_KEY" in report.failures


@pytest.mark.parametrize(
    "name",
    (
        "ANTHROPIC_AUTH_TOKEN",
        "SUNCHASER_ZAI_CODING_PLAN_TOKEN",
        "ZAI_API_KEY",
        "GH_TOKEN",
        "ZAI_CODING_PLAN_TOKEN",
        "GITHUB_API_TOKEN",
    ),
)
def test_provider_and_github_credential_aliases_are_probed_and_denied(name):
    assert name in _FORBIDDEN_ENV
    result = _positive_results()
    result["forbidden_env"][name] = True
    report = evaluate_probe_results(result, NetworkPolicy.load(POLICY_PATH))
    assert not report.passed
    assert name in report.failures


def test_preflight_accepts_supplied_archive_and_approved_routes():
    report = evaluate_probe_results(_positive_results(), NetworkPolicy.load(POLICY_PATH))
    assert report.passed
    assert report.failures == ()


@dataclass
class _RecordingExecutor:
    fail_name: str | None = None
    fail_context: str | None = None
    wrong_context: bool = False
    mode: str = "synthetic"

    def __post_init__(self):
        self.seen = []

    def run(self, spec, container):
        self.seen.append(spec)
        failed = spec.name == self.fail_name and spec.context == self.fail_context
        return ProbeExecution(
            exit_code=1 if failed else 0,
            stdout=b"SECRET_VALUE_MUST_NOT_LEAK",
            stderr=b"",
            observed_context="other" if self.wrong_context else spec.context,
            observed_container_id=container.container_id,
        )


def _run(tmp_path, executor):
    root = tmp_path / "task"
    root.mkdir()
    evidence = tmp_path / "controller-evidence"
    manifest = evidence / "task-manifest.json"
    evidence.mkdir()
    manifest.write_text('{"task_id":"synthetic"}', encoding="utf-8")
    container = _TaskContainer("container-123", "synthetic", 2222)
    report = run_preflight(
        container=container,
        workspace_manifest=manifest,
        workspace_root=root,
        policy=NetworkPolicy.load(POLICY_PATH),
        executor=executor,
        evidence_dir=evidence,
    )
    return report, executor, evidence


def test_run_preflight_executes_both_contexts_before_model_and_writes_private_evidence(tmp_path):
    report, executor, evidence = _run(tmp_path, _RecordingExecutor())
    assert report.passed
    assert report.execution_mode == "synthetic"
    assert {spec.context for spec in executor.seen} == {"parent", "child"}
    assert {spec.name for spec in executor.seen} >= {
        "path:/tmp/poc",
        "path:/workspace/repo-vul.tar.gz",
        "route:external-target-patch",
        "route:documentation-gateway",
        "env:DEEPSEEK_API_KEY",
        "mount:workspace_readonly",
        "tool:clangd",
    }
    saved = json.loads((evidence / "preflight-report.json").read_text())
    assert saved["passed"] is True
    assert saved["container_id"] == "container-123"
    assert saved["workspace_manifest_sha256"]
    assert saved["policy_sha256"] == NetworkPolicy.load(POLICY_PATH).digest
    assert "SECRET_VALUE_MUST_NOT_LEAK" not in json.dumps(saved)
    assert all(len(item["stdout_sha256"]) == 64 for item in saved["probes"])


def test_added_credential_names_are_probed_in_parent_and_child(tmp_path):
    _, executor, _ = _run(tmp_path, _RecordingExecutor())
    seen = {
        (spec.context, spec.target) for spec in executor.seen if spec.category == "forbidden_env"
    }
    for context in ("parent", "child"):
        for name in (
            "ANTHROPIC_AUTH_TOKEN",
            "SUNCHASER_ZAI_CODING_PLAN_TOKEN",
            "ZAI_API_KEY",
            "GH_TOKEN",
        ):
            assert (context, name) in seen


def test_run_preflight_fails_when_child_probe_fails_or_context_is_forged(tmp_path):
    report, _, _ = _run(
        tmp_path,
        _RecordingExecutor(fail_name="route:external-target-patch", fail_context="child"),
    )
    assert not report.passed
    assert "child:external-target-patch" in report.failures


def test_run_preflight_rejects_evidence_inside_agent_root(tmp_path):
    root = tmp_path / "task"
    root.mkdir()
    manifest = tmp_path / "task-manifest.json"
    manifest.write_text("{}")
    with pytest.raises(ValueError, match="outside"):
        run_preflight(
            container=_TaskContainer("id", "name", 2222),
            workspace_manifest=manifest,
            workspace_root=root,
            policy=NetworkPolicy.load(POLICY_PATH),
            executor=_RecordingExecutor(),
            evidence_dir=root / "evidence",
        )


def test_tls_failure_is_not_evidence_that_egress_was_denied():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        command = [
            "python3",
            "-c",
            _DENIED_ROUTE_SCRIPT,
            f"https://127.0.0.1:{server.server_port}/",
        ]
        outcome = subprocess.run(command, capture_output=True, check=False, timeout=10)
    finally:
        server.shutdown()
        thread.join(timeout=10)
    assert outcome.returncode != 0


@pytest.mark.parametrize("kind", ["file", "directory", "symlink"])
def test_nested_git_metadata_probe_detects_every_node_kind(tmp_path, kind):
    source = tmp_path / "source"
    nested = source / "subproject"
    nested.mkdir(parents=True)
    metadata = nested / ".git"
    if kind == "file":
        metadata.write_text("gitdir: elsewhere")
    elif kind == "directory":
        metadata.mkdir()
    else:
        metadata.symlink_to(tmp_path / "missing-target")
    command = ["python3", "-c", _PATH_SCRIPT, f"{source}/**/.git", "0"]
    outcome = subprocess.run(command, capture_output=True, check=False, timeout=10)
    assert outcome.returncode != 0
