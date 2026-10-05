from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from nooa_cybergym.leaderboard.deepseek import (
    AlternateModelPolicy,
    DeepSeekController,
    SharedCampaignBudget,
)
from nooa_cybergym.leaderboard.host_boundary_runtime import AdmittedPeer
from nooa_cybergym.leaderboard.native_tool_runtime import NativeToolCall
from nooa_cybergym.leaderboard.vulnerable_runtime import VulnerableRecipe, VulnerableRunner


def response(exit_code=0, output=b"observed output"):
    return {
        "exit_code": exit_code,
        "output_sha256": hashlib.sha256(output).hexdigest(),
        "output_bytes": len(output),
        "output_base64": base64.b64encode(output[:65536]).decode(),
        "output_truncated": len(output) > 65536,
        "capture_complete": True,
        "timed_out": False,
    }


@pytest.fixture
def fixture():
    class Audit:
        def __init__(self):
            self.events = []
            self.reject = None

        def record(self, event):
            self.events.append(event)
            return event["event"] != self.reject

    class Container:
        id = "container-1"

        def __init__(self):
            self.calls = []
            self.responses = [response(), response(-6)]

        def exec_run(self, cmd, **kwargs):
            self.calls.append((cmd, kwargs))
            return SimpleNamespace(exit_code=0, output=json.dumps(self.responses.pop(0)).encode())

    audit = Audit()
    container = Container()
    observed = []
    policy = AlternateModelPolicy.model_validate_json(
        (
            Path(__file__).resolve().parents[2] / "leaderboard/config/alternate-model.json"
        ).read_bytes()
    )
    controller = DeepSeekController(
        policy,
        "synthetic-secret",
        audit=audit,
        registry_digest="a" * 64,
        budget=SharedCampaignBudget(),
    )
    runner = VulnerableRunner(
        container=container,
        peer=AdmittedPeer(container.id, "network-1", "172.30.0.2"),
        task_id="task-1",
        attempt_id="attempt-1",
        recipe=VulnerableRecipe(
            ("/usr/bin/cc", "-o", "target", "main.c"),
            ("/workspace/src/target", "{candidate}"),
            "/workspace/src",
            30,
            10,
        ),
        controller=controller,
        observe_failure=observed.append,
        snapshot_candidate=lambda path: {
            "sha256": hashlib.sha256(b"poc").hexdigest(),
            "byte_length": 3,
        },
        audit=audit,
    )
    call = NativeToolCall(
        "task-1",
        "attempt-1",
        "request-1",
        "session-1",
        None,
        "parent",
        "tool-1",
        "mcp__vulnerable__run_test",
        {"candidate_path": "/workspace/output/poc.bin"},
    )
    return runner, call, container, audit, observed


def test_actual_bounded_supervisor_result_enables_debug_after_audit(fixture):
    runner, call, container, audit, observed = fixture
    result = runner.run(call)
    assert result["test"]["exit_code"] == -6 and result["debug_available"] and len(observed) == 1
    assert observed[0].evidence_digest == result["evidence_sha256"]
    cmd, options = container.calls[0]
    assert cmd[:7] == [
        "/usr/bin/timeout",
        "--signal=KILL",
        "35s",
        "/usr/bin/python3",
        "-I",
        "-S",
        "-c",
    ]
    assert options["stderr"] is False and options["user"] == "agent"
    assert audit.events[0]["event"] == "vulnerable_test_started"


@pytest.mark.parametrize("rejected", ["vulnerable_test_started", "vulnerable_test_observed"])
def test_audit_acknowledgment_required_before_execution_or_failure_admission(fixture, rejected):
    runner, call, container, audit, observed = fixture
    audit.reject = rejected
    with pytest.raises(RuntimeError, match="audit"):
        runner.run(call)
    assert not observed
    if rejected == "vulnerable_test_started":
        assert not container.calls


def test_incomplete_capture_or_fake_digest_does_not_create_failure_evidence(fixture):
    runner, call, container, _, observed = fixture
    container.responses = [{**response(-6), "output_sha256": "0" * 64}]
    with pytest.raises(RuntimeError):
        runner.run(call)
    assert not observed


@pytest.mark.skipif(os.name != "posix", reason="isolated process-group supervisor requires POSIX")
def test_supervisor_stream_hashes_full_output_without_retaining_it():
    from nooa_cybergym.leaderboard.vulnerable_runtime import _SUPERVISE

    payload = {
        "argv": [sys.executable, "-c", 'import sys;sys.stdout.buffer.write(b"x"*1048576)'],
        "timeout_seconds": 5,
    }
    process = subprocess.run(
        [sys.executable, "-I", "-S", "-c", _SUPERVISE, json.dumps(payload)],
        capture_output=True,
        timeout=10,
    )
    assert process.returncode == 0
    result = json.loads(process.stdout)
    assert (
        result["output_bytes"] == 1048576
        and result["output_sha256"] == hashlib.sha256(b"x" * 1048576).hexdigest()
    )
    assert len(base64.b64decode(result["output_base64"])) == 65536 and result["capture_complete"]


@pytest.mark.skipif(os.name != "posix", reason="isolated process-group supervisor requires POSIX")
def test_supervisor_kills_actual_timed_out_process_group():
    from nooa_cybergym.leaderboard.vulnerable_runtime import _SUPERVISE

    payload = {"argv": [sys.executable, "-c", "import time;time.sleep(20)"], "timeout_seconds": 1}
    process = subprocess.run(
        [sys.executable, "-I", "-S", "-c", _SUPERVISE, json.dumps(payload)],
        capture_output=True,
        timeout=7,
    )
    assert process.returncode == 0
    result = json.loads(process.stdout)
    assert result["timed_out"] and result["exit_code"] == -9 and result["capture_complete"]
