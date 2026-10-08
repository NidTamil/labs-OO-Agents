# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from dataclasses import replace

import pytest
from nooa_cybergym.leaderboard.advisory_runtime import AdvisoryAction
from nooa_cybergym.leaderboard.deepseek import DeepSeekRole
from nooa_cybergym.leaderboard.native_launcher import _canonical


def action(name, args):
    return AdvisoryAction(
        "action-1",
        "provider-1",
        "task-1",
        "attempt-1",
        DeepSeekRole.INDEPENDENT_RECON,
        name,
        hashlib.sha256(_canonical(args)).hexdigest(),
    )


@pytest.fixture
def fixture():
    from nooa_cybergym.leaderboard.advisory_tools_runtime import AdvisoryTools
    from nooa_cybergym.leaderboard.memory import MemoryFacade
    from nooa_cybergym.leaderboard.tool_services_runtime import ClangdClient

    class API:
        def __init__(self):
            self.calls = []
            self.exit = 0

        def exec_create(self, container_id, **kwargs):
            self.calls.append((container_id, kwargs))
            return {"Id": "exec-1"}

        def exec_start(self, *args, **kwargs):
            return b'{"operation":"read","lines":[{"line":1,"text":"synthetic source"}]}'

        def exec_inspect(self, exec_id):
            return {"Running": False, "ExitCode": self.exit}

    class Clangd(ClangdClient):
        def __init__(self):
            self.container_id = "container-1"
            self.source_roots = ("/workspace/src",)
            self.calls = []

        def invoke(self, name, args):
            self.calls.append((name, args))
            return {"symbols": ["symbol"]}

    class Memory(MemoryFacade):
        def __init__(self):
            self.calls = []

        def model_tool(self, *args, **kwargs):
            self.calls.append((args, kwargs))
            return []

    api = API()
    clangd = Clangd()
    memory = Memory()
    grants = []
    tools = AdvisoryTools(
        api,
        container_id="container-1",
        source_roots=("/workspace/src",),
        task_id="task-1",
        attempt_id="attempt-1",
        clangd=clangd,
        memory=memory,
        structural_terms=("length field",),
        authorize=lambda observed, args: grants.append((observed, args)) or True,
    )
    return tools, api, clangd, memory, grants


def test_local_read_is_fixed_nonshell_exec_and_inspects_actual_completion(fixture):
    tools, api, _, _, grants = fixture
    args = {"operation": "read", "path": "/workspace/src/a.c", "start_line": 1, "max_lines": 20}
    result = tools.callbacks()["local_read"](
        args, DeepSeekRole.INDEPENDENT_RECON, action("local_read", args)
    )
    assert result["lines"][0]["text"] == "synthetic source" and len(grants) == 1
    container, kwargs = api.calls[0]
    assert container == "container-1" and kwargs["user"] == "agent"
    assert kwargs["cmd"][:7] == [
        "/usr/bin/timeout",
        "--signal=KILL",
        "20s",
        "/usr/bin/python3",
        "-I",
        "-S",
        "-c",
    ]
    assert json.loads(kwargs["cmd"][-1])["arguments"] == args
    api.exit = 1
    with pytest.raises(PermissionError):
        tools.callbacks()["local_read"](
            args, DeepSeekRole.INDEPENDENT_RECON, action("local_read", args)
        )


@pytest.mark.skipif(os.name == "nt", reason="source reader runs in Linux task containers")
def test_local_reader_reports_non_utf8_source_without_exposing_binary_bytes(tmp_path):
    from nooa_cybergym.leaderboard.advisory_tools_runtime import _SOURCE_QUERY

    root = tmp_path / "src"
    root.mkdir()
    binary = root / "candidate.bin"
    binary.write_bytes(b"prefix\xff\x00secret")
    request = {"roots": [str(root)], "arguments": {"operation": "read", "path": str(binary)}}
    completed = subprocess.run(
        [sys.executable, "-I", "-S", "-c", _SOURCE_QUERY, json.dumps(request)],
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0
    assert completed.stderr == b""
    assert json.loads(completed.stdout) == {
        "operation": "read",
        "path": str(binary),
        "truncated": False,
        "error": "non_utf8_source",
        "lines": [],
    }


@pytest.mark.parametrize(
    "path",
    ["/etc/passwd", "/workspace/output/poc", "/workspace/src/../secret", "/workspace/src//a.c"],
)
def test_local_scope_escape_rejected_before_dispatch(fixture, path):
    tools, api, *_ = fixture
    args = {"operation": "read", "path": path}
    with pytest.raises((PermissionError, ValueError)):
        tools.callbacks()["local_read"](
            args, DeepSeekRole.INDEPENDENT_RECON, action("local_read", args)
        )
    assert not api.calls


def test_actual_action_context_cannot_be_replaced_with_parent_or_changed_args(fixture):
    tools, api, *_ = fixture
    args = {"operation": "read", "path": "/workspace/src/a.c"}
    with pytest.raises(PermissionError):
        tools.callbacks()["local_read"](
            args,
            DeepSeekRole.INDEPENDENT_RECON,
            replace(action("local_read", args), arguments_sha256="0" * 64),
        )
    assert not api.calls


def test_clangd_and_memory_reuse_real_typed_routes_with_child_provenance(fixture):
    tools, _, clangd, memory, _ = fixture
    args = {"operation": "hover", "path": "/workspace/src/a.c", "line": 0, "character": 3}
    tools.callbacks()["clangd_read"](
        args, DeepSeekRole.INDEPENDENT_RECON, action("clangd_read", args)
    )
    assert clangd.calls == [("hover", {"path": "/workspace/src/a.c", "line": 0, "character": 3})]
    args = {"query": "length field"}
    tools.callbacks()["gbrain_recall"](
        args, DeepSeekRole.INDEPENDENT_RECON, action("gbrain_recall", args)
    )
    call, identity = memory.calls[0]
    assert call == ("recall", "length field") and identity["caller"].value == "child"
    assert identity["model_id"] == "deepseek-flash" and identity["request_id"] == "action-1"


@pytest.mark.skipif(os.name != "posix", reason="actual nofollow source helper requires POSIX")
def test_fixed_source_helper_rejects_symlink_and_reads_searches_real_files(tmp_path):
    from nooa_cybergym.leaderboard.advisory_tools_runtime import _SOURCE_QUERY

    root = tmp_path / "src"
    root.mkdir()
    (root / "a.c").write_text("int length;\nreturn length;\n")
    secret = tmp_path / "secret"
    secret.write_text("private")
    (root / "escape").symlink_to(secret)

    def run(args):
        return subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                "-c",
                _SOURCE_QUERY,
                json.dumps({"roots": [str(root)], "arguments": args}),
            ],
            capture_output=True,
        )

    result = run({"operation": "read", "path": str(root / "a.c")})
    assert result.returncode == 0 and len(json.loads(result.stdout)["lines"]) == 2
    assert run({"operation": "read", "path": str(root / "escape")}).returncode != 0
    matches = run({"operation": "search", "path": str(root), "query": "length"})
    assert matches.returncode == 0 and len(json.loads(matches.stdout)["matches"]) == 2

    file_matches = run({"operation": "search", "path": str(root / "a.c"), "query": "length"})
    assert file_matches.returncode == 0
    assert [match["line"] for match in json.loads(file_matches.stdout)["matches"]] == [1, 2]
    assert (
        run({"operation": "search", "path": str(root / "escape"), "query": "private"}).returncode
        != 0
    )
