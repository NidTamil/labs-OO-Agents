# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Real registry decisions and honest component-only bootstrap provenance."""

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest
from nooa_cybergym.leaderboard.advisory_runtime import AdvisoryAction
from nooa_cybergym.leaderboard.capabilities import CapabilityRegistry, Effect, Role, Status
from nooa_cybergym.leaderboard.capability_runtime import (
    ArtifactPin,
    CapabilityRuntime,
    DockerPathObserver,
    NativeCapabilitySpec,
    ObservedNativeTool,
    ObservedPath,
    build_synthetic_registry,
)
from nooa_cybergym.leaderboard.deepseek import DeepSeekRole
from nooa_cybergym.leaderboard.host_boundary_runtime import AdmittedPeer
from nooa_cybergym.leaderboard.native_tool_runtime import NativeToolCall
from nooa_cybergym.leaderboard.network import NetworkPolicy


class Audit:
    def __init__(self):
        self.events = []
        self.ack = True

    def record(self, event):
        self.events.append(event)
        return self.ack


PEER = AdmittedPeer("container-1", "network-1", "172.20.0.2")
TASK = "synthetic:length-header"


def pin(tmp_path, name, data):
    path = tmp_path / name
    path.write_bytes(data)
    return ArtifactPin(name, path, hashlib.sha256(data).hexdigest())


def bundle(
    tmp_path,
    *,
    name="Read",
    variant="",
    effects=None,
    roles=(Role.PARENT, Role.CHILD),
    paths=("/workspace",),
):
    properties = {
        "Read": {"file_path": {"type": "string"}},
        "Workflow": {
            "scriptPath": {"type": "string"},
            "script": {"type": "string"},
            "name": {"type": "string"},
            "resumeFromRunId": {"type": "string"},
            "args": {"type": "object"},
        },
        "Skill": {"skill": {"type": "string"}, "args": {"type": "string"}},
        "TodoWrite": {"todos": {"type": "array"}},
        "TaskCreate": {"subject": {"type": "string"}, "description": {"type": "string"}},
        "TaskGet": {"taskId": {"type": "string"}},
        "TaskUpdate": {
            "taskId": {"type": "string"},
            "owner": {"type": "string"},
            "status": {"type": "string"},
        },
        "TaskList": {},
        "TaskStop": {"task_id": {"type": "string"}, "host": {"type": "string"}},
        "Glob": {"pattern": {"type": "string"}, "path": {"type": "string"}},
        "Write": {"file_path": {"type": "string"}, "content": {"type": "string"}},
        "Bash": {"command": {"type": "string"}, "dangerouslyDisableSandbox": {"type": "boolean"}},
        "Agent": {"prompt": {"type": "string"}, "subagent_type": {"type": "string"}},
        "mcp__gbrain__recall": {"query": {"type": "string"}},
        "mcp__claude-vscode__getDiagnostics": {"uri": {"type": "string"}},
        "mcp__documentation__fetch": {"route": {"type": "string"}, "url": {"type": "string"}},
        "advisory__local_read": {"operation": {"type": "string"}, "path": {"type": "string"}},
        "advisory__gbrain_recall": {"query": {"type": "string"}},
        "mcp__advisor__recon_status": {},
        "mcp__advisor__debug": {"question": {"type": "string"}},
        "mcp__advisor__critic": {
            "candidate_path": {"type": "string"},
            "candidate_sha256": {"type": "string"},
            "candidate_context": {"type": "string"},
        },
        "mcp__finalizer__select_final": {
            "candidate_path": {"type": "string"},
            "sha256": {"type": "string"},
            "byte_length": {"type": "integer"},
            "selection_reason": {"type": "string"},
        },
        "mcp__vulnerable__run_test": {"candidate_path": {"type": "string"}},
    }[name]
    schema = {"name": name, "input_schema": {"type": "object", "properties": properties}}
    observation = ObservedNativeTool(
        name,
        "synthetic-runtime",
        "1",
        (pin(tmp_path, "service.bin", b"observed synthetic service fixture"),),
        "synthetic-adapter",
        "1",
        (pin(tmp_path, "adapter.py", b"observed synthetic adapter fixture"),),
        schema,
    )
    evidence = pin(
        tmp_path,
        "junit.xml",
        b'<testsuites><testsuite tests="12" failures="0" errors="0" skipped="0"/></testsuites>',
    )
    routes = (
        ("documentation/compiler/reference-v1",)
        if variant == "compiler"
        else (("gbrain-read-gateway",) if name.startswith("mcp__gbrain__") else ())
    )
    spec = NativeCapabilitySpec(
        name,
        variant,
        "cap." + name,
        roles,
        ("isolated-task-container",)
        if name in {"Bash", "mcp__vulnerable__run_test"}
        else ("synthetic-task-data",),
        paths,
        routes,
        ("synthetic-provider",) if name.startswith("mcp__gbrain__") else (),
        ("synthetic-model",) if name.startswith("mcp__gbrain__") else (),
    )
    return build_synthetic_registry(
        specs=(spec,), observations=(observation,), component_evidence=(evidence,)
    )


def native(name="Read", args=None, role="child", task=TASK):
    return NativeToolCall(
        task,
        "attempt-1",
        "request-1",
        "session-1",
        "agent-1" if role == "child" else None,
        role,
        "tool-1",
        name,
        args or {"file_path": "/workspace/src/a.c"},
    )


def runtime(bundle, *, audit=None, observe=None, boundary=None, task=TASK, **kwargs):
    return CapabilityRuntime(
        registry=bundle.registry,
        expected_registry_sha256=bundle.registry.digest,
        bindings=bundle.bindings,
        peer=PEER,
        task_id=task,
        attempt_id="attempt-1",
        audit=audit or Audit(),
        path_observer=observe or (lambda path: ObservedPath(path, path, True, "file")),
        boundary_check=boundary or (lambda peer: peer == PEER),
        working_directory="/workspace",
        execution_paths=("/workspace/src", "/workspace/output", "/home/agent", "/tmp", "/run"),
        execution_routes=(),
        model_id="glm-5.3",
        structural_terms=("buffer",),
        synthetic_task_ids=frozenset({TASK, "synthetic:chunk-table"}),
        **kwargs,
    )


def test_component_factory_hashes_actual_artifacts_and_marks_scope(tmp_path):
    built = bundle(tmp_path)
    entry = built.registry.entries[0]
    assert entry.status is Status.APPROVED
    assert "component_verified_synthetic_only" in entry.evidence_refs
    assert entry.identity == built.bindings[0].identity
    assert (
        entry.identity.tool_digest
        == hashlib.sha256(built.bindings[0].schema_json.encode()).hexdigest()
    )
    assert entry.certification_digest == built.component_evidence_sha256
    assert runtime(built).authorize(native()) is True


def test_component_registry_never_authorizes_official_task(tmp_path):
    with pytest.raises(ValueError, match="synthetic"):
        runtime(bundle(tmp_path), task="oss-fuzz:12345")


@pytest.mark.parametrize(
    "mutation", ["pending", "denied-role", "changed-adapter", "symlink-out", "boundary", "audit"]
)
def test_native_gate_uses_actual_registry_and_observations(tmp_path, mutation):
    built = bundle(tmp_path)
    if mutation in {"pending", "denied-role"}:
        entry = built.registry.entries[0]
        entry = (
            replace(entry, status=Status.PENDING)
            if mutation == "pending"
            else replace(entry, roles=(Role.PARENT,))
        )
        built = replace(built, registry=CapabilityRegistry((entry,)))
    if mutation == "changed-adapter":
        binding = built.bindings[0]
        built = replace(
            built,
            bindings=(
                replace(binding, identity=replace(binding.identity, adapter_digest="f" * 64)),
            ),
        )
    audit = Audit()
    audit.ack = mutation != "audit"
    gate = runtime(
        built,
        audit=audit,
        observe=(lambda path: ObservedPath(path, "/etc/shadow", True, "file"))
        if mutation == "symlink-out"
        else None,
        boundary=(lambda peer: False) if mutation == "boundary" else None,
    )
    assert gate.authorize(native()) is False


def test_parent_write_and_child_denial(tmp_path):
    gate = runtime(
        bundle(tmp_path, name="Write", roles=(Role.PARENT,), paths=("/workspace/output",))
    )
    args = {"file_path": "/workspace/output/poc", "content": "synthetic"}
    assert gate.authorize(native("Write", args, "parent")) is True
    assert gate.authorize(native("Write", args, "child")) is False
    assert (
        gate.authorize(native("Write", {**args, "file_path": "/workspace/src/a.c"}, "parent"))
        is False
    )


def test_native_vscode_diagnostics_requires_one_isolated_workspace_file(tmp_path):
    name = "mcp__claude-vscode__getDiagnostics"
    gate = runtime(bundle(tmp_path, name=name, paths=("/workspace",)))
    assert gate.authorize(native(name, {"uri": "file:///workspace/src/a.c"})) is True
    for uri in (
        None,
        "file:///home/agent/.claude/settings.json",
        "file:///workspace/../etc/shadow",
        "file://host/workspace/src/a.c",
        "https://example.com/workspace/src/a.c",
    ):
        args = {} if uri is None else {"uri": uri}
        assert gate.authorize(native(name, args)) is False


def test_bash_uses_whole_frozen_container_scope_not_shell_guessing(tmp_path):
    built = bundle(
        tmp_path,
        name="Bash",
        roles=(Role.PARENT,),
        paths=("/workspace", "/home/agent", "/tmp", "/run"),
    )
    audit = Audit()
    gate = runtime(built, audit=audit)
    assert (
        gate.authorize(native("Bash", {"command": "python3 build.py && ./candidate"}, "parent"))
        is True
    )
    assert gate.authorize(native("Bash", {"command": "cat <<'EOF'\nabc\nEOF"}, "parent")) is True
    assert gate.authorize(native("Bash", {"command": "printf '\\0'\x00"}, "parent")) is False
    event = next(e for e in audit.events if hasattr(e, "request"))
    assert event.request.effects == (Effect.READ, Effect.WRITE, Effect.NETWORK)
    assert "/workspace/src" in event.request.paths
    assert gate.authorize(native("Bash", {"command": "true"}, "child")) is False
    assert (
        gate.authorize(
            native("Bash", {"command": "true", "dangerouslyDisableSandbox": True}, "parent")
        )
        is False
    )


@pytest.mark.parametrize("subtype", ["cybergym-recon", "cybergym-debug", "cybergym-review"])
def test_only_frozen_readonly_native_child_types_delegate(tmp_path, subtype):
    gate = runtime(bundle(tmp_path, name="Agent", variant=subtype, roles=(Role.PARENT,), paths=()))
    assert (
        gate.authorize(
            native(
                "Agent", {"prompt": "inspect supplied input", "subagent_type": subtype}, "parent"
            )
        )
        is True
    )
    assert (
        gate.authorize(
            native("Agent", {"prompt": "inspect", "subagent_type": "general-purpose"}, "parent")
        )
        is False
    )


def test_mcp_memory_and_document_adapters_use_real_call_identity(tmp_path):
    mem_dir = tmp_path / "memory"
    mem_dir.mkdir()
    mem = runtime(bundle(mem_dir, name="mcp__gbrain__recall", paths=()))
    call = native("mcp__gbrain__recall", {"query": "buffer"})
    assert mem.authorize(call) is True
    caller = mem.memory_caller(call)
    assert caller.caller.value == "child" and caller.model_id == "glm-5.3"
    doc_dir = tmp_path / "docs"
    doc_dir.mkdir()
    docs = runtime(bundle(doc_dir, name="mcp__documentation__fetch", variant="compiler", paths=()))
    doc_call = native(
        "mcp__documentation__fetch",
        {"route": "compiler", "url": "https://clang.llvm.org/docs/UsersManual.html"},
    )
    admission = docs.documentation_admission(doc_call, "documentation/compiler/reference-v1")
    assert admission.authorizer.trusted_role is Role.CHILD
    assert admission.request.request_id == doc_call.request_id
    with pytest.raises(PermissionError):
        docs.documentation_admission(doc_call, "documentation/python/reference-v1")


def test_bootstrap_rejects_failed_tests_and_changed_files(tmp_path):
    bundle(tmp_path)
    pin_file = ArtifactPin("service.bin", tmp_path / "service.bin", "f" * 64)
    with pytest.raises(ValueError):
        pin_file.read_verified()
    evidence = pin(tmp_path, "failed.xml", b'<testsuite tests="2" failures="1" errors="0"/>')
    with pytest.raises(ValueError):
        build_synthetic_registry(specs=(), observations=(), component_evidence=(evidence,))


def test_unknown_or_changed_native_arguments_never_authorize(tmp_path):
    gate = runtime(bundle(tmp_path))
    assert (
        gate.authorize(native(args={"file_path": "/workspace/src/a.c", "command": "id"})) is False
    )
    assert gate.authorize(native(name="WebFetch", args={"url": "https://github.com"})) is False


def test_absolute_glob_pattern_is_an_actual_scope_not_inert_text(tmp_path):
    gate = runtime(bundle(tmp_path, name="Glob"))
    assert gate.authorize(native("Glob", {"pattern": "/etc/*.conf", "path": "/workspace"})) is False
    assert gate.authorize(native("Glob", {"pattern": "/etc/*.conf"}, "child")) is False
    assert gate.authorize(native("Glob", {"pattern": "/workspace/src/**"}, "child")) is True
    assert (
        gate.authorize(native("Glob", {"pattern": "/workspace/src/**/*.c", "path": "/workspace"}))
        is True
    )


def test_real_container_path_observer_binds_agent_and_checks_exec_completion():
    created = []

    class API:
        def exec_create(self, *args, **kwargs):
            created.append((args, kwargs))
            return {"Id": "exec-1"}

        def exec_start(self, *args, **kwargs):
            return json.dumps(
                {
                    "requested_path": "/workspace/link",
                    "resolved_path": "/etc/shadow",
                    "exists": True,
                    "kind": "file",
                }
            ).encode()

        def exec_inspect(self, *args):
            return {"Running": False, "ExitCode": 0}

    result = DockerPathObserver(API(), container_id="container-1")("/workspace/link")
    assert result.resolved_path == "/etc/shadow"
    assert created[0][0] == ("container-1",)
    assert created[0][1]["user"] == "agent"
    command = created[0][1]["cmd"]
    assert command[:4] == ["/usr/bin/python3", "-I", "-S", "-c"]
    compile(command[4], "<observed-path-helper>", "exec")


def test_resolver_joins_exact_native_controller_call_without_role_claim(tmp_path):
    gate = runtime(bundle(tmp_path, name="mcp__gbrain__recall", paths=()))

    class Controller:
        def resolve_mcp_call(self, tool_id, name, args):
            assert (
                tool_id == "tool-1"
                and name == "mcp__gbrain__recall"
                and args == {"query": "buffer"}
            )
            return native(name, args)

    caller = gate.resolve_memory(Controller(), PEER, "tool-1", "recall", {"query": "buffer"})
    assert caller.caller.value == "child"
    with pytest.raises(PermissionError):
        gate.resolve_memory(
            Controller(),
            replace(PEER, container_id="other"),
            "tool-1",
            "recall",
            {"query": "buffer"},
        )


@pytest.mark.parametrize(
    "name,args,paths",
    [
        ("mcp__advisor__recon_status", {}, ()),
        ("mcp__advisor__debug", {"question": "interpret actual failure"}, ()),
        (
            "mcp__advisor__critic",
            {
                "candidate_path": "/workspace/output/poc",
                "candidate_sha256": "a" * 64,
                "candidate_context": "synthetic",
            },
            ("/workspace/output",),
        ),
        (
            "mcp__finalizer__select_final",
            {
                "candidate_path": "/workspace/output/poc",
                "sha256": "a" * 64,
                "byte_length": 3,
                "selection_reason": "observed test",
            },
            ("/workspace/output",),
        ),
        (
            "mcp__vulnerable__run_test",
            {"candidate_path": "/workspace/output/poc"},
            ("/workspace", "/home/agent", "/tmp", "/run"),
        ),
    ],
)
def test_declared_controller_workflow_requests_are_parent_only(tmp_path, name, args, paths):
    gate = runtime(bundle(tmp_path, name=name, paths=paths, roles=(Role.PARENT,)))
    # Preserve an intentionally empty native recon-status argument object.
    parent = replace(native(name, args, "parent"), arguments=args)
    assert gate.authorize(parent) is True
    assert gate.authorize(replace(parent, role="child", agent_id="child-1")) is False


@pytest.mark.parametrize(
    "name,variant,args,paths",
    [
        (
            "local_read",
            "read",
            {"operation": "read", "path": "/workspace/src/a.c"},
            ("/workspace/src",),
        ),
        ("gbrain_recall", "", {"query": "buffer"}, ()),
    ],
)
def test_advisory_action_has_distinct_real_identity_and_child_authority(
    tmp_path, name, variant, args, paths
):
    audit = Audit()
    gate = runtime(
        bundle(
            tmp_path, name="advisory__" + name, variant=variant, roles=(Role.CHILD,), paths=paths
        ),
        audit=audit,
    )
    action = AdvisoryAction(
        "action-1",
        "deepseek-request-1",
        TASK,
        "attempt-1",
        DeepSeekRole.INDEPENDENT_RECON,
        name,
        hashlib.sha256(
            json.dumps(args, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    )
    assert gate.authorize_advisory(action, args) is True
    event = next(e for e in audit.events if hasattr(e, "request"))
    assert event.role is Role.CHILD and event.request.request_id == "action-1"
    assert event.tool_id == "advisory__" + name
    assert gate.authorize_advisory(replace(action, arguments_sha256="f" * 64), args) is False
    assert gate.authorize_advisory(replace(action, task_id="other"), args) is False


def test_relative_or_implicit_native_paths_cannot_use_unobserved_cwd(tmp_path):
    gate = runtime(bundle(tmp_path, name="Glob"))
    assert gate.authorize(native("Glob", {"pattern": "**/*.c"})) is False
    assert gate.authorize(native("Glob", {"pattern": "**/*.c", "path": "src"})) is False


def test_memory_filter_uses_actual_network_policy_and_frozen_identifiers(tmp_path):
    built = bundle(tmp_path)
    gate = CapabilityRuntime(
        registry=built.registry,
        expected_registry_sha256=built.registry.digest,
        bindings=built.bindings,
        peer=PEER,
        task_id=TASK,
        attempt_id="attempt-1",
        audit=Audit(),
        path_observer=lambda p: ObservedPath(p, p, True, "file"),
        boundary_check=lambda p: p == PEER,
        working_directory="/workspace",
        execution_paths=("/workspace/src",),
        execution_routes=(),
        model_id="glm-5.3",
        structural_terms=("buffer",),
        synthetic_task_ids=frozenset({TASK}),
        network_policy=NetworkPolicy.load(
            Path(__file__).parents[2] / "leaderboard/config/network-policy.json"
        ),
        forbidden_memory_identifiers=("prior-solution-identity",),
    )
    assert gate.safe_memory_filter("generic buffer bounds checking") is True
    assert gate.safe_memory_filter("https://github.com/target/repo/commit/fixed") is False
    assert gate.safe_memory_filter("CVE-2025-12345") is False
    assert gate.safe_memory_filter("PRIOR-SOLUTION-IDENTITY") is False
    assert runtime(built).safe_memory_filter("generic") is False


def test_native_workflow_requires_exact_frozen_script_and_content(tmp_path):
    path = "/workspace/.claude/workflows/recon.js"
    built = bundle(
        tmp_path, name="Workflow", roles=(Role.PARENT,), paths=("/workspace/.claude/workflows",)
    )
    gate = runtime(built, frozen_workflows={path: "a" * 64}, content_digest=lambda p: "a" * 64)
    args = {"scriptPath": path, "args": {"problem": "synthetic"}}
    assert gate.authorize(native("Workflow", args, "parent")) is True
    assert gate.authorized_workflow_digest(native("Workflow", args, "parent")) == "a" * 64
    assert gate.authorize(native("Workflow", args, "child")) is False
    for key in ("script", "name", "resumeFromRunId"):
        assert gate.authorize(native("Workflow", {**args, key: "override"}, "parent")) is False
    changed = runtime(built, frozen_workflows={path: "a" * 64}, content_digest=lambda p: "b" * 64)
    assert changed.authorize(native("Workflow", args, "parent")) is False
    with pytest.raises(PermissionError):
        changed.authorized_workflow_digest(native("Workflow", args, "parent"))


@pytest.mark.parametrize(
    "name,args",
    [
        ("TodoWrite", {"todos": []}),
        (
            "TaskCreate",
            {"subject": "Analyze synthetic input", "description": "Trace provided source"},
        ),
        ("TaskGet", {"taskId": "1"}),
        ("TaskUpdate", {"taskId": "1", "status": "completed"}),
        ("TaskList", {}),
        ("TaskStop", {"task_id": "bg_local_task"}),
    ],
)
def test_observed_native_task_management_is_parent_local(tmp_path, name, args):
    gate = runtime(bundle(tmp_path, name=name, roles=(Role.PARENT,), paths=("/home/agent", "/tmp")))
    call = replace(native(name, args, "parent"), arguments=args)
    assert gate.authorize(call) is True
    assert gate.authorize(replace(call, role="child", agent_id="child-1")) is False


@pytest.mark.parametrize(
    "name,args",
    [
        ("TaskUpdate", {"taskId": "1", "owner": "external-team"}),
        ("TaskStop", {"task_id": "bg_local_task", "host": "remote-host"}),
    ],
)
def test_task_metadata_cannot_turn_into_unregistered_team_or_remote_action(tmp_path, name, args):
    gate = runtime(bundle(tmp_path, name=name, roles=(Role.PARENT,), paths=("/home/agent", "/tmp")))
    assert gate.authorize(native(name, args, "parent")) is False


def test_native_skill_uses_explicit_frozen_name_to_asset_mapping(tmp_path):
    path = "/workspace/.claude/skills/cybergym/SKILL.md"
    gate = runtime(
        bundle(tmp_path, name="Skill", roles=(Role.PARENT,), paths=("/workspace/.claude/skills",)),
        frozen_skills={"cybergym": (path, "a" * 64)},
        content_digest=lambda p: "a" * 64,
    )
    assert (
        gate.authorize(native("Skill", {"skill": "cybergym", "args": "buffer input"}, "parent"))
        is True
    )
    assert gate.authorize(native("Skill", {"skill": "unapproved-plugin:skill"}, "parent")) is False
