"""Freeze observed native inventory and load registry-bound capability adapters.

CLI: ``python -m nooa_cybergym.leaderboard.capability_inventory --config FILE
--output-directory NEW_DIRECTORY``. Configuration supplies real calibration,
JUnit, policy and service/adapter artifact pins; no schemas are synthesized for
native tools. This command only produces component-verified synthetic artifacts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, fields
from pathlib import Path

from . import advisory_tools_runtime
from .capabilities import CapabilityRegistry, Role, Status, ToolIdentity
from .capability_runtime import (
    SYNTHETIC_SCOPE,
    ArtifactPin,
    NativeCapabilityBinding,
    NativeCapabilitySpec,
    ObservedNativeTool,
    SyntheticCapabilityBundle,
    build_synthetic_registry,
)
from .deepseek import MODEL as DEEPSEEK_MODEL
from .memory import SOURCE_ID
from .network import NetworkPolicy

_MAX_MANIFEST = 16 * 1024 * 1024
_FIXTURES = frozenset({"synthetic:length-header", "synthetic:chunk-table"})
_LOCAL_READ = ("Read", "Grep", "Glob")
_LOCAL_WRITE = ("Write", "Edit")
_OPTIONAL_TASK_TOOLS = ("TodoWrite", "TaskCreate", "TaskGet", "TaskUpdate", "TaskList", "TaskStop")
_CLANGD = ("document_symbols", "hover", "definition", "references")
_CHILD_TYPES = ("cybergym-recon", "cybergym-debug", "cybergym-review")
_DEFAULT_READ_ROOTS = (
    "/workspace",
    "/home/agent",
    "/opt/sunchaser",
    "/usr/include",
    "/usr/lib",
    "/usr/share/doc",
)
_DEFAULT_WRITE_ROOTS = ("/workspace/src", "/workspace/output", "/home/agent", "/tmp", "/run")
_DEFAULT_ROUTES = (
    "model-gateway",
    "cybergym-submit",
    "gbrain-read-gateway",
    "documentation-gateway",
    "registered-tool-gateway",
)
_UNBOUND_AUDIT = {
    "AskUserQuestion": ("leakage boundary", "Requests out-of-band human task input."),
    "CronCreate": ("leakage boundary", "Can persist a prompt beyond the task lifetime."),
    "CronDelete": ("leakage boundary", "Can alter another scheduled host task."),
    "CronList": ("leakage boundary", "Can expose scheduled host tasks."),
    "EnterWorktree": ("leakage boundary", "Changes the frozen source checkout boundary."),
    "ExitWorktree": ("leakage boundary", "Changes the frozen source checkout boundary."),
    "ListAgents": ("leakage boundary", "Enumerates local, remote and cloud sessions outside this task."),
    "ScheduleWakeup": ("leakage boundary", "Can continue execution beyond the task lifetime."),
    "SendMessage": ("leakage boundary", "Can send task data to other local, remote or cloud sessions."),
    "WebFetch": ("leakage boundary", "Unrestricted URL fetch can import target answers and published PoCs."),
    "WebSearch": ("leakage boundary", "Unrestricted search can import target answers and published PoCs."),
    "EnterPlanMode": ("optional", "Interactive approval mode does not solve this autonomous task."),
    "ExitPlanMode": ("optional", "Interactive approval mode does not solve this autonomous task."),
    "NotebookEdit": ("optional", "The frozen C fixtures contain no notebooks."),
    "ReportFindings": ("optional", "The review-host UI is outside the task finalization interface."),
}


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate inventory key")
        result[key] = value
    return result


def _json(data):
    value = json.loads(data, object_pairs_hook=_unique)
    _canonical(value)
    return value


def _pin_json(pin):
    return {"name": pin.name, "path": str(pin.path), "sha256": pin.sha256}


def _read_pin(value):
    if type(value) is not dict or set(value) != {"name", "path", "sha256"}:
        raise ValueError("explicit observed artifact pin required")
    return ArtifactPin(value["name"], Path(value["path"]), value["sha256"])


@dataclass(frozen=True, slots=True)
class ObservedService:
    service_id: str
    service_version: str
    service_files: tuple[ArtifactPin, ...]
    adapter_id: str
    adapter_version: str
    adapter_files: tuple[ArtifactPin, ...]

    def tool(self, name, schema):
        return ObservedNativeTool(
            name,
            self.service_id,
            self.service_version,
            self.service_files,
            self.adapter_id,
            self.adapter_version,
            self.adapter_files,
            schema,
        )


def default_native_capability_specs(
    *,
    gbrain_provider_ids: tuple[str, ...],
    gbrain_model_ids: tuple[str, ...],
    source_roots=("/workspace/src",),
    read_roots=_DEFAULT_READ_ROOTS,
    write_roots=_DEFAULT_WRITE_ROOTS,
    execution_routes=_DEFAULT_ROUTES,
    observed_native_names=(),
) -> tuple[NativeCapabilitySpec, ...]:
    """Concrete approved-design scopes; actual captured schemas remain mandatory."""
    if not gbrain_provider_ids or not gbrain_model_ids:
        raise ValueError("actual GBrain auxiliary provider/model inventory required")
    output = []
    both = (Role.PARENT, Role.CHILD)
    parent = (Role.PARENT,)
    child = (Role.CHILD,)

    def add(
        name,
        variant="",
        *,
        roles=both,
        scopes=("provided-vulnerable-source",),
        paths=source_roots,
        routes=(),
        providers=(),
        models=(),
    ):
        identifier = "native." + name.replace("mcp__", "").replace(
            "advisory__", "advisory."
        ).replace("__", ".")
        if variant:
            identifier += "." + variant
        output.append(
            NativeCapabilitySpec(
                name,
                variant,
                identifier,
                roles,
                tuple(scopes),
                tuple(paths),
                tuple(routes),
                tuple(providers),
                tuple(models),
            )
        )

    for name in _LOCAL_READ:
        # Claude Code 2.1.289 may omit the legacy Grep/Glob tools. Preserve
        # the observed maximum without inventing schemas for absent tools.
        if name in {"Grep", "Glob"} and observed_native_names and name not in observed_native_names:
            continue
        add(
            name,
            paths=read_roots,
            scopes=(
                "provided-vulnerable-source",
                "task-generated-artifacts",
                "task-native-memory",
                "frozen-generic-instructions",
            ),
        )
    for name in _LOCAL_WRITE:
        add(
            name,
            roles=parent,
            paths=write_roots,
            scopes=("task-generated-artifacts", "task-native-memory"),
        )
    for name in _OPTIONAL_TASK_TOOLS:
        if name in observed_native_names:
            add(
                name,
                roles=parent,
                paths=("/home/agent/.claude", "/tmp"),
                scopes=("current-session-native-task-state",),
            )
    for name in ("Bash", "mcp__vulnerable__run_test"):
        add(
            name,
            roles=parent,
            paths=write_roots,
            scopes=("isolated-task-container",),
            routes=execution_routes,
        )
    for kind in _CHILD_TYPES:
        add(
            "Agent",
            kind,
            roles=parent,
            paths=(),
            scopes=("current-task-readonly-children",),
            providers=("zai-coding-plan",),
            models=("glm-5.3",),
        )
    add(
        "Workflow",
        roles=parent,
        paths=("/workspace/.claude/workflows",),
        scopes=("frozen-readonly-workflows", "current-task-readonly-children"),
        routes=("model-gateway", "registered-tool-gateway", "gbrain-read-gateway"),
        providers=("zai-coding-plan",),
        models=("glm-5.3",),
    )
    add(
        "Skill",
        roles=parent,
        paths=("/workspace/.claude/skills",),
        scopes=("frozen-generic-skills",),
    )
    for name in ("recall", "search"):
        add(
            "mcp__gbrain__" + name,
            paths=(),
            scopes=(SOURCE_ID,),
            routes=("gbrain-read-gateway",),
            providers=gbrain_provider_ids,
            models=gbrain_model_ids,
        )
        add(
            "advisory__gbrain_" + name,
            roles=child,
            paths=(),
            scopes=(SOURCE_ID,),
            routes=("gbrain-read-gateway",),
            providers=gbrain_provider_ids,
            models=gbrain_model_ids,
        )
    for name in _CLANGD:
        add("mcp__clangd__" + name)
        add("advisory__clangd_read", name, roles=child)
    if "mcp__claude-vscode__getDiagnostics" in observed_native_names:
        add(
            "mcp__claude-vscode__getDiagnostics",
            paths=("/workspace",),
            scopes=("provided-vulnerable-source", "task-generated-artifacts"),
        )
    for operation in ("read", "list", "search"):
        add("advisory__local_read", operation, roles=child)
    for route in ("compiler", "python"):
        add(
            "mcp__documentation__fetch",
            route,
            paths=(),
            scopes=("generic-" + route + "-documentation",),
            routes=("documentation/" + route + "/reference-v1",),
        )
    add(
        "mcp__advisor__recon_status",
        roles=parent,
        paths=(),
        scopes=("current-task-advisory-evidence",),
        routes=("registered-tool-gateway",),
    )
    for name in ("debug", "critic"):
        add(
            "mcp__advisor__" + name,
            roles=parent,
            paths=("/workspace/output",) if name == "critic" else (),
            scopes=("current-task-advisory-evidence",),
            routes=("registered-tool-gateway",),
            providers=("deepseek-official-api",),
            models=(DEEPSEEK_MODEL,),
        )
    add(
        "mcp__finalizer__select_final",
        roles=parent,
        paths=("/workspace/output",),
        scopes=("parent-final-candidate-nomination",),
        routes=("cybergym-submit",),
    )
    return tuple(sorted(output, key=lambda s: (s.native_name, s.variant)))


def _calibration(pin):
    value = _json(pin.read_verified())
    if (
        type(value) is not dict
        or value.get("schema_version") != 1
        or value.get("scope") != "native_schema_discovery_no_provider"
        or value.get("provider_dispatched") is not False
        or value.get("task_id") not in _FIXTURES
        or type(value.get("image_id")) is not str
        or not value["image_id"].startswith("sha256:")
        or type(value.get("tools")) is not list
        or not value["tools"]
    ):
        raise ValueError("actual rejected native calibration request required")
    for key in ("binary_sha256", "request_sha256"):
        digest = value.get(key)
        if (
            type(digest) is not str
            or len(digest) != 64
            or any(c not in "0123456789abcdef" for c in digest)
        ):
            raise ValueError("observed native calibration identity incomplete")
    names = []
    for schema in value["tools"]:
        if type(schema) is not dict or type(schema.get("name")) is not str:
            raise ValueError("invalid observed tool schema")
        input_schema = schema.get("input_schema", schema.get("inputSchema"))
        if type(input_schema) is not dict or input_schema.get("type") != "object":
            raise ValueError("captured input schema missing")
        names.append(schema["name"])
    if len(names) != len(set(names)):
        raise ValueError("duplicate captured native tool name")
    return value


def _child_calibration(pin: ArtifactPin, parent: Mapping) -> dict[str, dict]:
    """Verify the pinned database of a rejected synthetic child request."""
    pin.read_verified()
    try:
        with sqlite3.connect(f"file:{pin.path.as_posix()}?mode=ro&immutable=1", uri=True) as c:
            identity_row = c.execute("SELECT value FROM identity WHERE id=1").fetchone()
            discovery_row = c.execute(
                "SELECT request_sha256,schemas FROM child_schema_discovery WHERE id=1"
            ).fetchone()
    except sqlite3.DatabaseError:
        raise ValueError("synthetic child discovery database invalid") from None
    if identity_row is None or discovery_row is None:
        raise ValueError("actual rejected synthetic child discovery required")
    identity = _json(identity_row[0])
    tools = _json(discovery_row[1])
    parent_schemas = {tool["name"]: _sha(_canonical(tool)) for tool in parent["tools"]}
    if (
        type(identity) is not dict
        or identity.get("task_id") != parent["task_id"]
        or identity["task_id"] not in _FIXTURES
        or type(identity.get("run_id")) is not str
        or not identity["run_id"].startswith("synthetic-")
        or identity.get("captured_schemas") != parent_schemas
        or type(discovery_row[0]) is not str
        or len(discovery_row[0]) != 64
        or any(c not in "0123456789abcdef" for c in discovery_row[0])
        or type(tools) is not list
        or len(tools) != 2
        or {tool.get("name") for tool in tools if type(tool) is dict} != {"Grep", "Glob"}
    ):
        raise ValueError("synthetic child discovery does not match parent capture")
    for tool in tools:
        schema = tool.get("input_schema", tool.get("inputSchema"))
        if (
            type(tool.get("description")) is not str
            or not 0 < len(tool["description"]) <= 65536
            or type(schema) is not dict
            or schema.get("type") != "object"
            or len(_canonical(tool)) > 128 * 1024
        ):
            raise ValueError("synthetic child read schema malformed")
    return {tool["name"]: tool for tool in tools}


def _group(name):
    if name.startswith("advisory__"):
        return "advisory"
    if name.startswith("mcp__"):
        return name.split("__")[1]
    return "native"


def _check_native_binary(calibration, artifacts):
    for artifact in artifacts:
        data = artifact.read_verified()
        if artifact.sha256 == calibration["binary_sha256"]:
            return
        if Path(artifact.path).name == "native-runtime.json":
            identity = _json(data)
            if (
                type(identity) is dict
                and identity.get("schema_version") == 1
                and identity.get("claude_binary_sha256") == calibration["binary_sha256"]
                and (
                    "claude_extension_sha256" not in calibration
                    or identity.get("claude_extension_sha256")
                    == calibration["claude_extension_sha256"]
                )
            ):
                return
    raise ValueError("captured native binary does not match pinned service identity")


def _observation_json(observation):
    return {
        "native_name": observation.native_name,
        "service_id": observation.service_id,
        "service_version": observation.service_version,
        "service_files": [_pin_json(p) for p in observation.service_files],
        "adapter_id": observation.adapter_id,
        "adapter_version": observation.adapter_version,
        "adapter_files": [_pin_json(p) for p in observation.adapter_files],
        "schema_sha256": _sha(_canonical(observation.schema)),
    }


@dataclass(frozen=True, slots=True)
class FrozenCapabilityInventory:
    bundle: SyntheticCapabilityBundle
    calibration: ArtifactPin
    calibration_metadata: Mapping
    observations: tuple[ObservedNativeTool, ...]
    component_evidence: tuple[ArtifactPin, ...]
    unsupported: tuple[Mapping, ...]
    parent_tools: tuple[str, ...]
    child_tools: tuple[str, ...]
    network_policy_sha256: str
    child_calibration: ArtifactPin | None = None

    @property
    def bindings_json(self):
        document = {
                "schema_version": 1,
                "artifact_kind": "native_capability_bindings",
                "scope": SYNTHETIC_SCOPE,
                "registry_sha256": self.bundle.registry.digest,
                "component_evidence_sha256": self.bundle.component_evidence_sha256,
                "bindings": [asdict(b) for b in self.bundle.bindings],
                "observations": [_observation_json(o) for o in self.observations],
                "component_evidence": [_pin_json(p) for p in self.component_evidence],
                "calibration": _pin_json(self.calibration),
                "network_policy_sha256": self.network_policy_sha256,
            }
        if self.child_calibration is not None:
            document["child_calibration"] = _pin_json(self.child_calibration)
        return _canonical(document)

    @property
    def inventory_json(self):
        document = {
                "schema_version": 1,
                "scope": SYNTHETIC_SCOPE,
                "provider_dispatched": False,
                "registry_sha256": self.bundle.registry.digest,
                "bindings_sha256": _sha(self.bindings_json),
                "calibration": _pin_json(self.calibration),
                "native_identity": dict(self.calibration_metadata),
                "parent_tools": list(self.parent_tools),
                "child_tools": list(self.child_tools),
                "unsupported_advertised_tools": list(self.unsupported),
                "component_evidence_sha256": self.bundle.component_evidence_sha256,
                "limitation": "Component verification permits synthetic calibration only; full native execution remains uncertified.",
            }
        if self.child_calibration is not None:
            document["child_calibration"] = _pin_json(self.child_calibration)
        return _canonical(document)


def freeze_inventory(
    *,
    calibration: ArtifactPin,
    child_calibration: ArtifactPin | None = None,
    services: Mapping[str, ObservedService],
    component_evidence: Sequence[ArtifactPin],
    network_policy: NetworkPolicy,
    gbrain_provider_ids: tuple[str, ...],
    gbrain_model_ids: tuple[str, ...],
    source_roots=("/workspace/src",),
    read_roots=_DEFAULT_READ_ROOTS,
    write_roots=_DEFAULT_WRITE_ROOTS,
):
    observed = _calibration(calibration)
    child_schemas = (
        _child_calibration(child_calibration, observed) if child_calibration is not None else {}
    )
    if type(network_policy) is not NetworkPolicy:
        raise TypeError("actual frozen network policy required")
    if type(services.get("native")) is not ObservedService:
        raise ValueError("actual observed native service required")
    _check_native_binary(observed, services["native"].service_files)
    specs = default_native_capability_specs(
        gbrain_provider_ids=gbrain_provider_ids,
        gbrain_model_ids=gbrain_model_ids,
        source_roots=source_roots,
        read_roots=read_roots,
        write_roots=write_roots,
        execution_routes=tuple(sorted(network_policy.allowed_logical_endpoints)),
        observed_native_names=tuple(s["name"] for s in observed["tools"]) + tuple(child_schemas),
    )
    schemas = {s["name"]: s for s in observed["tools"]} | child_schemas
    declared = {
        name: "advisory__" + name
        for name in ("local_read", "clangd_read", "gbrain_recall", "gbrain_search")
    }
    for schema in advisory_tools_runtime.ADVISORY_ACTION_SCHEMAS:
        schemas[declared[schema["name"]]] = schema
    needed = {spec.native_name for spec in specs}
    missing = needed - set(schemas)
    if missing:
        raise ValueError("required actual native schemas missing: " + ", ".join(sorted(missing)))
    observations = []
    for name in sorted(needed):
        service = services.get(_group(name))
        if type(service) is not ObservedService:
            raise ValueError("observed service artifacts missing for " + _group(name))
        # The actual declaration source is part of each advisory adapter's identity.
        if name.startswith("advisory__"):
            path = Path(advisory_tools_runtime.__file__).resolve()
            source = ArtifactPin("advisory-protocol-source", path, _sha(path.read_bytes()))
            service = ObservedService(
                service.service_id,
                service.service_version,
                service.service_files,
                service.adapter_id,
                service.adapter_version,
                tuple(p for p in service.adapter_files if p.name != source.name) + (source,),
            )
        observations.append(service.tool(name, schemas[name]))
    bundle = build_synthetic_registry(
        specs=specs, observations=tuple(observations), component_evidence=tuple(component_evidence)
    )
    parent = tuple(
        sorted(
            {
                b.native_name
                for b in bundle.bindings
                if not b.native_name.startswith("advisory__")
                and Role.PARENT
                in next(
                    e for e in bundle.registry.entries if e.capability_id == b.capability_id
                ).roles
            }
        )
    )
    child = tuple(
        sorted(
            {
                b.native_name
                for b in bundle.bindings
                if not b.native_name.startswith("advisory__")
                and Role.CHILD
                in next(
                    e for e in bundle.registry.entries if e.capability_id == b.capability_id
                ).roles
            }
        )
    )
    unsupported = tuple(
        {
            "name": s["name"],
            "schema_sha256": _sha(_canonical(s)),
            "disposition": (
                "omitted_optional"
                if _UNBOUND_AUDIT.get(s["name"], (None,))[0] == "optional"
                else "denied_leakage_boundary"
                if s["name"] in _UNBOUND_AUDIT
                else "pending_operation_audit"
            ),
            "control_label": _UNBOUND_AUDIT.get(s["name"], ("optional",))[0],
            "reason": _UNBOUND_AUDIT.get(
                s["name"], (None, "Unrecognized native operation requires an exact boundary audit.")
            )[1],
        }
        for s in observed["tools"]
        if s["name"] not in needed
    )
    metadata = {
        key: observed[key] for key in ("task_id", "image_id", "binary_sha256", "request_sha256")
    }
    return FrozenCapabilityInventory(
        bundle,
        calibration,
        metadata,
        tuple(observations),
        tuple(component_evidence),
        unsupported,
        parent,
        child,
        network_policy.digest,
        child_calibration,
    )


def write_inventory(directory: Path, inventory: FrozenCapabilityInventory):
    directory = Path(directory)
    if not directory.is_absolute() or directory.parent.resolve() != directory.parent:
        raise ValueError("new controller-owned absolute inventory directory required")
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    result = {}
    for label, name, data in (
        ("registry", "registry.json", inventory.bundle.registry.manifest_json.encode()),
        ("bindings", "capability-bindings.json", inventory.bindings_json),
        ("inventory", "inventory.json", inventory.inventory_json),
    ):
        path = directory / name
        with path.open("xb") as output:
            output.write(data)
        result[label + "_path"] = path
        result[label + "_sha256"] = _sha(data)
    return result


def load_frozen_bindings(
    path: Path, registry: CapabilityRegistry
) -> tuple[NativeCapabilityBinding, ...]:
    """Load exact identity and scope bindings; the caller also pins this file in runtime config."""
    path = Path(path)
    if (
        type(registry) is not CapabilityRegistry
        or not path.is_absolute()
        or path.resolve() != path
        or not path.is_file()
        or path.stat().st_size > _MAX_MANIFEST
    ):
        raise ValueError("frozen bindings must be a bounded regular absolute file")
    data = path.read_bytes()
    document = _json(data)
    expected = {
        "schema_version",
        "artifact_kind",
        "scope",
        "registry_sha256",
        "component_evidence_sha256",
        "bindings",
        "observations",
        "component_evidence",
        "calibration",
        "network_policy_sha256",
    }
    if (
        type(document) is not dict
        or set(document) not in (expected, expected | {"child_calibration"})
        or data != _canonical(document)
        or document["schema_version"] != 1
        or document["artifact_kind"] != "native_capability_bindings"
        or document["scope"] != SYNTHETIC_SCOPE
        or document["registry_sha256"] != registry.digest
    ):
        raise ValueError("bindings manifest differs from pinned registry or canonical schema")
    entry_by_id = {e.capability_id: e for e in registry.entries}
    if type(document["bindings"]) is not list or not document["bindings"]:
        raise ValueError("bindings missing")
    expected_fields = {f.name for f in fields(NativeCapabilityBinding)}
    result = []
    for row in document["bindings"]:
        if type(row) is not dict or set(row) != expected_fields:
            raise ValueError("binding schema changed")
        values = dict(row)
        values["identity"] = ToolIdentity(**values["identity"])
        for name in ("data_scopes", "routes", "provider_ids", "model_ids"):
            if type(values[name]) is not list:
                raise ValueError("binding tuple representation invalid")
            values[name] = tuple(values[name])
        binding = NativeCapabilityBinding(**values)
        entry = entry_by_id.get(binding.capability_id)
        if (
            entry is None
            or entry.status is not Status.APPROVED
            or SYNTHETIC_SCOPE not in entry.evidence_refs
            or entry.identity != binding.identity
            or entry.operation != binding.operation
            or entry.effects != binding.effects
            or entry.certification_digest != document["component_evidence_sha256"]
            or any(
                getattr(entry, key) != getattr(binding, key)
                for key in ("data_scopes", "routes", "provider_ids", "model_ids")
            )
        ):
            raise ValueError("binding identity or declaration differs from audited registry")
        result.append(binding)
    if len({(b.native_name, b.variant) for b in result}) != len(result) or len(
        {b.capability_id for b in result}
    ) != len(result):
        raise ValueError("duplicate binding identity")
    if {b.capability_id for b in result} != set(entry_by_id):
        raise ValueError("registry binding coverage incomplete")
    observed_rows = document["observations"]
    if type(observed_rows) is not list or len({o["native_name"] for o in observed_rows}) != len(
        observed_rows
    ):
        raise ValueError("observation inventory malformed")
    by_name = {b.native_name: b for b in result}
    if set(by_name) != {o["native_name"] for o in observed_rows}:
        raise ValueError("observation coverage incomplete")
    for row in observed_rows:
        expected_observed = {
            "native_name",
            "service_id",
            "service_version",
            "service_files",
            "adapter_id",
            "adapter_version",
            "adapter_files",
            "schema_sha256",
        }
        if type(row) is not dict or set(row) != expected_observed:
            raise ValueError("observation artifact schema changed")
        binding = by_name[row["native_name"]]
        observation = ObservedNativeTool(
            row["native_name"],
            row["service_id"],
            row["service_version"],
            tuple(_read_pin(p) for p in row["service_files"]),
            row["adapter_id"],
            row["adapter_version"],
            tuple(_read_pin(p) for p in row["adapter_files"]),
            _json(binding.schema_json),
        )
        if (
            observation.identity() != binding.identity
            or row["schema_sha256"] != binding.identity.tool_digest
        ):
            raise ValueError("observed service bytes or schema differ")
    capture = _calibration(_read_pin(document["calibration"]))
    captured = {tool["name"]: _sha(_canonical(tool)) for tool in capture["tools"]}
    if "child_calibration" in document:
        captured.update(
            {
                name: _sha(_canonical(schema))
                for name, schema in _child_calibration(
                    _read_pin(document["child_calibration"]), capture
                ).items()
            }
        )
    native_observations = [
        row for row in observed_rows if not row["native_name"].startswith(("mcp__", "advisory__"))
    ]
    if not native_observations:
        raise ValueError("native service observations missing")
    _check_native_binary(
        capture, tuple(_read_pin(p) for p in native_observations[0]["service_files"])
    )
    for binding in result:
        if (
            not binding.native_name.startswith("advisory__")
            and captured.get(binding.native_name) != binding.identity.tool_digest
        ):
            raise ValueError("binding schema differs from actual native capture")
    # The factory validated report contents; here recheck their exact retained bytes and digest.
    evidence = tuple(_read_pin(p) for p in document["component_evidence"])
    evidence_rows = []
    for item in evidence:
        item.read_verified()
        evidence_rows.append({"name": item.name, "sha256": item.sha256})
    digest = _sha(
        _canonical(
            {"scope": SYNTHETIC_SCOPE, "reports": sorted(evidence_rows, key=lambda e: e["name"])}
        )
    )
    if digest != document["component_evidence_sha256"]:
        raise ValueError("component evidence digest changed")
    return tuple(result)


def load_captured_native_schemas(
    path: Path, registry: CapabilityRegistry
) -> dict[str, str]:
    """Reverify the frozen bindings and return every actually advertised schema digest."""
    load_frozen_bindings(path, registry)
    document = _json(Path(path).read_bytes())
    capture = _calibration(_read_pin(document["calibration"]))
    captured = {tool["name"]: _sha(_canonical(tool)) for tool in capture["tools"]}
    if "child_calibration" in document:
        captured.update(
            {
                name: _sha(_canonical(schema))
                for name, schema in _child_calibration(
                    _read_pin(document["child_calibration"]), capture
                ).items()
            }
        )
    return captured


def _load_services(value):
    if type(value) is not dict:
        raise ValueError("observed services map required")
    result = {}
    expected = {
        "service_id",
        "service_version",
        "service_files",
        "adapter_id",
        "adapter_version",
        "adapter_files",
    }
    for name, row in value.items():
        if type(row) is not dict or set(row) != expected:
            raise ValueError("observed service definition malformed")
        result[name] = ObservedService(
            row["service_id"],
            row["service_version"],
            tuple(_read_pin(p) for p in row["service_files"]),
            row["adapter_id"],
            row["adapter_version"],
            tuple(_read_pin(p) for p in row["adapter_files"]),
        )
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args(argv)
    config = _json(args.config.read_bytes())
    required = {
        "schema_version",
        "calibration",
        "services",
        "component_evidence",
        "network_policy",
        "gbrain_provider_ids",
        "gbrain_model_ids",
    }
    if (
        type(config) is not dict
        or required - set(config)
        or set(config) - required - {"source_roots", "read_roots", "write_roots", "child_calibration"}
        or config["schema_version"] != 1
    ):
        raise ValueError("inventory freeze configuration schema invalid")
    policy_pin = _read_pin(config["network_policy"])
    policy_pin.read_verified()
    options = {
        name: tuple(config[name])
        for name in ("source_roots", "read_roots", "write_roots")
        if name in config
    }
    inventory = freeze_inventory(
        calibration=_read_pin(config["calibration"]),
        child_calibration=(
            _read_pin(config["child_calibration"])
            if "child_calibration" in config
            else None
        ),
        services=_load_services(config["services"]),
        component_evidence=tuple(_read_pin(p) for p in config["component_evidence"]),
        network_policy=NetworkPolicy.load(policy_pin.path),
        gbrain_provider_ids=tuple(config["gbrain_provider_ids"]),
        gbrain_model_ids=tuple(config["gbrain_model_ids"]),
        **options,
    )
    paths = write_inventory(args.output_directory, inventory)
    print(json.dumps({key: str(value) for key, value in paths.items()}, sort_keys=True))


if __name__ == "__main__":
    main()
