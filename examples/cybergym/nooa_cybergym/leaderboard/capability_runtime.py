"""Controller adapters from observed native calls to the real capability registry.

The synthetic factory approves only component-verified synthetic calibration.
It never emits full-native or official certification. Runtime identities and
schemas come from observed, digest-pinned artifacts supplied by the controller.
"""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
import xml.etree.ElementTree as ET
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlsplit

from .capabilities import (
    Capability,
    CapabilityAuthorizer,
    CapabilityRegistry,
    CapabilityRequest,
    ControlLabel,
    Effect,
    Role,
    Status,
    ToolIdentity,
    WriteDomain,
)
from .documentation_service import DocumentationAdmission
from .host_boundary_runtime import AdmittedPeer
from .memory import Caller
from .memory_runtime import TrustedMemoryCaller
from .native_tool_runtime import NativeToolCall
from .network import NetworkDenied, NetworkPolicy

SYNTHETIC_SCOPE = "component_verified_synthetic_only"
_CHILD_TYPES = frozenset({"cybergym-recon", "cybergym-debug", "cybergym-review"})
_READ = frozenset({"Read", "Grep", "Glob"})
_WRITE = frozenset({"Write", "Edit"})
_TASK_READ = frozenset({"TaskGet", "TaskList"})
_TASK_WRITE = frozenset({"TodoWrite", "TaskCreate", "TaskUpdate", "TaskStop"})
_TASK_STATE = _TASK_READ | _TASK_WRITE
_TASK_STATE_ROOTS = ("/home/agent/.claude", "/tmp")
_CLANGD = frozenset(
    "mcp__clangd__" + name for name in ("document_symbols", "hover", "definition", "references")
)
_MEMORY = frozenset({"mcp__gbrain__recall", "mcp__gbrain__search"})
_DIAGNOSTICS = "mcp__claude-vscode__getDiagnostics"
_EXECUTE = frozenset({"Bash", "mcp__vulnerable__run_test"})
_WORKFLOWS = frozenset(
    {
        "mcp__advisor__recon_status",
        "mcp__advisor__debug",
        "mcp__advisor__critic",
        "mcp__finalizer__select_final",
    }
)
_ADVISORY = frozenset(
    {
        "advisory__local_read",
        "advisory__clangd_read",
        "advisory__gbrain_recall",
        "advisory__gbrain_search",
    }
)
_SUPPORTED = (
    _READ
    | _WRITE
    | _CLANGD
    | _MEMORY
    | _EXECUTE
    | _WORKFLOWS
    | _ADVISORY
    | _TASK_STATE
    | {"Agent", "Workflow", "Skill", "mcp__documentation__fetch", _DIAGNOSTICS}
)


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def _text(value):
    return type(value) is str and bool(value.strip()) and not any(ord(c) < 32 for c in value)


def _shell_text(value):
    # Shell here-documents and multi-step tests need line breaks. This does not
    # change the container, role, route, or filesystem authority of Bash.
    return (
        type(value) is str
        and bool(value.strip())
        and not any(ord(c) < 32 and c not in "\n\t" for c in value)
    )


def _absolute(value, cwd=None):
    if not _text(value) or "\\" in value or value.startswith("//"):
        raise ValueError("invalid container path")
    if not value.startswith("/"):
        if cwd is None:
            raise ValueError("absolute container path required")
        value = posixpath.join(cwd, value)
    normalized = posixpath.normpath(value)
    if normalized == "/" or ".." in value.split("/"):
        raise ValueError("path traversal outside explicit scope")
    return normalized


def _operation(name):
    return {
        "Read": "read",
        "Grep": "search",
        "Glob": "glob",
        "Write": "write",
        "Edit": "edit",
        "Bash": "execute",
        "Agent": "delegate",
    }.get(name, name.rsplit("__", 1)[-1])


def _effects(name):
    if name in _EXECUTE:
        return (Effect.READ, Effect.WRITE, Effect.NETWORK)
    if name in _WRITE | _TASK_WRITE:
        return (Effect.READ, Effect.WRITE)
    if name == "Workflow":
        return (Effect.READ, Effect.NETWORK, Effect.MODEL)
    if name == "Agent":
        return (Effect.READ, Effect.MODEL)
    if name in _MEMORY or name in {
        "advisory__gbrain_recall",
        "advisory__gbrain_search",
        "mcp__advisor__debug",
        "mcp__advisor__critic",
    }:
        return (Effect.READ, Effect.NETWORK, Effect.MODEL)
    if name == "mcp__finalizer__select_final":
        return (Effect.READ, Effect.WRITE, Effect.NETWORK)
    if name == "mcp__advisor__recon_status":
        return (Effect.READ, Effect.NETWORK)
    if name == "mcp__documentation__fetch":
        return (Effect.READ, Effect.NETWORK)
    return (Effect.READ,)


@dataclass(frozen=True, slots=True)
class ArtifactPin:
    name: str
    path: Path
    sha256: str

    def read_verified(self):
        path = Path(self.path)
        if (
            not _text(self.name)
            or not re.fullmatch("[a-f0-9]{64}", self.sha256)
            or not path.is_absolute()
            or path.resolve() != path
            or not path.is_file()
            or path.stat().st_size > 512 * 1024 * 1024
        ):
            raise ValueError("observed artifact must be a pinned regular absolute file")
        data = path.read_bytes()
        if _sha(data) != self.sha256:
            raise ValueError("observed artifact changed")
        return data


@dataclass(frozen=True, slots=True)
class ObservedNativeTool:
    native_name: str
    service_id: str
    service_version: str
    service_files: tuple[ArtifactPin, ...]
    adapter_id: str
    adapter_version: str
    adapter_files: tuple[ArtifactPin, ...]
    schema: Mapping

    def identity(self):
        if self.native_name not in _SUPPORTED or type(self.schema) is not dict:
            raise ValueError("unsupported observed native tool")
        names = {self.native_name}
        if self.native_name.startswith(("mcp__", "advisory__")):
            names.add(self.native_name.rsplit("__", 1)[-1])
        if self.schema.get("name") not in names:
            raise ValueError("observed schema name differs from bound native tool")
        digests = []
        for files in (self.service_files, self.adapter_files):
            if not files or len({f.name for f in files}) != len(files):
                raise ValueError("unambiguous observed service and adapter files required")
            manifest = []
            for artifact in sorted(files, key=lambda v: v.name):
                artifact.read_verified()
                manifest.append({"name": artifact.name, "sha256": artifact.sha256})
            digests.append(_sha(_canonical(manifest)))
        return ToolIdentity(
            self.service_id,
            self.service_version,
            digests[0],
            self.native_name,
            self.service_version,
            _sha(_canonical(self.schema)),
            self.adapter_id,
            self.adapter_version,
            digests[1],
        )


@dataclass(frozen=True, slots=True)
class NativeCapabilitySpec:
    native_name: str
    variant: str
    capability_id: str
    roles: tuple[Role, ...]
    data_scopes: tuple[str, ...]
    path_scopes: tuple[str, ...]
    routes: tuple[str, ...]
    provider_ids: tuple[str, ...]
    model_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class NativeCapabilityBinding:
    native_name: str
    variant: str
    capability_id: str
    identity: ToolIdentity
    schema_json: str
    data_scopes: tuple[str, ...]
    routes: tuple[str, ...]
    provider_ids: tuple[str, ...]
    model_ids: tuple[str, ...]

    def __post_init__(self):
        if (
            self.native_name not in _SUPPORTED
            or type(self.identity) is not ToolIdentity
            or _sha(self.schema_json.encode()) != self.identity.tool_digest
            or _canonical(json.loads(self.schema_json)).decode() != self.schema_json
            or not self.data_scopes
        ):
            raise ValueError(
                "binding requires independently observed identity and canonical schema"
            )
        if self.native_name == "Agent":
            valid = self.variant in _CHILD_TYPES
        elif self.native_name == "mcp__documentation__fetch":
            valid = self.variant in {"compiler", "python"} and self.routes == (
                "documentation/" + self.variant + "/reference-v1",
            )
        elif self.native_name == "advisory__local_read":
            valid = self.variant in {"read", "list", "search"}
        elif self.native_name == "advisory__clangd_read":
            valid = self.variant in {"document_symbols", "hover", "definition", "references"}
        else:
            valid = self.variant == ""
        if not valid:
            raise ValueError("unsupported native binding variant")

    @property
    def operation(self):
        return (
            self.variant
            if self.native_name in {"advisory__local_read", "advisory__clangd_read"}
            else _operation(self.native_name)
        )

    @property
    def effects(self):
        return _effects(self.native_name)

    def request(self, *, task_id, attempt_id, request_id, paths=(), routes=None):
        """Also usable by a controller-owned advisory adapter with its real action ID."""
        return CapabilityRequest(
            self.capability_id,
            self.identity.tool_id,
            self.identity,
            self.operation,
            self.identity.adapter_digest,
            self.effects,
            self.data_scopes,
            tuple(paths),
            self.routes if routes is None else tuple(routes),
            self.provider_ids,
            self.model_ids,
            task_id,
            attempt_id,
            request_id,
        )


@dataclass(frozen=True, slots=True)
class SyntheticCapabilityBundle:
    registry: CapabilityRegistry
    bindings: tuple[NativeCapabilityBinding, ...]
    component_evidence_sha256: str


def build_synthetic_registry(
    *,
    specs: Sequence[NativeCapabilitySpec],
    observations: Sequence[ObservedNativeTool],
    component_evidence: Sequence[ArtifactPin],
):
    """Approve synthetic calibration from real passing component JUnit reports.

    The controller must run the tests and pin their report bytes. No test result,
    native schema or service version is inferred, generated, or marked official.
    Observations should include the captured denied calibration request schema;
    native model/provider execution is unnecessary for that discovery.
    """
    if not component_evidence:
        raise ValueError("actual passing component evidence required")
    evidence = []
    for artifact in component_evidence:
        data = artifact.read_verified()
        if (
            len(data) > 16 * 1024 * 1024
            or b"<!DOCTYPE" in data.upper()
            or b"<!ENTITY" in data.upper()
        ):
            raise ValueError("invalid component JUnit report")
        document = ET.fromstring(data)
        suites = [document] if document.tag == "testsuite" else list(document.iter("testsuite"))
        if (
            not suites
            or sum(int(s.get("tests", "0")) - int(s.get("skipped", "0")) for s in suites) <= 0
            or any(int(s.get("failures", "0")) or int(s.get("errors", "0")) for s in suites)
            or list(document.iter("failure"))
            or list(document.iter("error"))
        ):
            raise ValueError("component tests did not pass")
        evidence.append({"name": artifact.name, "sha256": artifact.sha256})
    evidence_digest = _sha(
        _canonical({"scope": SYNTHETIC_SCOPE, "reports": sorted(evidence, key=lambda e: e["name"])})
    )
    observed = {o.native_name: o for o in observations}
    if len(observed) != len(observations) or not specs:
        raise ValueError("exact observed tool inventory required")
    bindings = []
    entries = []
    for spec in specs:
        observation = observed.get(spec.native_name)
        if observation is None:
            raise ValueError("native schema observation missing")
        identity = observation.identity()
        binding = NativeCapabilityBinding(
            spec.native_name,
            spec.variant,
            spec.capability_id,
            identity,
            _canonical(observation.schema).decode(),
            spec.data_scopes,
            spec.routes,
            spec.provider_ids,
            spec.model_ids,
        )
        bindings.append(binding)
        entries.append(
            Capability(
                spec.capability_id,
                identity,
                binding.operation,
                Status.APPROVED,
                ControlLabel.LEAKAGE_BOUNDARY,
                "Component-verified synthetic calibration: " + spec.native_name,
                spec.roles,
                binding.effects,
                spec.data_scopes,
                spec.path_scopes,
                spec.routes,
                spec.provider_ids,
                spec.model_ids,
                (),
                "native tool call plus all separately metered provider invocations",
                "capability-runtime-v1",
                (
                    SYNTHETIC_SCOPE,
                    *(item["name"] + ":sha256:" + item["sha256"] for item in evidence),
                ),
                evidence_digest,
                write_domain=WriteDomain.TASK_WORKSPACE
                if Effect.WRITE in binding.effects
                else None,
            )
        )
    if len({(b.native_name, b.variant) for b in bindings}) != len(bindings):
        raise ValueError("duplicate native binding")
    return SyntheticCapabilityBundle(
        CapabilityRegistry(tuple(entries)), tuple(bindings), evidence_digest
    )


@dataclass(frozen=True, slots=True)
class ObservedPath:
    requested_path: str
    resolved_path: str
    exists: bool
    kind: str


_PATH_OBSERVATION = """import json,os,stat,sys
p=sys.argv[1]
r=os.path.realpath(p,strict=False)
try:
 s=os.stat(p);exists=True
 kind="directory" if stat.S_ISDIR(s.st_mode) else "file" if stat.S_ISREG(s.st_mode) else "other"
except FileNotFoundError:
 exists=False;kind="missing"
print(json.dumps({"requested_path":p,"resolved_path":r,"exists":exists,"kind":kind}))
"""


class DockerPathObserver:
    """Resolve actual task-container paths as agent; never inspect host files.

    This is an admission-time observation. Native builtins perform their own
    subsequent syscalls; continuous task isolation remains the OS boundary.
    """

    def __init__(self, api, *, container_id):
        self._api, self.container_id = api, container_id

    def __call__(self, path):
        path = _absolute(path)
        created = self._api.exec_create(
            self.container_id,
            cmd=["/usr/bin/python3", "-I", "-S", "-c", _PATH_OBSERVATION, path],
            user="agent",
            stdin=False,
            stdout=True,
            stderr=False,
            tty=False,
            workdir="/workspace",
        )
        data = self._api.exec_start(created["Id"], stream=False, tty=False)
        state = self._api.exec_inspect(created["Id"])
        if (
            state.get("Running") is not False
            or state.get("ExitCode") != 0
            or type(data) is not bytes
            or len(data) > 16384
        ):
            raise PermissionError("container path observation unavailable")
        result = ObservedPath(**json.loads(data))
        if result.requested_path != path:
            raise PermissionError("container path observation changed")
        return result

    def digest(self, path):
        """Hash a bounded immutable workflow/skill as agent without releasing its text."""
        path = _absolute(path)
        script = """import hashlib,os,stat,sys
parts=sys.argv[1].split("/")[1:];fd=os.open("/",os.O_RDONLY|os.O_DIRECTORY)
try:
 for part in parts[:-1]:
  child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=child
 target=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
 try:
  before=os.fstat(target)
  if not stat.S_ISREG(before.st_mode) or before.st_size>1048576: raise ValueError("bounded frozen file required")
  value=b""
  while len(value)<=1048576:
   chunk=os.read(target,min(65536,1048577-len(value)))
   if not chunk: break
   value+=chunk
  after=os.fstat(target)
  if len(value)>1048576 or (before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_size,after.st_mtime_ns,after.st_ctime_ns): raise ValueError("file changed")
  print(hashlib.sha256(value).hexdigest())
 finally: os.close(target)
finally: os.close(fd)
"""
        created = self._api.exec_create(
            self.container_id,
            cmd=[
                "/usr/bin/timeout",
                "--signal=KILL",
                "20s",
                "/usr/bin/python3",
                "-I",
                "-S",
                "-c",
                script,
                path,
            ],
            user="agent",
            stdin=False,
            stdout=True,
            stderr=False,
            tty=False,
            workdir="/workspace",
        )
        data = self._api.exec_start(created["Id"], stream=False, tty=False)
        state = self._api.exec_inspect(created["Id"])
        if (
            state.get("Running") is not False
            or state.get("ExitCode") != 0
            or type(data) is not bytes
            or re.fullmatch(rb"[a-f0-9]{64}\n", data) is None
        ):
            raise PermissionError("frozen native asset hash unavailable")
        return data.decode().strip()


def _validate_schema(binding, args):
    schema = json.loads(binding.schema_json)
    schema = schema.get("input_schema", schema.get("inputSchema"))
    if type(schema) is not dict or schema.get("type") != "object" or type(args) is not dict:
        raise PermissionError("observed tool schema unavailable")
    properties = schema.get("properties", {})
    if (
        type(properties) is not dict
        or set(args) - set(properties)
        or set(schema.get("required", ())) - set(args)
    ):
        raise PermissionError("arguments differ from observed native schema")
    kinds = {
        "string": str,
        "integer": int,
        "number": (int, float),
        "boolean": bool,
        "object": dict,
        "array": list,
        "null": type(None),
    }
    for key, value in args.items():
        spec = properties[key]
        if type(spec) is not dict:
            raise PermissionError("invalid observed schema")
        kind = spec.get("type")
        if (
            type(kind) is str
            and kind in kinds
            and type(value) not in (kinds[kind] if type(kinds[kind]) is tuple else (kinds[kind],))
        ):
            raise PermissionError("native argument type differs from observed schema")
        if "enum" in spec and value not in spec["enum"]:
            raise PermissionError("native argument enum denied")


class CapabilityRuntime:
    """Real registry admission callbacks; no approval or role is inferred from HTTP."""

    def __init__(
        self,
        *,
        registry: CapabilityRegistry,
        expected_registry_sha256: str,
        bindings: Sequence[NativeCapabilityBinding],
        peer: AdmittedPeer,
        task_id: str,
        attempt_id: str,
        audit,
        path_observer: Callable[[str], ObservedPath],
        boundary_check: Callable[[AdmittedPeer], bool],
        working_directory: str,
        execution_paths: tuple[str, ...],
        execution_routes: tuple[str, ...],
        model_id: str,
        structural_terms: tuple[str, ...],
        synthetic_task_ids=frozenset(),
        network_policy: NetworkPolicy | None = None,
        forbidden_memory_identifiers: tuple[str, ...] = (),
        frozen_workflows: Mapping[str, str] | None = None,
        frozen_skills: Mapping[str, tuple[str, str]] | None = None,
        content_digest: Callable[[str], str] | None = None,
    ):
        """Bind already-frozen identities to controller observations.

        ``boundary_check`` must check the live controller-owned task boundary;
        it is not a client assertion. Native file tools must supply explicit
        absolute paths because NativeToolCall has no independently observed cwd.
        ``execution_paths/routes`` disclose Bash's entire certified container
        scope. Shell syntax is never treated as a reliable filesystem sandbox.
        """
        if type(registry) is not CapabilityRegistry or registry.digest != expected_registry_sha256:
            raise ValueError("exact frozen capability registry required")
        if not all(
            callable(x) for x in (path_observer, boundary_check, getattr(audit, "record", None))
        ):
            raise TypeError("actual boundary/path observers and durable audit required")
        if type(peer) is not AdmittedPeer:
            raise TypeError("controller-admitted task peer required")
        if any(SYNTHETIC_SCOPE in e.evidence_refs for e in registry.entries):
            if (
                not synthetic_task_ids
                or any(not _text(t) or not t.startswith("synthetic:") for t in synthetic_task_ids)
                or task_id not in synthetic_task_ids
            ):
                raise ValueError(
                    "component-only registry is restricted to explicit synthetic task IDs"
                )
        self.registry, self.peer, self.task_id, self.attempt_id = (
            registry,
            peer,
            task_id,
            attempt_id,
        )
        self._bindings = {(b.native_name, b.variant): b for b in bindings}
        if len(self._bindings) != len(bindings):
            raise ValueError("duplicate native binding")
        self._audit, self._observe, self._boundary = audit, path_observer, boundary_check
        self._cwd = _absolute(working_directory)
        self._execution_paths = tuple(_absolute(p) for p in execution_paths)
        self._execution_routes = execution_routes
        self._model, self._terms = model_id, structural_terms
        if network_policy is not None and type(network_policy) is not NetworkPolicy:
            raise TypeError("frozen NetworkPolicy required")
        if type(forbidden_memory_identifiers) is not tuple or any(
            not _text(value) for value in forbidden_memory_identifiers
        ):
            raise ValueError("explicit frozen denied memory identifiers required")
        self._network, self._denied_memory = (
            network_policy,
            tuple(v.casefold() for v in forbidden_memory_identifiers),
        )
        self._workflows = dict(frozen_workflows or {})
        self._skills = dict(frozen_skills or {})
        self._content_digest = content_digest
        for path, digest in self._workflows.items():
            _absolute(path)
            if re.fullmatch(r"[a-f0-9]{64}", digest) is None:
                raise ValueError("workflow asset hash required")
        for name, (path, digest) in self._skills.items():
            _absolute(path)
            if not _text(name) or re.fullmatch(r"[a-f0-9]{64}", digest) is None:
                raise ValueError("skill name and asset hash required")
        TrustedMemoryCaller(task_id, attempt_id, Caller.PARENT, model_id, structural_terms)

    def authorize_peer(self, peer):
        return peer == self.peer and self._boundary(peer) is True

    @property
    def bindings(self):
        return tuple(self._bindings.values())

    @property
    def audit(self):
        return self._audit

    def binding(self, native_name, variant=""):
        try:
            return self._bindings[(native_name, variant)]
        except KeyError:
            raise PermissionError("tool has no frozen capability binding") from None

    def _request(self, call):
        if (
            type(call) is not NativeToolCall
            or call.task_id != self.task_id
            or call.attempt_id != self.attempt_id
            or call.role not in {"parent", "child"}
            or not self.authorize_peer(self.peer)
        ):
            raise PermissionError("native caller or task boundary unavailable")
        args = dict(call.arguments)
        variant = (
            args.get("subagent_type", "")
            if call.name == "Agent"
            else args.get("route", "")
            if call.name == "mcp__documentation__fetch"
            else ""
        )
        binding = self.binding(call.name, variant)
        _validate_schema(binding, args)
        if call.name in _ADVISORY:
            raise PermissionError("advisory action is not a native tool")
        if call.role == "child" and call.name in _WRITE | _EXECUTE | _WORKFLOWS | _TASK_STATE | {
            "Agent",
            "Workflow",
            "Skill",
        }:
            raise PermissionError("native children are read-only")
        if call.name == "Agent" and variant not in _CHILD_TYPES:
            raise PermissionError("unregistered native child type")
        paths = []
        routes = binding.routes
        asset_digest = None
        field = "file_path" if call.name in {"Read", "Write", "Edit"} else "path"
        if call.name in {"Grep", "Glob"}:
            value = args.get("path")
            if call.name == "Glob" and value is None:
                # Native children commonly provide an absolute pattern without
                # the optional path. Bind its concrete prefix to the same
                # observed task-root check used for explicit paths.
                pattern = args.get("pattern")
                if (
                    not _text(pattern)
                    or not pattern.startswith("/")
                    or "\\" in pattern
                    or ".." in pattern.split("/")
                ):
                    raise PermissionError("glob pattern scope is ambiguous")
                wildcard = re.search(r"[*?\[\{]", pattern)
                prefix = pattern[: wildcard.start()] if wildcard else pattern
                value = prefix.rstrip("/") if prefix.endswith("/") else posixpath.dirname(prefix)
        elif call.name in _READ | _WRITE | _CLANGD:
            value = args.get(field)
        elif call.name in {
            "mcp__vulnerable__run_test",
            "mcp__advisor__critic",
            "mcp__finalizer__select_final",
        }:
            value = args.get("candidate_path")
        elif call.name == "Workflow":
            if any(key in args for key in ("script", "name", "resumeFromRunId")):
                raise PermissionError("only the exact frozen workflow scriptPath is admitted")
            value = args.get("scriptPath")
            if type(value) is not str or value not in self._workflows:
                raise PermissionError("workflow script was not frozen")
            asset_digest = self._workflows[value]
        elif call.name == "Skill":
            skill = args.get("skill")
            if type(skill) is not str or skill not in self._skills:
                raise PermissionError("skill template was not frozen")
            value, asset_digest = self._skills[skill]
        elif call.name == _DIAGNOSTICS:
            uri = args.get("uri")
            if type(uri) is not str or not uri.startswith("file:///workspace/"):
                raise PermissionError("one explicit task file diagnostic URI required")
            parsed = urlsplit(uri)
            if parsed.scheme != "file" or parsed.netloc or parsed.query or parsed.fragment:
                raise PermissionError("diagnostic URI is outside task files")
            value = unquote(parsed.path, errors="strict")
            if "%" in value or not value.startswith("/workspace/"):
                raise PermissionError("diagnostic URI has ambiguous encoding")
        else:
            value = None
        if value is not None:
            path = _absolute(value)
            observed = self._observe(path)
            if (
                type(observed) is not ObservedPath
                or observed.requested_path != path
                or type(observed.exists) is not bool
                or observed.kind not in {"file", "directory", "missing"}
            ):
                raise PermissionError("path observation invalid")
            if call.name not in _WRITE and not observed.exists:
                raise PermissionError("native read path does not exist")
            if call.name == _DIAGNOSTICS and observed.kind != "file":
                raise PermissionError("diagnostics require one task file")
            paths = list(dict.fromkeys((path, _absolute(observed.resolved_path))))
            if asset_digest is not None:
                if not callable(self._content_digest) or self._content_digest(path) != asset_digest:
                    raise PermissionError("frozen native template content changed")
            if call.name == "Glob":
                pattern = args.get("pattern")
                if not _text(pattern) or "\\" in pattern or ".." in pattern.split("/"):
                    raise PermissionError("glob pattern scope is ambiguous")
                combined = pattern if pattern.startswith("/") else posixpath.join(path, pattern)
                match = re.search(r"[*?\[\{]", combined)
                prefix = combined[: match.start()] if match else combined
                prefix = prefix.rstrip("/") if prefix.endswith("/") else posixpath.dirname(prefix)
                prefix = _absolute(prefix)
                observed_prefix = self._observe(prefix)
                if (
                    type(observed_prefix) is not ObservedPath
                    or observed_prefix.requested_path != prefix
                ):
                    raise PermissionError("glob prefix observation unavailable")
                paths = list(
                    dict.fromkeys((*paths, prefix, _absolute(observed_prefix.resolved_path)))
                )
        elif call.name in _READ | _WRITE | _CLANGD | {
            _DIAGNOSTICS,
            "mcp__vulnerable__run_test",
            "mcp__advisor__critic",
            "mcp__finalizer__select_final",
        }:
            raise PermissionError("native operation path missing")
        if call.name in _EXECUTE:
            if call.name == "Bash" and (
                not _shell_text(args.get("command"))
                or args.get("dangerouslyDisableSandbox", False) is not False
            ):
                raise PermissionError("sandbox escape override denied")
            if "isolated-task-container" not in binding.data_scopes or not self._execution_paths:
                raise PermissionError("whole task-container execution scope required")
            paths = list(dict.fromkeys((*paths, *self._execution_paths)))
            routes = tuple(dict.fromkeys((*routes, *self._execution_routes)))
        if call.name in _TASK_STATE:
            # The pinned native handlers use session storage and sanitized task IDs.
            # TaskUpdate's owner branch can message teams; that needs a separate policy.
            if call.name == "TaskUpdate" and args.get("owner") not in (None, ""):
                raise PermissionError("cross-team task assignment is not registered")
            if call.name == "TaskStop" and set(args) - {"task_id", "shell_id"}:
                raise PermissionError("only local native task cancellation is registered")
            for root in _TASK_STATE_ROOTS:
                observed = self._observe(root)
                if type(observed) is not ObservedPath or observed.requested_path != root:
                    raise PermissionError("native task state path observation unavailable")
                paths.extend((root, _absolute(observed.resolved_path)))
            paths = list(dict.fromkeys(paths))
        request = binding.request(
            task_id=call.task_id,
            attempt_id=call.attempt_id,
            request_id=call.request_id,
            paths=paths,
            routes=routes,
        )
        return binding, request, CapabilityAuthorizer(self.registry, Role(call.role), self._audit)

    def authorize(self, call):
        try:
            _, request, authorizer = self._request(call)
            return authorizer.authorize(request).allowed is True
        except Exception:
            try:
                self._audit.record(
                    {
                        "event": "native_capability_denied",
                        "task_id": self.task_id,
                        "attempt_id": self.attempt_id,
                        "tool_use_id": getattr(call, "tool_id", None),
                        "reason": "identity, observed arguments, boundary, path or audit unavailable",
                    }
                )
            except Exception:
                pass
            return False

    def documentation_admission(self, call, route_id):
        if call.name != "mcp__documentation__fetch":
            raise PermissionError("not a documentation call")
        _, request, authorizer = self._request(call)
        if request.routes != (route_id,) or not authorizer.authorize(request).allowed:
            raise PermissionError("documentation capability denied")
        return DocumentationAdmission(authorizer, request)

    def authorized_workflow_digest(self, call):
        """Recheck actual frozen script bytes before controller child reservations."""
        if type(call) is not NativeToolCall or call.name != "Workflow" or not self.authorize(call):
            raise PermissionError("workflow capability denied")
        path = call.arguments["scriptPath"]
        observed = self._content_digest(path)
        if observed != self._workflows[path]:
            raise PermissionError("frozen workflow content changed after authorization")
        return observed

    def memory_caller(self, call):
        if call.name not in _MEMORY or not self.authorize(call):
            raise PermissionError("memory capability denied")
        return TrustedMemoryCaller(
            call.task_id, call.attempt_id, Caller(call.role), self._model, self._terms
        )

    def resolve_registered(self, controller, peer, tool_use_id, native_name, arguments):
        if not self.authorize_peer(peer):
            raise PermissionError("task peer denied")
        return controller.resolve_mcp_call(tool_use_id, native_name, dict(arguments))

    def resolve_memory(self, controller, peer, tool_use_id, name, arguments):
        if name not in {"recall", "search"}:
            raise PermissionError("memory operation denied")
        return self.memory_caller(
            self.resolve_registered(
                controller, peer, tool_use_id, "mcp__gbrain__" + name, arguments
            )
        )

    def authorize_advisory(self, action, arguments):
        """Authorize an observed DeepSeek JSON action without inventing native custody."""
        from .advisory_runtime import AdvisoryAction
        from .deepseek import DeepSeekRole

        try:
            if (
                type(action) is not AdvisoryAction
                or type(action.role) is not DeepSeekRole
                or not _text(action.action_id)
                or not _text(action.provider_request_id)
                or action.task_id != self.task_id
                or action.attempt_id != self.attempt_id
                or type(arguments) is not dict
                or action.arguments_sha256 != _sha(_canonical(arguments))
                or not self.authorize_peer(self.peer)
            ):
                raise PermissionError("advisory action identity denied")
            name = "advisory__" + action.name
            if name not in _ADVISORY:
                raise PermissionError("unknown advisory action")
            variant = (
                arguments.get("operation", "")
                if name in {"advisory__local_read", "advisory__clangd_read"}
                else ""
            )
            binding = self.binding(name, variant)
            _validate_schema(binding, arguments)
            paths = ()
            if name in {"advisory__local_read", "advisory__clangd_read"}:
                path = _absolute(arguments.get("path"))
                observed = self._observe(path)
                if (
                    type(observed) is not ObservedPath
                    or observed.requested_path != path
                    or observed.exists is not True
                ):
                    raise PermissionError("advisory source observation unavailable")
                paths = tuple(dict.fromkeys((path, _absolute(observed.resolved_path))))
            request = binding.request(
                task_id=action.task_id,
                attempt_id=action.attempt_id,
                request_id=action.action_id,
                paths=paths,
            )
            return (
                CapabilityAuthorizer(self.registry, Role.CHILD, self._audit)
                .authorize(request)
                .allowed
                is True
            )
        except Exception:
            try:
                self._audit.record(
                    {
                        "event": "advisory_capability_denied",
                        "task_id": self.task_id,
                        "attempt_id": self.attempt_id,
                        "action_id": getattr(action, "action_id", None),
                    }
                )
            except Exception:
                pass
            return False

    def safe_memory_filter(self, text):
        """True means safe under the frozen network filter and denied task identifiers.

        Structural terms remain allowed current-task query material; they do not
        confer provenance. Actual page provenance remains the signed allowlist.
        """
        if self._network is None or type(text) is not str or "\x00" in text:
            return False
        if any(identifier in text.casefold() for identifier in self._denied_memory):
            return False
        try:
            self._network.check_document_body(text.encode("utf-8"), "text/plain")
            return True
        except (NetworkDenied, UnicodeError):
            return False
