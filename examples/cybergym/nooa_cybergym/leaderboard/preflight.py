# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Active pre-model isolation probes for the exact native execution contexts.

The controller supplies a ProbeExecutor that runs each command *inside* the
real extension parent and local child contexts of the same task container.
Unit doubles exercise this contract but do not count as live certification.
Raw command output never enters the task; controller evidence stores only
digests and exit codes so a failed secret probe cannot print a credential.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from .network import NetworkPolicy

_FORBIDDEN_PATHS = (
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
)
_REQUIRED_PATHS = (
    "/workspace/description.txt",
    "/workspace/README.md",
    "/workspace/repo-vul.tar.gz",
    "/workspace/submit.sh",
    "/workspace/src",
)
_FORBIDDEN_ENV = (
    "DEEPSEEK_API_KEY",
    "DEEPSEEK_AUTH_TOKEN",
    "DEEPSEEK_TOKEN",
    "OPENAI_API_KEY",
    "OPENAI_AUTH_TOKEN",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_TOKEN",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "AWS_SECRET_ACCESS_KEY",
    "AZURE_OPENAI_API_KEY",
    "SUNCHASER_ZAI_CODING_PLAN_TOKEN",
    "SUNCHASER_ZAI_CODING_PLAN_API_KEY",
    "SUNCHASER_ZAI_API_KEY",
    "ZAI_API_KEY",
    "ZAI_AUTH_TOKEN",
    "ZAI_CODING_PLAN_TOKEN",
    "ZAI_CODING_PLAN_API_KEY",
    "GITHUB_TOKEN",
    "GITHUB_API_TOKEN",
    "GITHUB_PERSONAL_ACCESS_TOKEN",
    "GH_TOKEN",
    "CYBERGYM_TASK_TOKEN",
    "CYBERGYM_SSH_PUBLIC_KEY",
    "GBRAIN_API_KEY",
    "GBRAIN_AUTH_TOKEN",
)
_MOUNTS = (
    "workspace_readonly",
    "output_writable",
    "src_tmpfs",
    "src_executable",
    "home_tmpfs",
    "tmp_tmpfs",
    "no_host_processes",
)
_DENIED_ROUTE_URLS = {
    "external-target-repository": "https://github.com/example/public-repo",
    "external-target-patch": "https://github.com/example/public-repo/commit/deadbeef",
    "target-issue-or-changelog": "https://github.com/example/public-repo/issues/1",
    "cve-or-published-poc": "https://nvd.nist.gov/vuln/detail/CVE-2025-12345",
    "fixed-or-prior-task-answer": "https://github.com/example/public-repo/raw/main/repo-fix.tar.gz",
    "credential-or-host-access": "http://169.254.169.254/latest/meta-data/",
    "direct-provider-api": "https://api.deepseek.com/",
}

_PATH_SCRIPT = (
    "import os,sys; p=sys.argv[1]; "
    "present=any('.git' in dirs or '.git' in files "
    "for _,dirs,files in os.walk(p[:-len('/**/.git')])) "
    "if p.endswith('/**/.git') else os.path.lexists(p); "
    "sys.exit(0 if present==int(sys.argv[2]) else 1)"
)
_UID_SCRIPT = (
    "import os,pwd,shutil,sys; u=os.getuid(); "
    "sys.exit(0 if u!=0 and pwd.getpwuid(u).pw_name=='agent' "
    "and shutil.which('sudo') is None else 1)"
)
_ENV_SCRIPT = (
    "import os,sys; name=sys.argv[1]; value=os.environ.get(name); "
    "sys.exit(0 if value is None or "
    "(name=='ANTHROPIC_AUTH_TOKEN' and value=='xeus-container-peer-auth') else 1)"
)
_MOUNT_SCRIPT = (
    "import os,sys; name=sys.argv[1]; entries={}; "
    "[(lambda p: entries.update({p[4]:(set(p[5].split(',')),p[p.index('-')+1])}))"
    "(line.split()) for line in open('/proc/self/mountinfo')]; "
    "checks={'workspace_readonly':lambda:'ro' in entries['/workspace'][0],"
    "'output_writable':lambda:'rw' in entries['/workspace/output'][0],"
    "'src_tmpfs':lambda:entries['/workspace/src'][1]=='tmpfs',"
    "'src_executable':lambda:'noexec' not in entries['/workspace/src'][0],"
    "'home_tmpfs':lambda:entries['/home/agent'][1]=='tmpfs',"
    "'tmp_tmpfs':lambda:entries['/tmp'][1]=='tmpfs',"
    "'no_host_processes':lambda:open('/proc/1/comm').read().strip()=='sshd'}; "
    "sys.exit(0 if checks[name]() else 1)"
)
_ALLOWED_ROUTE_SCRIPT = (
    "import sys,urllib.request; "
    "r=urllib.request.urlopen(sys.argv[1],timeout=5); "
    "sys.exit(0 if 200<=r.status<300 else 1)"
)
_DENIED_ROUTE_SCRIPT = (
    "import errno,socket,sys,urllib.request,urllib.error; url=sys.argv[1]; "
    "\ntry:\n r=urllib.request.urlopen(url,timeout=5)\n"
    "except urllib.error.HTTPError as e:\n"
    " sys.exit(0 if e.headers.get('X-Squid-Error','').startswith('ERR_ACCESS_DENIED') else 1)\n"
    "except urllib.error.URLError as e:\n"
    " reason=e.reason\n"
    " blocked=(isinstance(reason,socket.gaierror) or "
    "(isinstance(reason,OSError) and reason.errno in "
    "(errno.EACCES,errno.ENETUNREACH,errno.EHOSTUNREACH,errno.ECONNREFUSED)) or "
    "(isinstance(reason,str) and reason.startswith('Tunnel connection failed: 403')))\n"
    " sys.exit(0 if blocked else 1)\n"
    "else:\n sys.exit(1)"
)
_TOOL_SCRIPT = "import shutil,sys; sys.exit(0 if shutil.which(sys.argv[1]) else 1)"


@dataclass(frozen=True, slots=True)
class ProbeSpec:
    name: str
    context: str
    category: str
    target: str
    command: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ProbeExecution:
    exit_code: int
    stdout: bytes
    stderr: bytes
    observed_context: str
    observed_container_id: str


@dataclass(frozen=True, slots=True)
class ProbeRecord:
    name: str
    context: str
    command: tuple[str, ...]
    exit_code: int | None
    passed: bool
    stdout_sha256: str
    stderr_sha256: str
    observed_context: str
    observed_container_id: str
    timestamp: str


@dataclass(frozen=True, slots=True)
class PreflightReport:
    passed: bool
    failures: tuple[str, ...]
    probes: tuple[ProbeRecord, ...] = ()
    contexts: tuple[str, ...] = ()
    execution_mode: str = "evaluation-only"
    container_id: str = ""
    workspace_manifest_sha256: str = ""
    policy_sha256: str = ""
    evidence_path: Path | None = None


class ProbeExecutor(Protocol):
    mode: str  # "native" only after independently verified execution wiring

    def run(self, spec: ProbeSpec, container: object) -> ProbeExecution:
        """Execute inside spec.context of container; never substitute host shell."""


def _timestamp() -> str:
    return datetime.now(UTC).isoformat()


def evaluate_probe_results(results: dict, policy: NetworkPolicy) -> PreflightReport:
    """Interpret observed facts; absent facts are failures, not assumptions."""
    if type(results) is not dict or type(policy) is not NetworkPolicy:
        raise TypeError("observed probe map and frozen network policy are required")
    failures = []
    categories = (
        ("forbidden_paths", _FORBIDDEN_PATHS, False),
        ("required_paths", _REQUIRED_PATHS, True),
        ("network", sorted(policy.allowed_logical_endpoints), True),
        ("forbidden_routes", sorted(policy.required_denied_routes), False),
        ("forbidden_env", _FORBIDDEN_ENV, False),
        ("mounts", _MOUNTS, True),
        ("registered_tools", ("clangd",), True),
    )
    for group_name, required, expected in categories:
        group = results.get(group_name)
        if type(group) is not dict:
            failures.extend(required)
            continue
        for name in required:
            if type(group.get(name)) is not bool or group[name] is not expected:
                failures.append(name)
    uid = results.get("uid")
    if type(uid) is not int or uid == 0:
        failures.append("uid")
    return PreflightReport(not failures, tuple(failures))


def _specs(
    policy: NetworkPolicy, context: str, prior_task_ids: tuple[str, ...]
) -> tuple[ProbeSpec, ...]:
    specs = []
    forbidden_paths = (*_FORBIDDEN_PATHS, *(f"/workspace/{task_id}" for task_id in prior_task_ids))
    for path in forbidden_paths:
        specs.append(
            ProbeSpec(
                f"path:{path}",
                context,
                "forbidden_paths",
                path,
                ("python3", "-c", _PATH_SCRIPT, path, "0"),
            )
        )
    for path in _REQUIRED_PATHS:
        specs.append(
            ProbeSpec(
                f"path:{path}",
                context,
                "required_paths",
                path,
                ("python3", "-c", _PATH_SCRIPT, path, "1"),
            )
        )
    specs.append(ProbeSpec("uid", context, "uid", "uid", ("python3", "-c", _UID_SCRIPT)))
    for endpoint in sorted(policy.allowed_logical_endpoints):
        specs.append(
            ProbeSpec(
                f"route:{endpoint}",
                context,
                "network",
                endpoint,
                ("python3", "-c", _ALLOWED_ROUTE_SCRIPT, f"http://{endpoint}/health"),
            )
        )
    for route in sorted(policy.required_denied_routes | {"direct-provider-api"}):
        if route not in _DENIED_ROUTE_URLS:
            raise ValueError(f"no negative probe URL for required route {route}")
        specs.append(
            ProbeSpec(
                f"route:{route}",
                context,
                "forbidden_routes",
                route,
                ("python3", "-c", _DENIED_ROUTE_SCRIPT, _DENIED_ROUTE_URLS[route]),
            )
        )
    for name in _FORBIDDEN_ENV:
        specs.append(
            ProbeSpec(
                f"env:{name}", context, "forbidden_env", name, ("python3", "-c", _ENV_SCRIPT, name)
            )
        )
    for name in _MOUNTS:
        specs.append(
            ProbeSpec(
                f"mount:{name}", context, "mounts", name, ("python3", "-c", _MOUNT_SCRIPT, name)
            )
        )
    specs.append(
        ProbeSpec(
            "tool:clangd",
            context,
            "registered_tools",
            "clangd",
            ("python3", "-c", _TOOL_SCRIPT, "clangd"),
        )
    )
    return tuple(specs)


def run_preflight(
    *,
    container: object,
    workspace_manifest: Path,
    workspace_root: Path,
    policy: NetworkPolicy,
    executor: ProbeExecutor,
    evidence_dir: Path,
    prior_task_ids: tuple[str, ...] = (),
    contexts: tuple[str, ...] = ("parent", "child"),
) -> PreflightReport:
    """Probe the selected native contexts before their model requests.

    The caller must wire an executor to the native extension and child process;
    a unit fake yields execution_mode=synthetic and cannot certify isolation.
    """
    workspace_root = Path(workspace_root)
    evidence_dir = Path(evidence_dir)
    workspace_manifest = Path(workspace_manifest)
    if workspace_root.is_symlink() or not workspace_root.is_dir():
        raise ValueError("workspace root must be a real directory")
    task_root = workspace_root.resolve()
    evidence_root = evidence_dir.resolve()
    if evidence_root == task_root or evidence_root.is_relative_to(task_root):
        raise ValueError("preflight evidence must be outside agent root")
    if (
        workspace_manifest.is_symlink()
        or not workspace_manifest.is_file()
        or workspace_manifest.resolve().is_relative_to(task_root)
    ):
        raise ValueError("trusted workspace manifest must be outside agent root")
    if type(policy) is not NetworkPolicy:
        raise TypeError("frozen network policy required")
    if not callable(getattr(executor, "run", None)) or not isinstance(
        getattr(executor, "mode", None), str
    ):
        raise TypeError("an attested probe executor is required")
    container_id = getattr(container, "container_id", None)
    if type(container_id) is not str or not container_id:
        raise ValueError("task container identity is required")
    if type(prior_task_ids) is not tuple or any(
        type(item) is not str or re.fullmatch(r"[A-Za-z0-9_-]+", item) is None
        for item in prior_task_ids
    ):
        raise ValueError("prior task IDs must be safe immutable identifiers")
    if type(contexts) is not tuple or contexts not in {
        ("parent",),
        ("child",),
        ("parent", "child"),
    }:
        raise ValueError("preflight context selection is incomplete or duplicated")

    records = []
    failures = []
    for context in contexts:
        observed = {
            "forbidden_paths": {},
            "required_paths": {},
            "network": {},
            "forbidden_routes": {},
            "forbidden_env": {},
            "mounts": {},
            "registered_tools": {},
        }
        for spec in _specs(policy, context, prior_task_ids):
            try:
                execution = executor.run(spec, container)
                valid = (
                    type(execution) is ProbeExecution
                    and type(execution.exit_code) is int
                    and type(execution.stdout) is bytes
                    and type(execution.stderr) is bytes
                    and execution.observed_context == context
                    and execution.observed_container_id == container_id
                )
            except Exception:
                execution = None
                valid = False
            passed = bool(valid and execution.exit_code == 0)
            if not passed:
                failures.append(f"{context}:{spec.target}")
            stdout = execution.stdout if valid else b""
            stderr = execution.stderr if valid else b""
            records.append(
                ProbeRecord(
                    spec.name,
                    context,
                    spec.command,
                    execution.exit_code if valid else None,
                    passed,
                    hashlib.sha256(stdout).hexdigest(),
                    hashlib.sha256(stderr).hexdigest(),
                    execution.observed_context if valid else "unverified",
                    execution.observed_container_id if valid else "unverified",
                    _timestamp(),
                )
            )
            observed_value = (
                passed
                if spec.category
                in {
                    "required_paths",
                    "network",
                    "mounts",
                    "registered_tools",
                }
                else not passed
            )
            if spec.category == "uid":
                observed["uid"] = 1000 if passed else 0
            else:
                observed[spec.category][spec.target] = observed_value
        checked = evaluate_probe_results(observed, policy)
        failures.extend(f"{context}:{item}" for item in checked.failures)
        for task_id in prior_task_ids:
            if observed["forbidden_paths"].get(f"/workspace/{task_id}") is not False:
                failures.append(f"{context}:/workspace/{task_id}")
        if observed["forbidden_routes"].get("direct-provider-api") is not False:
            failures.append(f"{context}:direct-provider-api")

    failures = list(dict.fromkeys(failures))
    report_name = (
        f"preflight-{contexts[0]}-report.json" if len(contexts) == 1 else "preflight-report.json"
    )
    report_path = evidence_dir / report_name
    report = PreflightReport(
        passed=not failures,
        failures=tuple(failures),
        probes=tuple(records),
        contexts=contexts,
        execution_mode=executor.mode,
        container_id=container_id,
        workspace_manifest_sha256=hashlib.sha256(workspace_manifest.read_bytes()).hexdigest(),
        policy_sha256=policy.digest,
        evidence_path=report_path,
    )
    evidence_dir.mkdir(parents=True, exist_ok=True)
    payload = asdict(report)
    payload["evidence_path"] = str(report_path)
    data = (
        json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode()
    descriptor = os.open(report_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        report_path.unlink(missing_ok=True)
        raise
    return report
