# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Read-only inventory of the native Claude harness integration boundary.

Source inspection is an observation, never evidence of a running task. A future
controller can inject a trusted Xeus verifier for signed live integration
evidence; without it the gate stays blocked. This module reads no provider
credentials, task inputs, Claude sessions, or private controller evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
_OPEN_COMMAND = "claude-vscode.editor.open"
_CONTROLLER_COMPONENTS = {
    "campaign": "campaign.py",
    "workspace": "workspace.py",
    "container": "container.py",
    "host_boundary": "host_boundary.py",
    "model_service": "model_service.py",
    "preflight": "preflight.py",
    "memory_transport": "memory_transport.py",
    "capability_gate": "capabilities.py",
}

# Each live interface must have its own raw-evidence digest in the trusted
# verifier's result. A generic "native harness passed" flag cannot replace it.
REQUIRED_LIVE_INTERFACES = (
    "signed_harness_lock_and_workspace_manifest",
    "workspace_native_launcher",
    "remote_extension_host_identity",
    "host_gateway_boundary",
    "native_parent_child_preflight",
    "authenticated_model_connection",
    "trusted_parent_child_model_admission",
    "native_parent_child_tool_trace",
    "capability_authorization_and_tool_results",
    "guarded_gbrain_bridge",
    "task_token_without_agent_exposure",
    "parent_final_and_terminal_receipt",
)

INTERFACE_CONTRACTS = {
    "vscode_version_observation": "Observe VS Code version and commit from the exact workstation client.",
    "version_locked_native_command": (
        "Inspect the frozen Claude extension command registration and prove its second "
        "argument reaches the native conversation's initial prompt."
    ),
    "controller_component_sources": "Keep campaign, workspace, container, model, preflight, memory, and capability code present.",
    "signed_live_integration_evidence": (
        "Verify one signed raw native run with Xeus authority; static source inspection is insufficient."
    ),
    "signed_harness_lock_and_workspace_manifest": (
        "Bind the signed campaign/harness lock to CampaignState.verified_staging_paths "
        "and the exact staged workspace manifest."
    ),
    "workspace_native_launcher": (
        "Install one workspace-host launcher that writes a durable launch receipt, "
        "opens one Claude conversation, and never relaunches on reconnect."
    ),
    "remote_extension_host_identity": (
        "Attest the VS Code remote extension host, task container ID, Claude extension "
        "version, and its execution location in the isolated task boundary."
    ),
    "host_gateway_boundary": (
        "Bind signed raw evidence for each task container to its Docker network ID, "
        "bridge, subnet, gateway, exact logical endpoints and allowed ports; verify "
        "active bridge-scoped default-deny firewall rules and a live host-gateway "
        "canary listener blocked from the container. Also require native negative "
        "HTTP probes proving the port-80 proxy rejects unknown Host, direct-IP, "
        "canary passthrough, and CONNECT-to-canary requests. A refused connection "
        "alone is insufficient."
    ),
    "native_parent_child_preflight": (
        "Supply ProbeExecutor.mode=native from actual parent and local-child processes "
        "in the same container before the first model request."
    ),
    "authenticated_model_connection": (
        "Mount ModelHTTPService on a listener that injects the opaque "
        "xeus.model_connection ASGI scope handle from authenticated transport."
    ),
    "trusted_parent_child_model_admission": (
        "Resolve each handle to TrustedAdmission using native parent/child process "
        "identity and controller workflow state, never solver body or headers."
    ),
    "native_parent_child_tool_trace": (
        "Capture exact native parent/child tool-call start, result, failure, and "
        "terminal events with runtime identity and stable call IDs."
    ),
    "capability_authorization_and_tool_results": (
        "Match every observed tool call and result one-to-one with a controller "
        "CapabilityRequest, its approved signed ToolIdentity, and durable AuthorizationEvent."
    ),
    "guarded_gbrain_bridge": (
        "Provide ControllerMcpBridge read_evidence/exchange/notify with authenticated "
        "source scope and native AI invocation guard; keep OAuth controller-only."
    ),
    "task_token_without_agent_exposure": (
        "Deliver only the task-scoped model token through an authenticated native "
        "channel; prove it and provider keys never enter agent environment or output."
    ),
    "parent_final_and_terminal_receipt": (
        "Bind the one parent-selected final to native parent event evidence and "
        "an Xeus-signed terminal receipt after container stop."
    ),
}


@dataclass(frozen=True, slots=True)
class VerifiedNativeIntegration:
    """Trusted verifier output over a signed raw native run, never solver input.

    The verifier must match every interface digest to raw evidence, including
    role-bound native tool-call starts/results and controller capability audit
    decisions. Constructing this type alone does not establish that trust.
    """

    envelope_sha256: str
    signature_key_id: str
    scope: str
    execution_source: str
    run_id: str
    task_id: str
    container_id: str
    vscode_version: str
    vscode_commit: str
    claude_extension_version: str
    interface_evidence: Mapping[str, str]
    credential_exposure_surfaces: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class NativeReadinessReport:
    schema_version: int
    scope: str
    gate: str
    observed: Mapping[str, Any]
    missing_interfaces: tuple[str, ...]
    missing_contracts: Mapping[str, str]

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"), allow_nan=False)


def _vscode_identity(output: str | None) -> tuple[str | None, str | None]:
    if type(output) is not str:
        return None, None
    lines = output.splitlines()
    if len(lines) < 2 or not _VERSION.fullmatch(lines[0]) or not _COMMIT.fullmatch(lines[1]):
        return None, None
    return lines[0], lines[1]


def _native_command_contract(source: str, contributed: bool) -> bool:
    if not contributed:
        return False
    registered = re.search(
        r'registerCommand\("claude-vscode\.editor\.open",\s*async\(([^)]{1,128})\)\s*=>',
        source,
    )
    if registered is None:
        return False
    parameters = tuple(part.strip() for part in registered.group(1).split(","))
    if len(parameters) < 2 or not all(re.fullmatch(r"[$A-Za-z_][$\w]*", p) for p in parameters):
        return False
    first, prompt = map(re.escape, parameters[:2])
    panel_call = rf"createPanel\(\s*{first}\s*,\s*{prompt}\s*,"
    return re.search(panel_call, source[registered.end() : registered.end() + 2400]) is not None


def _extension_observation(extension_dir: Path) -> tuple[str | None, str | None, bool]:
    package_path = extension_dir / "package.json"
    source_path = extension_dir / "extension.js"
    try:
        if package_path.is_symlink() or source_path.is_symlink():
            return None, None, False
        package = json.loads(package_path.read_bytes())
        raw_source = source_path.read_bytes()
        source = raw_source.decode("utf-8")
        version = package.get("version")
        commands = package.get("contributes", {}).get("commands", [])
        contributed = type(commands) is list and any(
            type(item) is dict and item.get("command") == _OPEN_COMMAND for item in commands
        )
        if (
            type(package) is not dict
            or package.get("name") != "claude-code"
            or type(version) is not str
            or not _VERSION.fullmatch(version)
        ):
            return None, None, False
    except (OSError, UnicodeError, ValueError, AttributeError, TypeError):
        return None, None, False
    return (
        version,
        hashlib.sha256(raw_source).hexdigest(),
        _native_command_contract(source, contributed),
    )


def _verified_live(
    envelope: bytes | None,
    attest_live: Callable[[bytes], VerifiedNativeIntegration] | None,
    *,
    run_id: str | None,
    task_id: str | None,
    container_id: str | None,
    vscode_version: str | None,
    vscode_commit: str | None,
    extension_version: str | None,
) -> VerifiedNativeIntegration | None:
    if (
        type(envelope) is not bytes
        or not envelope
        or not callable(attest_live)
        or any(type(value) is not str or not value for value in (run_id, task_id, container_id))
    ):
        return None
    try:
        verified = attest_live(envelope)
    except Exception:
        return None
    if type(verified) is not VerifiedNativeIntegration:
        return None
    evidence = verified.interface_evidence
    if (
        verified.envelope_sha256 != hashlib.sha256(envelope).hexdigest()
        or type(verified.signature_key_id) is not str
        or not verified.signature_key_id
        or len(verified.signature_key_id) > 128
        or any(ord(char) < 32 for char in verified.signature_key_id)
        or verified.scope != "live_native"
        or verified.execution_source != "native-vscode-extension"
        or (verified.run_id, verified.task_id, verified.container_id)
        != (run_id, task_id, container_id)
        or (verified.vscode_version, verified.vscode_commit, verified.claude_extension_version)
        != (vscode_version, vscode_commit, extension_version)
        or type(evidence) is not dict
        or set(evidence) != set(REQUIRED_LIVE_INTERFACES)
        or any(
            type(digest) is not str or not _SHA256.fullmatch(digest) or digest == "0" * 64
            for digest in evidence.values()
        )
        or verified.credential_exposure_surfaces != ()
    ):
        return None
    return verified


def audit_native_readiness(
    *,
    repo_root: Path,
    extension_dir: Path,
    vscode_version_output: str | None = None,
    signed_live_evidence: bytes | None = None,
    attest_live: Callable[[bytes], VerifiedNativeIntegration] | None = None,
    expected_run_id: str | None = None,
    expected_task_id: str | None = None,
    expected_container_id: str | None = None,
) -> NativeReadinessReport:
    """Inventory static seams and require a trusted live attestor for release.

    A synthetic verifier can exercise this API in tests, but only the real Xeus
    authority over raw native evidence can support a live campaign decision.
    ``attest_live`` is never called with solver-controlled input.
    """

    repo_root = Path(repo_root)
    extension_dir = Path(extension_dir)
    vscode_version, vscode_commit = _vscode_identity(vscode_version_output)
    extension_version, extension_sha256, command_observed = _extension_observation(extension_dir)
    controller_dir = repo_root / "examples" / "cybergym" / "nooa_cybergym" / "leaderboard"
    components = {
        name: (controller_dir / filename).is_file()
        for name, filename in _CONTROLLER_COMPONENTS.items()
    }
    launcher_dir = repo_root / "examples" / "cybergym" / "leaderboard" / "native-launcher"
    launcher_present = (launcher_dir / "extension.js").is_file() and (
        launcher_dir / "package.json"
    ).is_file()
    observed: dict[str, Any] = {
        "vscode_version": vscode_version,
        "vscode_commit": vscode_commit,
        "claude_extension_version": extension_version,
        "extension_js_sha256": extension_sha256,
        "native_command_contract_observed": command_observed,
        "controller_components_present": components,
        "workspace_launcher_files_present": launcher_present,
        "signature_key_id": None,
    }
    missing = []
    if vscode_version is None or vscode_commit is None:
        missing.append("vscode_version_observation")
    if not command_observed:
        missing.append("version_locked_native_command")
    if not all(components.values()):
        missing.append("controller_component_sources")
    if not launcher_present:
        missing.append("workspace_native_launcher")

    verified = _verified_live(
        signed_live_evidence,
        attest_live,
        run_id=expected_run_id,
        task_id=expected_task_id,
        container_id=expected_container_id,
        vscode_version=vscode_version,
        vscode_commit=vscode_commit,
        extension_version=extension_version,
    )
    if verified is None:
        missing.append("signed_live_integration_evidence")
        missing.extend(REQUIRED_LIVE_INTERFACES)
    else:
        observed["signature_key_id"] = verified.signature_key_id

    missing_interfaces = tuple(dict.fromkeys(missing))
    return NativeReadinessReport(
        schema_version=1,
        scope="read_only_native_readiness",
        gate="interfaces-attested" if not missing_interfaces else "blocked",
        observed=observed,
        missing_interfaces=missing_interfaces,
        missing_contracts={name: INTERFACE_CONTRACTS[name] for name in missing_interfaces},
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only native harness readiness audit")
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--extension-dir", type=Path, required=True)
    parser.add_argument("--vscode-version")
    parser.add_argument("--vscode-commit")
    args = parser.parse_args(argv)
    version_output = (
        f"{args.vscode_version}\n{args.vscode_commit}\n"
        if args.vscode_version is not None and args.vscode_commit is not None
        else None
    )
    report = audit_native_readiness(
        repo_root=args.repo_root,
        extension_dir=args.extension_dir,
        vscode_version_output=version_output,
    )
    print(report.to_json())
    return 0 if report.gate == "interfaces-attested" else 1


if __name__ == "__main__":
    raise SystemExit(main())
