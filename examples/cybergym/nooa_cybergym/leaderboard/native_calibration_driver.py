# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Run one disposable, provider-free native schema discovery on SunChaser.

This is a calibration controller, never a benchmark or certification run. It
holds a real Docker boundary while a separate pinned VS Code profile connects
over the SSH relay. The first observed model request receives HTTP 503 and its
tool schemas are recorded without forwarding to a model provider.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import threading
import time
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import docker
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from xeus_cybergym.canonical import canonical_json
from xeus_cybergym.ledger import Ed25519Signer

from .advisory_runtime import _TOOLS as ADVISOR_TOOLS
from .container import start_task_container
from .finalization_runtime import SELECT_FINAL_TOOL
from .host_boundary_runtime import GatewayReply, HostBoundaryRuntime
from .memory_runtime import _SOLVER_TOOLS as MEMORY_TOOLS
from .native_calibration import NativeCalibration
from .native_hook_runtime import NativeHookCollector, native_hook_handler
from .native_launcher import NativeLaunchAuthority, build_launch_manifest, native_launch_handler
from .native_preflight_gate import NativePreflightAdmission
from .native_preflight_protocol import NativePreflightProtocol
from .native_process import frozen_hook_verifier, frozen_parent_verifier
from .network import NetworkPolicy
from .services_runtime import SealedRoutes, _gateway_health
from .synthetic_workspace import SYNTHETIC_README, SYNTHETIC_SUBMIT, _archive
from .tool_services_runtime import _schema as registered_schema
from .vulnerable_runtime import TOOL as VULNERABLE_TOOL

TASK_ID = "synthetic:length-header"
_RELATIVE_TEMPLATE = Path("examples/cybergym/leaderboard/agent-template")
_POLICY = Path("examples/cybergym/leaderboard/config/network-policy.json")
_FIXTURE = Path("examples/cybergym/leaderboard/certification/fixtures/length-header")


def _write_new(path: Path, content: bytes, mode: int = 0o600) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


def _source_files(repo: Path) -> dict[str, bytes]:
    template = repo / _RELATIVE_TEMPLATE
    files = {
        "description.txt": (repo / _FIXTURE / "description.txt").read_bytes(),
        "repo-vul.tar.gz": _archive((repo / _FIXTURE / "vulnerable/parser.c").read_bytes()),
        "README.md": SYNTHETIC_README,
        "submit.sh": SYNTHETIC_SUBMIT,
    }
    for path in sorted(template.rglob("*")):
        if path.is_symlink():
            raise ValueError("calibration template contains symlink")
        if path.is_file():
            files[path.relative_to(template).as_posix()] = path.read_bytes()
    if "CLAUDE.md" not in files:
        raise ValueError("calibration template lacks task contract")
    return files


def _stage(repo: Path, root: Path) -> tuple[bytes, dict[str, str]]:
    root.mkdir(mode=0o755)
    for name in ("output", "src", ".sunchaser"):
        (root / name).mkdir(mode=0o755)
    if os.name == "posix":
        os.chown(root / "output", 1001, 1001)
        (root / "output").chmod(0o700)
    files = _source_files(repo)
    for name, content in files.items():
        target = root.joinpath(*name.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        _write_new(target, content, 0o444)
    hashes = {name: hashlib.sha256(data).hexdigest() for name, data in sorted(files.items())}
    manifest = canonical_json({"schema_version": 1, "scope": "native_schema_discovery_no_provider",
        "task_id": TASK_ID, "file_hashes": hashes})
    return manifest, hashes


def _mcp(request, tools: list[dict], name: str) -> GatewayReply:
    if request.method != "POST" or not 0 < len(request.body) <= 256 * 1024:
        return GatewayReply(403, b'{"error":"calibration MCP denied"}')
    try:
        body = json.loads(request.body)
        if type(body) is not dict or body.get("jsonrpc") != "2.0":
            raise ValueError()
        method, params = body.get("method"), body.get("params") or {}
        if method == "notifications/initialized" and "id" not in body and not params:
            return GatewayReply(202, b"")
        if type(body.get("id")) not in (int, str) or type(params) is not dict:
            raise ValueError()
        if method == "initialize":
            version = params.get("protocolVersion")
            if version not in {"2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"}:
                raise ValueError()
            result = {"protocolVersion": version, "capabilities": {"tools": {}},
                "serverInfo": {"name": name, "version": "calibration-only-1"}}
        elif method == "tools/list" and not params:
            result = {"tools": tools}
        elif method == "ping" and not params:
            result = {}
        else:
            return GatewayReply(403, b'{"error":"calibration permits discovery only"}')
        return GatewayReply(200, canonical_json({"jsonrpc": "2.0", "id": body["id"], "result": result}))
    except (ValueError, TypeError):
        return GatewayReply(400, b'{"error":"invalid calibration MCP request"}')


def _redact(value: str) -> str:
    # Discovery retains native tool schemas verbatim. Reject anything that
    # resembles a token rather than silently changing a frozen schema.
    if re.search(r"(?i)(?:sk-[A-Za-z0-9]{16,}|bearer\s+[A-Za-z0-9._-]{16,})", value):
        return "[redacted calibration input]"
    return value


def run(*, repo: Path, root: Path, native_runtime: Path, public_ssh_key: Path,
        image_id: str, timeout: int, ssh_port: int) -> None:
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", image_id) or timeout < 60 or timeout > 3600:
        raise ValueError("pinned image and bounded calibration timeout required")
    if not 1024 <= ssh_port <= 65535:
        raise ValueError("dedicated loopback SSH port required")
    repo, root = repo.resolve(strict=True), root.resolve(strict=True)
    if root.is_symlink() or any(root.iterdir()):
        raise ValueError("empty private calibration root required")
    root.chmod(0o700)
    task, evidence = root / "workspace", root / "evidence"
    evidence.mkdir(mode=0o700)
    task_manifest, hashes = _stage(repo, task)
    workspace_manifest = evidence / "task-manifest.json"
    _write_new(workspace_manifest, task_manifest, 0o444)
    public_key = public_ssh_key.read_text().strip()
    if not re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/]+={0,2}(?: [^\s\x00-\x1f]+)?", public_key):
        raise ValueError("dedicated SSH public key required")
    private_key = Ed25519PrivateKey.generate()
    pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    trust = root / "native-launch-trust.json"
    _write_new(trust, canonical_json({"calibration": pem}), 0o444)
    runtime = json.loads(native_runtime.read_bytes())
    if (runtime.get("schema_version") != 1
        or runtime.get("vscode_commit") != "07f806f999227108933c2e30515b26eecc1fda74"
        or runtime.get("launcher_vsix_sha256") != "865bba2eeea461b0dfaa71341e563615f12342db77a13d493eae753976b9d778"):
        raise ValueError("calibration native runtime differs from built image")
    binary_sha = runtime["claude_binary_sha256"]
    extension_sha = runtime["claude_extension_sha256"]
    if not all(re.fullmatch(r"[a-f0-9]{64}", value) for value in (binary_sha, extension_sha)):
        raise ValueError("observed native runtime hashes required")
    client = docker.from_env()
    if client.images.get(image_id).id != image_id:
        raise RuntimeError("native image pin changed")
    observed_runtime = client.containers.run(image_id,
        command="/opt/sunchaser/native-runtime.json", entrypoint="/usr/bin/cat",
        network_disabled=True, read_only=True, remove=True)
    if observed_runtime != native_runtime.read_bytes():
        raise RuntimeError("controller native runtime file differs from image bytes")
    policy = NetworkPolicy.load(repo / _POLICY)
    network = client.networks.create("cg-cal-" + uuid4().hex[:12], driver="bridge",
        internal=True, labels={"org.xeus.cybergym.boundary": "task-v1"})
    sealed = SealedRoutes(policy)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    with ExitStack() as stack:
        stack.callback(network.remove)
        boundary = stack.enter_context(HostBoundaryRuntime(
            docker_client=client, network=network, policy=policy,
            handlers=sealed.handlers, audit_path=evidence / "gateway.jsonl"))
        stack.callback(sealed.close)
        class CalibrationSentinel:
            def attest(self, observed_boundary, *, container_id, challenge):
                try:
                    return boundary.attest(observed_boundary, container_id=container_id,
                        challenge=challenge)
                except Exception as error:
                    candidate = client.containers.get(container_id)
                    candidate.reload()
                    logs = candidate.logs(tail=64)
                    _write_new(evidence / "attestation-failure.json", canonical_json({
                        "exception_type": type(error).__name__,
                        "exception_text": _redact(str(error))[:512],
                        "container_status": candidate.status,
                        "log_sha256": hashlib.sha256(logs).hexdigest(),
                        "log_tail": _redact(logs.decode("utf8", errors="replace")[-4096:]),
                    }))
                    raise
        task_container = start_task_container(task, evidence, network.name, public_key,
            expected_network_id=network.id, image=image_id, docker_client=client,
            host_gateway_sentinel=CalibrationSentinel(), native_trust_file=trust,
            ssh_port=ssh_port, startup_timeout_seconds=120)
        container = client.containers.get(task_container.container_id)
        stack.callback(container.remove, force=True)
        stack.callback(task_container.close_relay)
        def observe(*command: str) -> str:
            result = container.exec_run(list(command), user="agent")
            if result.exit_code != 0 or len(result.output) > 4096:
                raise RuntimeError("native container observation failed")
            return result.output.decode().strip()
        uid = int(observe("id", "-u"))
        if uid != 1001:
            raise RuntimeError("native agent UID differs from output volume owner")
        hostname = observe("hostname")
        pid_ns = observe("readlink", "/proc/self/ns/pid")
        mount_ns = observe("readlink", "/proc/self/ns/mnt")
        launch_id = "cal-" + uuid4().hex
        run_id = "calibration-" + uuid4().hex
        manifest = build_launch_manifest(scope="synthetic", run_id=run_id,
            task_id=TASK_ID, launch_id=launch_id, ordinal=1,
            harness_sha256=hashlib.sha256(task_manifest).hexdigest(),
            task_manifest_bytes=task_manifest, file_hashes=hashes,
            container_id=task_container.container_id, hostname=hostname, uid=uid,
            pid_namespace=pid_ns, mount_namespace=mount_ns,
            vscode_version="1.140.0",
            claude_extension_version="2.1.289",
            claude_extension_sha256=extension_sha,
            native_launch_url="http://registered-tool-gateway/native-launch")
        signer = Ed25519Signer(private_key=private_key, key_id="calibration")
        envelope = signer.sign(canonical_json(manifest))
        raw_envelope = canonical_json(envelope.model_dump())
        _write_new(task / ".sunchaser/launch.json", raw_envelope, 0o444)
        authority = NativeLaunchAuthority.from_signed_envelope(
            raw_envelope, {"calibration": private_key.public_key()}, evidence)
        collector = NativeHookCollector(evidence / "native-hooks.sqlite", run_id=run_id,
            task_id=TASK_ID, launch_id=launch_id)
        peer = boundary.peers[task_container.container_ip]
        def preflight_audit(event):
            descriptor = os.open(
                evidence / "preflight-audit.jsonl",
                os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW,
                0o600,
            )
            with os.fdopen(descriptor, "ab") as stream:
                stream.write(canonical_json(event) + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
            return True

        inspected = client.api.inspect_container(container.id)
        process_audit = SimpleNamespace(record=preflight_audit)
        hook_verifier = frozen_hook_verifier(inspect=inspected, peer=peer,
            audit=process_audit)
        parent_verifier = frozen_parent_verifier(inspect=inspected, peer=peer,
            launch_authority=authority,
            audit=process_audit)
        preflight_gate = NativePreflightAdmission(
            container_id=container.id,
            policy=policy,
            workspace_manifest=workspace_manifest,
            evidence_root=evidence,
            observed_role=collector.model_role,
            audit=preflight_audit,
        )
        preflight_protocol = NativePreflightProtocol(
            peer=peer,
            run_id=run_id,
            task_id=TASK_ID,
            launch_id=launch_id,
            policy=policy,
            workspace_root=task,
            workspace_manifest=workspace_manifest,
            evidence_root=evidence,
            gate=preflight_gate,
            verify_parent=parent_verifier,
            verify_child=hook_verifier,
            audit=preflight_audit,
        )
        capture = NativeCalibration(authority=authority, collector=collector, peer=peer,
            image_id=image_id, binary_sha256=binary_sha, evidence_dir=evidence / "capture",
            inspect_container=lambda: client.api.inspect_container(container.id), redact=_redact)
        launch_handler = native_launch_handler(authority, network_id=network.id)
        # Calibration has no provider forwarding or certification authority.
        hook_handler = native_hook_handler(
            collector,
            container_id=container.id,
            network_id=network.id,
            verify_process=hook_verifier,
        )
        catalogs = {
            ("gbrain-read-gateway", "/mcp"): (MEMORY_TOOLS, "gbrain"),
            ("registered-tool-gateway", "/mcp/clangd"): (registered_schema("clangd"), "clangd"),
            ("registered-tool-gateway", "/mcp/documentation"): (registered_schema("documentation"), "documentation"),
            ("registered-tool-gateway", "/advisor/mcp"): (ADVISOR_TOOLS, "advisor"),
            ("registered-tool-gateway", "/mcp/finalizer"): ([SELECT_FINAL_TOOL], "finalizer"),
            ("cybergym-submit", "/mcp"): ([VULNERABLE_TOOL], "vulnerable"),
        }
        def route(request):
            if request.peer != peer:
                return GatewayReply(403, b'{"error":"calibration peer denied"}')
            health = _gateway_health(request)
            if health is not None:
                return health
            if request.endpoint == "model-gateway":
                return capture(request)
            if request.endpoint == "registered-tool-gateway" and request.path in {
                "/native-launch/reserve", "/native-launch/events"}:
                return launch_handler(request)
            if request.endpoint == "registered-tool-gateway" and request.path == "/native-launch/hooks":
                reply = hook_handler(request)
                if reply.status != 200:
                    digest = hashlib.sha256(request.body).hexdigest()
                    target = evidence / f"rejected-hook-{digest}.json"
                    try:
                        _write_new(target, request.body)
                    except FileExistsError:
                        if target.read_bytes() != request.body:
                            raise RuntimeError("rejected hook observation changed") from None
                return reply
            if request.endpoint == "registered-tool-gateway" and request.path in {
                "/native-launch/preflight/begin", "/native-launch/preflight/submit"}:
                return preflight_protocol(request)
            if request.endpoint == "registered-tool-gateway" and request.path == "/native-tools/authorize":
                return GatewayReply(200, b'{"permissionDecision":"deny"}')
            key = (request.endpoint, request.path)
            if key in catalogs:
                tools, name = catalogs[key]
                return _mcp(request, tools, name)
            return GatewayReply(403, b'{"error":"calibration route denied"}')
        sealed.seal(dict.fromkeys(policy.allowed_logical_endpoints, route))
        connection = {"scope": "native_schema_discovery_no_provider", "provider_dispatched": False,
            "image_id": image_id, "container_id": container.id,
            "ssh_host_port": task_container.host_ssh_port,
            "known_hosts": str(evidence / "known_hosts"), "workspace": str(task),
            "run_id": run_id, "launch_id": launch_id}
        _write_new(evidence / "connection.json", canonical_json(connection))
        print(json.dumps(connection, sort_keys=True), flush=True)
        deadline = time.monotonic() + timeout
        while not stop.wait(1):
            if (evidence / "capture/request-000001.json").is_file():
                print(json.dumps({"capture": str(evidence / "capture/request-000001.json"),
                    "hook_summary": collector.summary()}, sort_keys=True), flush=True)
                return
            if boundary.failed.is_set() or time.monotonic() >= deadline:
                raise RuntimeError("native calibration boundary failed or timed out")
        raise RuntimeError("native calibration stopped before first provider request")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--native-runtime", type=Path, required=True)
    parser.add_argument("--public-ssh-key", type=Path, required=True)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--ssh-port", type=int, required=True)
    parser.add_argument("--timeout", type=int, default=1800)
    args = parser.parse_args(argv)
    run(repo=args.repo, root=args.root, native_runtime=args.native_runtime,
        public_ssh_key=args.public_ssh_key,
        image_id=args.image_id, timeout=args.timeout, ssh_port=args.ssh_port)


if __name__ == "__main__":
    main()
