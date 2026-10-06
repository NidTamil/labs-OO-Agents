# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Provider-free observation of the actual native advertised tool schemas.

This handler has no provider transport. Its artifacts are calibration evidence,
never benchmark events or synthetic certification. The signed one-launch
reservation is consumed normally, and a calibration run cannot be reopened.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import threading
from collections.abc import Callable, Mapping
from dataclasses import asdict
from pathlib import Path

from .host_boundary_runtime import AdmittedPeer, GatewayReply, GatewayRequest
from .native_hook_runtime import NativeHookCollector, native_request_identity
from .native_launcher import NativeLaunchAuthority, _canonical

SCOPE = "native_schema_discovery_no_provider"
_SHA = re.compile(r"[a-f0-9]{64}")
_MAX_BODY = 8 * 1024 * 1024
_HEADERS = frozenset(
    {
        "content-type",
        "anthropic-version",
        "anthropic-beta",
        "user-agent",
        "x-claude-code-agent-id",
        "x-claude-code-parent-agent-id",
    }
)


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate calibration JSON field")
        result[key] = value
    return result


def _parse(raw):
    def invalid(_):
        raise ValueError("nonfinite calibration JSON value")

    return json.loads(raw, object_pairs_hook=_object, parse_constant=invalid)


def _write_once(path: Path, value):
    data = _canonical(value)
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    if os.name == "posix":
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


class NativeCalibration:
    """Gateway handler bound to one signed, synthetic, non-reusable launch.

    ``binary_sha256`` must come from the inspected immutable image identity;
    it is a controller pin, not an agent-supplied assertion. Docker inspection
    is repeated for every capture. Hooks are observations, not authorization.
    """

    def __init__(
        self,
        *,
        authority: NativeLaunchAuthority,
        collector: NativeHookCollector,
        peer: AdmittedPeer,
        image_id: str,
        binary_sha256: str,
        evidence_dir: Path,
        inspect_container: Callable[[], Mapping],
        redact: Callable[[str], str],
    ):
        manifest = authority.manifest
        if (
            manifest["scope"] != "synthetic"
            or manifest["task_id"] not in {"synthetic:length-header", "synthetic:chunk-table"}
            or manifest["container_id"] != peer.container_id
            or any(manifest[key] != value for key, value in collector.identity.items())
            or not re.fullmatch(r"sha256:[a-f0-9]{64}", image_id)
            or not _SHA.fullmatch(binary_sha256)
        ):
            raise ValueError("calibration requires exact synthetic native launch identity")
        self.authority, self.collector, self.peer = authority, collector, peer
        self.image_id, self.binary_sha256 = image_id, binary_sha256
        self.inspect_container, self.redact = inspect_container, redact
        self.root = Path(evidence_dir)
        if (
            not self.root.is_absolute()
            or self.root.parent.resolve() != self.root.parent
            or not self.root.parent.is_dir()
        ):
            raise ValueError("private absolute calibration evidence directory required")
        self.root.mkdir(mode=0o700)
        self.lock = threading.Lock()
        self.sequence = 0
        # A controller-visible terminal purpose marker is written before launch.
        # Root driver must never promote/reuse this attempt as a benchmark run.
        marker = {
            "schema_version": 1,
            "scope": SCOPE,
            "provider_dispatched": False,
            "benchmark_eligible": False,
            **collector.identity,
            "manifest_sha256": authority.manifest_sha256,
            "image_id": image_id,
            "binary_sha256": binary_sha256,
            "peer": asdict(peer),
        }
        _write_once(authority.root / (authority.launch_dir.name + "-calibration-only.json"), marker)
        _write_once(self.root / "calibration.json", marker)

    def __call__(self, request: GatewayRequest) -> GatewayReply:
        try:
            with self.lock:
                return self._capture(request)
        except (ValueError, TypeError, KeyError, OSError):
            return GatewayReply(403, b'{"error":"native calibration evidence rejected"}')

    def _capture(self, request):
        if (
            request.peer != self.peer
            or request.endpoint != "model-gateway"
            or request.method != "POST"
            or request.path not in {"/v1/messages", "/v1/messages?beta=true"}
            or not 0 < len(request.body) <= _MAX_BODY
        ):
            raise ValueError("unbound calibration request")
        observed = self.inspect_container()
        if (
            observed.get("Id") != self.peer.container_id
            or observed.get("Image") != self.image_id
            or observed.get("State", {}).get("Running") is not True
        ):
            raise ValueError("calibration container identity changed")
        receipt = self.authority.launch_dir / "launcher-receipt.json"
        if receipt.is_symlink():
            raise ValueError("calibration launch receipt linked")
        self.authority._check_receipt(_parse(receipt.read_bytes()))
        body = _parse(request.body)
        if type(body) is not dict:
            raise ValueError("calibration request must be object")
        identity = native_request_identity(request.headers, body)
        role = self.collector.model_role(identity["session_id"], identity["agent_id"])
        if role not in {"parent", "child"}:
            raise ValueError("calibration native lifecycle not observed")
        tools = body.get("tools")
        if type(tools) is not list or not tools or len(tools) > 1024:
            raise ValueError("calibration tool inventory absent")
        names = set()
        for tool in tools:
            if (
                type(tool) is not dict
                or type(tool.get("name")) is not str
                or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.:-]{0,255}", tool["name"])
                or tool["name"] in names
                or type(tool.get("input_schema")) is not dict
            ):
                raise ValueError("calibration advertised tool schema malformed")
            names.add(tool["name"])
        # Preserve exact native schemas. A redacted schema is not an inventory pin.
        tools_json = _canonical({"tools": tools}).decode()
        if self.redact(tools_json) != tools_json:
            raise ValueError("calibration schema requires redaction")
        payload = {**body, "metadata": {"user_id": identity}}
        headers = {key.lower(): value for key, value in request.headers if key.lower() in _HEADERS}
        safe = _parse(self.redact(_canonical({"payload": payload, "headers": headers}).decode()))
        if safe["payload"].get("tools") != tools:
            raise ValueError("calibration redactor changed tools")
        self.sequence += 1
        artifact = {
            "schema_version": 1,
            "scope": SCOPE,
            "provider_dispatched": False,
            "benchmark_eligible": False,
            **self.collector.identity,
            "image_id": self.image_id,
            "binary_sha256": self.binary_sha256,
            "claude_extension_sha256": self.authority.manifest["claude_extension_sha256"],
            "manifest_sha256": self.authority.manifest_sha256,
            "peer": asdict(self.peer),
            "role": role,
            "native_identity": identity,
            "request_sha256": hashlib.sha256(request.body).hexdigest(),
            "tools": tools,
            **safe,
        }
        _write_once(self.root / f"request-{self.sequence:06d}.json", artifact)
        return GatewayReply(
            503,
            b'{"error":{"type":"api_error","message":"Native schema calibration recorded; provider dispatch disabled. This consumed calibration cannot become a benchmark run."}}',
        )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    inspect = commands.add_parser(
        "inspect", help="Verify and summarize a captured native inventory"
    )
    inspect.add_argument("artifact", type=Path)
    inspect.add_argument("--sha256", required=True)
    args = parser.parse_args(argv)
    raw = args.artifact.read_bytes()
    if hashlib.sha256(raw).hexdigest() != args.sha256:
        raise ValueError("calibration artifact digest mismatch")
    artifact = _parse(raw)
    if artifact.get("scope") != SCOPE or artifact.get("provider_dispatched") is not False:
        raise ValueError("not provider-free native calibration evidence")
    print(
        json.dumps(
            {
                key: artifact[key]
                for key in (
                    "scope",
                    "provider_dispatched",
                    "task_id",
                    "image_id",
                    "binary_sha256",
                    "role",
                )
            }
            | {"tool_names": [tool["name"] for tool in artifact["tools"]]},
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
