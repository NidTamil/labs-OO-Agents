# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""One-shot native parent/child probe handshake over the task gateway."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import threading
from pathlib import Path
from types import SimpleNamespace

from .host_boundary_runtime import AdmittedPeer, GatewayReply, GatewayRequest
from .native_preflight_gate import NativePreflightAdmission
from .native_process import NativeSocketProcess
from .network import NetworkPolicy
from .preflight import ProbeExecution, ProbeSpec, _specs, run_preflight


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _unique_json(raw: bytes):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate native preflight field")
            result[key] = value
        return result

    return json.loads(raw, object_pairs_hook=pairs)


class _ExitExecutor:
    mode = "native"

    def __init__(self, exits: dict[str, int], context: str, container_id: str):
        self.exits, self.context, self.container_id = exits, context, container_id

    def run(self, spec: ProbeSpec, container: object) -> ProbeExecution:
        if spec.context != self.context or container.container_id != self.container_id:
            raise ValueError("native probe context changed")
        return ProbeExecution(self.exits[spec.name], b"", b"", self.context, self.container_id)


class NativePreflightProtocol:
    """Issue exact scripts, bind both requests to one PID, then admit a report."""

    def __init__(
        self,
        *,
        peer: AdmittedPeer,
        run_id: str,
        task_id: str,
        launch_id: str,
        policy: NetworkPolicy,
        workspace_root: Path,
        workspace_manifest: Path,
        evidence_root: Path,
        gate: NativePreflightAdmission,
        verify_parent,
        verify_child,
        audit,
        prior_task_ids: tuple[str, ...] = (),
    ):
        if (
            type(peer) is not AdmittedPeer
            or type(policy) is not NetworkPolicy
            or type(gate) is not NativePreflightAdmission
            or any(type(value) is not str or not value for value in (run_id, task_id, launch_id))
            or not all(callable(value) for value in (verify_parent, verify_child, audit))
            or type(prior_task_ids) is not tuple
            or any(
                type(item) is not str or re.fullmatch(r"[A-Za-z0-9_-]+", item) is None
                for item in prior_task_ids
            )
        ):
            raise ValueError("trusted native preflight protocol inputs required")
        self.peer, self.identity = peer, (run_id, task_id, launch_id)
        self.policy, self.gate = policy, gate
        self.workspace_root = Path(workspace_root)
        self.workspace_manifest = Path(workspace_manifest)
        self.evidence_root = Path(evidence_root)
        self.verify_parent, self.verify_child, self.audit = verify_parent, verify_child, audit
        self.prior_task_ids = prior_task_ids
        self._lock = threading.RLock()
        self._pending: dict[tuple[str, str], tuple[str, int, tuple[ProbeSpec, ...]]] = {}
        self._used: set[tuple[str, str]] = set()
        self._passed: set[tuple[str, str]] = set()

    def _identity(self, body: dict) -> tuple[str, str]:
        if (
            type(body) is not dict
            or any(
                body.get(name) != value
                for name, value in zip(
                    ("run_id", "task_id", "launch_id"), self.identity, strict=True
                )
            )
            or type(body.get("schema_version")) is not int
            or body["schema_version"] != 1
            or body.get("context") not in {"parent", "child"}
        ):
            raise ValueError("native preflight launch identity differs")
        context, agent = body["context"], body.get("agent_id")
        if context == "parent":
            if agent is not None:
                raise ValueError("native parent cannot claim child identity")
            return ("parent", "")
        if (
            type(agent) is not str
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,255}", agent) is None
        ):
            raise ValueError("native child identity malformed")
        return ("child", agent)

    def __call__(self, request: GatewayRequest) -> GatewayReply:
        if (
            type(request) is not GatewayRequest
            or request.peer != self.peer
            or request.endpoint != "registered-tool-gateway"
            or request.method != "POST"
            or request.path
            not in {"/native-launch/preflight/begin", "/native-launch/preflight/submit"}
            or type(request.body) is not bytes
            or not 0 < len(request.body) <= 256 * 1024
        ):
            return GatewayReply(403, b'{"error":"native preflight denied"}')
        try:
            body = _unique_json(request.body)
            key = self._identity(body)
            if request.path.endswith("/begin"):
                if set(body) != {
                    "schema_version",
                    "run_id",
                    "task_id",
                    "launch_id",
                    "context",
                    "agent_id",
                }:
                    raise ValueError("native preflight begin fields differ")
                return self._begin(request, key)
            if set(body) != {
                "schema_version",
                "run_id",
                "task_id",
                "launch_id",
                "context",
                "agent_id",
                "nonce",
                "results",
            }:
                raise ValueError("native preflight submit fields differ")
            return self._submit(request, key, body)
        except (ValueError, TypeError, KeyError, json.JSONDecodeError):
            return GatewayReply(403, b'{"error":"native preflight denied"}')
        except Exception:
            return GatewayReply(503, b'{"error":"native preflight unavailable"}')

    def _observe(self, request: GatewayRequest, context: str) -> NativeSocketProcess:
        observed = (self.verify_parent if context == "parent" else self.verify_child)(request)
        if type(observed) is not NativeSocketProcess:
            raise ValueError("native preflight process provenance unavailable")
        return observed

    def _begin(self, request: GatewayRequest, key: tuple[str, str]) -> GatewayReply:
        context, _agent = key
        with self._lock:
            if (
                key in self._pending
                or key in self._used
                or (context == "child" and ("parent", "") not in self._passed)
            ):
                raise ValueError("native preflight already issued or parent absent")
            observed = self._observe(request, context)
            specs = _specs(self.policy, context, self.prior_task_ids)
            nonce = secrets.token_hex(16)
            self.audit(
                {
                    "event": "native_preflight_issued",
                    "context": context,
                    "agent_id": key[1] or None,
                    "host_pid": observed.host_pid,
                    "nonce_sha256": hashlib.sha256(nonce.encode()).hexdigest(),
                }
            )
            self._pending[key] = (nonce, observed.host_pid, specs)
            return GatewayReply(
                200,
                _canonical(
                    {
                        "nonce": nonce,
                        "probes": [{"name": spec.name, "command": spec.command} for spec in specs],
                    }
                ),
            )

    def _submit(self, request: GatewayRequest, key: tuple[str, str], body: dict) -> GatewayReply:
        context, agent = key
        with self._lock:
            pending = self._pending.get(key)
            if pending is None or body["nonce"] != pending[0]:
                raise ValueError("native preflight nonce absent or changed")
            del self._pending[key]
            self._used.add(key)
            observed = self._observe(request, context)
            if observed.host_pid != pending[1]:
                raise ValueError("native preflight process changed")
            results, specs = body["results"], pending[2]
            if (
                type(results) is not list
                or len(results) != len(specs)
                or any(
                    type(item) is not dict
                    or set(item) != {"name", "exit_code"}
                    or item["name"] != spec.name
                    or type(item["exit_code"]) is not int
                    or not 0 <= item["exit_code"] <= 255
                    for item, spec in zip(results, specs, strict=True)
                )
            ):
                raise ValueError("native preflight result inventory malformed")
            exits = {item["name"]: item["exit_code"] for item in results}
            report = run_preflight(
                container=SimpleNamespace(container_id=self.peer.container_id),
                workspace_manifest=self.workspace_manifest,
                workspace_root=self.workspace_root,
                policy=self.policy,
                executor=_ExitExecutor(exits, context, self.peer.container_id),
                evidence_dir=self.evidence_root / "preflight" / context / (agent or "parent"),
                prior_task_ids=self.prior_task_ids,
                contexts=(context,),
            )
            digest = hashlib.sha256(report.evidence_path.read_bytes()).hexdigest()
            self.audit(
                {
                    "event": "native_preflight_settled",
                    "context": context,
                    "agent_id": agent or None,
                    "passed": report.passed,
                    "report_sha256": digest,
                }
            )
            if report.passed:
                self.gate.record(report, agent_id=agent or None)
                self._passed.add(key)
            return GatewayReply(
                200,
                _canonical(
                    {
                        "passed": report.passed,
                        "report_sha256": digest,
                    }
                ),
            )
