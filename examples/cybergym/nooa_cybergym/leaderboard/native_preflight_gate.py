# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Controller admission gate for exact-context native preflight reports."""

from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import asdict
from pathlib import Path

from .network import NetworkPolicy
from .preflight import PreflightReport, _specs


class NativePreflightAdmission:
    """Deny first parent/child model admission until its report is durable."""

    def __init__(
        self,
        *,
        container_id: str,
        policy: NetworkPolicy,
        workspace_manifest: Path,
        evidence_root: Path,
        observed_role,
        audit,
        prior_task_ids: tuple[str, ...] = (),
    ):
        workspace_manifest = Path(workspace_manifest)
        evidence_root = Path(evidence_root)
        if (
            type(container_id) is not str
            or re.fullmatch(r"[a-f0-9]{64}", container_id) is None
            or type(policy) is not NetworkPolicy
            or not workspace_manifest.is_file()
            or workspace_manifest.is_symlink()
            or not evidence_root.is_dir()
            or evidence_root.is_symlink()
            or not callable(observed_role)
            or not callable(audit)
            or type(prior_task_ids) is not tuple
            or any(type(item) is not str for item in prior_task_ids)
        ):
            raise ValueError("trusted native preflight gate inputs required")
        self.container_id = container_id
        self.policy = policy
        self.manifest_sha256 = hashlib.sha256(workspace_manifest.read_bytes()).hexdigest()
        self.evidence_root = evidence_root.resolve()
        self.observed_role = observed_role
        self.audit = audit
        self.prior_task_ids = prior_task_ids
        self._lock = threading.RLock()
        self._parent = False
        self._children: set[str] = set()
        self._used_reports: set[str] = set()

    def record(self, report: PreflightReport, *, agent_id: str | None = None) -> None:
        context = "child" if agent_id is not None else "parent"
        if agent_id is not None and (
            type(agent_id) is not str
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,255}", agent_id) is None
        ):
            raise ValueError("native child identity is malformed")
        if (
            type(report) is not PreflightReport
            or not report.passed
            or report.failures
            or report.contexts != (context,)
            or report.execution_mode != "native"
            or report.container_id != self.container_id
            or report.workspace_manifest_sha256 != self.manifest_sha256
            or report.policy_sha256 != self.policy.digest
        ):
            raise ValueError("matching native preflight pass required")
        expected = _specs(self.policy, context, self.prior_task_ids)
        if len(report.probes) != len(expected) or any(
            (
                record.name,
                record.context,
                record.command,
                record.exit_code,
                record.passed,
                record.observed_context,
                record.observed_container_id,
            )
            != (spec.name, context, spec.command, 0, True, context, self.container_id)
            for record, spec in zip(report.probes, expected, strict=True)
        ):
            raise ValueError("native preflight probe inventory or origin differs")
        path = report.evidence_path
        if (
            not isinstance(path, Path)
            or path.is_symlink()
            or not path.is_file()
            or path.resolve() != path
            or not path.is_relative_to(self.evidence_root)
            or path.name != f"preflight-{context}-report.json"
        ):
            raise ValueError("native preflight evidence path is untrusted")
        payload = asdict(report)
        payload["evidence_path"] = str(path)
        expected_bytes = (
            json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
        ).encode()
        if path.read_bytes() != expected_bytes:
            raise ValueError("native preflight evidence differs from report")
        digest = hashlib.sha256(expected_bytes).hexdigest()
        with self._lock:
            if (
                digest in self._used_reports
                or (agent_id is None and self._parent)
                or (agent_id is not None and agent_id in self._children)
            ):
                raise ValueError("duplicate native preflight admission")
            self.audit(
                {
                    "event": "native_preflight_admitted",
                    "context": context,
                    "agent_id": agent_id,
                    "report_sha256": digest,
                    "container_id": self.container_id,
                }
            )
            self._used_reports.add(digest)
            if agent_id is None:
                self._parent = True
            else:
                self._children.add(agent_id)

    def model_role(self, session_id: str, agent_id: str | None) -> str | None:
        with self._lock:
            if agent_id is None and not self._parent:
                return None
            if agent_id is not None and agent_id not in self._children:
                return None
            return self.observed_role(session_id, agent_id)
