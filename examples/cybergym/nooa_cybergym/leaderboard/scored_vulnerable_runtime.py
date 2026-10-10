# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Audited vulnerable-only native run_test for either official scored family."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import threading
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .deepseek import DeepSeekController
from .host_boundary_runtime import AdmittedPeer
from .native_tool_runtime import NativeToolCall
from .official_image_runner import run_official_image
from .vulnerable_runtime import NATIVE_NAME

_TASK = re.compile(r"(?:arvo|oss-fuzz):[0-9]+\Z")
_IMAGE = re.compile(r"sha256:[a-f0-9]{64}\Z")
_HASH = re.compile(r"[a-f0-9]{64}\Z")


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


@dataclass(frozen=True)
class OfficialCohortRecipe:
    task_id: str
    image_id: str

    def __post_init__(self):
        if (
            type(self.task_id) is not str
            or _TASK.fullmatch(self.task_id) is None
            or type(self.image_id) is not str
            or _IMAGE.fullmatch(self.image_id) is None
        ):
            raise ValueError("pinned vulnerable scored image and task family required")


class OfficialCohortVulnerableRunner:
    """Expose only the vulnerable image while the native parent is active."""

    def __init__(
        self,
        *,
        docker_client,
        peer: AdmittedPeer,
        task_id: str,
        attempt_id: str,
        recipe: OfficialCohortRecipe,
        output: Path,
        evidence: Path,
        controller: DeepSeekController,
        observe_failure,
        snapshot_candidate,
        audit,
    ):
        if (
            type(peer) is not AdmittedPeer
            or type(recipe) is not OfficialCohortRecipe
            or recipe.task_id != task_id
            or not isinstance(controller, DeepSeekController)
            or not callable(snapshot_candidate)
            or not callable(observe_failure)
        ):
            raise ValueError("observed scored task identity and pinned vulnerable image required")
        self.docker_client, self.peer = docker_client, peer
        self.task_id, self.attempt_id, self.recipe = task_id, attempt_id, recipe
        self.output, self.evidence = Path(output), Path(evidence)
        self.controller, self.observe_failure = controller, observe_failure
        self.snapshot_candidate, self.audit = snapshot_candidate, audit
        self._lock = threading.Lock()

    def _record(self, event):
        if self.audit.record(event) is not True:
            raise RuntimeError("vulnerable execution audit acknowledgment unavailable")

    def run(self, call: NativeToolCall):
        if self.recipe.task_id != self.task_id:
            raise RuntimeError("vulnerable image task binding changed")
        if (
            type(call) is not NativeToolCall
            or call.task_id != self.task_id
            or call.attempt_id != self.attempt_id
            or call.role != "parent"
            or call.agent_id is not None
            or call.name != NATIVE_NAME
            or set(call.arguments) != {"candidate_path"}
        ):
            raise PermissionError("exact parent vulnerable-test call required")
        path = call.arguments["candidate_path"]
        if (
            type(path) is not str
            or not path.startswith("/workspace/output/")
            or str(PurePosixPath(path)) != path
            or ".." in path.split("/")
            or "\\" in path
            or len(path) > 4096
        ):
            raise PermissionError("candidate must remain under task output")
        with self._lock:
            candidate = self.snapshot_candidate(path)
            if (
                type(candidate) is not dict
                or candidate.get("candidate_path") != path
                or type(candidate.get("sha256")) is not str
                or _HASH.fullmatch(candidate["sha256"]) is None
                or type(candidate.get("byte_length")) is not int
                or candidate["byte_length"] <= 0
            ):
                raise RuntimeError("controller candidate snapshot unavailable")
            identity = {"sha256": candidate["sha256"], "byte_length": candidate["byte_length"]}
            self._record(
                {"event": "vulnerable_test_started", "tool_id": call.tool_id, "candidate": identity}
            )
            snapshot_dir = self.evidence / "vulnerable-scored-snapshots"
            snapshot_dir.mkdir(mode=0o700, exist_ok=True)
            observed = run_official_image(
                self.docker_client,
                task_id=self.task_id,
                image_id=self.recipe.image_id,
                candidate=self.output.joinpath(*path.removeprefix("/workspace/output/").split("/")),
                snapshot_dir=snapshot_dir,
                expected_sha256=identity["sha256"],
            )
            after = self.snapshot_candidate(path)
            unchanged = after == candidate
            full = {
                "container_id": self.peer.container_id,
                "tool_id": call.tool_id,
                "candidate": identity,
                "test": observed,
                "candidate_unchanged": unchanged,
            }
            evidence_digest = hashlib.sha256(_canonical(full)).hexdigest()
            self._record(
                {"event": "vulnerable_test_observed", "evidence_sha256": evidence_digest, **full}
            )
            if not unchanged:
                raise RuntimeError("candidate changed during vulnerable test")
            failed = observed["raw_exit_code"] not in {0, 300}
            if failed:
                failure = self.controller.admit_failure(
                    task_id=self.task_id,
                    attempt_id=self.attempt_id,
                    source="vulnerable_test",
                    exit_code=observed["raw_exit_code"],
                    evidence_digest=evidence_digest,
                )
                self.observe_failure(failure)
            visible_test = {
                "raw_exit_code": observed["raw_exit_code"],
                "output_sha256": observed["output_sha256"],
                "output_bytes": observed["output_bytes"],
                "output": base64.b64decode(observed["output_prefix_base64"], validate=True).decode(
                    "utf8", "replace"
                ),
                "output_truncated": observed["output_truncated"],
            }
            return {
                "container_id": self.peer.container_id,
                "tool_id": call.tool_id,
                "candidate": identity,
                "test": visible_test,
                "candidate_unchanged": True,
                "evidence_sha256": evidence_digest,
                "debug_available": failed,
            }
