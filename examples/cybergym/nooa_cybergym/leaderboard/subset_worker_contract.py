# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Inert identity contract for one future budgeted subset worker.

These values are not launch authority or proof of immutable material. In
particular, an FD number does not prove sealing, and a pinned path does not
prove a read-only runtime. The complete import/resource graph, manager-owned
deadline, process containment, and signature verification remain external.
There is deliberately no worker entrypoint, process creation or file read here.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Literal

from .budgeted_subset_admission import BudgetedSubsetPreview
from .budgeted_subset_runner import PreparedSubsetLaunch
from .subset_dry_run_admission import OFFICIAL_SUBSET_TASK_IDS
from .subset_run_budget import VerifiedSubsetBudget

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_NAME = re.compile(r"[a-z][a-z0-9_.-]{0,127}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_MAX_SEALED = 64 * 1024 * 1024
_MAX_PINNED = 128 * 1024 * 1024 * 1024
# Leave one byte for the terminating NUL under a 4096-byte POSIX path ceiling.
_MAX_RUNTIME_PATH_BYTES = 4095
_MAX_EVIDENCE = 1024 * 1024


class WorkerContractError(ValueError):
    """Worker-boundary identity is malformed or differs from existing state."""


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _digest(value: object) -> bool:
    return type(value) is str and _SHA.fullmatch(value) is not None


def _identity(value: object) -> bool:
    return type(value) is str and _ID.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class MaterialReference:
    """Declared delivery class, not proof of seal or path immutability."""

    name: str
    delivery: Literal["sealed_fd", "pinned_runtime"]
    sha256: str
    size_bytes: int
    fd: int | None = None
    path: str | None = None

    def __post_init__(self) -> None:
        if (
            type(self.name) is not str
            or _NAME.fullmatch(self.name) is None
            or not _digest(self.sha256)
            or type(self.size_bytes) is not int
            or self.size_bytes <= 0
        ):
            raise WorkerContractError("bounded named material reference required")
        if self.delivery == "sealed_fd":
            if (
                type(self.fd) is not int
                or not 3 <= self.fd <= 1_048_576
                or self.path is not None
                or self.size_bytes > _MAX_SEALED
            ):
                raise WorkerContractError("sealed FD material cannot fall back to a path")
        elif self.delivery == "pinned_runtime":
            if (
                self.fd is not None
                or type(self.path) is not str
                or len(self.path) > _MAX_RUNTIME_PATH_BYTES
            ):
                raise WorkerContractError("bounded pinned runtime path required")
            try:
                path_bytes = self.path.encode("utf-8", errors="strict")
            except UnicodeEncodeError as exc:
                raise WorkerContractError("valid UTF-8 pinned runtime path required") from exc
            if (
                len(path_bytes) > _MAX_RUNTIME_PATH_BYTES
                or not self.path.isprintable()
                or not self.path.startswith("/")
                or any(part in {".", ".."} for part in self.path.split("/"))
                or str(PurePosixPath(self.path)) != self.path
                or self.size_bytes > _MAX_PINNED
            ):
                raise WorkerContractError("canonical pinned runtime path required")
        else:
            raise WorkerContractError("explicit material delivery class required")

    def manifest_record(self) -> dict:
        value = {
            "name": self.name,
            "delivery": self.delivery,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }
        if self.delivery == "pinned_runtime":
            value["path"] = self.path
        return value


@dataclass(frozen=True, slots=True)
class BoundSubsetTaskInputs:
    """One preparation's declared inputs, checked against existing authorities.

    ``require_existing_identity`` only compares facts produced by the signed
    state, runtime binding and durable resource store. Its caller must reverify
    those authorities and actual bytes; this object never grants release.
    ``identity_sha256`` excludes ephemeral FD numbers, and cannot prove the
    listed material is the complete dependency graph.
    """

    run_id: str
    epoch: str
    task_id: str
    preparation_id: str
    attempt_id: str
    preparation_started_event_sha256: str
    source_commit: str
    cohort_sha256: str
    admission_sha256: str
    freeze_sha256: str
    certification_sha256: str
    budget_sha256: str
    model_policy_sha256: str
    metering_policy_sha256: str
    launch_config_sha256: str
    material_manifest_sha256: str
    aggregate_deadline_ns: int
    manager_deadline_ns: int
    stop_grace_ns: int
    material: tuple[MaterialReference, ...]

    def __post_init__(self) -> None:
        if (
            not all(
                _identity(item)
                for item in (self.run_id, self.epoch, self.preparation_id, self.attempt_id)
            )
            or self.task_id not in OFFICIAL_SUBSET_TASK_IDS
            or type(self.source_commit) is not str
            or _COMMIT.fullmatch(self.source_commit) is None
            or not all(
                _digest(item)
                for item in (
                    self.preparation_started_event_sha256,
                    self.cohort_sha256,
                    self.admission_sha256,
                    self.freeze_sha256,
                    self.certification_sha256,
                    self.budget_sha256,
                    self.model_policy_sha256,
                    self.metering_policy_sha256,
                    self.launch_config_sha256,
                    self.material_manifest_sha256,
                )
            )
        ):
            raise WorkerContractError("exact subset preparation and signed pin identities required")
        if (
            type(self.aggregate_deadline_ns) is not int
            or type(self.manager_deadline_ns) is not int
            or type(self.stop_grace_ns) is not int
            or self.stop_grace_ns <= 0
            or self.manager_deadline_ns <= 0
            or self.manager_deadline_ns + self.stop_grace_ns > self.aggregate_deadline_ns
        ):
            raise WorkerContractError("manager runtime and stop grace exceed aggregate deadline")
        if (
            type(self.material) is not tuple
            or not 2 <= len(self.material) <= 512
            or any(type(item) is not MaterialReference for item in self.material)
            or tuple(item.name for item in self.material)
            != tuple(sorted({item.name for item in self.material}))
            or len({item.fd for item in self.material if item.fd is not None})
            != sum(item.fd is not None for item in self.material)
            or {item.name: item.delivery for item in self.material}.get("entrypoint") != "sealed_fd"
            or {item.name: item.delivery for item in self.material}.get("interpreter")
            != "pinned_runtime"
            or self.material_manifest_sha256
            != _sha(
                _canonical(
                    {
                        "schema_version": 1,
                        "items": [item.manifest_record() for item in self.material],
                    }
                )
            )
        ):
            raise WorkerContractError("exact classified material manifest differs")

    @property
    def identity_sha256(self) -> str:
        return _sha(
            _canonical(
                {
                    "schema_version": 1,
                    "run_id": self.run_id,
                    "epoch": self.epoch,
                    "task_id": self.task_id,
                    "preparation_id": self.preparation_id,
                    "attempt_id": self.attempt_id,
                    "preparation_started_event_sha256": self.preparation_started_event_sha256,
                    "source_commit": self.source_commit,
                    "cohort_sha256": self.cohort_sha256,
                    "admission_sha256": self.admission_sha256,
                    "freeze_sha256": self.freeze_sha256,
                    "certification_sha256": self.certification_sha256,
                    "budget_sha256": self.budget_sha256,
                    "model_policy_sha256": self.model_policy_sha256,
                    "metering_policy_sha256": self.metering_policy_sha256,
                    "launch_config_sha256": self.launch_config_sha256,
                    "material_manifest_sha256": self.material_manifest_sha256,
                    "aggregate_deadline_ns": self.aggregate_deadline_ns,
                    "manager_deadline_ns": self.manager_deadline_ns,
                    "stop_grace_ns": self.stop_grace_ns,
                }
            )
        )

    def require_existing_identity(
        self,
        *,
        preview: BudgetedSubsetPreview,
        preparation: Mapping,
        resource_snapshot: Mapping,
        signed_launch_config_sha256: str,
        expected_attempt_id: str,
    ) -> None:
        """Compare independent already-verified facts; perform no effects."""
        if (
            type(preview) is not BudgetedSubsetPreview
            or type(preview.budget) is not VerifiedSubsetBudget
            or preview.task_ids != OFFICIAL_SUBSET_TASK_IDS
            or preview.budget.task_ids != OFFICIAL_SUBSET_TASK_IDS
            or preview.budget.run_id != self.run_id
            or preview.budget.epoch != self.epoch
            or preview.budget.max_model_requests != 15000
            or preview.budget.max_elapsed_seconds != 432000
            or preview.budget.max_spend_units != 500000000
            or preview.budget.spend_unit != "usd_micros"
            or self.task_id not in preview.task_ids
            or (
                preview.run_id,
                preview.epoch,
                preview.source_commit,
                preview.cohort_sha256,
                preview.admission_sha256,
                preview.freeze_sha256,
                preview.certification_sha256,
                preview.budget.envelope_sha256,
                preview.budget.model_policy_sha256,
                preview.budget.metering_policy_sha256,
            )
            != (
                self.run_id,
                self.epoch,
                self.source_commit,
                self.cohort_sha256,
                self.admission_sha256,
                self.freeze_sha256,
                self.certification_sha256,
                self.budget_sha256,
                self.model_policy_sha256,
                self.metering_policy_sha256,
            )
            or not isinstance(preparation, Mapping)
            or preparation.get("preparation_id") != self.preparation_id
            or preparation.get("preparation_started_event_sha256")
            != self.preparation_started_event_sha256
            or not isinstance(preparation.get("preparation_started"), Mapping)
            or preparation["preparation_started"].get("type") != "preparation_started"
            or preparation["preparation_started"].get("task_id") != self.task_id
            or preparation["preparation_started"].get("preparation_id") != self.preparation_id
            or preparation.get("prepared") is not None
            or not isinstance(resource_snapshot, Mapping)
            or resource_snapshot.get("run_id") != self.run_id
            or resource_snapshot.get("epoch") != self.epoch
            or resource_snapshot.get("budget_sha256") != self.budget_sha256
            or resource_snapshot.get("deadline_ns") != self.aggregate_deadline_ns
            or type(resource_snapshot.get("started_at_ns")) is not int
            or type(resource_snapshot.get("last_observed_ns")) is not int
            or not 0 < resource_snapshot["started_at_ns"] <= resource_snapshot["last_observed_ns"]
            or resource_snapshot["last_observed_ns"] >= self.manager_deadline_ns
            or resource_snapshot.get("stop", object()) is not None
            or signed_launch_config_sha256 != self.launch_config_sha256
            or expected_attempt_id != self.attempt_id
        ):
            raise WorkerContractError("subset worker inputs differ from existing authorities")


@dataclass(frozen=True, slots=True)
class BoundSubsetTaskOutput:
    """Unattested bytes with exact identity; signature verification is separate."""

    kind: Literal["prepared", "terminal", "driver_stopped"]
    inputs_sha256: str
    task_id: str
    preparation_id: str
    attempt_id: str
    request_id: str
    launch_sha256: str
    payload: bytes
    payload_sha256: str

    def __post_init__(self) -> None:
        if (
            self.kind not in {"prepared", "terminal", "driver_stopped"}
            or not _digest(self.inputs_sha256)
            or not _identity(self.preparation_id)
            or not _identity(self.attempt_id)
            or not _identity(self.request_id)
            or self.task_id not in OFFICIAL_SUBSET_TASK_IDS
            or not _digest(self.launch_sha256)
            or type(self.payload) is not bytes
            or not 0 < len(self.payload) <= _MAX_EVIDENCE
            or not _digest(self.payload_sha256)
            or _sha(self.payload) != self.payload_sha256
        ):
            raise WorkerContractError("bounded exact worker evidence bytes required")

    def require_binding(
        self, inputs: BoundSubsetTaskInputs, prepared: PreparedSubsetLaunch
    ) -> bytes:
        """Check identity only; never assert a receipt or cleanup is authentic."""
        if (
            type(inputs) is not BoundSubsetTaskInputs
            or type(prepared) is not PreparedSubsetLaunch
            or self.inputs_sha256 != inputs.identity_sha256
            or (
                self.task_id,
                self.preparation_id,
                self.attempt_id,
                self.request_id,
                self.launch_sha256,
            )
            != (
                inputs.task_id,
                inputs.preparation_id,
                inputs.attempt_id,
                prepared.request_id,
                prepared.launch_sha256,
            )
            or (
                prepared.task_id,
                prepared.preparation_id,
                prepared.attempt_id,
            )
            != (inputs.task_id, inputs.preparation_id, inputs.attempt_id)
        ):
            raise WorkerContractError("worker evidence differs from exact prepared launch")
        return self.payload
