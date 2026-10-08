# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Frozen operation inventory and controller-side authorization gate.

This is disclosure and authorization metadata, not a sandbox or MCP proxy.
Only audited adapters may dispatch tools. Each adapter must derive a request
from the actual inputs, enforce paths (including symlinks), effects, providers,
models and exact routes, and inspect redirects/results for answer leakage.
Never expose this gate, its trusted role binding, or its audit sink to generated
code; the controller selects roles from authenticated execution context.
Approval of an adapter does not authorize arbitrary host MCP pass-through.
No live capabilities are pre-approved by this module's synthetic tests.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, fields
from enum import Enum, StrEnum
from pathlib import Path, PurePosixPath
from typing import Protocol


class Status(StrEnum):
    APPROVED = "approved"
    DENIED = "denied"
    PENDING = "pending"


class ControlLabel(StrEnum):
    OFFICIAL_REQUIREMENT = "official_requirement"
    LEAKAGE_BOUNDARY = "leakage_boundary"
    PERFORMANCE_OPTIMISATION = "performance_optimisation"
    OPTIONAL = "optional"


class Role(StrEnum):
    CONTROLLER = "controller"
    PARENT = "parent"
    CHILD = "child"


class Effect(StrEnum):
    READ = "read"
    WRITE = "write"
    NETWORK = "network"
    MODEL = "model"
    HOST = "host"
    CREDENTIAL = "credential"


class DenialReason(StrEnum):
    ANSWER_LEAKAGE = "answer_leakage"
    CREDENTIAL_EXPOSURE = "credential_exposure"
    HOST_BOUNDARY = "host_boundary"


class WriteDomain(StrEnum):
    TASK_WORKSPACE = "task_workspace"
    CONTROLLER_AUTHORITY = "controller_authority"


def _text(value: str, field: str) -> None:
    if type(value) is not str or not value.strip() or any(ord(c) < 32 for c in value):
        raise ValueError(f"{field} must be a nonempty string without control characters")


def _digest(value: str, field: str) -> None:
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")


def _enum(value: Enum, kind: type[Enum], field: str) -> None:
    if type(value) is not kind:
        raise TypeError(f"{field} must be a {kind.__name__}")


def _tuple(values: tuple, field: str, kind: type = str) -> None:
    if type(values) is not tuple:
        raise TypeError(f"{field} must be an immutable tuple")
    for value in values:
        if kind is str:
            _text(value, field)
        else:
            _enum(value, kind, field)
    if len(set(values)) != len(values):
        raise ValueError(f"{field} contains duplicates")


def _path(value: str) -> None:
    _text(value, "path")
    if (
        not value.startswith("/")
        or value.startswith("//")
        or value == "/"
        or "\\" in value
        or str(PurePosixPath(value)) != value
        or ".." in value.split("/")
    ):
        raise ValueError("paths must be normalized absolute POSIX paths below a scoped root")


@dataclass(frozen=True, slots=True)
class ToolIdentity:
    service_id: str
    service_version: str
    service_digest: str
    tool_id: str
    tool_version: str
    tool_digest: str
    adapter_id: str
    adapter_version: str
    adapter_digest: str

    def __post_init__(self) -> None:
        for field in (
            "service_id",
            "service_version",
            "tool_id",
            "tool_version",
            "adapter_id",
            "adapter_version",
        ):
            _text(getattr(self, field), field)
        for field in ("service_digest", "tool_digest", "adapter_digest"):
            _digest(getattr(self, field), field)


@dataclass(frozen=True, slots=True)
class Capability:
    capability_id: str
    identity: ToolIdentity
    operation: str
    status: Status
    control_label: ControlLabel
    purpose: str
    roles: tuple[Role, ...]
    effects: tuple[Effect, ...]
    data_scopes: tuple[str, ...]
    path_scopes: tuple[str, ...]
    routes: tuple[str, ...]
    provider_ids: tuple[str, ...]
    model_ids: tuple[str, ...]
    credential_refs: tuple[str, ...]
    accounting: str
    log_schema: str
    evidence_refs: tuple[str, ...]
    certification_digest: str
    denial_reason: DenialReason | None = None
    write_domain: WriteDomain | None = None

    def __post_init__(self) -> None:
        for field in ("capability_id", "operation", "purpose", "accounting", "log_schema"):
            _text(getattr(self, field), field)
        if type(self.identity) is not ToolIdentity:
            raise TypeError("identity must be an immutable ToolIdentity")
        _enum(self.status, Status, "status")
        _enum(self.control_label, ControlLabel, "control_label")
        _tuple(self.roles, "roles", Role)
        _tuple(self.effects, "effects", Effect)
        for field in (
            "data_scopes",
            "path_scopes",
            "routes",
            "provider_ids",
            "model_ids",
            "credential_refs",
            "evidence_refs",
        ):
            _tuple(getattr(self, field), field)
        for path in self.path_scopes:
            _path(path)
        if not self.roles or not self.effects or not self.data_scopes:
            raise ValueError("roles, effects, and data_scopes must be explicit")
        if self.denial_reason is not None:
            _enum(self.denial_reason, DenialReason, "denial_reason")
        if self.write_domain is not None:
            _enum(self.write_domain, WriteDomain, "write_domain")
            if Effect.WRITE not in self.effects:
                raise ValueError("write_domain requires a write effect")
        if self.status is Status.DENIED:
            if self.denial_reason is None or not self.evidence_refs:
                raise ValueError("denied operations require an evidenced boundary reason")
        elif self.denial_reason is not None:
            raise ValueError("only denied operations may have a denial_reason")
        if self.certification_digest:
            _digest(self.certification_digest, "certification_digest")
        elif type(self.certification_digest) is not str:
            raise TypeError("certification_digest must be a string")
        if self.status is Status.APPROVED:
            if not self.evidence_refs or not self.certification_digest:
                raise ValueError("approved operations require audit and certification evidence")
            if set(self.effects) & {Effect.HOST, Effect.CREDENTIAL} and self.roles != (
                Role.CONTROLLER,
            ):
                raise ValueError("credentials and host access are controller-only")
            if Effect.WRITE in self.effects:
                if self.write_domain is None:
                    raise ValueError("approved writes require an explicit write domain")
                if Role.CHILD in self.roles:
                    raise ValueError("children are read-only")
                if self.write_domain is WriteDomain.CONTROLLER_AUTHORITY:
                    if self.roles != (Role.CONTROLLER,):
                        raise ValueError("authoritative writes are controller-only")
                elif not self.path_scopes:
                    raise ValueError("task workspace writes require explicit path scopes")


@dataclass(frozen=True, slots=True)
class CapabilityRegistry:
    entries: tuple[Capability, ...]

    def __post_init__(self) -> None:
        if type(self.entries) is not tuple or any(type(e) is not Capability for e in self.entries):
            raise TypeError("entries must be a tuple of immutable Capabilities")
        ids = [entry.capability_id for entry in self.entries]
        if len(set(ids)) != len(ids):
            raise ValueError(
                "duplicate capability IDs are ambiguous, including identical duplicates"
            )
        object.__setattr__(
            self, "entries", tuple(sorted(self.entries, key=lambda e: e.capability_id))
        )

    @property
    def manifest_json(self) -> str:
        """Registry-specific canonical JSON; does not replace Xeus signing/ledger."""
        return json.dumps(
            {"schema_version": 1, "capabilities": [asdict(e) for e in self.entries]},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.manifest_json.encode("utf-8")).hexdigest()

    @classmethod
    def load(cls, path: Path, *, expected_sha256: str) -> CapabilityRegistry:
        """Load only the exact canonical, digest-pinned audited inventory."""

        _digest(expected_sha256, "expected_sha256")
        path = Path(path)
        if path.is_symlink() or not path.is_file():
            raise ValueError("capability registry must be a regular file")
        data = path.read_bytes()
        if len(data) > 2_097_152:
            raise ValueError("capability registry exceeds frozen size limit")

        def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate capability manifest key")
                result[key] = value
            return result

        try:
            raw = json.loads(data.decode("utf-8"), object_pairs_hook=unique_object)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("capability registry is not valid UTF-8 JSON") from error
        if (
            type(raw) is not dict
            or set(raw) != {"schema_version", "capabilities"}
            or type(raw["schema_version"]) is not int
            or raw["schema_version"] != 1
            or type(raw["capabilities"]) is not list
            or len(raw["capabilities"]) > 1024
        ):
            raise ValueError("capability registry schema is invalid")
        entry_fields = {item.name for item in fields(Capability)}
        identity_fields = {item.name for item in fields(ToolIdentity)}
        tuple_fields = {
            "roles",
            "effects",
            "data_scopes",
            "path_scopes",
            "routes",
            "provider_ids",
            "model_ids",
            "credential_refs",
            "evidence_refs",
        }
        entries = []
        for row in raw["capabilities"]:
            if type(row) is not dict or set(row) != entry_fields:
                raise ValueError("capability entry schema is invalid")
            identity = row["identity"]
            if type(identity) is not dict or set(identity) != identity_fields:
                raise ValueError("capability tool identity schema is invalid")
            values = dict(row)
            values["identity"] = ToolIdentity(**identity)
            for name in tuple_fields:
                if type(values[name]) is not list:
                    raise ValueError(f"{name} must be a manifest array")
                values[name] = tuple(values[name])
            values["roles"] = tuple(Role(value) for value in values["roles"])
            values["effects"] = tuple(Effect(value) for value in values["effects"])
            values["status"] = Status(values["status"])
            values["control_label"] = ControlLabel(values["control_label"])
            if values["denial_reason"] is not None:
                values["denial_reason"] = DenialReason(values["denial_reason"])
            if values["write_domain"] is not None:
                values["write_domain"] = WriteDomain(values["write_domain"])
            entries.append(Capability(**values))
        registry = cls(tuple(entries))
        if data != registry.manifest_json.encode("utf-8"):
            raise ValueError("capability registry is not canonical")
        if registry.digest != expected_sha256:
            raise ValueError("capability registry differs from frozen digest")
        return registry


@dataclass(frozen=True, slots=True)
class CapabilityRequest:
    """Trusted adapter's declaration of actual call inputs, never a role grant."""

    capability_id: str
    tool_id: str
    identity: ToolIdentity
    operation: str
    adapter_digest: str
    effects: tuple[Effect, ...]
    data_scopes: tuple[str, ...]
    paths: tuple[str, ...]
    routes: tuple[str, ...]
    provider_ids: tuple[str, ...]
    model_ids: tuple[str, ...]
    task_id: str
    attempt_id: str
    request_id: str
    invocation_id: str | None = None

    def __post_init__(self) -> None:
        for field in (
            "capability_id",
            "tool_id",
            "operation",
            "task_id",
            "attempt_id",
            "request_id",
        ):
            _text(getattr(self, field), field)
        if self.invocation_id is not None:
            _text(self.invocation_id, "invocation_id")
        if type(self.identity) is not ToolIdentity:
            raise TypeError("identity must be the adapter's observed immutable ToolIdentity")
        _digest(self.adapter_digest, "adapter_digest")
        _tuple(self.effects, "effects", Effect)
        if not self.effects:
            raise ValueError("actual effects must be declared")
        for field in ("data_scopes", "paths", "routes", "provider_ids", "model_ids"):
            _tuple(getattr(self, field), field)
        if not self.data_scopes:
            raise ValueError("actual data scopes must be declared")
        for path in self.paths:
            _path(path)


@dataclass(frozen=True, slots=True)
class AuthorizationEvent:
    registry_digest: str
    capability_id: str
    tool_id: str
    operation: str
    role: Role
    task_id: str
    attempt_id: str
    request_id: str
    disposition: str
    reason: str
    request: CapabilityRequest


@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    allowed: bool
    reason: str


class AuditSink(Protocol):
    def record(self, event: AuthorizationEvent) -> bool:
        """Persist to controller-owned evidence; return True only on acknowledgement."""


class AuditFailure(RuntimeError):
    """No permission is returned if controller evidence cannot acknowledge it."""


@dataclass(frozen=True, slots=True)
class CapabilityAuthorizer:
    registry: CapabilityRegistry
    trusted_role: Role
    audit_sink: AuditSink

    def __post_init__(self) -> None:
        if type(self.registry) is not CapabilityRegistry:
            raise TypeError("registry must be an immutable CapabilityRegistry")
        _enum(self.trusted_role, Role, "trusted_role")
        if not callable(getattr(self.audit_sink, "record", None)):
            raise TypeError("a controller-owned audit sink is required")

    def authorize(self, request: CapabilityRequest) -> AuthorizationDecision:
        if type(request) is not CapabilityRequest:
            raise TypeError("request must be a validated CapabilityRequest")
        reason = self._reason(request)
        allowed = reason == "approved audited operation within declared scope"
        event = AuthorizationEvent(
            self.registry.digest,
            request.capability_id,
            request.tool_id,
            request.operation,
            self.trusted_role,
            request.task_id,
            request.attempt_id,
            request.request_id,
            "allowed" if allowed else "denied",
            reason,
            request,
        )
        try:
            if self.audit_sink.record(event) is not True:
                raise AuditFailure("controller audit did not acknowledge authorization")
        except Exception:
            raise AuditFailure(
                "authorization failed closed: controller audit unavailable"
            ) from None
        return AuthorizationDecision(allowed, reason)

    def _reason(self, request: CapabilityRequest) -> str:
        entry = next(
            (e for e in self.registry.entries if e.capability_id == request.capability_id), None
        )
        if entry is None:
            return "unknown capability: audit and new certified registry required"
        if entry.status is Status.DENIED:
            return f"denied: {entry.denial_reason.value}; evidence={','.join(entry.evidence_refs)}"
        if entry.status is Status.PENDING:
            return "pending capability audit: unavailable"
        if self.trusted_role not in entry.roles:
            return "role is outside approved scope"
        if (
            request.tool_id != entry.identity.tool_id
            or request.operation != entry.operation
            or request.identity != entry.identity
            or request.adapter_digest != entry.identity.adapter_digest
        ):
            return "tool, operation, or adapter identity differs from audited entry"
        for field in ("effects", "data_scopes", "routes", "provider_ids", "model_ids"):
            if not set(getattr(request, field)) <= set(getattr(entry, field)):
                return f"{field} outside approved scope"
        if entry.path_scopes and not request.paths:
            return "paths required for scoped filesystem operation"
        for path in request.paths:
            if not any(path == root or path.startswith(root + "/") for root in entry.path_scopes):
                return "path outside approved scope"
        return "approved audited operation within declared scope"
