# SPDX-License-Identifier: Apache-2.0
"""Inert handle-custody contract for a future owned Windows SSH launcher.

This module has no Win32 backend, process creation, or transport integration.
The backend must independently prove the reported handle, path, sharing and
Job Object facts on Windows before this contract can be used operationally.
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass
from pathlib import PureWindowsPath
from typing import Protocol

_ROLES = frozenset(
    {"transport_config", "ssh_executable", "ssh_config", "tailscale_executable", "known_hosts"}
)
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")
_APPROVED_KNOWN_HOSTS_PATH = r"D:\GLM\secrets\cybergym-tailscale-v25i-known_hosts"
_APPROVED_KNOWN_HOSTS_SHA256 = "a1c2ebbffa50d9ea4e495a44b85a0199cc0f5a4ee2e387431148eb6a5dd056fc"


@dataclass(frozen=True)
class PinnedRouteFile:
    role: str
    path: str
    sha256: str


@dataclass(frozen=True)
class NodeObservation:
    """Facts a platform backend must derive from still-held OS handles."""

    path: str
    kind: str
    held_id: str
    path_id: str
    lock_open: bool
    blocks_write: bool
    blocks_delete: bool
    reparse: bool
    raw: bytes | None


@dataclass(frozen=True)
class RouteLeaseObservation:
    """Backend-observed exclusive identity for one preparation's held handles."""

    preparation_id: str
    lease_id: str
    lease_open: bool
    exclusive_owner: bool


@dataclass(frozen=True)
class ProcessCreationObservation:
    """Independent creation proof tied to a verified hold and held image."""

    preparation_id: str
    lease_id: str
    creation_guard_id: str
    job_id: str
    process_identity: str
    image_file_id: str
    created_after_verified_hold: bool


@dataclass(frozen=True)
class OwnedJobObservation:
    """Facts a platform backend must derive from one preparation's Job."""

    preparation_id: str
    job_id: str
    process_identity: str
    created_suspended: bool
    assigned_before_resume: bool
    breakaway_disabled: bool
    kill_on_job_close: bool
    job_handle_open: bool
    process_terminated: bool
    enumeration_complete: bool
    members_empty: bool
    member_ids: tuple[str, ...]


class RouteCustodyBackend(Protocol):
    """Platform seam; no production implementation is provided here."""

    def acquire(self, preparation_id: str, paths: tuple[str, ...]) -> object: ...

    def observe(self, lease: object) -> dict[str, NodeObservation]: ...

    def observe_lease(self, lease: object) -> RouteLeaseObservation: ...

    def arm_creation(self, lease: object) -> str: ...

    def observe_creation(
        self, lease: object, job: OwnedJobObservation
    ) -> ProcessCreationObservation: ...

    def observe_job(self, job: OwnedJobObservation) -> OwnedJobObservation: ...

    def resume_assigned(self, lease: object, job: OwnedJobObservation) -> None: ...

    def release(self, lease: object) -> None: ...


class VerifiedRouteCustody:
    """Retain checked route handles until an exact owned job is proven empty.

    The known-hosts path and digest are fixed here. The other four pins must
    come from a separately verified preparation binding and transport config;
    this class alone does not authorize a route or prove Windows handle locks.
    No process is created here. The backend's creation gate is armed only after
    verified custody, and it must independently prove CreateProcess happened
    under that gate using the held SSH image. `resume_assigned` calls a supplied
    backend while route handles remain held. Its backend must prove suspended
    creation, assignment and OS handle continuity; a lost return is ambiguous,
    never a reason to release the route or repeat Resume.
    """

    _active_lock = threading.Lock()
    _active_leases: dict[str, VerifiedRouteCustody] = {}

    def __init__(
        self, preparation_id: str, pins: tuple[PinnedRouteFile, ...], backend: RouteCustodyBackend
    ) -> None:
        if type(preparation_id) is not str or not preparation_id:
            raise ValueError("exact preparation identity required")
        if type(pins) is not tuple or len(pins) != len(_ROLES):
            raise ValueError("all exact route pins required")
        by_role: dict[str, PinnedRouteFile] = {}
        expected_nodes: dict[str, str] = {}
        for pin in pins:
            if (
                type(pin) is not PinnedRouteFile
                or type(pin.role) is not str
                or pin.role not in _ROLES
                or pin.role in by_role
            ):
                raise ValueError("distinct route roles required")
            path = PureWindowsPath(pin.path) if type(pin.path) is str else None
            if (
                type(pin.path) is not str
                or not pin.path
                or path is None
                or not path.is_absolute()
                or re.fullmatch(r"[A-Za-z]:", path.drive) is None
                or str(path) != pin.path
                or ".." in path.parts
                or re.search(r'[\x00-\x1f"%!^&|<>?*]', pin.path) is not None
                or ":" in pin.path[2:]
                or any(part.endswith((" ", ".")) for part in path.parts[1:])
                or type(pin.sha256) is not str
                or _DIGEST.fullmatch(pin.sha256) is None
                or pin.path in expected_nodes
            ):
                raise ValueError("canonical absolute path and SHA-256 pin required")
            by_role[pin.role] = pin
            expected_nodes[pin.path] = "file"
            for parent in path.parents:
                expected_nodes[str(parent)] = "directory"
        if set(by_role) != _ROLES:
            raise ValueError("all exact route roles required")
        known_hosts = by_role["known_hosts"]
        if (
            known_hosts.path != _APPROVED_KNOWN_HOSTS_PATH
            or known_hosts.sha256 != _APPROVED_KNOWN_HOSTS_SHA256
        ):
            raise ValueError("exact approved known-hosts path and SHA-256 required")
        self._preparation_id = preparation_id
        self._pins = by_role
        self._nodes = expected_nodes
        self._backend = backend
        self._lease: object | None = None
        self._initial_ids: dict[str, str] | None = None
        self._lease_id: str | None = None
        self._creation_guard_id: str | None = None
        self._state = "new"
        self._job_id: str | None = None
        self._process_identity: str | None = None

    def _check(self) -> tuple[dict[str, str], str]:
        if self._lease is None:
            raise RuntimeError("route handles are not held")
        lease = self._backend.observe_lease(self._lease)
        if (
            type(lease) is not RouteLeaseObservation
            or lease.preparation_id != self._preparation_id
            or type(lease.lease_id) is not str
            or not lease.lease_id
            or lease.lease_open is not True
            or lease.exclusive_owner is not True
            or (self._lease_id is not None and lease.lease_id != self._lease_id)
        ):
            raise RuntimeError("exclusive preparation route lease lost")
        observed = self._backend.observe(self._lease)
        if type(observed) is not dict or set(observed) != set(self._nodes):
            raise RuntimeError("incomplete route and ancestor custody")
        identities: dict[str, str] = {}
        for path, kind in self._nodes.items():
            node = observed[path]
            if (
                type(node) is not NodeObservation
                or node.path != path
                or node.kind != kind
                or type(node.held_id) is not str
                or not node.held_id
                or node.path_id != node.held_id
                or node.lock_open is not True
                or node.blocks_write is not True
                or node.blocks_delete is not True
                or node.reparse is not False
                or (self._initial_ids is not None and node.held_id != self._initial_ids[path])
            ):
                raise RuntimeError("route handle or path identity changed")
            identities[path] = node.held_id
            if kind == "directory" and node.raw is not None:
                raise RuntimeError("directory custody observation malformed")
        for pin in self._pins.values():
            raw = observed[pin.path].raw
            if type(raw) is not bytes or hashlib.sha256(raw).hexdigest() != pin.sha256:
                raise RuntimeError("pinned route bytes changed")
        return identities, lease.lease_id

    def hold(self) -> None:
        if self._state != "new":
            raise RuntimeError("route custody cannot be acquired again")
        self._state = "acquire_ambiguous"
        self._lease = self._backend.acquire(self._preparation_id, tuple(self._nodes))
        self._state = "hold_unverified"
        identities, lease_id = self._check()
        with self._active_lock:
            if lease_id in self._active_leases:
                raise RuntimeError("route lease is already owned by another preparation")
            self._active_leases[lease_id] = self
        self._initial_ids = identities
        self._lease_id = lease_id
        self._state = "creation_arm_ambiguous"
        guard_id = self._backend.arm_creation(self._lease)
        if type(guard_id) is not str or not guard_id:
            raise RuntimeError("verified route creation gate was not armed")
        self._creation_guard_id = guard_id
        self._state = "held"

    def resume_assigned(self, job: OwnedJobObservation) -> None:
        if self._state != "held":
            raise RuntimeError("held route custody required before resume")
        self._check()
        if type(job) is not OwnedJobObservation:
            raise RuntimeError("exact suspended and assigned owned job required")
        creation = self._backend.observe_creation(self._lease, job)
        if (
            type(creation) is not ProcessCreationObservation
            or creation.preparation_id != self._preparation_id
            or creation.lease_id != self._lease_id
            or creation.creation_guard_id != self._creation_guard_id
            or creation.job_id != job.job_id
            or creation.process_identity != job.process_identity
            or creation.image_file_id != self._initial_ids[self._pins["ssh_executable"].path]
            or creation.created_after_verified_hold is not True
        ):
            raise RuntimeError("owned process creation under verified held route required")
        if (
            type(job) is not OwnedJobObservation
            or self._backend.observe_job(job) != job
            or job.preparation_id != self._preparation_id
            or type(job.job_id) is not str
            or not job.job_id
            or type(job.process_identity) is not str
            or not job.process_identity
            or job.created_suspended is not True
            or job.assigned_before_resume is not True
            or job.breakaway_disabled is not True
            or job.kill_on_job_close is not True
            or job.job_handle_open is not True
            or job.process_terminated is not False
        ):
            raise RuntimeError("exact suspended and assigned owned job required")
        self._job_id = job.job_id
        self._process_identity = job.process_identity
        self._state = "resume_ambiguous"
        self._backend.resume_assigned(self._lease, job)
        self._state = "running"

    def finish(self, job: OwnedJobObservation) -> None:
        if self._state not in ("running", "resume_ambiguous"):
            raise RuntimeError("owned job is not running under route custody")
        if (
            type(job) is not OwnedJobObservation
            or self._backend.observe_job(job) != job
            or job.preparation_id != self._preparation_id
            or job.job_id != self._job_id
            or job.process_identity != self._process_identity
            or job.created_suspended is not True
            or job.assigned_before_resume is not True
            or job.breakaway_disabled is not True
            or job.kill_on_job_close is not True
            or job.job_handle_open is not True
            or job.process_terminated is not True
            or job.enumeration_complete is not True
            or job.members_empty is not True
            or type(job.member_ids) is not tuple
            or job.member_ids
        ):
            raise RuntimeError("exact empty owned job required before unlocking route")
        self._check()
        self._state = "release_ambiguous"
        self._backend.release(self._lease)
        with self._active_lock:
            if self._active_leases.get(self._lease_id) is not self:
                raise RuntimeError("route lease registry ownership changed")
            del self._active_leases[self._lease_id]
        self._state = "closed"
        self._lease = None
