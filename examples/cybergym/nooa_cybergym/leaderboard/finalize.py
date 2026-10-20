# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""One-shot custody of the admitted primary parent's declared final PoC.

The caller must supply an attestor backed by the native parent event and Xeus
evidence authority. This component does not nominate a candidate, recover a
timeout, invoke a fixed-side oracle, or sign a result by itself.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from collections.abc import Callable, Mapping
from contextlib import ExitStack
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any

from .primary_takeover import PrimaryTakeoverPolicy

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_MAX_DECLARATION_BYTES = 1024 * 1024
_DECLARATION_FIELDS = frozenset(
    {
        "schema_version",
        "task_id",
        "candidate_path",
        "sha256",
        "byte_length",
        "selected_at",
        "selection_reason",
        "final_declaration",
        "selected_by",
    }
)
_PRIMARY_IDENTITY_FIELDS = frozenset(
    {
        "provider",
        "configured_model",
        "provider_model",
        "provider_attempt_id",
        "takeover_policy_sha256",
        "attempt_id",
        "request_id",
        "session_id",
        "tool_id",
    }
)


@dataclass(frozen=True, slots=True)
class ParentSelectionProof:
    """Trusted verification result for the specific native GLM parent event."""

    task_id: str
    declaration_sha256: str
    candidate_sha256: str
    model: str
    role: str
    event_digest: str


@dataclass(frozen=True, slots=True)
class PrimaryParentSelectionProof:
    """V2 trusted native selection; never accepted by the legacy GLM verifier."""

    schema_version: int
    task_id: str
    declaration_sha256: str
    candidate_sha256: str
    model: str
    role: str
    event_digest: str
    provider: str
    provider_model: str
    provider_attempt_id: str
    takeover_policy_sha256: str
    attempt_id: str
    request_id: str
    session_id: str
    tool_id: str


@dataclass(frozen=True, slots=True)
class FinalLock:
    task_id: str
    sha256: str
    byte_length: int
    poc_path: Path
    declaration_path: Path
    declaration: Mapping[str, Any]
    parent_event_digest: str


def _validate_primary_identity(
    identity: Mapping[str, Any], policy: PrimaryTakeoverPolicy
) -> None:
    if type(policy) is not PrimaryTakeoverPolicy:
        raise ValueError("trusted primary takeover policy required")
    if (
        type(identity["takeover_policy_sha256"]) is not str
        or identity["takeover_policy_sha256"] != policy.digest
        or not any(
            (
                identity["provider"],
                identity["configured_model"],
                identity["provider_model"],
            )
            == (route.provider, route.model, route.wire_model)
            for route in (policy.initial, policy.fallback)
        )
        or any(
            type(identity[key]) is not str
            for key in ("provider", "configured_model", "provider_model")
        )
    ):
        raise ValueError("primary provider identity disagrees with takeover policy")
    if any(
        type(identity[key]) is not str or not _IDENTIFIER.fullmatch(identity[key])
        for key in ("attempt_id", "request_id", "session_id", "tool_id", "provider_attempt_id")
    ) or identity["provider_attempt_id"] == identity["request_id"]:
        raise ValueError("distinct bounded native request and provider attempt identity required")


def _primary_event_digest(declaration: Mapping[str, Any]) -> str:
    """Bind the complete native parent invocation, independent of serialization."""
    event = {
        "schema_version": 2,
        "task_id": declaration["task_id"],
        "attempt_id": declaration["attempt_id"],
        "request_id": declaration["request_id"],
        "session_id": declaration["session_id"],
        "agent_id": None,
        "role": "parent",
        "tool_id": declaration["tool_id"],
        "tool_name": "mcp__finalizer__select_final",
        "provider": declaration["provider"],
        "configured_model": declaration["configured_model"],
        "observed_provider_model": declaration["provider_model"],
        "provider_attempt_id": declaration["provider_attempt_id"],
        "takeover_policy_sha256": declaration["takeover_policy_sha256"],
        "authority": "NativeToolController.resolve_mcp_call",
        "arguments": {
            key: declaration[key]
            for key in ("candidate_path", "sha256", "byte_length", "selection_reason")
        },
    }
    return hashlib.sha256(
        json.dumps(event, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def _validate_declaration(
    raw: bytes,
    expected_task_id: str,
    *,
    takeover_policy: PrimaryTakeoverPolicy | None = None,
) -> dict[str, Any]:
    try:
        declaration = json.loads(raw)
    except (UnicodeDecodeError, ValueError):
        raise ValueError("invalid agent final declaration") from None
    fields = _DECLARATION_FIELDS
    version, selector = 1, "glm_parent"
    if takeover_policy is not None:
        if type(takeover_policy) is not PrimaryTakeoverPolicy:
            raise ValueError("trusted primary takeover policy required")
        fields |= _PRIMARY_IDENTITY_FIELDS
        version, selector = 2, "primary_parent"
    if not isinstance(declaration, dict) or frozenset(declaration) != fields:
        raise ValueError("agent final declaration fields are invalid")
    if type(declaration["schema_version"]) is not int or declaration["schema_version"] != version:
        raise ValueError("agent final declaration schema is invalid")
    if declaration["task_id"] != expected_task_id:
        raise ValueError("agent final task ID does not match")
    if declaration["selected_by"] != selector or declaration["final_declaration"] is not True:
        parent = "GLM" if takeover_policy is None else "primary"
        raise ValueError(f"{parent} parent did not declare an official final")
    if takeover_policy is not None:
        _validate_primary_identity(declaration, takeover_policy)
    if (
        type(declaration["sha256"]) is not str
        or not _SHA256.fullmatch(declaration["sha256"])
        or type(declaration["byte_length"]) is not int
        or declaration["byte_length"] < 0
    ):
        raise ValueError("agent final hash or length is invalid")
    reason = declaration["selection_reason"]
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("agent final selection reason is missing")
    selected_at = declaration["selected_at"]
    if not isinstance(selected_at, str):
        raise ValueError("agent final selection timestamp is invalid")
    try:
        timestamp = datetime.fromisoformat(selected_at.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("agent final selection timestamp is invalid") from None
    if timestamp.tzinfo is None:
        raise ValueError("agent final selection timestamp must have a timezone")
    return declaration


def _candidate_components(declared_path: object) -> tuple[str, ...]:
    if not isinstance(declared_path, str):
        raise ValueError("candidate path must be a string")
    parsed = PurePosixPath(declared_path)
    prefix = ("/", "workspace", "output")
    if (
        parsed.parts[:3] != prefix
        or len(parsed.parts) <= 3
        or any(part in {".", ".."} for part in parsed.parts[3:])
    ):
        raise ValueError("candidate path must remain under /workspace/output")
    return parsed.parts[3:]


def _candidate_file(output: Path, declared_path: object) -> Path:
    components = _candidate_components(declared_path)
    path = output.joinpath(*components)
    ancestor = output
    for component in components:
        ancestor = ancestor / component
        if ancestor.is_symlink():
            raise RuntimeError("candidate symlink is forbidden")
    if not path.is_file() or not stat.S_ISREG(path.stat().st_mode):
        raise RuntimeError("declared final PoC is missing or non-regular")
    return path


def _rooted_directory_fd(path: Path) -> int:
    """Open every absolute ancestor without following a replaceable symlink."""
    if (
        os.name != "posix"
        or os.open not in os.supports_dir_fd
        or not getattr(os, "O_NOFOLLOW", 0)
        or not getattr(os, "O_DIRECTORY", 0)
    ):
        raise RuntimeError("rooted directory traversal is unavailable")
    absolute = path.absolute()
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(absolute.anchor, flags)
    except OSError:
        raise RuntimeError("agent output directory is missing or linked") from None
    try:
        for component in absolute.parts[1:]:
            if component in ("", ".", ".."):
                raise ValueError("invalid output directory component")
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except (OSError, ValueError):
        os.close(descriptor)
        raise RuntimeError("agent output directory is missing or linked") from None


def _regular_file_fd(directory_fd: int, components: tuple[str, ...], label: str) -> int:
    """Keep the output root and each candidate parent pinned during file open."""
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    file_flags = (
        os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    )
    parent_fd = os.dup(directory_fd)
    try:
        for component in components[:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = next_fd
        descriptor = os.open(components[-1], file_flags, dir_fd=parent_fd)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise RuntimeError(f"{label} is not a regular file")
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise
    except (OSError, ValueError):
        raise RuntimeError(f"{label} is missing or contains a symlink") from None
    finally:
        os.close(parent_fd)


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _copy_candidate(source: Path | int, destination: Path) -> tuple[str, int]:
    if type(source) is int:
        descriptor = os.dup(source)
    else:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(source, flags)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise RuntimeError("declared final PoC is non-regular")
        digest = hashlib.sha256()
        byte_length = 0
        with os.fdopen(descriptor, "rb", closefd=False) as stream, destination.open("xb") as target:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                target.write(block)
                digest.update(block)
                byte_length += len(block)
            target.flush()
            os.fsync(target.fileno())
        return digest.hexdigest(), byte_length
    finally:
        os.close(descriptor)


def lock_agent_final(
    output_dir: Path,
    evidence_dir: Path,
    expected_task_id: str,
    *,
    attest_parent_selection: Callable[[bytes], ParentSelectionProof | PrimaryParentSelectionProof],
    takeover_policy: PrimaryTakeoverPolicy | None = None,
) -> FinalLock:
    """Copy exactly one attested agent-selected final into immutable custody."""

    output = Path(output_dir)
    evidence = Path(evidence_dir)
    if os.name != "posix" and (output.is_symlink() or not output.is_dir()):
        raise RuntimeError("agent output directory is missing or linked")
    if not callable(attest_parent_selection):
        parent = "GLM" if takeover_policy is None else "primary"
        raise RuntimeError(f"trusted {parent} parent selection attestor is required")
    if evidence.is_symlink() or evidence.resolve().is_relative_to(output.parent.resolve()):
        raise ValueError("final evidence must be outside the agent workspace")
    final = evidence / "final"
    if final.exists() or final.is_symlink():
        raise FileExistsError("agent final already locked")
    with ExitStack() as opened:
        output_fd: int | None = None
        if os.name == "posix":
            output_fd = _rooted_directory_fd(output)
            opened.callback(os.close, output_fd)
            declared = sorted(
                name
                for name in os.listdir(output_fd)
                if name.startswith("agent-final") and name.endswith(".json")
            )
        else:
            declared = sorted(path.name for path in output.glob("agent-final*.json"))
        if declared != ["agent-final.json"]:
            if not declared:
                raise RuntimeError("missing agent final")
            raise RuntimeError("multiple agent final declarations")

        if output_fd is not None:
            declaration_fd = _regular_file_fd(
                output_fd, ("agent-final.json",), "agent final declaration"
            )
            opened.callback(os.close, declaration_fd)
            with os.fdopen(os.dup(declaration_fd), "rb") as stream:
                raw_declaration = stream.read(_MAX_DECLARATION_BYTES + 1)
        else:
            declaration_file = output / "agent-final.json"
            if declaration_file.is_symlink() or not declaration_file.is_file():
                raise RuntimeError("agent final declaration is not a regular file")
            raw_declaration = declaration_file.read_bytes()
        if len(raw_declaration) > _MAX_DECLARATION_BYTES:
            raise ValueError("agent final declaration is too large")
        declaration = _validate_declaration(
            raw_declaration, expected_task_id, takeover_policy=takeover_policy
        )
        if output_fd is not None:
            candidate = _regular_file_fd(
                output_fd, _candidate_components(declaration["candidate_path"]), "candidate"
            )
            opened.callback(os.close, candidate)
        else:
            candidate = _candidate_file(output, declaration["candidate_path"])

        parent = "GLM" if takeover_policy is None else "primary"
        try:
            proof = attest_parent_selection(raw_declaration)
        except Exception:
            raise RuntimeError(f"{parent} parent selection attestation failed") from None
        proof_type = ParentSelectionProof if takeover_policy is None else PrimaryParentSelectionProof
        expected_model = (
            "glm-5.3[1m]" if takeover_policy is None else declaration["configured_model"]
        )
        expected_role = "glm_parent" if takeover_policy is None else "primary_parent"
        if (
            type(proof) is not proof_type
            or proof.task_id != expected_task_id
            or proof.declaration_sha256 != hashlib.sha256(raw_declaration).hexdigest()
            or proof.candidate_sha256 != declaration["sha256"]
            or proof.model != expected_model
            or proof.role != expected_role
            or type(proof.event_digest) is not str
            or not _SHA256.fullmatch(proof.event_digest)
        ):
            raise RuntimeError(f"{parent} parent selection attestation disagrees with declaration")
        if takeover_policy is not None and (
            type(proof.schema_version) is not int
            or proof.schema_version != 2
            or any(
                type(getattr(proof, key)) is not str
                or getattr(proof, key) != declaration[key]
                for key in _PRIMARY_IDENTITY_FIELDS - {"configured_model"}
            )
            or proof.event_digest != _primary_event_digest(declaration)
        ):
            raise RuntimeError("primary parent selection attestation disagrees with declaration")

        evidence.mkdir(parents=True, exist_ok=True)
        stage = Path(tempfile.mkdtemp(prefix=".final-stage-", dir=evidence))
        try:
            copied = stage / "poc"
            actual_sha, actual_length = _copy_candidate(candidate, copied)
            if actual_sha != declaration["sha256"] or actual_length != declaration["byte_length"]:
                raise RuntimeError("declared final PoC changed or disagrees with hash/length")
            declaration_copy = stage / "agent-final.json"
            with declaration_copy.open("xb") as stream:
                stream.write(raw_declaration)
                stream.flush()
                os.fsync(stream.fileno())
            for path in (copied, declaration_copy):
                path.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
            _fsync_directory(stage)
            final.mkdir(mode=0o700, exist_ok=False)
            os.replace(copied, final / "poc")
            os.replace(declaration_copy, final / "agent-final.json")
            _fsync_directory(final)
            final.chmod(
                stat.S_IRUSR
                | stat.S_IXUSR
                | stat.S_IRGRP
                | stat.S_IXGRP
                | stat.S_IROTH
                | stat.S_IXOTH
            )
            _fsync_directory(evidence)
            return FinalLock(
                task_id=expected_task_id,
                sha256=actual_sha,
                byte_length=actual_length,
                poc_path=final / "poc",
                declaration_path=final / "agent-final.json",
                declaration=MappingProxyType(declaration),
                parent_event_digest=proof.event_digest,
            )
        finally:
            # A partial final directory deliberately remains after post-creation
            # failure: it blocks a second lock and requires controller recovery.
            shutil.rmtree(stage)
