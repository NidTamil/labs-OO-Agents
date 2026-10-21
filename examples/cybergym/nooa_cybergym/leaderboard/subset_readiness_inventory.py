# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Read-only byte custody for raw subset readiness material.

The caller must supply the descriptor digest from independently frozen trust.
This module neither interprets a control nor attests a gate or run. A repeated
byte check detects ordinary changes; it is not proof that writers are stopped.
Each walk is limited by a pinned byte total and entry/file caps. An independent
provisional aggregate ceiling applies across all seven roots. These caps need
calibration against finished evidence. Cooperative monotonic checks cannot
interrupt blocked syscalls; an owned-process supervisor must enforce a hard
deadline before production use.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

_FIXTURE_ORDER = ("synthetic:length-header", "synthetic:chunk-table")
_FIXTURES = frozenset(_FIXTURE_ORDER)
_CONTROL_KINDS = (
    "primary_takeover",
    "interruption_reconnection",
    "timeout_failure",
    "version_drift",
    "memory_write_denial",
)
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_DESCRIPTOR_BYTES = 8 * 1024 * 1024
# A legacy pair can carry up to 20,000 file rows; avoid a tighter manifest cap.
_MAX_PAIR_MANIFEST_BYTES = _MAX_DESCRIPTOR_BYTES
_MAX_FILES = 10_000
_MAX_ENTRIES = 20_000
_MAX_REPETITION_FILES = 25_000
_MAX_REPETITION_ENTRIES = 50_000
_MAX_FILE_BYTES = 512 * 1024 * 1024
# Provisional source guard only; not an approved evidence or readiness limit.
_PROVISIONAL_AGGREGATE_BYTES = 1024 * 1024 * 1024


def _check_deadline(deadline_monotonic: float) -> None:
    if time.monotonic() >= deadline_monotonic:
        raise ValueError("readiness inventory deadline expired")


def _aggregate_cap(max_aggregate_bytes: int | None) -> int:
    if max_aggregate_bytes is None:
        return _PROVISIONAL_AGGREGATE_BYTES
    if (
        type(max_aggregate_bytes) is not int
        or not 0 < max_aggregate_bytes <= _PROVISIONAL_AGGREGATE_BYTES
    ):
        raise ValueError("narrower aggregate byte cap required")
    return max_aggregate_bytes


def _digest(value: Any) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _canonical(raw: bytes, *, limit: int, label: str) -> dict[str, Any]:
    if type(raw) is not bytes or not 0 < len(raw) <= limit:
        raise ValueError(f"bounded {label} bytes required")
    try:
        value = json.loads(raw)
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise ValueError(f"{label} JSON invalid") from error
    if type(value) is not dict or encoded != raw:
        raise ValueError(f"{label} must be canonical object")
    return value


def _root(raw: Any) -> Path:
    if type(raw) is not str:
        raise ValueError("canonical absolute evidence root required")
    path = Path(raw)
    try:
        if (
            not path.is_absolute()
            or path.is_symlink()
            or path.is_junction()
            or not path.is_dir()
            or path.resolve(strict=True) != path
        ):
            raise ValueError("canonical absolute evidence root required")
    except (OSError, RuntimeError) as error:
        raise ValueError("canonical absolute evidence root required") from error
    return path


def _overlap(left: Path, right: Path) -> bool:
    return left == right or left.is_relative_to(right) or right.is_relative_to(left)


def _file_rows(raw: Any, *, label: str, max_files: int) -> int:
    if type(raw) is not list or not 0 < len(raw) <= max_files:
        raise ValueError(f"bounded {label} file inventory required")
    names = []
    total_bytes = 0
    for row in raw:
        if type(row) is not dict or set(row) != {"path", "bytes", "sha256"}:
            raise ValueError(f"{label} file inventory row invalid")
        name = row["path"]
        if type(name) is not str or not name or "\\" in name:
            raise ValueError(f"{label} file path invalid")
        parsed = PurePosixPath(name)
        if (
            parsed.is_absolute()
            or str(parsed) != name
            or any(part in {".", ".."} for part in name.split("/"))
            or type(row["bytes"]) is not int
            or not 0 <= row["bytes"] <= _MAX_FILE_BYTES
            or not _digest(row["sha256"])
        ):
            raise ValueError(f"{label} file inventory row invalid")
        names.append(name)
        total_bytes += row["bytes"]
    if names != sorted(set(names)):
        raise ValueError(f"{label} file inventory paths must be unique and sorted")
    return total_bytes


def _policy_totals(descriptor: dict[str, Any], cap: int) -> tuple[tuple[int, int], tuple[int, ...]]:
    """Reject aggregate declared bytes before opening any evidence tree."""
    repetitions = descriptor["repetitions"]
    controls = descriptor["controls"]
    if type(repetitions) is not list or len(repetitions) != 2:
        raise ValueError("exact two repetitions required")
    if (
        type(controls) is not list
        or tuple(row.get("kind") if type(row) is dict else None for row in controls)
        != _CONTROL_KINDS
    ):
        raise ValueError("exact typed controls required")
    repetition_totals: list[int] = []
    control_totals: list[int] = []
    aggregate = 0
    for row in repetitions:
        if type(row) is not dict or "files" not in row:
            raise ValueError("repetition descriptor invalid")
        total = _file_rows(row["files"], label="repetition", max_files=_MAX_REPETITION_FILES)
        aggregate += total
        if aggregate > cap:
            raise ValueError("readiness inventory exceeds aggregate byte cap")
        repetition_totals.append(total)
    for row in controls:
        if "files" not in row:
            raise ValueError("control descriptor invalid")
        total = _file_rows(row["files"], label="control", max_files=_MAX_FILES)
        aggregate += total
        if aggregate > cap:
            raise ValueError("readiness inventory exceeds aggregate byte cap")
        control_totals.append(total)
    return (repetition_totals[0], repetition_totals[1]), tuple(control_totals)


def _inventory_files(
    root: Path,
    *,
    label: str,
    max_files: int,
    max_entries: int,
    max_total_bytes: int,
    deadline_monotonic: float,
) -> list[dict[str, str | int]]:
    def walk(directory: Path) -> Iterator[Path]:
        # pathlib.rglob suppresses scan errors on supported Python versions.
        _check_deadline(deadline_monotonic)
        try:
            with os.scandir(directory) as children:
                for child in children:
                    _check_deadline(deadline_monotonic)
                    path = Path(child.path)
                    yield path
                    if child.is_dir(follow_symlinks=False):
                        yield from walk(path)
        except OSError as error:
            raise ValueError(f"{label} evidence scan failed") from error

    observed: list[dict[str, str | int]] = []
    entries = 0
    total_bytes = 0
    for path in walk(root):
        _check_deadline(deadline_monotonic)
        entries += 1
        if entries > max_entries:
            raise ValueError(f"{label} evidence exceeds entry bound")
        if path.is_symlink() or path.is_junction():
            raise ValueError(f"linked {label} evidence forbidden")
        before = path.lstat()
        if stat.S_ISDIR(before.st_mode):
            continue
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"nonregular {label} evidence forbidden")
        if before.st_size > _MAX_FILE_BYTES or len(observed) >= max_files:
            raise ValueError(f"{label} evidence exceeds file bound")
        if total_bytes + before.st_size > max_total_bytes:
            raise ValueError(f"{label} bytes changed or exceed pinned byte total")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or opened.st_size > _MAX_FILE_BYTES:
                raise ValueError(f"nonregular or oversized {label} evidence forbidden")
            size = 0

            def read_block() -> bytes:
                _check_deadline(deadline_monotonic)
                return stream.read(1024 * 1024)

            for block in iter(read_block, b""):
                _check_deadline(deadline_monotonic)
                size += len(block)
                if size > _MAX_FILE_BYTES:
                    raise ValueError(f"{label} evidence exceeds byte bound")
                if total_bytes + size > max_total_bytes:
                    raise ValueError(f"{label} bytes changed or exceed pinned byte total")
                digest.update(block)
            closed = os.fstat(stream.fileno())
        after = path.lstat()

        def identity(item: os.stat_result) -> tuple[int, int, int, int]:
            return item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns

        if (
            identity(before) != identity(opened)
            or identity(opened) != identity(closed)
            or identity(closed) != identity(after)
            or size != opened.st_size
        ):
            raise ValueError(f"{label} evidence changed while hashing")
        total_bytes += size
        observed.append(
            {
                "path": path.relative_to(root).as_posix(),
                "bytes": size,
                "sha256": digest.hexdigest(),
            }
        )
    _check_deadline(deadline_monotonic)
    return sorted(observed, key=lambda row: str(row["path"]))


def _pair_projection(
    run_id: str,
    run_root: Path,
    fixture_roots: dict[str, Path],
    repetition_files: list[dict[str, str | int]],
) -> dict[str, Any]:
    """Project legacy pair-manifest rows from one already bounded repetition scan."""
    first, second = (fixture_roots[fixture] for fixture in _FIXTURE_ORDER)
    if _overlap(first, second):
        raise ValueError("fixture roots overlap")
    files: dict[str, list[dict[str, str | int]]] = {}
    for fixture in _FIXTURE_ORDER:
        prefix = fixture_roots[fixture].relative_to(run_root).as_posix() + "/"
        rows = [
            {
                "path": str(row["path"])[len(prefix) :],
                "bytes": row["bytes"],
                "sha256": row["sha256"],
            }
            for row in repetition_files
            if str(row["path"]).startswith(prefix)
        ]
        # Match the legacy builder's Path ordering, including Windows case folding.
        rows.sort(key=lambda row: Path(str(row["path"])))
        if not 0 < len(rows) <= _MAX_FILES or not any(row["path"] == "result.json" for row in rows):
            raise ValueError("bounded terminal fixture pair required")
        files[fixture] = rows
    return {
        "schema_version": 1,
        "scope": "raw_fixture_pair_provenance",
        "run_id": run_id,
        "fixture_ids": list(_FIXTURE_ORDER),
        "roots": {fixture: str(fixture_roots[fixture]) for fixture in _FIXTURE_ORDER},
        "files": files,
    }


def _check_repetition_files(
    row: dict[str, Any],
    manifest: dict[str, Any],
    *,
    pinned_total: int,
    deadline_monotonic: float,
) -> None:
    """Check all repetition bytes once, then compare legacy fixture projections."""
    run_root = _root(row["root"])
    fixture_roots = {fixture: _root(path) for fixture, path in row["fixtures"].items()}
    if any(
        root == run_root or not root.is_relative_to(run_root) for root in fixture_roots.values()
    ):
        raise ValueError("fixture root outside repetition")
    observed = _inventory_files(
        run_root,
        label="repetition",
        max_files=_MAX_REPETITION_FILES,
        max_entries=_MAX_REPETITION_ENTRIES,
        max_total_bytes=pinned_total,
        deadline_monotonic=deadline_monotonic,
    )
    if observed != row["files"]:
        raise ValueError("repetition bytes changed")
    if manifest != _pair_projection(row["run_id"], run_root, fixture_roots, observed):
        raise ValueError("pair manifest bytes changed")


@dataclass(frozen=True, slots=True)
class ReadinessInventory:
    """Immutable references for rechecking bytes, without readiness authority."""

    descriptor_sha256: str
    repetition_ids: tuple[str, str]
    control_kinds: tuple[str, ...]
    _descriptor_bytes: bytes = field(repr=False)
    _pair_manifests: tuple[tuple[str, bytes], ...] = field(repr=False)
    _max_aggregate_bytes: int = field(repr=False)
    _deadline_monotonic: float = field(repr=False)

    def repetition_root(self, run_id: str) -> Path:
        """Resolve only a pinned repetition root for a separate raw reader."""
        if run_id not in self.repetition_ids:
            raise ValueError("repetition root not inventoried")
        descriptor = _canonical(
            self._descriptor_bytes, limit=_MAX_DESCRIPTOR_BYTES, label="readiness descriptor"
        )
        for repetition in descriptor["repetitions"]:
            if repetition["run_id"] == run_id:
                return Path(repetition["root"])
        raise ValueError("repetition root not inventoried")

    def fixture_root(self, run_id: str, fixture_id: str) -> Path:
        """Resolve only a pinned fixture root for a separate raw reader."""
        if run_id not in self.repetition_ids or fixture_id not in _FIXTURES:
            raise ValueError("fixture root not inventoried")
        descriptor = _canonical(
            self._descriptor_bytes, limit=_MAX_DESCRIPTOR_BYTES, label="readiness descriptor"
        )
        for repetition in descriptor["repetitions"]:
            if repetition["run_id"] == run_id:
                return Path(repetition["fixtures"][fixture_id])
        raise ValueError("fixture root not inventoried")

    def control_root(self, kind: str) -> Path:
        """Resolve only a pinned typed control root for a separate raw reader."""
        if kind not in self.control_kinds:
            raise ValueError("control root not inventoried")
        descriptor = _canonical(
            self._descriptor_bytes, limit=_MAX_DESCRIPTOR_BYTES, label="readiness descriptor"
        )
        for control in descriptor["controls"]:
            if control["kind"] == kind:
                return Path(control["root"])
        raise ValueError("control root not inventoried")

    def control_id(self, kind: str) -> str:
        """Resolve a typed control ID from independently pinned descriptor bytes."""
        if kind not in self.control_kinds:
            raise ValueError("control ID not inventoried")
        descriptor = _canonical(
            self._descriptor_bytes, limit=_MAX_DESCRIPTOR_BYTES, label="readiness descriptor"
        )
        for control in descriptor["controls"]:
            if control["kind"] == kind:
                return control["control_id"]
        raise ValueError("control ID not inventoried")

    @contextmanager
    def observed_bytes(self) -> Iterator[None]:
        """Bracket a separate raw reader with before/after byte checks."""
        self.recheck()
        try:
            yield
        finally:
            self.recheck()

    def recheck(self) -> None:
        """Recompute fixture and control inventories after raw interpretation."""
        _check_deadline(self._deadline_monotonic)
        descriptor = _canonical(
            self._descriptor_bytes, limit=_MAX_DESCRIPTOR_BYTES, label="readiness descriptor"
        )
        repetition_totals, control_totals = _policy_totals(descriptor, self._max_aggregate_bytes)
        manifests = dict(self._pair_manifests)
        for repetition, pinned_total in zip(
            descriptor["repetitions"], repetition_totals, strict=True
        ):
            manifest = _canonical(
                manifests[repetition["run_id"]],
                limit=_MAX_PAIR_MANIFEST_BYTES,
                label="pair manifest",
            )
            _check_repetition_files(
                repetition,
                manifest,
                pinned_total=pinned_total,
                deadline_monotonic=self._deadline_monotonic,
            )
        for control, pinned_total in zip(descriptor["controls"], control_totals, strict=True):
            if (
                _inventory_files(
                    _root(control["root"]),
                    label="control",
                    max_files=_MAX_FILES,
                    max_entries=_MAX_ENTRIES,
                    max_total_bytes=pinned_total,
                    deadline_monotonic=self._deadline_monotonic,
                )
                != control["files"]
            ):
                raise ValueError("control bytes changed")


def load_subset_readiness_inventory(
    descriptor_bytes: bytes,
    *,
    expected_sha256: str,
    pair_manifests: Mapping[str, bytes],
    deadline_monotonic: float,
    max_aggregate_bytes: int | None = None,
) -> ReadinessInventory:
    """Check pinned custody facts within a provisional cap and monotonic deadline."""
    if type(deadline_monotonic) not in (int, float) or not math.isfinite(deadline_monotonic):
        raise ValueError("finite monotonic deadline required")
    _check_deadline(deadline_monotonic)
    aggregate_cap = _aggregate_cap(max_aggregate_bytes)
    if not _digest(expected_sha256):
        raise ValueError("independent readiness descriptor pin required")
    descriptor = _canonical(
        descriptor_bytes, limit=_MAX_DESCRIPTOR_BYTES, label="readiness descriptor"
    )
    if hashlib.sha256(descriptor_bytes).hexdigest() != expected_sha256:
        raise ValueError("readiness descriptor pin differs")
    if set(descriptor) != {"schema_version", "scope", "repetitions", "controls"} or (
        type(descriptor["schema_version"]) is not int
        or descriptor["schema_version"] != 1
        or descriptor["scope"] != "subset_raw_readiness_inventory"
    ):
        raise ValueError("readiness descriptor schema invalid")
    repetitions = descriptor["repetitions"]
    repetition_totals, control_totals = _policy_totals(descriptor, aggregate_cap)
    if not isinstance(pair_manifests, Mapping):
        raise ValueError("pair manifests required")
    ids: list[str] = []
    run_roots: list[Path] = []
    frozen_manifests: list[tuple[str, bytes]] = []
    for row, pinned_total in zip(repetitions, repetition_totals, strict=True):
        _check_deadline(deadline_monotonic)
        if type(row) is not dict or set(row) != {
            "run_id",
            "root",
            "pair_manifest_sha256",
            "fixtures",
            "files",
        }:
            raise ValueError("repetition descriptor invalid")
        run_id = row["run_id"]
        fixtures = row["fixtures"]
        if (
            type(run_id) is not str
            or _ID.fullmatch(run_id) is None
            or run_id in ids
            or not _digest(row["pair_manifest_sha256"])
            or type(fixtures) is not dict
            or set(fixtures) != _FIXTURES
        ):
            raise ValueError("repetition identity or fixtures invalid")
        run_root = _root(row["root"])
        manifest_bytes = pair_manifests.get(run_id)
        manifest = _canonical(manifest_bytes, limit=_MAX_PAIR_MANIFEST_BYTES, label="pair manifest")
        if (
            hashlib.sha256(manifest_bytes).hexdigest() != row["pair_manifest_sha256"]
            or manifest.get("run_id") != run_id
            or manifest.get("roots") != fixtures
        ):
            raise ValueError("pair manifest identity or pin differs")
        _check_repetition_files(
            row,
            manifest,
            pinned_total=pinned_total,
            deadline_monotonic=deadline_monotonic,
        )
        ids.append(run_id)
        run_roots.append(run_root)
        frozen_manifests.append((run_id, manifest_bytes))
    if set(pair_manifests) != set(ids) or _overlap(*run_roots):
        raise ValueError("repetition roots or manifests overlap")

    controls = descriptor["controls"]
    if (
        type(controls) is not list
        or tuple(row.get("kind") if type(row) is dict else None for row in controls)
        != _CONTROL_KINDS
    ):
        raise ValueError("exact typed controls required")
    control_ids: set[str] = set()
    control_roots: list[Path] = []
    for row, pinned_total in zip(controls, control_totals, strict=True):
        _check_deadline(deadline_monotonic)
        if type(row) is not dict or set(row) != {"kind", "control_id", "root", "files"}:
            raise ValueError("control descriptor invalid")
        control_id = row["control_id"]
        if (
            type(control_id) is not str
            or _ID.fullmatch(control_id) is None
            or control_id in control_ids
            or control_id in ids
        ):
            raise ValueError("control identity invalid or reused")
        control_ids.add(control_id)
        root = _root(row["root"])
        if any(_overlap(root, other) for other in (*run_roots, *control_roots)):
            raise ValueError("control root overlaps other evidence")
        if (
            _inventory_files(
                root,
                label="control",
                max_files=_MAX_FILES,
                max_entries=_MAX_ENTRIES,
                max_total_bytes=pinned_total,
                deadline_monotonic=deadline_monotonic,
            )
            != row["files"]
        ):
            raise ValueError("control bytes changed")
        control_roots.append(root)
    return ReadinessInventory(
        descriptor_sha256=expected_sha256,
        repetition_ids=(ids[0], ids[1]),
        control_kinds=_CONTROL_KINDS,
        _descriptor_bytes=descriptor_bytes,
        _pair_manifests=tuple(frozen_manifests),
        _max_aggregate_bytes=aggregate_cap,
        _deadline_monotonic=deadline_monotonic,
    )
