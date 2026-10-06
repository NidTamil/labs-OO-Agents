# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Controller-only lock of the full CyberGym Level 1 cohort and source bytes.

The Xeus official-input resource currently pins a ten-task validation slice.
This campaign lock covers all 1,507 tasks; its asset manifest is kept outside
every agent-visible workspace and must be signed by the Xeus evidence authority.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

_TASK_ID = re.compile(r"(arvo|oss-fuzz):([0-9]+)\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_LFS_HEADER = b"version https://git-lfs.github.com/spec/v1"
_FORBIDDEN_HARNESS_PARTS = frozenset(
    {".git", ".env", ".ssh", "repo-fix.tar.gz", "patch.diff", "error.txt", "poc"}
)


@dataclass(frozen=True)
class VulnerableArchive:
    sha256: str
    bytes: int


@dataclass(frozen=True)
class FrozenTaskInput:
    task_id: str
    description_sha256: str
    description_bytes: int
    vulnerable_archive: VulnerableArchive
    description_lfs_pointer: bool
    vulnerable_archive_lfs_pointer: bool


@dataclass(frozen=True)
class Cohort:
    benchmark_commit: str
    dataset_commit: str
    tasks_json_sha256: str
    asset_hashes_sha256: str
    mask_map_sha256: str
    generator_sha256: str
    harness_manifest_sha256: str
    task_ids: tuple[str, ...]


class FrozenAssetRegistry:
    """A verified 1,507-entry registry loaded from a locked manifest digest."""

    def __init__(self, entries: tuple[FrozenTaskInput, ...]) -> None:
        if len(entries) != 1507 or len({entry.task_id for entry in entries}) != 1507:
            raise ValueError("asset registry must contain 1507 unique tasks")
        self._entries = {entry.task_id: entry for entry in entries}
        self.task_ids = tuple(self._entries)

    def inputs_for(self, task_id: str) -> FrozenTaskInput:
        return self._entries[task_id]

    @classmethod
    def load(
        cls,
        path: Path,
        *,
        expected_sha256: str,
        expected_benchmark_commit: str | None = None,
        expected_dataset_commit: str | None = None,
    ) -> FrozenAssetRegistry:
        if not _SHA256.fullmatch(expected_sha256):
            raise ValueError("asset manifest digest must be lowercase SHA-256")
        data = _read_regular_bytes(path)
        if hashlib.sha256(data).hexdigest() != expected_sha256:
            raise RuntimeError("asset manifest disagrees with signed benchmark lock")
        payload = json.loads(data)
        if not isinstance(payload, dict) or payload.get("schema_version") != 1:
            raise ValueError("asset manifest schema is invalid")
        for field, expected in (
            ("benchmark_commit", expected_benchmark_commit),
            ("dataset_commit", expected_dataset_commit),
        ):
            if expected is None:
                continue
            label = field.replace("_", " ")
            if type(expected) is not str or not _COMMIT.fullmatch(expected):
                raise ValueError(f"expected {label} must be a lowercase Git commit")
            if payload.get(field) != expected:
                raise RuntimeError(f"asset manifest {label} disagrees with signed cohort")
        rows = payload.get("assets")
        if not isinstance(rows, list):
            raise ValueError("asset manifest assets must be a list")
        entries: list[FrozenTaskInput] = []
        for row in rows:
            if not isinstance(row, dict) or set(row) != {
                "task_id",
                "description_sha256",
                "description_bytes",
                "description_lfs_pointer",
                "vulnerable_archive_sha256",
                "vulnerable_archive_bytes",
                "vulnerable_archive_lfs_pointer",
            }:
                raise ValueError("asset manifest row is invalid")
            task_id = row["task_id"]
            description = row["description_sha256"]
            archive = row["vulnerable_archive_sha256"]
            description_bytes = row["description_bytes"]
            archive_bytes = row["vulnerable_archive_bytes"]
            if (
                not isinstance(task_id, str)
                or not _TASK_ID.fullmatch(task_id)
                or not isinstance(description, str)
                or not _SHA256.fullmatch(description)
                or not isinstance(archive, str)
                or not _SHA256.fullmatch(archive)
                or type(description_bytes) is not int
                or description_bytes <= 0
                or type(archive_bytes) is not int
                or archive_bytes <= 0
                or type(row["description_lfs_pointer"]) is not bool
                or type(row["vulnerable_archive_lfs_pointer"]) is not bool
            ):
                raise ValueError("asset manifest identity is invalid")
            entries.append(
                FrozenTaskInput(
                    task_id,
                    description,
                    description_bytes,
                    VulnerableArchive(archive, archive_bytes),
                    row["description_lfs_pointer"],
                    row["vulnerable_archive_lfs_pointer"],
                )
            )
        return cls(tuple(entries))


def _read_regular_bytes(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"required regular file is missing: {path}")
    return path.read_bytes()


def _hash_regular(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"required regular file is missing: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        first = stream.read(len(_LFS_HEADER))
        if first == _LFS_HEADER:
            raise RuntimeError(f"unresolved Git LFS pointer: {path}")
        digest.update(first)
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_asset_identity(path: Path) -> tuple[str, int, bool]:
    """Return actual bytes' identity or a Git LFS pointer's OID and size.

    A clean, revision-pinned dataset checkout authenticates the pointer. The
    task staging path must still download the object and verify these values
    before any inference; this function alone never certifies materialization.
    """

    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"required regular task asset is missing: {path}")
    with path.open("rb") as stream:
        prefix = stream.read(256)
    if prefix.startswith(_LFS_HEADER):
        try:
            lines = prefix.decode("ascii").splitlines()
            if len(lines) != 3 or lines[0] != _LFS_HEADER.decode("ascii"):
                raise ValueError("LFS pointer must contain exactly three lines")
            if not lines[1].startswith("oid sha256:") or not lines[2].startswith("size "):
                raise ValueError("LFS pointer fields are invalid")
            digest = lines[1].removeprefix("oid sha256:")
            size_text = lines[2].removeprefix("size ")
            if not _SHA256.fullmatch(digest) or not size_text.isdecimal():
                raise ValueError("LFS pointer identity is invalid")
            size = int(size_text)
            if size <= 0 or path.stat().st_size > 256:
                raise ValueError("LFS pointer size is invalid")
        except (UnicodeDecodeError, ValueError):
            raise RuntimeError(f"invalid Git LFS pointer: {path}") from None
        return digest, size, True
    return _hash_regular(path), path.stat().st_size, False


def _json_bytes(payload: object) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _harness_relative_path(value: str) -> bool:
    if type(value) is not str or not value or "\\" in value or ":" in value or "\x00" in value:
        return False
    parsed = PurePosixPath(value)
    return (
        not parsed.is_absolute()
        and bool(parsed.parts)
        and value != "."
        and parsed.as_posix() == value
        and all(part not in {"", ".", ".."} for part in parsed.parts)
        and not any(part.lower() in _FORBIDDEN_HARNESS_PARTS for part in parsed.parts)
    )


def _harness_file_hashes(root: Path) -> dict[str, str]:
    if root.is_symlink() or root.is_junction() or not root.is_dir():
        raise RuntimeError("generic harness is not a directory")
    files: dict[str, str] = {}
    directories: set[str] = set()
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink() or path.is_junction():
            raise RuntimeError(f"generic harness link is forbidden: {relative}")
        if not _harness_relative_path(relative):
            raise RuntimeError(f"forbidden generic harness path: {relative}")
        if path.is_file():
            files[relative] = _hash_regular(path)
        elif path.is_dir():
            directories.add(relative)
        else:
            raise RuntimeError(f"non-regular generic harness path: {relative}")
    if not files:
        raise RuntimeError("generic harness has no frozen files")
    represented_directories = {
        "/".join(PurePosixPath(name).parts[:index])
        for name in files
        for index in range(1, len(PurePosixPath(name).parts))
    }
    unlisted = sorted(directories - represented_directories)
    if unlisted:
        raise RuntimeError(f"unexpected generic harness directory: {unlisted}")
    return files


def freeze_harness_manifest(harness_dir: Path) -> bytes:
    """Produce a canonical exact path/hash manifest for one generic harness."""
    return _json_bytes({"schema_version": 1, "file_hashes": _harness_file_hashes(harness_dir)})


def read_harness_manifest(path: Path, *, expected_sha256: str) -> dict[str, str]:
    """Read only the manifest whose digest is bound by the signed cohort lock."""
    if type(expected_sha256) is not str or not _SHA256.fullmatch(expected_sha256):
        raise RuntimeError("frozen harness manifest digest is invalid")
    raw = _read_regular_bytes(path)
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise RuntimeError("frozen harness manifest hash mismatch")
    try:
        payload = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise RuntimeError("frozen harness manifest is malformed") from None
    if (
        type(payload) is not dict
        or set(payload) != {"schema_version", "file_hashes"}
        or type(payload["schema_version"]) is not int
        or payload["schema_version"] != 1
        or type(payload["file_hashes"]) is not dict
        or not payload["file_hashes"]
        or any(
            not _harness_relative_path(name)
            or type(digest) is not str
            or not _SHA256.fullmatch(digest)
            for name, digest in payload["file_hashes"].items()
        )
        or _json_bytes(payload) != raw
    ):
        raise RuntimeError("frozen harness manifest is invalid")
    return payload["file_hashes"]


def verify_harness_tree(root: Path, expected: dict[str, str]) -> tuple[Path, ...]:
    actual = _harness_file_hashes(root)
    extra = sorted(set(actual) - set(expected))
    missing = sorted(set(expected) - set(actual))
    if extra:
        raise RuntimeError(f"unexpected generic harness file: {extra}")
    if missing:
        raise RuntimeError(f"missing generic harness file: {missing}")
    for name in sorted(expected):
        if actual[name] != expected[name]:
            raise RuntimeError(f"generic harness hash mismatch: {name}")
    return tuple(root / Path(*PurePosixPath(name).parts) for name in sorted(expected))


def _clean_git_commit(repo: Path) -> str:
    status = subprocess.run(
        ["git", "-C", str(repo), "status", "--porcelain"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    if status.strip():
        raise RuntimeError(f"benchmark source checkout is dirty: {repo}")
    commit = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if not _COMMIT.fullmatch(commit):
        raise RuntimeError(f"invalid Git commit identity: {repo}")
    return commit


def freeze_cohort(
    *,
    cybergym_repo: Path,
    harness_dir: Path,
    generator_path: Path,
    output_dir: Path,
    benchmark_commit: str | None = None,
    dataset_commit: str | None = None,
) -> Cohort:
    """Lock the ordered cohort and all 1,507 vulnerable input identities."""

    if output_dir.exists() or output_dir.is_symlink():
        raise RuntimeError(f"cohort output already exists: {output_dir}")
    if (benchmark_commit is None) != (dataset_commit is None):
        raise ValueError("benchmark and dataset commits must be supplied together")
    data_root = cybergym_repo / "cybergym_data"
    asset_root = data_root / "data"
    for directory in (cybergym_repo, data_root, asset_root):
        if directory.is_symlink() or not directory.is_dir():
            raise RuntimeError(f"benchmark source directory is missing or linked: {directory}")
    if not generator_path.resolve().is_relative_to(cybergym_repo.resolve()):
        raise RuntimeError("generator source lies outside frozen benchmark checkout")
    generator_sha256 = _hash_regular(generator_path)
    harness_manifest_bytes = freeze_harness_manifest(harness_dir)
    harness_manifest_sha256 = hashlib.sha256(harness_manifest_bytes).hexdigest()
    if benchmark_commit is None:
        benchmark_commit = _clean_git_commit(cybergym_repo)
        dataset_commit = _clean_git_commit(data_root)
    else:
        # Explicit commits are useful to construct synthetic fixtures. A real
        # checkout still has to be clean and match the supplied identities.
        for source, expected in (
            (cybergym_repo, benchmark_commit),
            (data_root, dataset_commit),
        ):
            if (source / ".git").exists() and _clean_git_commit(source) != expected:
                raise RuntimeError(f"supplied commit disagrees with checkout: {source}")
    if not _COMMIT.fullmatch(benchmark_commit) or not _COMMIT.fullmatch(dataset_commit):
        raise ValueError("benchmark and dataset commits must be 40 lowercase hex digits")

    tasks_path = data_root / "tasks.json"
    mask_path = cybergym_repo / "mask_map.json"
    if not mask_path.is_file() or mask_path.is_symlink():
        raise RuntimeError("mask_map.json is missing or linked")
    rows = json.loads(_read_regular_bytes(tasks_path))
    if not isinstance(rows, list):
        raise ValueError("tasks.json must contain a JSON array")
    task_ids = [row.get("task_id") if isinstance(row, dict) else None for row in rows]
    if (
        len(task_ids) != 1507
        or any(
            not isinstance(task_id, str) or not _TASK_ID.fullmatch(task_id) for task_id in task_ids
        )
        or len(set(task_ids)) != 1507
    ):
        raise ValueError("cohort must contain 1507 unique supported task IDs")

    assets: list[dict[str, str | int | bool]] = []
    for task_id in task_ids:
        kind, number = task_id.split(":", 1)
        task_dir = asset_root / kind / number
        if task_dir.is_symlink() or not task_dir.is_dir():
            raise RuntimeError(f"materialized task directory is missing or linked: {task_id}")
        description_sha, description_bytes, description_pointer = read_asset_identity(
            task_dir / "description.txt"
        )
        archive_sha, archive_bytes, archive_pointer = read_asset_identity(
            task_dir / "repo-vul.tar.gz"
        )
        assets.append(
            {
                "task_id": task_id,
                "description_sha256": description_sha,
                "description_bytes": description_bytes,
                "description_lfs_pointer": description_pointer,
                "vulnerable_archive_sha256": archive_sha,
                "vulnerable_archive_bytes": archive_bytes,
                "vulnerable_archive_lfs_pointer": archive_pointer,
            }
        )

    asset_bytes = _json_bytes(
        {
            "schema_version": 1,
            "benchmark_commit": benchmark_commit,
            "dataset_commit": dataset_commit,
            "assets": assets,
        }
    )
    cohort = Cohort(
        benchmark_commit=benchmark_commit,
        dataset_commit=dataset_commit,
        tasks_json_sha256=_hash_regular(tasks_path),
        asset_hashes_sha256=hashlib.sha256(asset_bytes).hexdigest(),
        mask_map_sha256=_hash_regular(mask_path),
        generator_sha256=generator_sha256,
        harness_manifest_sha256=harness_manifest_sha256,
        task_ids=tuple(task_ids),
    )
    cohort_bytes = _json_bytes(
        {
            "schema_version": 1,
            "benchmark_commit": cohort.benchmark_commit,
            "dataset_commit": cohort.dataset_commit,
            "tasks_json_sha256": cohort.tasks_json_sha256,
            "asset_hashes_sha256": cohort.asset_hashes_sha256,
            "mask_map_sha256": cohort.mask_map_sha256,
            "generator_sha256": cohort.generator_sha256,
            "harness_manifest_sha256": cohort.harness_manifest_sha256,
            "difficulty": "level1",
            "task_ids": task_ids,
        }
    )
    lock_bytes = _json_bytes(
        {
            "schema_version": 1,
            "benchmark_commit": cohort.benchmark_commit,
            "dataset_commit": cohort.dataset_commit,
            "tasks_json_sha256": cohort.tasks_json_sha256,
            "mask_map_sha256": cohort.mask_map_sha256,
            "generator_sha256": cohort.generator_sha256,
            "harness_manifest_sha256": cohort.harness_manifest_sha256,
            "cohort_sha256": hashlib.sha256(cohort_bytes).hexdigest(),
            "asset_hashes_sha256": cohort.asset_hashes_sha256,
        }
    )
    output_dir.mkdir(parents=True, exist_ok=False)
    (output_dir / "cohort.json").write_bytes(cohort_bytes)
    (output_dir / "asset-hashes.json").write_bytes(asset_bytes)
    (output_dir / "harness-manifest.json").write_bytes(harness_manifest_bytes)
    (output_dir / "benchmark-lock.json").write_bytes(lock_bytes)
    return cohort
