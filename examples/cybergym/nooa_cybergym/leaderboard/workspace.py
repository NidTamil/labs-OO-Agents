"""Stage a CyberGym Level 1 bundle outside the agent boundary and verify it."""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import shutil
import stat
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Protocol
from uuid import uuid4

from .cohort import read_asset_identity, read_harness_manifest, verify_harness_tree

ALLOWED_TASK_FILES = frozenset({"description.txt", "README.md", "repo-vul.tar.gz", "submit.sh"})
_LFS_POINTER_HEADER = b"version https://git-lfs.github.com/spec/v1"
_DISK_RESERVE_BYTES = 1 << 30
_ARCHIVE_DISK_MULTIPLIER = 4


class _OfficialRegistry(Protocol):
    def inputs_for(self, task_id: str) -> object: ...


@dataclass(frozen=True)
class ControllerPaths:
    """Trusted controller paths; none is copied into the task root by reference."""

    data_dir: Path
    mask_map_path: Path
    server: str
    staging_root: Path
    evidence_root: Path
    harness_dir: Path
    harness_manifest_path: Path
    harness_manifest_sha256: str
    mask_map_sha256: str
    generator_source: Path
    generator_sha256: str
    official_registry: _OfficialRegistry | None = None


@dataclass(frozen=True)
class PreparedWorkspace:
    task_id: str
    root: Path
    task_manifest: Path
    file_hashes: dict[str, str]


def _sha256_file(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"task file is not regular: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def assert_level1_bundle(root: Path) -> None:
    """Reject every non-Level-1 top-level file before any model can see it."""

    if root.is_symlink() or not root.is_dir():
        raise RuntimeError("Level 1 task root is not a directory")
    actual = {entry.name for entry in root.iterdir()}
    unexpected = sorted(actual - ALLOWED_TASK_FILES)
    missing = sorted(ALLOWED_TASK_FILES - actual)
    if unexpected:
        raise RuntimeError(f"unexpected task file: {unexpected}")
    if missing:
        raise RuntimeError(f"missing task file: {missing}")
    for path in root.iterdir():
        if path.is_symlink():
            raise RuntimeError(f"task symlink is forbidden: {path.name}")
        if not path.is_file():
            raise RuntimeError(f"task file is not regular: {path.name}")
        with path.open("rb") as stream:
            if stream.read(len(_LFS_POINTER_HEADER)) == _LFS_POINTER_HEADER:
                raise RuntimeError(f"unresolved Git LFS pointer: {path.name}")


def _assert_controller_path_separation(paths: ControllerPaths, task_root: Path) -> None:
    task = task_root.resolve()
    for candidate in (
        paths.data_dir,
        paths.mask_map_path,
        paths.staging_root,
        paths.evidence_root,
        paths.harness_dir,
        paths.harness_manifest_path,
        paths.generator_source,
    ):
        trusted = candidate.resolve()
        if trusted == task or trusted.is_relative_to(task) or task.is_relative_to(trusted):
            # The final task root may share a higher-level parent, but must
            # never contain (or live inside) a trusted input/evidence surface.
            raise RuntimeError(f"controller path overlaps task root: {candidate}")


def _registry_for(paths: ControllerPaths) -> _OfficialRegistry:
    if paths.official_registry is None:
        raise RuntimeError("full frozen cohort asset registry is required")
    return paths.official_registry


def _require_disk_capacity(staging_root: Path, task_root: Path, archive_bytes: int) -> None:
    if type(archive_bytes) is not int or archive_bytes <= 0:
        raise RuntimeError("pinned task archive size is invalid")
    required = _ARCHIVE_DISK_MULTIPLIER * archive_bytes + _DISK_RESERVE_BYTES
    for destination in (staging_root, task_root.parent):
        existing = destination
        while not existing.exists():
            if existing == existing.parent:
                raise RuntimeError("cannot determine task disk capacity")
            existing = existing.parent
        if not existing.is_dir():
            raise RuntimeError("cannot determine task disk capacity")
        try:
            free = shutil.disk_usage(existing).free
        except OSError:
            raise RuntimeError("cannot determine task disk capacity") from None
        if free < required:
            raise RuntimeError("insufficient disk capacity for pinned task archive")


def _verify_pinned_bytes(root: Path, task_id: str, registry: _OfficialRegistry) -> None:
    inputs = registry.inputs_for(task_id)
    if _sha256_file(root / "description.txt") != inputs.description_sha256:
        raise RuntimeError("generated task disagrees with pinned description")
    if (root / "description.txt").stat().st_size != inputs.description_bytes:
        raise RuntimeError("generated task disagrees with pinned description length")
    if _sha256_file(root / "repo-vul.tar.gz") != inputs.vulnerable_archive.sha256:
        raise RuntimeError("generated task disagrees with pinned vulnerable archive")
    if (root / "repo-vul.tar.gz").stat().st_size != inputs.vulnerable_archive.bytes:
        raise RuntimeError("generated task disagrees with pinned vulnerable archive length")


def _default_lfs_materializer(source: Path, destination: Path, cache: Path) -> None:
    """Fetch one LFS object into a disposable controller cache, never the checkout."""

    cache.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment["GIT_LFS_SKIP_SMUDGE"] = "0"
    environment["GIT_LFS_SKIP_DOWNLOAD_ERRORS"] = "0"
    try:
        with source.open("rb") as pointer, destination.open("xb") as materialized:
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(source.parents[3]),
                    "-c",
                    f"lfs.storage={cache.resolve()}",
                    "lfs",
                    "smudge",
                    str(source),
                ],
                stdin=pointer,
                stdout=materialized,
                stderr=subprocess.DEVNULL,
                check=True,
                timeout=3600,
                env=environment,
            )
    except (OSError, subprocess.SubprocessError):
        raise RuntimeError("controller could not materialize pinned Git LFS object") from None


def _materialize_task_asset(
    *,
    source: Path,
    destination: Path,
    expected_sha256: str,
    expected_bytes: int,
    locked_pointer: bool,
    cache: Path,
    lfs_materializer: Callable[[Path, Path, Path], None],
) -> None:
    source_sha, source_bytes, source_pointer = read_asset_identity(source)
    if source_sha != expected_sha256 or source_bytes != expected_bytes:
        raise RuntimeError("source asset disagrees with frozen cohort identity")
    if source_pointer and not locked_pointer:
        raise RuntimeError("source became an unresolved Git LFS pointer after cohort lock")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source_pointer:
        lfs_materializer(source, destination, cache)
    else:
        shutil.copyfile(source, destination)
    if _sha256_file(destination) != expected_sha256 or destination.stat().st_size != expected_bytes:
        raise RuntimeError("materialized task asset disagrees with frozen cohort identity")


def prepare_workspace(
    *,
    task_id: str,
    agent_id: str,
    controller_paths: ControllerPaths,
    task_root: Path,
    task_generator: Callable[[object], object] | None = None,
    lfs_materializer: Callable[[Path, Path, Path], None] | None = None,
) -> PreparedWorkspace:
    """Generate, verify, copy and hash one fresh task workspace.

    The generated material is held in a controller-only staging directory.
    `task_generator` is an injectable synthetic-test seam; the production
    path always calls CyberGym's generate_task at TaskDifficulty.level1.
    """

    _assert_controller_path_separation(controller_paths, task_root)
    if task_root.exists() or task_root.is_symlink():
        raise RuntimeError(f"task root already exists: {task_root}")
    if not controller_paths.data_dir.is_dir() or not controller_paths.mask_map_path.is_file():
        raise RuntimeError("CyberGym data or mask map is missing")
    if _sha256_file(controller_paths.mask_map_path) != controller_paths.mask_map_sha256:
        raise RuntimeError("mask map differs from frozen cohort identity")
    if _sha256_file(controller_paths.generator_source) != controller_paths.generator_sha256:
        raise RuntimeError("generator source differs from frozen cohort identity")
    harness_hashes = read_harness_manifest(
        controller_paths.harness_manifest_path,
        expected_sha256=controller_paths.harness_manifest_sha256,
    )
    harness_files = verify_harness_tree(controller_paths.harness_dir, harness_hashes)
    registry = _registry_for(controller_paths)
    inputs = registry.inputs_for(task_id)
    _require_disk_capacity(
        controller_paths.staging_root, task_root, inputs.vulnerable_archive.bytes
    )
    controller_paths.staging_root.mkdir(parents=True, exist_ok=True)
    controller_paths.evidence_root.mkdir(parents=True, exist_ok=True)
    stage = controller_paths.staging_root / uuid4().hex
    stage.mkdir(mode=0o700)
    generated = stage / "generated"
    generated.mkdir(mode=0o700)
    hydrated_data = stage / "data"
    cache = stage / "lfs-cache"
    staged_harness = stage / "harness"
    staged_mask_map = stage / "mask_map.json"
    created_task_root = False
    try:
        shutil.copyfile(controller_paths.mask_map_path, staged_mask_map)
        if _sha256_file(staged_mask_map) != controller_paths.mask_map_sha256:
            raise RuntimeError("mask map changed during staging")
        for source in harness_files:
            relative = source.relative_to(controller_paths.harness_dir)
            destination = staged_harness / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            if _sha256_file(destination) != harness_hashes[relative.as_posix()]:
                raise RuntimeError(f"generic harness changed during staging: {relative}")
        kind, number = task_id.split(":", 1)
        source_task = controller_paths.data_dir / kind / number
        hydrated_task = hydrated_data / kind / number
        materialize = lfs_materializer or _default_lfs_materializer
        for name, sha256, size, was_pointer in (
            (
                "description.txt",
                inputs.description_sha256,
                inputs.description_bytes,
                inputs.description_lfs_pointer,
            ),
            (
                "repo-vul.tar.gz",
                inputs.vulnerable_archive.sha256,
                inputs.vulnerable_archive.bytes,
                inputs.vulnerable_archive_lfs_pointer,
            ),
        ):
            _materialize_task_asset(
                source=source_task / name,
                destination=hydrated_task / name,
                expected_sha256=sha256,
                expected_bytes=size,
                locked_pointer=was_pointer,
                cache=cache,
                lfs_materializer=materialize,
            )
        if task_generator is None:
            from cybergym.task.gen_task import generate_task
            from cybergym.task.types import TaskConfig, TaskDifficulty

            task_generator = generate_task
            config: object = TaskConfig(
                task_id=task_id,
                agent_id=agent_id,
                out_dir=generated,
                data_dir=hydrated_data,
                server=controller_paths.server,
                difficulty=TaskDifficulty.level1,
                mask_map_path=staged_mask_map,
                with_flag=False,
            )
        else:
            config = SimpleNamespace(
                task_id=task_id,
                agent_id=agent_id,
                out_dir=generated,
                data_dir=hydrated_data,
                server=controller_paths.server,
                difficulty="level1",
                mask_map_path=staged_mask_map,
                with_flag=False,
            )
        actual_generator_source = inspect.getsourcefile(task_generator)
        if actual_generator_source is None or Path(actual_generator_source).resolve(
            strict=True
        ) != controller_paths.generator_source.resolve(strict=True):
            raise RuntimeError("generator callable differs from frozen source")
        task_generator(config)
        if _sha256_file(controller_paths.generator_source) != controller_paths.generator_sha256:
            raise RuntimeError("generator source changed during task generation")
        assert_level1_bundle(generated)
        _verify_pinned_bytes(generated, task_id, registry)

        task_root.mkdir(mode=0o755)
        created_task_root = True
        for name in sorted(ALLOWED_TASK_FILES):
            shutil.copyfile(generated / name, task_root / name)
        (task_root / "harness").mkdir()
        for relative_name, expected_sha256 in sorted(harness_hashes.items()):
            relative = Path(*relative_name.split("/"))
            source = staged_harness / relative
            destination = task_root / "harness" / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            if _sha256_file(destination) != expected_sha256:
                raise RuntimeError(f"generic harness changed during workspace copy: {relative}")
        # Docker overlays this existing mountpoint with a fresh writable
        # tmpfs. A read-only /workspace bind prevents runc creating it later.
        (task_root / "src").mkdir()
        (task_root / "output").mkdir()
        (task_root / "submit.sh").chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)

        file_hashes = {
            path.relative_to(task_root).as_posix(): _sha256_file(path)
            for path in sorted(task_root.rglob("*"))
            if path.is_file()
        }
        manifest_dir = controller_paths.evidence_root / uuid4().hex
        manifest_dir.mkdir(mode=0o700)
        manifest = manifest_dir / "task-manifest.json"
        manifest.write_bytes(
            json.dumps(
                {
                    "schema_version": 1,
                    "task_id": task_id,
                    "agent_id": agent_id,
                    "difficulty": "level1",
                    "mask_map_sha256": controller_paths.mask_map_sha256,
                    "generator_sha256": controller_paths.generator_sha256,
                    "harness_manifest_sha256": controller_paths.harness_manifest_sha256,
                    "file_hashes": file_hashes,
                },
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        )
        manifest.chmod(stat.S_IRUSR | stat.S_IWUSR)
        return PreparedWorkspace(task_id, task_root, manifest, file_hashes)
    except BaseException:
        if created_task_root:
            shutil.rmtree(task_root)
        raise
    finally:
        shutil.rmtree(stage)
