"""The scored task root contains only verified Level 1 material."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from nooa_cybergym.leaderboard.cohort import freeze_harness_manifest, read_harness_manifest
from nooa_cybergym.leaderboard.workspace import (
    ControllerPaths,
    assert_level1_bundle,
    prepare_workspace,
)

TASK_FILES = ("description.txt", "README.md", "repo-vul.tar.gz", "submit.sh")


def _bundle(root: Path) -> None:
    root.mkdir()
    for name in TASK_FILES:
        (root / name).write_bytes(name.encode())


def test_level1_bundle_rejects_extra_and_missing_files(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    _bundle(root)
    (root / "patch.diff").write_text("fixed-side leak")
    with pytest.raises(RuntimeError, match="unexpected task file"):
        assert_level1_bundle(root)
    (root / "patch.diff").unlink()
    (root / "description.txt").unlink()
    with pytest.raises(RuntimeError, match="missing task file"):
        assert_level1_bundle(root)


def test_level1_bundle_rejects_symlink_and_lfs_pointer(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    _bundle(root)
    (root / "README.md").unlink()
    (root / "README.md").symlink_to(root / "description.txt")
    with pytest.raises(RuntimeError, match="symlink"):
        assert_level1_bundle(root)
    (root / "README.md").unlink()
    (root / "README.md").write_text("version https://git-lfs.github.com/spec/v1\n")
    with pytest.raises(RuntimeError, match="unresolved Git LFS pointer"):
        assert_level1_bundle(root)


@dataclass(frozen=True)
class _PinnedInputs:
    description_sha256: str
    description_bytes: int
    vulnerable_archive: SimpleNamespace
    description_lfs_pointer: bool = False
    vulnerable_archive_lfs_pointer: bool = False


class _Registry:
    def __init__(self, description: bytes, archive: bytes) -> None:
        self.inputs = _PinnedInputs(
            hashlib.sha256(description).hexdigest(),
            len(description),
            SimpleNamespace(sha256=hashlib.sha256(archive).hexdigest(), bytes=len(archive)),
        )

    def inputs_for(self, task_id: str) -> _PinnedInputs:
        assert task_id == "synthetic:length-header"
        return self.inputs


def _paths(tmp_path: Path, description: bytes, archive: bytes) -> ControllerPaths:
    data_dir = tmp_path / "master-data"
    data_dir.mkdir()
    task_assets = data_dir / "synthetic" / "length-header"
    task_assets.mkdir(parents=True)
    (task_assets / "description.txt").write_bytes(description)
    (task_assets / "repo-vul.tar.gz").write_bytes(archive)
    mask_map = tmp_path / "mask_map.json"
    mask_map.write_text("{}")
    harness = tmp_path / "generic-harness"
    harness.mkdir()
    (harness / "prompt.md").write_text("Generic task prompt\n")
    harness_manifest = tmp_path / "harness-manifest.json"
    harness_manifest.write_bytes(freeze_harness_manifest(harness))
    generator_source = Path(__file__).resolve()
    return ControllerPaths(
        data_dir=data_dir,
        mask_map_path=mask_map,
        server="http://submission.internal:8666",
        staging_root=tmp_path / "staging",
        evidence_root=tmp_path / "evidence",
        harness_dir=harness,
        harness_manifest_path=harness_manifest,
        harness_manifest_sha256=hashlib.sha256(harness_manifest.read_bytes()).hexdigest(),
        mask_map_sha256=hashlib.sha256(mask_map.read_bytes()).hexdigest(),
        generator_source=generator_source,
        generator_sha256=hashlib.sha256(generator_source.read_bytes()).hexdigest(),
        official_registry=_Registry(description, archive),
    )


def _generator(description: bytes, archive: bytes, *, extra: bool = False):
    def generate(config: object) -> object:
        assert str(config.difficulty) == "level1"
        assert config.with_flag is False
        assert config.mask_map_path is not None
        assert config.mask_map_path.is_relative_to(config.data_dir.parent)
        assert config.mask_map_path.read_text() == "{}"
        for name, content in {
            "description.txt": description,
            "README.md": b"Instructions\n",
            "repo-vul.tar.gz": archive,
            "submit.sh": b"#!/bin/sh\n",
        }.items():
            (config.out_dir / name).write_bytes(content)
        if extra:
            (config.out_dir / "repo-fix.tar.gz").write_bytes(b"fixed")
        return SimpleNamespace(agent_id=config.agent_id)

    return generate


def test_prepare_workspace_copies_verified_bytes_and_externalizes_manifest(
    tmp_path: Path,
) -> None:
    description, archive = b"A parser issue\n", b"\x1f\x8barchive"
    paths = _paths(tmp_path, description, archive)
    root = tmp_path / "agent-visible"

    prepared = prepare_workspace(
        task_id="synthetic:length-header",
        agent_id="masked-1",
        controller_paths=paths,
        task_root=root,
        task_generator=_generator(description, archive),
    )

    assert prepared.root == root
    assert {p.name for p in root.iterdir()} == {*TASK_FILES, "harness", "src", "output"}
    assert list((root / "src").iterdir()) == []
    assert list((root / "output").iterdir()) == []
    assert (root / "description.txt").read_bytes() == description
    assert (root / "repo-vul.tar.gz").read_bytes() == archive
    assert prepared.task_manifest.is_file()
    assert not prepared.task_manifest.is_relative_to(root)
    manifest = json.loads(prepared.task_manifest.read_text())
    assert manifest["file_hashes"]["description.txt"] == hashlib.sha256(description).hexdigest()
    assert prepared.file_hashes["repo-vul.tar.gz"] == hashlib.sha256(archive).hexdigest()
    assert not ((root / "submit.sh").stat().st_mode & 0o222)


def test_prepare_workspace_fails_closed_on_leak_or_identity_mismatch(tmp_path: Path) -> None:
    description, archive = b"A parser issue\n", b"\x1f\x8barchive"
    paths = _paths(tmp_path, description, archive)
    root = tmp_path / "agent-visible"
    with pytest.raises(RuntimeError, match="unexpected task file"):
        prepare_workspace(
            task_id="synthetic:length-header",
            agent_id="masked-1",
            controller_paths=paths,
            task_root=root,
            task_generator=_generator(description, archive, extra=True),
        )
    assert not root.exists()

    with pytest.raises(RuntimeError, match="pinned description"):
        prepare_workspace(
            task_id="synthetic:length-header",
            agent_id="masked-1",
            controller_paths=paths,
            task_root=root,
            task_generator=_generator(b"tampered", archive),
        )
    assert not root.exists()


def test_prepare_workspace_rejects_untrusted_harness_and_overlapping_roots(
    tmp_path: Path,
) -> None:
    description, archive = b"A parser issue\n", b"\x1f\x8barchive"
    paths = _paths(tmp_path, description, archive)
    (paths.harness_dir / ".env").write_text("do not copy")
    root = tmp_path / "agent-visible"
    with pytest.raises(RuntimeError, match="forbidden generic harness path"):
        prepare_workspace(
            task_id="synthetic:length-header",
            agent_id="masked-1",
            controller_paths=paths,
            task_root=root,
            task_generator=_generator(description, archive),
        )
    assert not root.exists()
    (paths.harness_dir / ".env").unlink()

    private_file = tmp_path / "task-specific.txt"
    private_file.write_text("task-specific answer source")
    linked_file = paths.harness_dir / "alias.txt"
    linked_file.symlink_to(private_file)
    with pytest.raises(RuntimeError, match="generic harness link is forbidden"):
        prepare_workspace(
            task_id="synthetic:length-header",
            agent_id="masked-1",
            controller_paths=paths,
            task_root=root,
            task_generator=_generator(description, archive),
        )
    assert not root.exists()
    linked_file.unlink()

    with pytest.raises(RuntimeError, match="controller path overlaps"):
        prepare_workspace(
            task_id="synthetic:length-header",
            agent_id="masked-1",
            controller_paths=paths,
            task_root=paths.evidence_root / "bad",
            task_generator=_generator(description, archive),
        )
    assert not (paths.evidence_root / "bad").exists()


def test_prepare_workspace_rejects_unlisted_generic_harness_file_before_exposure(
    tmp_path: Path,
) -> None:
    description, archive = b"A parser issue\n", b"\x1f\x8barchive"
    paths = _paths(tmp_path, description, archive)
    (paths.harness_dir / "notes.txt").write_text("task-specific answer source")
    root = tmp_path / "agent-visible"
    with pytest.raises(RuntimeError, match="unexpected generic harness file"):
        prepare_workspace(
            task_id="synthetic:length-header",
            agent_id="masked-1",
            controller_paths=paths,
            task_root=root,
            task_generator=_generator(description, archive),
        )
    assert not root.exists()


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ("manifest", "frozen harness manifest hash mismatch"),
        ("harness", "generic harness hash mismatch"),
        ("mask_map", "mask map differs"),
        ("generator", "generator source differs"),
    ],
)
def test_prepare_workspace_rejects_changed_frozen_inputs_before_exposure(
    tmp_path: Path, change: str, message: str
) -> None:
    description, archive = b"A parser issue\n", b"\x1f\x8barchive"
    paths = _paths(tmp_path, description, archive)
    if change == "manifest":
        paths.harness_manifest_path.write_bytes(paths.harness_manifest_path.read_bytes() + b" ")
    elif change == "harness":
        (paths.harness_dir / "prompt.md").write_text("Changed generic prompt\n")
    elif change == "mask_map":
        paths.mask_map_path.write_text('{"changed": true}')
    else:
        paths = replace(paths, generator_sha256="0" * 64)
    root = tmp_path / "agent-visible"
    with pytest.raises(RuntimeError, match=message):
        prepare_workspace(
            task_id="synthetic:length-header",
            agent_id="masked-1",
            controller_paths=paths,
            task_root=root,
            task_generator=_generator(description, archive),
        )
    assert not root.exists()


def test_prepare_workspace_rejects_unlisted_empty_harness_directory(
    tmp_path: Path,
) -> None:
    description, archive = b"A parser issue\n", b"\x1f\x8barchive"
    paths = _paths(tmp_path, description, archive)
    (paths.harness_dir / "extra").mkdir()
    root = tmp_path / "agent-visible"
    with pytest.raises(RuntimeError, match="unexpected generic harness directory"):
        prepare_workspace(
            task_id="synthetic:length-header",
            agent_id="masked-1",
            controller_paths=paths,
            task_root=root,
            task_generator=_generator(description, archive),
        )
    assert not root.exists()


def test_frozen_harness_manifest_rejects_path_traversal_even_with_matching_digest(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "harness-manifest.json"
    manifest.write_bytes(
        json.dumps(
            {
                "schema_version": 1,
                "file_hashes": {"../task-specific.txt": "0" * 64},
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    )
    with pytest.raises(RuntimeError, match="frozen harness manifest is invalid"):
        read_harness_manifest(
            manifest, expected_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest()
        )


def test_prepare_workspace_rejects_harness_corrupted_during_final_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    description, archive = b"A parser issue\n", b"\x1f\x8barchive"
    paths = _paths(tmp_path, description, archive)
    root = tmp_path / "agent-visible"
    from nooa_cybergym.leaderboard import workspace

    real_copyfile = workspace.shutil.copyfile

    def corrupt_final_harness_copy(source: Path, destination: Path) -> None:
        real_copyfile(source, destination)
        if destination == root / "harness" / "prompt.md":
            destination.write_text("task-specific answer source")

    monkeypatch.setattr(workspace.shutil, "copyfile", corrupt_final_harness_copy)
    with pytest.raises(RuntimeError, match="generic harness changed during workspace copy"):
        prepare_workspace(
            task_id="synthetic:length-header",
            agent_id="masked-1",
            controller_paths=paths,
            task_root=root,
            task_generator=_generator(description, archive),
        )
    assert not root.exists()


def test_prepare_workspace_rejects_mask_map_corrupted_during_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    description, archive = b"A parser issue\n", b"\x1f\x8barchive"
    paths = _paths(tmp_path, description, archive)
    root = tmp_path / "agent-visible"
    from nooa_cybergym.leaderboard import workspace

    real_copyfile = workspace.shutil.copyfile

    def corrupt_staged_mask_map(source: Path, destination: Path) -> None:
        real_copyfile(source, destination)
        if destination.name == "mask_map.json" and destination.is_relative_to(paths.staging_root):
            destination.write_text("tampered")

    monkeypatch.setattr(workspace.shutil, "copyfile", corrupt_staged_mask_map)
    with pytest.raises(RuntimeError, match="mask map changed during staging"):
        prepare_workspace(
            task_id="synthetic:length-header",
            agent_id="masked-1",
            controller_paths=paths,
            task_root=root,
            task_generator=_generator(description, archive),
        )
    assert not root.exists()


def test_prepare_workspace_rejects_insufficient_disk_before_materialization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    description, archive = b"A parser issue\n", b"\x1f\x8barchive"
    paths = _paths(tmp_path, description, archive)
    root = tmp_path / "agent-visible"
    from nooa_cybergym.leaderboard import workspace

    free = 4 * len(archive) + (1 << 30) - 1
    monkeypatch.setattr(
        workspace.shutil,
        "disk_usage",
        lambda _: SimpleNamespace(total=free, used=0, free=free),
    )
    hydrated = False

    def reject_materialization(**_: object) -> None:
        nonlocal hydrated
        hydrated = True
        raise AssertionError("task hydration began before disk preflight")

    monkeypatch.setattr(workspace, "_materialize_task_asset", reject_materialization)
    with pytest.raises(RuntimeError, match="insufficient disk capacity"):
        prepare_workspace(
            task_id="synthetic:length-header",
            agent_id="masked-1",
            controller_paths=paths,
            task_root=root,
            task_generator=_generator(description, archive),
        )
    assert not hydrated
    assert not root.exists()


def test_prepare_workspace_materializes_lfs_only_in_controller_staging(tmp_path: Path) -> None:
    description, archive = b"A parser issue\n", b"\x1f\x8barchive"
    paths = _paths(tmp_path, description, archive)
    source = paths.data_dir / "synthetic" / "length-header" / "repo-vul.tar.gz"
    source.write_text(
        "version https://git-lfs.github.com/spec/v1\n"
        f"oid sha256:{hashlib.sha256(archive).hexdigest()}\n"
        f"size {len(archive)}\n"
    )
    paths.official_registry.inputs = _PinnedInputs(
        hashlib.sha256(description).hexdigest(),
        len(description),
        SimpleNamespace(sha256=hashlib.sha256(archive).hexdigest(), bytes=len(archive)),
        vulnerable_archive_lfs_pointer=True,
    )
    calls: list[Path] = []

    def materialize(pointer: Path, destination: Path, cache: Path) -> None:
        assert pointer == source
        assert destination.is_relative_to(paths.staging_root)
        assert cache.is_relative_to(paths.staging_root)
        calls.append(pointer)
        destination.write_bytes(archive)

    def generate(config: object) -> object:
        hydrated = config.data_dir / "synthetic" / "length-header" / "repo-vul.tar.gz"
        assert hydrated.read_bytes() == archive
        return _generator(description, archive)(config)

    prepared = prepare_workspace(
        task_id="synthetic:length-header",
        agent_id="masked-1",
        controller_paths=paths,
        task_root=tmp_path / "agent-visible",
        task_generator=generate,
        lfs_materializer=materialize,
    )
    assert calls == [source]
    assert (prepared.root / "repo-vul.tar.gz").read_bytes() == archive
    assert source.read_bytes().startswith(b"version https://git-lfs")
