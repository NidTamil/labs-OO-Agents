# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Freeze all 1,507 official task identities and vulnerable inputs once."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from nooa_cybergym.leaderboard.cohort import (
    FrozenAssetRegistry,
    freeze_cohort,
    read_asset_identity,
)


def _source(tmp_path: Path, *, tamper: bool = False, asset_count: int = 1507) -> Path:
    repo = tmp_path / "cybergym"
    data = repo / "cybergym_data"
    assets = data / "data" / "arvo"
    assets.mkdir(parents=True)
    tasks = []
    for index in range(1507):
        task_id = f"arvo:{index}"
        tasks.append({"task_id": task_id})
        if index >= asset_count:
            continue
        task_dir = assets / str(index)
        task_dir.mkdir()
        (task_dir / "description.txt").write_bytes(f"Description {index}\n".encode())
        (task_dir / "repo-vul.tar.gz").write_bytes(b"\x1f\x8b" + str(index).encode())
    if tamper:
        tasks[-1]["task_id"] = tasks[0]["task_id"]
    (data / "tasks.json").write_text(json.dumps(tasks))
    (repo / "mask_map.json").write_text("{}")
    generator = repo / "cybergym" / "task" / "gen_task.py"
    generator.parent.mkdir(parents=True)
    generator.write_text("def generate_task(config): pass\n")
    harness = tmp_path / "generic-harness"
    harness.mkdir()
    (harness / "prompt.md").write_text("Generic prompt\n")
    return repo


def test_freeze_cohort_preserves_order_and_pins_every_vulnerable_asset(
    tmp_path: Path,
) -> None:
    repo = _source(tmp_path)
    archive_content = b"\x1f\x8b0"
    (repo / "cybergym_data" / "data" / "arvo" / "0" / "repo-vul.tar.gz").write_text(
        "version https://git-lfs.github.com/spec/v1\n"
        f"oid sha256:{hashlib.sha256(archive_content).hexdigest()}\n"
        f"size {len(archive_content)}\n"
    )
    out = tmp_path / "locked"
    cohort = freeze_cohort(
        cybergym_repo=repo,
        harness_dir=tmp_path / "generic-harness",
        generator_path=repo / "cybergym" / "task" / "gen_task.py",
        output_dir=out,
        benchmark_commit="1" * 40,
        dataset_commit="2" * 40,
    )
    assert len(cohort.task_ids) == 1507
    assert cohort.task_ids[0] == "arvo:0"
    assert cohort.task_ids[-1] == "arvo:1506"
    registry = FrozenAssetRegistry.load(
        out / "asset-hashes.json",
        expected_sha256=hashlib.sha256((out / "asset-hashes.json").read_bytes()).hexdigest(),
        expected_benchmark_commit="1" * 40,
        expected_dataset_commit="2" * 40,
    )
    assert len(registry.task_ids) == 1507
    pinned = registry.inputs_for("arvo:0")
    assert pinned.description_sha256 == hashlib.sha256(b"Description 0\n").hexdigest()
    assert pinned.description_bytes == len(b"Description 0\n")
    assert pinned.vulnerable_archive.sha256 == hashlib.sha256(b"\x1f\x8b0").hexdigest()
    assert pinned.vulnerable_archive.bytes == len(b"\x1f\x8b0")
    assert pinned.vulnerable_archive_lfs_pointer is True
    lock = json.loads((out / "benchmark-lock.json").read_text())
    assert lock["cohort_sha256"] == hashlib.sha256((out / "cohort.json").read_bytes()).hexdigest()
    assert (
        lock["asset_hashes_sha256"]
        == hashlib.sha256((out / "asset-hashes.json").read_bytes()).hexdigest()
        == cohort.asset_hashes_sha256
    )
    frozen = json.loads((out / "cohort.json").read_text())
    assert frozen["asset_hashes_sha256"] == cohort.asset_hashes_sha256
    assert (
        lock["harness_manifest_sha256"]
        == hashlib.sha256((out / "harness-manifest.json").read_bytes()).hexdigest()
        == cohort.harness_manifest_sha256
    )
    assert lock["generator_sha256"] == cohort.generator_sha256
    assert lock["mask_map_sha256"] == cohort.mask_map_sha256
    with pytest.raises(RuntimeError, match="benchmark commit"):
        FrozenAssetRegistry.load(
            out / "asset-hashes.json",
            expected_sha256=cohort.asset_hashes_sha256,
            expected_benchmark_commit="3" * 40,
            expected_dataset_commit="2" * 40,
        )
    with pytest.raises(RuntimeError, match="dataset commit"):
        FrozenAssetRegistry.load(
            out / "asset-hashes.json",
            expected_sha256=cohort.asset_hashes_sha256,
            expected_benchmark_commit="1" * 40,
            expected_dataset_commit="3" * 40,
        )


def test_freeze_cohort_rejects_duplicate_id_before_writing(tmp_path: Path) -> None:
    repo = _source(tmp_path, tamper=True, asset_count=0)
    out = tmp_path / "locked"
    with pytest.raises(ValueError, match="1507 unique"):
        freeze_cohort(
            cybergym_repo=repo,
            harness_dir=tmp_path / "generic-harness",
            generator_path=repo / "cybergym" / "task" / "gen_task.py",
            output_dir=out,
            benchmark_commit="1" * 40,
            dataset_commit="2" * 40,
        )
    assert not out.exists()


def test_lfs_identity_is_pinned_without_bulk_download(tmp_path: Path) -> None:
    pointer = tmp_path / "repo-vul.tar.gz"
    content = b"large synthetic archive"
    digest = hashlib.sha256(content).hexdigest()
    pointer.write_text(
        f"version https://git-lfs.github.com/spec/v1\noid sha256:{digest}\nsize {len(content)}\n"
    )
    assert read_asset_identity(pointer) == (digest, len(content), True)
    pointer.write_text("version https://git-lfs.github.com/spec/v1\nsize 10\n")
    with pytest.raises(RuntimeError, match="invalid Git LFS pointer"):
        read_asset_identity(pointer)


def test_freeze_cohort_rejects_missing_mask_map(tmp_path: Path) -> None:
    repo = _source(tmp_path, asset_count=1)
    (repo / "mask_map.json").unlink()
    with pytest.raises(RuntimeError, match="mask_map"):
        freeze_cohort(
            cybergym_repo=repo,
            harness_dir=tmp_path / "generic-harness",
            generator_path=repo / "cybergym" / "task" / "gen_task.py",
            output_dir=tmp_path / "locked",
            benchmark_commit="1" * 40,
            dataset_commit="2" * 40,
        )


def test_explicit_commit_cannot_override_a_real_checkout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _source(tmp_path, asset_count=0)
    (repo / ".git").mkdir()
    monkeypatch.setattr("nooa_cybergym.leaderboard.cohort._clean_git_commit", lambda _: "3" * 40)
    with pytest.raises(RuntimeError, match="supplied commit disagrees"):
        freeze_cohort(
            cybergym_repo=repo,
            harness_dir=tmp_path / "generic-harness",
            generator_path=repo / "cybergym" / "task" / "gen_task.py",
            output_dir=tmp_path / "locked",
            benchmark_commit="1" * 40,
            dataset_commit="2" * 40,
        )
    assert not (tmp_path / "locked").exists()
