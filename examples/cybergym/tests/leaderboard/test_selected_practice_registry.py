# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""The practice worker must never admit a third task or fixed-side asset."""

import hashlib
import json

import pytest
from nooa_cybergym.leaderboard.practice_campaign import PRACTICE_TASK_IDS
from nooa_cybergym.leaderboard.selected_practice_registry import SelectedPracticeRegistry


def _manifest():
    return {
        "schema_version": 1,
        "scope": "native_practice_level1",
        "assets": [
            {
                "task_id": task_id,
                "description_sha256": "a" * 64,
                "description_bytes": 12,
                "description_lfs_pointer": False,
                "vulnerable_archive_sha256": "b" * 64,
                "vulnerable_archive_bytes": 34,
                "vulnerable_archive_lfs_pointer": False,
            }
            for task_id in PRACTICE_TASK_IDS
        ],
    }


def test_selected_registry_admits_only_ordered_pair(tmp_path):
    source = tmp_path / "practice-assets.json"
    source.write_text(json.dumps(_manifest()), encoding="utf-8")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    registry = SelectedPracticeRegistry.load(source, expected_sha256=digest)
    assert registry.task_ids == PRACTICE_TASK_IDS
    assert registry.inputs_for("arvo:47101").vulnerable_archive.sha256 == "b" * 64
    with pytest.raises(KeyError):
        registry.inputs_for("arvo:1065")


@pytest.mark.parametrize("mutation", ["third", "reorder", "fixed", "hash"])
def test_selected_registry_rejects_extra_or_changed_input(tmp_path, mutation):
    payload = _manifest()
    if mutation == "third":
        payload["assets"].append({**payload["assets"][0], "task_id": "arvo:1065"})
    elif mutation == "reorder":
        payload["assets"].reverse()
    elif mutation == "fixed":
        payload["assets"][0]["fixed_archive_sha256"] = "c" * 64
    else:
        payload["assets"][0]["description_sha256"] = "0" * 64
    source = tmp_path / "practice-assets.json"
    source.write_text(json.dumps(payload), encoding="utf-8")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="practice|selected"):
        SelectedPracticeRegistry.load(source, expected_sha256=digest)


def test_selected_registry_rejects_unpinned_bytes(tmp_path):
    source = tmp_path / "practice-assets.json"
    source.write_text(json.dumps(_manifest()), encoding="utf-8")
    with pytest.raises(RuntimeError, match="practice"):
        SelectedPracticeRegistry.load(source, expected_sha256="f" * 64)
