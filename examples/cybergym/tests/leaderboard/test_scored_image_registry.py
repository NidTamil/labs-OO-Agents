# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""A scored task can use only its own two controller-private image digests."""

from __future__ import annotations

import hashlib
import json

import pytest
from nooa_cybergym.leaderboard.scored_image_registry import ScoredImageRegistry

IDS = tuple([f"arvo:{i}" for i in range(1368)] + [f"oss-fuzz:{i}" for i in range(139)])


def _manifest():
    return {
        "schema_version": 1,
        "scope": "scored_official_images",
        "images": [
            {
                "task_id": task_id,
                "vulnerable": "sha256:" + hashlib.sha256(f"vul:{task_id}".encode()).hexdigest(),
                "fixed": "sha256:" + hashlib.sha256(f"fix:{task_id}".encode()).hexdigest(),
            }
            for task_id in IDS
        ],
    }


def _write(path, value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def test_scored_image_manifest_binds_both_families_and_exact_cohort_order(tmp_path):
    path = tmp_path / "scored-images.json"
    value = _manifest()
    digest = _write(path, value)
    registry = ScoredImageRegistry.load(path, expected_sha256=digest, task_ids=IDS)
    assert registry.images_for(IDS[0]).vulnerable == value["images"][0]["vulnerable"]
    assert registry.images_for(IDS[-1]).fixed == value["images"][-1]["fixed"]
    with pytest.raises(KeyError):
        registry.images_for("arvo:99999")
    with pytest.raises(RuntimeError, match="order|cohort"):
        ScoredImageRegistry.load(path, expected_sha256=digest, task_ids=IDS[::-1])
    value["images"][-1]["fixed"] = value["images"][-1]["vulnerable"]
    changed = _write(path, value)
    with pytest.raises(ValueError, match="distinct"):
        ScoredImageRegistry.load(path, expected_sha256=changed, task_ids=IDS)
