# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""A scored task can use only its own two controller-private image digests."""

from __future__ import annotations

import base64
import hashlib
import json

import pytest
from nooa_cybergym.leaderboard.scored_image_registry import (
    ScoredImageRegistry,
    assemble_scored_image_manifest,
    verify_docker_manifest_observation,
)

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


def _docker_observation(ref: str) -> bytes:
    config_digest = "sha256:" + hashlib.sha256(("config:" + ref).encode()).hexdigest()
    manifest = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "size": 42,
                "digest": config_digest,
            },
            "layers": [],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    value = {
        "Ref": "docker.io/" + ref,
        "Descriptor": {
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "digest": "sha256:" + hashlib.sha256(manifest).hexdigest(),
            "size": len(manifest),
            "platform": {"os": "linux", "architecture": "amd64"},
        },
        "Raw": base64.b64encode(manifest).decode(),
        "SchemaV2Manifest": json.loads(manifest),
    }
    return json.dumps(value, separators=(",", ":")).encode()


def test_registry_observation_hashes_manifest_bytes_not_config_digest():
    ref = "n132/arvo:47101-vul"
    raw = _docker_observation(ref)
    value = json.loads(raw)
    assert (
        verify_docker_manifest_observation(raw, expected_ref=ref) == value["Descriptor"]["digest"]
    )
    assert value["Descriptor"]["digest"] != value["SchemaV2Manifest"]["config"]["digest"]
    value["Raw"] = base64.b64encode(base64.b64decode(value["Raw"]) + b" ").decode()
    with pytest.raises(ValueError, match="digest|size"):
        verify_docker_manifest_observation(json.dumps(value).encode(), expected_ref=ref)
    with pytest.raises(ValueError, match="reference"):
        verify_docker_manifest_observation(raw, expected_ref="n132/arvo:47101-fix")


def test_assemble_scored_images_requires_exact_two_modes_for_full_cohort(tmp_path):
    refs = {
        f"{'n132/arvo' if task_id.startswith('arvo:') else 'cybergym/oss-fuzz'}:"
        f"{task_id.split(':')[1]}-{mode}"
        for task_id in IDS
        for mode in ("vul", "fix")
    }
    observations = {ref: _docker_observation(ref) for ref in refs}
    raw = assemble_scored_image_manifest(task_ids=IDS, observations=observations)
    path = tmp_path / "images.json"
    path.write_bytes(raw)
    loaded = ScoredImageRegistry.load(
        path, expected_sha256=hashlib.sha256(raw).hexdigest(), task_ids=IDS
    )
    first_ref = "n132/arvo:0-vul"
    assert (
        loaded.images_for(IDS[0]).vulnerable
        == json.loads(observations[first_ref])["Descriptor"]["digest"]
    )
    with pytest.raises(ValueError, match="missing|extra|complete"):
        assemble_scored_image_manifest(
            task_ids=IDS, observations={k: v for k, v in observations.items() if k != first_ref}
        )
    with pytest.raises(ValueError, match="missing|extra|complete"):
        assemble_scored_image_manifest(
            task_ids=IDS, observations={**observations, "n132/arvo:99999-vul": b"{}"}
        )
