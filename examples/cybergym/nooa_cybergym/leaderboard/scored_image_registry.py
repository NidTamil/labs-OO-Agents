# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Controller-only image identities for every task in the signed scored cohort.

The supplied digest must come from the separately signed harness lock. This
registry contains IDs only; it never opens fixed-side images or publishes them
to an agent workspace.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

_SHA = re.compile(r"[a-f0-9]{64}\Z")
_IMAGE = re.compile(r"sha256:[a-f0-9]{64}\Z")
_TASK = re.compile(r"(?:arvo|oss-fuzz):[0-9]+\Z")
_REF = re.compile(r"(?:n132/arvo|cybergym/oss-fuzz):[0-9]+-(?:vul|fix)\Z")
_MANIFEST_TYPES = frozenset(
    {
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
    }
)


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate registry manifest key")
        value[key] = item
    return value


def verify_docker_manifest_observation(raw_output: bytes, *, expected_ref: str) -> str:
    """Hash a registry manifest's raw bytes, never its image-config digest."""
    if (
        type(raw_output) is not bytes
        or not 0 < len(raw_output) <= 2 * 1024 * 1024
        or type(expected_ref) is not str
        or _REF.fullmatch(expected_ref) is None
    ):
        raise ValueError("bounded registry observation and reference required")
    try:
        observed = json.loads(raw_output, object_pairs_hook=_unique_pairs)
    except (UnicodeDecodeError, ValueError):
        raise ValueError("registry observation JSON is invalid") from None
    if type(observed) is not dict or observed.get("Ref") != f"docker.io/{expected_ref}":
        raise ValueError("registry observation reference differs")
    descriptor = observed.get("Descriptor")
    if type(descriptor) is not dict:
        raise ValueError("registry manifest descriptor absent")
    digest = descriptor.get("digest")
    media_type = descriptor.get("mediaType")
    platform = descriptor.get("platform")
    size = descriptor.get("size")
    if (
        type(digest) is not str
        or _IMAGE.fullmatch(digest) is None
        or media_type not in _MANIFEST_TYPES
        or type(size) is not int
        or not 0 < size <= 1024 * 1024
        or type(platform) is not dict
        or platform.get("os") != "linux"
        or platform.get("architecture") != "amd64"
    ):
        raise ValueError("Linux/amd64 registry manifest descriptor required")
    try:
        manifest_bytes = base64.b64decode(observed["Raw"], validate=True)
        manifest = json.loads(manifest_bytes, object_pairs_hook=_unique_pairs)
    except (KeyError, TypeError, binascii.Error, UnicodeDecodeError, ValueError):
        raise ValueError("raw registry manifest is invalid") from None
    if (
        len(manifest_bytes) != size
        or "sha256:" + hashlib.sha256(manifest_bytes).hexdigest() != digest
    ):
        raise ValueError("raw registry manifest size or digest differs")
    if (
        type(manifest) is not dict
        or manifest.get("schemaVersion") != 2
        or manifest.get("mediaType") != media_type
        or type(manifest.get("config")) is not dict
        or type(manifest["config"].get("digest")) is not str
        or _IMAGE.fullmatch(manifest["config"]["digest"]) is None
        or type(manifest.get("layers")) is not list
        or observed.get("SchemaV2Manifest") != manifest
    ):
        raise ValueError("parsed registry manifest differs from raw image manifest")
    return digest


def assemble_scored_image_manifest(
    *, task_ids: tuple[str, ...], observations: dict[str, bytes]
) -> bytes:
    """Create an unsigned exact-order candidate from independently hashed metadata."""
    if (
        type(task_ids) is not tuple
        or len(task_ids) != 1507
        or len(set(task_ids)) != 1507
        or any(type(task) is not str or _TASK.fullmatch(task) is None for task in task_ids)
        or type(observations) is not dict
    ):
        raise ValueError("complete signed-cohort image identities required")
    refs = {}
    for task_id in task_ids:
        family, number = task_id.split(":", 1)
        repository = "n132/arvo" if family == "arvo" else "cybergym/oss-fuzz"
        refs[task_id] = (f"{repository}:{number}-vul", f"{repository}:{number}-fix")
    if set(observations) != {ref for pair in refs.values() for ref in pair}:
        raise ValueError(
            "complete cohort registry observations required; missing or extra reference"
        )
    images = []
    for task_id in task_ids:
        vulnerable_ref, fixed_ref = refs[task_id]
        vulnerable = verify_docker_manifest_observation(
            observations[vulnerable_ref], expected_ref=vulnerable_ref
        )
        fixed = verify_docker_manifest_observation(observations[fixed_ref], expected_ref=fixed_ref)
        if vulnerable == fixed:
            raise ValueError("distinct vulnerable and fixed image manifests required")
        images.append({"task_id": task_id, "vulnerable": vulnerable, "fixed": fixed})
    return json.dumps(
        {"schema_version": 1, "scope": "scored_official_images", "images": images},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


@dataclass(frozen=True, slots=True)
class ScoredImages:
    vulnerable: str
    fixed: str


class ScoredImageRegistry:
    """Exact-order, separately pinned private evaluator image pairs."""

    def __init__(self, rows: tuple[tuple[str, ScoredImages], ...]) -> None:
        self.task_ids = tuple(task_id for task_id, _ in rows)
        self._images = dict(rows)

    def images_for(self, task_id: str) -> ScoredImages:
        return self._images[task_id]

    @classmethod
    def load(
        cls, path: Path, *, expected_sha256: str, task_ids: tuple[str, ...]
    ) -> ScoredImageRegistry:
        source = Path(path)
        if (
            not source.is_absolute()
            or source.is_symlink()
            or not source.is_file()
            or source.resolve() != source
            or not 0 < source.stat().st_size <= 1024 * 1024
            or type(expected_sha256) is not str
            or _SHA.fullmatch(expected_sha256) is None
            or type(task_ids) is not tuple
            or len(task_ids) != 1507
            or any(type(item) is not str or _TASK.fullmatch(item) is None for item in task_ids)
            or len(set(task_ids)) != 1507
        ):
            raise ValueError("bounded signed-cohort image manifest inputs required")
        raw = source.read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected_sha256:
            raise RuntimeError("scored image manifest differs from signed harness lock")
        try:
            value = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            raise ValueError("scored image manifest JSON is invalid") from None
        if (
            type(value) is not dict
            or set(value) != {"schema_version", "scope", "images"}
            or type(value["schema_version"]) is not int
            or value["schema_version"] != 1
            or value["scope"] != "scored_official_images"
            or type(value["images"]) is not list
            or len(value["images"]) != len(task_ids)
            or json.dumps(value, sort_keys=True, separators=(",", ":")).encode() != raw
        ):
            raise ValueError("scored image manifest schema or canonical bytes differ")
        rows = []
        for index, row in enumerate(value["images"]):
            if (
                type(row) is not dict
                or set(row) != {"task_id", "vulnerable", "fixed"}
                or row["task_id"] != task_ids[index]
                or type(row["vulnerable"]) is not str
                or _IMAGE.fullmatch(row["vulnerable"]) is None
                or type(row["fixed"]) is not str
                or _IMAGE.fullmatch(row["fixed"]) is None
            ):
                raise RuntimeError("scored image task order or cohort identity differs")
            if row["vulnerable"] == row["fixed"]:
                raise ValueError("distinct vulnerable and fixed scored images required")
            rows.append((row["task_id"], ScoredImages(row["vulnerable"], row["fixed"])))
        return cls(tuple(rows))
