# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Controller-only image identities for every task in the signed scored cohort.

The supplied digest must come from the separately signed harness lock. This
registry contains IDs only; it never opens fixed-side images or publishes them
to an agent workspace.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

_SHA = re.compile(r"[a-f0-9]{64}\Z")
_IMAGE = re.compile(r"sha256:[a-f0-9]{64}\Z")
_TASK = re.compile(r"(?:arvo|oss-fuzz):[0-9]+\Z")


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
