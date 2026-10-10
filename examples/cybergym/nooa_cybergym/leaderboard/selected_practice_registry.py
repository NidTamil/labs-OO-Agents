# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Two-task asset registry for isolated native practice admission."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from .cohort import FrozenTaskInput, VulnerableArchive
from .practice_campaign import PRACTICE_TASK_IDS

_SHA = re.compile(r"[a-f0-9]{64}\Z")
_ROW_FIELDS = frozenset(
    {
        "task_id",
        "description_sha256",
        "description_bytes",
        "description_lfs_pointer",
        "vulnerable_archive_sha256",
        "vulnerable_archive_bytes",
        "vulnerable_archive_lfs_pointer",
    }
)


class SelectedPracticeRegistry:
    def __init__(self, entries: tuple[FrozenTaskInput, FrozenTaskInput]):
        if tuple(entry.task_id for entry in entries) != PRACTICE_TASK_IDS:
            raise ValueError("selected practice task order differs")
        self._entries = {entry.task_id: entry for entry in entries}
        self.task_ids = PRACTICE_TASK_IDS

    def inputs_for(self, task_id: str) -> FrozenTaskInput:
        return self._entries[task_id]

    @classmethod
    def load(cls, path: Path, *, expected_sha256: str) -> SelectedPracticeRegistry:
        source = Path(path)
        if (
            type(expected_sha256) is not str
            or _SHA.fullmatch(expected_sha256) is None
            or not source.is_absolute()
            or source.is_symlink()
            or not source.is_file()
            or not 0 < source.stat().st_size <= 16 * 1024
        ):
            raise ValueError("bounded selected practice asset manifest required")
        raw = source.read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected_sha256:
            raise RuntimeError("selected practice asset manifest hash mismatch")
        try:
            payload = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            raise ValueError("selected practice asset manifest is malformed") from None
        if (
            type(payload) is not dict
            or set(payload) != {"schema_version", "scope", "assets"}
            or payload["schema_version"] != 1
            or payload["scope"] != "native_practice_level1"
            or type(payload["assets"]) is not list
            or len(payload["assets"]) != 2
        ):
            raise ValueError("selected practice asset manifest shape differs")
        entries = []
        for expected_id, row in zip(PRACTICE_TASK_IDS, payload["assets"], strict=True):
            if (
                type(row) is not dict
                or set(row) != _ROW_FIELDS
                or row["task_id"] != expected_id
                or any(
                    type(row[name]) is not str
                    or _SHA.fullmatch(row[name]) is None
                    or row[name] == "0" * 64
                    for name in ("description_sha256", "vulnerable_archive_sha256")
                )
                or any(
                    type(row[name]) is not int or row[name] <= 0
                    for name in ("description_bytes", "vulnerable_archive_bytes")
                )
                or row["description_lfs_pointer"] is not False
                or row["vulnerable_archive_lfs_pointer"] is not False
            ):
                raise ValueError("selected practice asset row differs")
            entries.append(
                FrozenTaskInput(
                    expected_id,
                    row["description_sha256"],
                    row["description_bytes"],
                    VulnerableArchive(
                        row["vulnerable_archive_sha256"], row["vulnerable_archive_bytes"]
                    ),
                    False,
                    False,
                )
            )
        return cls(tuple(entries))
