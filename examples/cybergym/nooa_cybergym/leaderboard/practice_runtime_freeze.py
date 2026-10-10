# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Exact, two-task practice freeze independent of the scored go-live gate."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PurePosixPath

from xeus_cybergym.canonical import canonical_json

from .practice_campaign import PRACTICE_TASK_IDS

_DIGEST = re.compile(r"[a-f0-9]{64}\Z")
_RUN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_ALIAS = re.compile(r"cybergym-[a-z0-9-]{1,56}\Z")
_REFS = frozenset(
    {
        "donor_config",
        "bindings",
        "asset_hashes",
        "selected_manifest",
        "code_archive",
        "signed_report",
        "report",
        "official_verifier",
        "public_ssh_key",
        "mask_map",
        "harness_manifest",
        "generator_source",
    }
)
_PATHS = frozenset({"input_root", "code_root", "staging_root", "evidence_root"})
_HASHES = frozenset(
    {
        "selected_assets_sha256",
        "host_key_sha256",
        "vscode_exe_sha256",
        "evaluator_public_key_sha256",
    }
)
_FIELDS = (
    frozenset(
        {
            "schema_version",
            "scope",
            "run_id",
            "epoch",
            "task_ids",
            "max_parallel_tasks",
            "remote_alias",
            "ssh_ports",
            "images",
            "evaluator_private_key_path",
            "evaluator_key_id",
        }
    )
    | _REFS
    | _PATHS
    | _HASHES
)


def _absolute(value: object) -> bool:
    return type(value) is str and PurePosixPath(value).is_absolute() and "\x00" not in value


def validate_practice_freeze(value: object) -> dict:
    """Reject extra fields, task drift, host drift, and unsupported concurrency."""
    if type(value) is not dict or set(value) != _FIELDS:
        raise ValueError("practice freeze fields differ")
    if (
        value["schema_version"] != 1
        or value["scope"] != "native_practice_level1"
        or type(value["run_id"]) is not str
        or _RUN.fullmatch(value["run_id"]) is None
        or type(value["epoch"]) is not str
        or _RUN.fullmatch(value["epoch"]) is None
        or value["task_ids"] != list(PRACTICE_TASK_IDS)
        or type(value["max_parallel_tasks"]) is not int
        or value["max_parallel_tasks"] != 1
        or type(value["remote_alias"]) is not str
        or _ALIAS.fullmatch(value["remote_alias"]) is None
        or any(not _absolute(value[name]) for name in _PATHS)
        or not _absolute(value["evaluator_private_key_path"])
        or type(value["evaluator_key_id"]) is not str
        or _RUN.fullmatch(value["evaluator_key_id"]) is None
        or any(
            type(value[name]) is not str or _DIGEST.fullmatch(value[name]) is None
            for name in _HASHES
        )
    ):
        raise ValueError("practice freeze identity differs")
    for name in _REFS:
        ref = value[name]
        if (
            type(ref) is not dict
            or set(ref) != {"path", "sha256"}
            or not _absolute(ref["path"])
            or type(ref["sha256"]) is not str
            or _DIGEST.fullmatch(ref["sha256"]) is None
        ):
            raise ValueError("practice freeze artifact reference differs")
    ports = value["ssh_ports"]
    images = value["images"]
    if (
        type(ports) is not dict
        or set(ports) != set(PRACTICE_TASK_IDS)
        or any(type(port) is not int or not 1024 <= port <= 65535 for port in ports.values())
        or len(set(ports.values())) != len(PRACTICE_TASK_IDS)
        or type(images) is not dict
        or set(images) != set(PRACTICE_TASK_IDS)
    ):
        raise ValueError("practice freeze task ports or images differ")
    for pair in images.values():
        if (
            type(pair) is not dict
            or set(pair) != {"vulnerable", "fixed"}
            or pair["vulnerable"] == pair["fixed"]
            or any(
                type(image) is not str or re.fullmatch(r"sha256:[a-f0-9]{64}", image) is None
                for image in pair.values()
            )
        ):
            raise ValueError("practice freeze image pin differs")
    return value


def load_practice_freeze(path: Path, expected_sha256: str) -> dict:
    """Read canonical bytes and rehash all referenced controller inputs."""
    source = Path(path)
    if (
        not source.is_absolute()
        or source.is_symlink()
        or not source.is_file()
        or not 0 < source.stat().st_size <= 16384
        or type(expected_sha256) is not str
        or _DIGEST.fullmatch(expected_sha256) is None
    ):
        raise ValueError("bounded practice freeze file and digest required")
    raw = source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise RuntimeError("practice freeze digest differs")
    try:
        value = validate_practice_freeze(json.loads(raw))
    except (ValueError, UnicodeDecodeError, TypeError, KeyError):
        raise RuntimeError("practice freeze document is invalid") from None
    if canonical_json(value) != raw:
        raise RuntimeError("practice freeze bytes are not canonical")
    for name in _REFS:
        ref = value[name]
        artifact = Path(ref["path"])
        if artifact.is_symlink() or not artifact.is_file():
            raise RuntimeError(f"practice freeze {name} is unavailable")
        digest = hashlib.sha256()
        with artifact.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        if digest.hexdigest() != ref["sha256"]:
            raise RuntimeError(f"practice freeze {name} digest differs")
    return value
