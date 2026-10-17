# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Hash-bound custody for one pair of raw synthetic fixture attempts.

This inventories bytes only. It makes no certification-gate or launch claim.
An independent attestor must still interpret and verify the raw evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from collections.abc import Mapping
from pathlib import Path

_FIXTURES = ("synthetic:length-header", "synthetic:chunk-table")
_RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_MAX_FILES = 10_000
_MAX_FILE_BYTES = 512 * 1024 * 1024


class RawPairManifestError(ValueError):
    """One raw attempt is absent, ambiguous, or changed."""


def _canonical_roots(roots: Mapping[str, Path]) -> dict[str, Path]:
    if not isinstance(roots, Mapping) or set(roots) != set(_FIXTURES):
        raise RawPairManifestError("exact synthetic fixture pair required")
    verified: dict[str, Path] = {}
    for fixture in _FIXTURES:
        raw = roots[fixture]
        if not isinstance(raw, Path) or not raw.is_absolute() or raw.is_symlink():
            raise RawPairManifestError("absolute raw evidence root required")
        try:
            resolved = raw.resolve(strict=True)
        except (OSError, RuntimeError):
            raise RawPairManifestError("raw evidence root missing") from None
        if resolved != raw or not raw.is_dir():
            raise RawPairManifestError("canonical raw evidence directory required")
        verified[fixture] = raw
    if len(set(verified.values())) != len(_FIXTURES):
        raise RawPairManifestError("distinct raw evidence roots required")
    first, second = (verified[fixture] for fixture in _FIXTURES)
    if first.is_relative_to(second) or second.is_relative_to(first):
        raise RawPairManifestError("distinct nonoverlapping raw evidence roots required")
    return verified


def _files(root: Path) -> list[dict[str, str | int]]:
    files: list[dict[str, str | int]] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise RawPairManifestError("linked raw evidence is forbidden")
        if path.is_dir():
            continue
        if not path.is_file():
            raise RawPairManifestError("nonregular raw evidence is forbidden")
        before = path.stat()
        if before.st_size > _MAX_FILE_BYTES or len(files) >= _MAX_FILES:
            raise RawPairManifestError("raw evidence inventory exceeds bound")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        after = path.stat()
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise RawPairManifestError("raw evidence changed while hashing")
        files.append(
            {
                "path": path.relative_to(root).as_posix(),
                "bytes": before.st_size,
                "sha256": digest.hexdigest(),
            }
        )
    if not any(row["path"] == "result.json" for row in files):
        raise RawPairManifestError("raw terminal result missing")
    return files


def build_raw_pair_manifest(run_id: str, roots: Mapping[str, Path]) -> dict:
    """Inventory exactly two distinct, terminal synthetic evidence directories."""
    if type(run_id) is not str or _RUN_ID.fullmatch(run_id) is None:
        raise RawPairManifestError("certification repetition identity required")
    verified = _canonical_roots(roots)
    return {
        "schema_version": 1,
        "scope": "raw_fixture_pair_provenance",
        "run_id": run_id,
        "fixture_ids": list(_FIXTURES),
        "roots": {fixture: str(verified[fixture]) for fixture in _FIXTURES},
        "files": {fixture: _files(verified[fixture]) for fixture in _FIXTURES},
    }


def verify_raw_pair_manifest(manifest: dict, roots: Mapping[str, Path]) -> None:
    """Reject any changed, missing or newly added raw artifact."""
    if type(manifest) is not dict or type(manifest.get("run_id")) is not str:
        raise RawPairManifestError("raw pair manifest invalid")
    current = build_raw_pair_manifest(manifest["run_id"], roots)
    if current != manifest:
        raise RawPairManifestError("raw evidence changed since manifest creation")


def main(argv: list[str] | None = None) -> int:
    """Write a private, create-once raw custody inventory; no gate claims."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--first", type=Path, required=True)
    parser.add_argument("--second", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    roots = dict(zip(_FIXTURES, (args.first, args.second), strict=True))
    manifest = build_raw_pair_manifest(args.run_id, roots)
    output = args.output
    if (
        not output.is_absolute()
        or output.is_symlink()
        or not output.parent.is_dir()
        or output.parent.resolve(strict=True) != output.parent
    ):
        raise RawPairManifestError("canonical absolute output path required")
    data = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps({"manifest_sha256": hashlib.sha256(data).hexdigest()}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
