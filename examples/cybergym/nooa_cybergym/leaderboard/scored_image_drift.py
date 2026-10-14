# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Bounded second registry pass for a complete, unsigned scored image candidate.

This re-fetches public metadata into a separate controller-only checkpoint
directory. It neither pulls layers nor signs or admits a scored campaign.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from pathlib import Path

from nooa_cybergym.leaderboard.scored_image_collector import (
    _atomic_write,
    _checkpoint_name,
    _references,
    fetch_docker_manifest,
)
from nooa_cybergym.leaderboard.scored_image_registry import (
    ScoredImageRegistry,
    verify_docker_manifest_observation,
)

_SHA = re.compile(r"[a-f0-9]{64}\Z")


def check_drift_batch(
    task_ids: tuple[str, ...],
    cohort_sha256: str,
    candidate_path: Path,
    candidate_sha256: str,
    output_dir: Path,
    *,
    limit: int,
    fetch: Callable[[str], bytes],
) -> int:
    """Reverify earlier checks and compare at most limit fresh tag descriptors."""
    refs = tuple(_references(task_ids))
    if (
        type(cohort_sha256) is not str
        or _SHA.fullmatch(cohort_sha256) is None
        or type(limit) is not int
        or not 0 <= limit <= 15
        or not callable(fetch)
    ):
        raise ValueError("bounded drift inputs required")
    registry = ScoredImageRegistry.load(
        candidate_path, expected_sha256=candidate_sha256, task_ids=task_ids
    )
    expected = tuple(
        digest
        for task_id in task_ids
        for digest in (
            registry.images_for(task_id).vulnerable,
            registry.images_for(task_id).fixed,
        )
    )
    root = Path(output_dir)
    if not root.is_absolute() or root.is_symlink():
        raise ValueError("absolute unlinked drift checkpoint directory required")
    root.mkdir(parents=True, exist_ok=True)
    identity_path = root / "drift.identity.json"
    identity = json.dumps(
        {"candidate_sha256": candidate_sha256, "cohort_sha256": cohort_sha256},
        sort_keys=True,
    ).encode()
    if identity_path.exists() or identity_path.is_symlink():
        if (
            identity_path.is_symlink()
            or not identity_path.is_file()
            or identity_path.read_bytes() != identity
        ):
            raise ValueError("drift checkpoint identity differs")
    else:
        _atomic_write(identity_path, identity)

    expected_names = {_checkpoint_name(ref) for ref in refs} | {identity_path.name}
    if {path.name for path in root.iterdir()} - expected_names:
        raise ValueError("unexpected drift checkpoint entry")
    pending = []
    for ref, digest in zip(refs, expected, strict=True):
        path = root / _checkpoint_name(ref)
        if path.exists() or path.is_symlink():
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
                raise ValueError("drift observation checkpoint is invalid")
            observed = verify_docker_manifest_observation(path.read_bytes(), expected_ref=ref)
            if observed != digest:
                raise ValueError(f"registry tag drift detected for {ref}")
        else:
            pending.append((ref, digest, path))
    for ref, digest, path in pending[:limit]:
        raw = fetch(ref)
        observed = verify_docker_manifest_observation(raw, expected_ref=ref)
        if observed != digest:
            raise ValueError(f"registry tag drift detected for {ref}")
        _atomic_write(path, raw)
    return min(limit, len(pending))


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cohort", type=Path, required=True)
    parser.add_argument("--cohort-sha256", required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--candidate-sha256", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--limit", type=int, default=15)
    args = parser.parse_args()
    cohort = args.cohort.read_bytes()
    if hashlib.sha256(cohort).hexdigest() != args.cohort_sha256:
        raise ValueError("cohort lock digest differs")
    task_ids = tuple(json.loads(cohort)["task_ids"])
    count = check_drift_batch(
        task_ids,
        args.cohort_sha256,
        args.candidate,
        args.candidate_sha256,
        args.output_dir,
        limit=args.limit,
        fetch=fetch_docker_manifest,
    )
    print(f"verified and rechecked {count} public image tags")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
