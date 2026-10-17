# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Preview a distinct signed ten-task practice decision without creating a ledger.

The preview is deliberately inert. A later runner must re-attest this decision
and bind a separately frozen worker before it may create durable state or Send.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from .campaign import CampaignAuthority, _attest

OFFICIAL_SUBSET_TASK_IDS = (
    "arvo:47101",
    "arvo:3938",
    "arvo:24993",
    "arvo:1065",
    "arvo:10400",
    "arvo:368",
    "oss-fuzz:42535201",
    "oss-fuzz:42535468",
    "oss-fuzz:370689421",
    "oss-fuzz:385167047",
)
PREVIOUSLY_EXPOSED_TASK_IDS = ("arvo:47101", "arvo:3938")
OFFICIAL_SUBSET_REGISTRY_SHA256 = "59d1fa85f6a681fc481f3ac4e14331586b7c9548972fd7ca661787da9995a7ad"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


@dataclass(frozen=True, slots=True)
class SubsetDryRunPreview:
    run_id: str
    epoch: str
    evidence_root: Path
    admission_sha256: str
    signed_admission: bytes = field(repr=False)
    task_ids: tuple[str, ...] = OFFICIAL_SUBSET_TASK_IDS
    previously_exposed_task_ids: tuple[str, ...] = PREVIOUSLY_EXPOSED_TASK_IDS


def preview_subset_dry_run_admission(
    *,
    signed_admission: bytes,
    authority: CampaignAuthority,
    run_id: str,
    epoch: str,
    evidence_root: Path,
    expected_cohort_sha256: str,
    expected_freeze_sha256: str,
    expected_certification_sha256: str,
    expected_budget_sha256: str,
) -> SubsetDryRunPreview:
    """Require exact official order and exposure disclosure; make no ledger write."""
    if (
        authority is None
        or type(signed_admission) is not bytes
        or not signed_admission
        or type(run_id) is not str
        or _RUN_ID.fullmatch(run_id) is None
        or type(epoch) is not str
        or _RUN_ID.fullmatch(epoch) is None
        or not isinstance(evidence_root, Path)
        or not evidence_root.is_absolute()
        or evidence_root.is_symlink()
        or not evidence_root.is_dir()
        or evidence_root.resolve(strict=True) != evidence_root
        or any(
            type(value) is not str or _DIGEST.fullmatch(value) is None
            for value in (
                expected_cohort_sha256,
                expected_freeze_sha256,
                expected_certification_sha256,
                expected_budget_sha256,
            )
        )
    ):
        raise RuntimeError("trusted subset dry-run admission inputs required")
    payload = _attest(authority, "subset_dry_run_admission", signed_admission)
    expected = {
        "schema_version": 1,
        "artifact_kind": "subset_dry_run_admission",
        "scope": "native_subset_dry_run_level1",
        "run_id": run_id,
        "epoch": epoch,
        "task_ids": list(OFFICIAL_SUBSET_TASK_IDS),
        "previously_exposed_task_ids": list(PREVIOUSLY_EXPOSED_TASK_IDS),
        "max_parallel_tasks": 1,
        "official_registry_sha256": OFFICIAL_SUBSET_REGISTRY_SHA256,
        "cohort_sha256": expected_cohort_sha256,
        "freeze_sha256": expected_freeze_sha256,
        "certification_sha256": expected_certification_sha256,
        "budget_sha256": expected_budget_sha256,
    }
    if type(payload) is not dict or payload != expected:
        raise RuntimeError("signed subset dry-run admission differs from exact scope")
    return SubsetDryRunPreview(
        run_id=run_id,
        epoch=epoch,
        evidence_root=evidence_root,
        admission_sha256=hashlib.sha256(signed_admission).hexdigest(),
        signed_admission=signed_admission,
    )
