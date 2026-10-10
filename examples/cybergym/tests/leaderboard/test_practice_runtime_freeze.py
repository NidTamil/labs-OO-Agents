# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Practice freeze must stay separate from scored and synthetic admissions."""

import pytest
from nooa_cybergym.leaderboard.practice_runtime_freeze import validate_practice_freeze


def _value():
    ref = {"path": "/controller/file", "sha256": "a" * 64}
    return {
        "schema_version": 1,
        "scope": "native_practice_level1",
        "run_id": "practice-v26q-20261010",
        "epoch": "practice-v26q",
        "task_ids": ["arvo:47101", "arvo:3938"],
        "max_parallel_tasks": 1,
        "donor_config": ref,
        "bindings": ref,
        "asset_hashes": ref,
        "selected_manifest": ref,
        "code_archive": ref,
        "signed_report": ref,
        "report": ref,
        "official_verifier": ref,
        "public_ssh_key": ref,
        "mask_map": ref,
        "harness_manifest": ref,
        "generator_source": ref,
        "input_root": "/controller/inputs",
        "code_root": "/controller/code",
        "staging_root": "/controller/staging",
        "evidence_root": "/controller/evidence",
        "selected_assets_sha256": "b" * 64,
        "host_key_sha256": "c" * 64,
        "vscode_exe_sha256": "d" * 64,
        "remote_alias": "cybergym-practice-v26q",
        "ssh_ports": {"arvo:47101": 22561, "arvo:3938": 22562},
        "images": {
            task: {"vulnerable": "sha256:" + "e" * 64, "fixed": "sha256:" + "f" * 64}
            for task in ("arvo:47101", "arvo:3938")
        },
        "evaluator_private_key_path": "/controller/secrets/evaluator.pem",
        "evaluator_public_key_sha256": "1" * 64,
        "evaluator_key_id": "practice-evaluator-v26q",
    }


def test_freeze_accepts_exact_practice_shape_and_rejects_scored_scope():
    value = _value()
    assert validate_practice_freeze(value) == value
    for change in (
        {"scope": "official"},
        {"task_ids": ["arvo:47101", "arvo:3938", "arvo:1065"]},
        {"max_parallel_tasks": 2},
        {"remote_alias": "digitalocean-gate"},
    ):
        with pytest.raises(ValueError, match="practice freeze"):
            validate_practice_freeze(value | change)
