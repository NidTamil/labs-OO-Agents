# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Practice task workspace must be outside controller-only staging custody."""

from nooa_cybergym.leaderboard import practice_native_driver
from nooa_cybergym.leaderboard.workspace import (
    ControllerPaths,
    _assert_controller_path_separation,
)


def test_practice_root_satisfies_real_workspace_boundary(tmp_path):
    run = tmp_path / "practice-run"
    paths = ControllerPaths(
        data_dir=tmp_path / "input/data",
        mask_map_path=tmp_path / "input/mask_map.json",
        server="http://registered-tool-gateway",
        staging_root=run / "staging",
        evidence_root=run / "evidence",
        harness_dir=tmp_path / "input/harness",
        harness_manifest_path=tmp_path / "input/harness-manifest.json",
        harness_manifest_sha256="a" * 64,
        mask_map_sha256="b" * 64,
        generator_source=tmp_path / "input/gen_task.py",
        generator_sha256="c" * 64,
    )
    root = practice_native_driver.practice_task_root(paths, "practice-run-arvo-47101")
    _assert_controller_path_separation(paths, root)
    assert root.parent == run
    assert not root.is_relative_to(paths.staging_root)
