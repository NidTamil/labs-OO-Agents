# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""A two-fixture provenance snapshot must not invent certification gates."""

from __future__ import annotations

import hashlib
import json

import pytest
from nooa_cybergym.leaderboard.raw_pair_manifest import (
    RawPairManifestError,
    build_raw_pair_manifest,
    main,
    verify_raw_pair_manifest,
)


def _fixture_roots(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir(parents=True)
    second.mkdir()
    (first / "result.json").write_bytes(b'{"run_id":"attempt-a"}')
    (second / "result.json").write_bytes(b'{"run_id":"attempt-b"}')
    return {
        "synthetic:length-header": first,
        "synthetic:chunk-table": second,
    }


def test_pair_manifest_binds_two_distinct_raw_attempts_without_claiming_gates(tmp_path):
    roots = _fixture_roots(tmp_path)
    manifest = build_raw_pair_manifest("cert-repeat-one", roots)

    assert manifest["run_id"] == "cert-repeat-one"
    assert manifest["fixture_ids"] == ["synthetic:length-header", "synthetic:chunk-table"]
    assert manifest["files"]["synthetic:length-header"] == [
        {
            "path": "result.json",
            "bytes": 22,
            "sha256": hashlib.sha256(b'{"run_id":"attempt-a"}').hexdigest(),
        }
    ]
    assert "gates" not in manifest
    verify_raw_pair_manifest(manifest, roots)


def test_pair_manifest_rejects_changed_raw_evidence(tmp_path):
    roots = _fixture_roots(tmp_path)
    manifest = build_raw_pair_manifest("cert-repeat-one", roots)
    (roots["synthetic:length-header"] / "result.json").write_bytes(b"{}")

    with pytest.raises(RawPairManifestError, match="changed"):
        verify_raw_pair_manifest(manifest, roots)


def test_pair_manifest_rejects_nested_attempt_roots(tmp_path):
    roots = _fixture_roots(tmp_path)
    nested = roots["synthetic:length-header"] / "second"
    nested.mkdir()
    (nested / "result.json").write_bytes(b'{"run_id":"attempt-b"}')
    roots["synthetic:chunk-table"] = nested

    with pytest.raises(RawPairManifestError, match="distinct"):
        build_raw_pair_manifest("cert-repeat-one", roots)


def test_pair_manifest_rejects_reused_or_linked_evidence(tmp_path):
    roots = _fixture_roots(tmp_path)
    roots["synthetic:chunk-table"] = roots["synthetic:length-header"]
    with pytest.raises(RawPairManifestError, match="distinct"):
        build_raw_pair_manifest("cert-repeat-one", roots)

    roots = _fixture_roots(tmp_path / "other")
    (roots["synthetic:length-header"] / "linked").symlink_to(
        roots["synthetic:chunk-table"] / "result.json"
    )
    with pytest.raises(RawPairManifestError, match="linked"):
        build_raw_pair_manifest("cert-repeat-one", roots)


def test_pair_manifest_cli_writes_once_and_rechecks_bytes(tmp_path):
    roots = _fixture_roots(tmp_path)
    output = tmp_path / "pair.json"
    args = [
        "--run-id",
        "cert-repeat-one",
        "--first",
        str(roots["synthetic:length-header"]),
        "--second",
        str(roots["synthetic:chunk-table"]),
        "--output",
        str(output),
    ]

    assert main(args) == 0
    manifest = json.loads(output.read_bytes())
    verify_raw_pair_manifest(manifest, roots)
    with pytest.raises(FileExistsError):
        main(args)
