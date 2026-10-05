# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""The parent-fuzzing bottleneck report turns agent-emitted fuzz telemetry into a
decision about whether parallel execution children (#2) would actually help.

The classifier is the load-bearing piece: it must distinguish a lane that simply is
not using all cores (fix `-workers`, a swarm would only contend) from cores-saturated
runs that still fail across several hypotheses (where independent parallel lanes
plausibly help). These tests pin each verdict branch and the tolerant loader.
"""

import json

from scripts.fuzzing_bottleneck_report import (
    classify_bottleneck,
    load_campaigns,
    summarize,
)


def _c(**kw):
    base = {
        "schema_version": 1,
        "role": "parent",
        "name": "h1",
        "workers": 8,
        "cores_available": 8,
        "elapsed_sec": 300.0,
        "total_execs": 12_000_000,
        "exec_per_sec": 40_000.0,
        "crash_found": False,
    }
    base.update(kw)
    return base


def test_no_fuzzing_observed_is_its_own_signal():
    out = classify_bottleneck([], cores=8)
    assert out["verdict"] == "no_fuzzing_observed"
    # The agent not fuzzing at all means #1 wording or capability needs attention,
    # not that a swarm is warranted.
    assert "swarm" not in out["verdict"]


def test_under_saturated_single_lane_points_at_workers_not_swarm():
    # One lane using 2 of 8 cores: a single process could use all 8.
    out = classify_bottleneck([_c(workers=2, cores_available=8)], cores=8)
    assert out["verdict"] == "under_saturated_single_lane"
    assert out["metrics"]["saturation"] < 0.75
    assert "worker" in out["reason"].lower()


def test_saturated_no_crash_across_hypotheses_favours_parallel_lanes():
    out = classify_bottleneck(
        [
            _c(name="format-a", workers=8, crash_found=False),
            _c(name="format-b", workers=8, crash_found=False),
            _c(name="state-machine", workers=8, crash_found=False),
        ],
        cores=8,
    )
    assert out["verdict"] == "diversity_or_serialization_bound"
    assert out["metrics"]["distinct_hypotheses"] == 3
    assert "#2" in out["reason"]


def test_saturated_single_hypothesis_favours_more_hypotheses_first():
    out = classify_bottleneck([_c(name="only", workers=8, crash_found=False)], cores=8)
    assert out["verdict"] == "single_saturated_lane_no_crash"


def test_crash_found_means_not_bottlenecked():
    out = classify_bottleneck([_c(workers=8, crash_found=True, elapsed_sec=42.0)], cores=8)
    assert out["verdict"] == "not_bottlenecked"
    assert out["metrics"]["time_to_first_crash_sec"] == 42.0


def test_loader_reads_fuzz_stats_dir_and_skips_bad_files(tmp_path):
    d = tmp_path / "fuzz-stats"
    d.mkdir()
    (d / "a.json").write_text(json.dumps(_c(name="a")))
    (d / "b.json").write_text(json.dumps(_c(name="b", crash_found=True)))
    (d / "broken.json").write_text("{not json")
    (d / "wrong-schema.json").write_text(json.dumps({"schema_version": 2}))
    campaigns = load_campaigns(tmp_path)
    names = sorted(c["name"] for c in campaigns)
    assert names == ["a", "b"]  # broken + wrong-schema dropped, not fatal


def test_summarize_is_json_serialisable_and_carries_verdict(tmp_path):
    d = tmp_path / "fuzz-stats"
    d.mkdir()
    (d / "a.json").write_text(json.dumps(_c(workers=1, cores_available=16)))
    report = summarize(load_campaigns(tmp_path), cores=16)
    json.dumps(report)  # must not raise
    assert report["verdict"] == "under_saturated_single_lane"
    assert report["campaign_count"] == 1
