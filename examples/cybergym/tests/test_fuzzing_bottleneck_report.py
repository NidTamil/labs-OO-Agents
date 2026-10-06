# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Agent-emitted fuzz stats are diagnostics, not bottleneck evidence."""

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
    assert "does not prove" in out["reason"]
    assert out["metrics"]["cpu_saturation"] is None


def test_reported_workers_do_not_establish_cpu_saturation_or_recommend_children():
    out = classify_bottleneck([_c(name="format-a"), _c(name="format-b")], cores=8)
    assert out["verdict"] == "insufficient_telemetry"
    assert out["metrics"]["cpu_saturation"] is None
    assert "#2" not in out["reason"]


def test_agent_reported_cpu_and_crash_cannot_change_verdict():
    out = classify_bottleneck(
        [_c(crash_found=True, cpu_saturation=1.0, cpu_usage_usec=900_000_000)],
        cores=8,
    )
    assert out["verdict"] == "insufficient_telemetry"
    assert out["metrics"]["cpu_saturation"] is None


def test_nonfinite_agent_worker_count_does_not_crash_report():
    out = classify_bottleneck([_c(workers=float("inf"))], cores=8)
    assert out["verdict"] == "insufficient_telemetry"
    assert out["metrics"]["reported_peak_workers"] == 0


def test_large_agent_execution_counts_keep_machine_report_valid_json():
    report = summarize([_c(total_execs=1e308), _c(total_execs=1e308)], cores=8)
    json.dumps(report, allow_nan=False)
    assert report["metrics"]["reported_aggregate_execs"] is None


def test_low_worker_claim_is_only_a_reported_diagnostic():
    out = classify_bottleneck([_c(workers=2, cores_available=8)], cores=8)
    assert out["verdict"] == "insufficient_telemetry"
    assert out["metrics"]["reported_peak_workers"] == 2
    assert out["metrics"]["core_capacity_hint"] == 8
    assert out["metrics"]["cpu_saturation"] is None


def test_multiple_reported_hypotheses_do_not_recommend_parallel_lanes():
    out = classify_bottleneck(
        [
            _c(name="format-a", workers=8, crash_found=False),
            _c(name="format-b", workers=8, crash_found=False),
            _c(name="state-machine", workers=8, crash_found=False),
        ],
        cores=8,
    )
    assert out["verdict"] == "insufficient_telemetry"
    assert out["metrics"]["campaign_count"] == 3


def test_single_reported_hypothesis_does_not_establish_saturation():
    out = classify_bottleneck([_c(name="only", workers=8, crash_found=False)], cores=8)
    assert out["verdict"] == "insufficient_telemetry"
    assert out["metrics"]["cpu_saturation"] is None


def test_agent_reported_crash_is_not_an_authoritative_outcome():
    out = classify_bottleneck([_c(workers=8, crash_found=True, elapsed_sec=42.0)], cores=8)
    assert out["verdict"] == "insufficient_telemetry"
    assert out["metrics"]["reported_crash_found"] is True


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


def test_loader_requires_all_fields_named_in_the_agent_contract(tmp_path):
    d = tmp_path / "fuzz-stats"
    d.mkdir()
    incomplete = _c()
    incomplete.pop("exec_per_sec")
    (d / "incomplete.json").write_text(json.dumps(incomplete))
    assert load_campaigns(tmp_path) == []


def test_summarize_is_json_serialisable_and_carries_verdict(tmp_path):
    d = tmp_path / "fuzz-stats"
    d.mkdir()
    (d / "a.json").write_text(json.dumps(_c(workers=1, cores_available=16)))
    report = summarize(load_campaigns(tmp_path), cores=16)
    json.dumps(report)  # must not raise
    assert report["verdict"] == "insufficient_telemetry"
    assert report["campaign_count"] == 1
