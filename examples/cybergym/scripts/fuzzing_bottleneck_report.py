#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Parent-fuzzing bottleneck report: decide whether parallel exec children (#2) help.

Reads the agent-emitted fuzz telemetry that the task contract now requires under
``<evidence>/fuzz-stats/*.json`` (one record per fuzzing campaign). It does not touch
the certified runtime and records no raw tool I/O: it only aggregates derived stats the
agent itself wrote into its allowed ``/workspace/output`` scope.

The point is to answer one question with data instead of assumption: is the single
parent executor the bottleneck (so parallel execution children would help), or is a
single process simply not using all cores (so the fix is more libFuzzer ``-workers``,
and a swarm would only contend for the same cores)?

Usage:
    python -m scripts.fuzzing_bottleneck_report --evidence-dir <dir> [--cores N] [--json]

``--evidence-dir`` is the run's output/evidence root (the parent of ``fuzz-stats``).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

SCHEMA_VERSION = 1
# Below this worker/core ratio a single process is leaving cores idle: raising
# ``-workers`` is higher ROI than spawning agent lanes that each under-use cores.
SATURATION_FLOOR = 0.75

_REQUIRED_FIELDS = ("role", "workers", "cores_available", "elapsed_sec", "crash_found")


def load_campaigns(evidence_dir: Path | str) -> list[dict]:
    """Load valid fuzz-stats records from ``<evidence_dir>/fuzz-stats/``.

    A malformed or wrong-schema file is skipped, not fatal: a run with broken telemetry
    should still yield a report from whatever campaigns are readable.
    """
    directory = Path(evidence_dir) / "fuzz-stats"
    if not directory.is_dir():
        return []
    campaigns: list[dict] = []
    for path in sorted(directory.glob("*.json")):
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(record, dict) or record.get("schema_version") != SCHEMA_VERSION:
            continue
        if any(key not in record for key in _REQUIRED_FIELDS):
            continue
        campaigns.append(record)
    return campaigns


def _num(value, default=0.0) -> float:
    return (
        float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else default
    )


def _detect_cores(campaigns: list[dict], cores: int | None) -> int:
    if cores and cores > 0:
        return int(cores)
    observed = [int(_num(c.get("cores_available"))) for c in campaigns]
    observed = [n for n in observed if n > 0]
    return max(observed) if observed else 1


def classify_bottleneck(campaigns: list[dict], cores: int | None = None) -> dict:
    """Return {verdict, reason, metrics} from the fuzzing telemetry.

    Pure and side-effect free so the decision logic is unit-testable.
    """
    resolved_cores = _detect_cores(campaigns, cores)
    if not campaigns:
        return {
            "verdict": "no_fuzzing_observed",
            "reason": (
                "No fuzz-stats records were emitted. The agent is not fuzzing; revisit the "
                "#1 contract wording or the Bash capability before considering a swarm."
            ),
            "metrics": {"cores": resolved_cores, "campaign_count": 0},
        }

    peak_workers = max(int(_num(c.get("workers"), 1)) for c in campaigns)
    saturation = min(1.0, peak_workers / resolved_cores) if resolved_cores else 0.0
    crashers = [c for c in campaigns if c.get("crash_found") is True]
    any_crash = bool(crashers)
    distinct = len({str(c.get("name") or c.get("harness") or i) for i, c in enumerate(campaigns)})
    time_to_first_crash = min(_num(c.get("elapsed_sec")) for c in crashers) if crashers else None
    metrics = {
        "cores": resolved_cores,
        "peak_workers": peak_workers,
        "saturation": round(saturation, 3),
        "campaign_count": len(campaigns),
        "distinct_hypotheses": distinct,
        "crash_found": any_crash,
        "time_to_first_crash_sec": time_to_first_crash,
        "aggregate_execs": sum(_num(c.get("total_execs")) for c in campaigns),
    }

    if any_crash:
        verdict = "not_bottlenecked"
        reason = (
            "A crash was discovered; fuzzing already solves these. #2 is unnecessary for "
            "this profile. Invest #2 only where no crash is found within budget."
        )
    elif saturation < SATURATION_FLOOR and resolved_cores > 1:
        verdict = "under_saturated_single_lane"
        reason = (
            f"Peak {peak_workers} workers on {resolved_cores} cores "
            f"(saturation {saturation:.2f}): a single process is leaving cores idle. Raise "
            "libFuzzer -workers/-jobs first; a swarm would contend for the same cores, not "
            "add compute. #2 is NOT the lever here."
        )
    elif distinct >= 2:
        verdict = "diversity_or_serialization_bound"
        reason = (
            f"Cores saturated (~{saturation:.2f}) yet no crash across {distinct} sequential "
            "hypotheses: independent parallel exec lanes (#2) plausibly help by exploring "
            "hypotheses concurrently rather than one after another."
        )
    else:
        verdict = "single_saturated_lane_no_crash"
        reason = (
            "One saturated lane, no crash, few distinct hypotheses tried. Try more diverse "
            "harnesses/seeds first (cheap); only escalate to #2 if diversity stays starved."
        )
    return {"verdict": verdict, "reason": reason, "metrics": metrics}


def summarize(campaigns: list[dict], cores: int | None = None) -> dict:
    result = classify_bottleneck(campaigns, cores)
    return {
        "schema_version": SCHEMA_VERSION,
        "campaign_count": len(campaigns),
        "verdict": result["verdict"],
        "reason": result["reason"],
        "metrics": result["metrics"],
    }


def _format(report: dict) -> str:
    m = report["metrics"]
    lines = [
        "Parent-fuzzing bottleneck report",
        f"  campaigns:   {report['campaign_count']}",
        f"  cores:       {m.get('cores')}  peak_workers: {m.get('peak_workers')}  "
        f"saturation: {m.get('saturation')}",
        f"  hypotheses:  {m.get('distinct_hypotheses')}  crash_found: {m.get('crash_found')}  "
        f"ttfc_sec: {m.get('time_to_first_crash_sec')}",
        f"  VERDICT:     {report['verdict']}",
        f"  {report['reason']}",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--cores", type=int, help="override detected core count (e.g. nproc)")
    parser.add_argument("--json", action="store_true", help="emit the machine report")
    args = parser.parse_args(argv)
    report = summarize(load_campaigns(args.evidence_dir), cores=args.cores)
    print(json.dumps(report, indent=2) if args.json else _format(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
