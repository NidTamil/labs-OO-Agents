#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Parent-fuzzing telemetry report for review of parallel exec children (#2).

Reads agent-emitted fuzz telemetry under ``<evidence>/fuzz-stats/*.json`` (one record
per campaign). These files are inside the agent's writable scope. They can describe
what the agent reported, but cannot establish actual CPU use or a bottleneck.

The controller does not currently emit CPU/cgroup usage for fuzzing intervals. Until
it does, this report returns insufficient telemetry for any recorded campaigns and
does not recommend parallel execution children from worker counts alone.

Usage:
    python -m scripts.fuzzing_bottleneck_report --evidence-dir <dir> [--cores N] [--json]

``--evidence-dir`` is the run's output/evidence root (the parent of ``fuzz-stats``).
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

SCHEMA_VERSION = 1

_REQUIRED_FIELDS = (
    "role",
    "workers",
    "cores_available",
    "elapsed_sec",
    "total_execs",
    "exec_per_sec",
    "crash_found",
)


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
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return default
    try:
        number = float(value)
    except OverflowError:
        return default
    return number if math.isfinite(number) else default


def classify_bottleneck(campaigns: list[dict], cores: int | None = None) -> dict:
    """Return {verdict, reason, metrics} from untrusted agent telemetry.

    ``cores`` is an operator capacity hint, not measured CPU consumption.
    This function never treats agent-supplied stats as controller evidence.
    """
    core_capacity_hint = (
        cores if isinstance(cores, int) and not isinstance(cores, bool) and cores > 0 else None
    )
    if not campaigns:
        return {
            "verdict": "no_fuzzing_observed",
            "reason": (
                "No valid agent-written fuzz-stats records were found. This does not "
                "prove that fuzzing did not run; inspect trusted execution evidence."
            ),
            "metrics": {
                "campaign_count": 0,
                "cpu_saturation": None,
                "core_capacity_hint": core_capacity_hint,
            },
        }

    reported_execs = sum(_num(c.get("total_execs")) for c in campaigns)
    metrics = {
        "campaign_count": len(campaigns),
        "cpu_saturation": None,
        "core_capacity_hint": core_capacity_hint,
        "reported_peak_workers": max(0, *(int(_num(c.get("workers"))) for c in campaigns)),
        "reported_crash_found": any(c.get("crash_found") is True for c in campaigns),
        "reported_aggregate_execs": reported_execs if math.isfinite(reported_execs) else None,
    }
    return {
        "verdict": "insufficient_telemetry",
        "reason": (
            "Agent-written campaign records do not measure CPU saturation and can be "
            "edited by the agent. Collect controller-owned CPU/cgroup usage over "
            "fuzzing intervals before deciding whether parallel execution children help."
        ),
        "metrics": metrics,
    }


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
        f"  CPU saturation: {m.get('cpu_saturation')}  "
        f"core capacity hint: {m.get('core_capacity_hint')}",
        f"  reported peak workers: {m.get('reported_peak_workers')}  "
        f"reported crash: {m.get('reported_crash_found')}",
        f"  VERDICT:     {report['verdict']}",
        f"  {report['reason']}",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--cores", type=int, help="operator core-capacity hint; not CPU usage")
    parser.add_argument("--json", action="store_true", help="emit the machine report")
    args = parser.parse_args(argv)
    report = summarize(load_campaigns(args.evidence_dir), cores=args.cores)
    print(json.dumps(report, indent=2) if args.json else _format(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
