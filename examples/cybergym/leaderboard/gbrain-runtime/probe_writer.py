# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Authenticate the separate writer and exercise native dry-run validation only."""

import argparse
import json
from pathlib import Path

from nooa_cybergym.leaderboard.deepseek import SharedCampaignBudget
from nooa_cybergym.leaderboard.gbrain_bridge import GBrainControllerBridge
from probe import DurableAudit

parser = argparse.ArgumentParser()
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("command", nargs=argparse.REMAINDER)
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=True)
command = args.command[1:] if args.command[0] == "--" else args.command
with GBrainControllerBridge(
    command,
    budget=SharedCampaignBudget(),
    audit=DurableAudit(args.output / "invocations.jsonl"),
    allowed_models={
        "openai:text-embedding-3-large": "embedding",
        "voyage:rerank-2.5": "rerank",
        "openai:gpt-5.6-luna": "chat",
    },
) as bridge:

    def call(method, params=None):
        return bridge.exchange(
            {
                "jsonrpc": "2.0",
                "id": "synthetic-writer-probe",
                "method": method,
                "params": params or {},
            },
            timeout_seconds=60,
        )

    report = {
        "scope": "synthetic_native_writer_dry_validation",
        "evidence": call("xeus/evidence"),
        "catalog": call("tools/list"),
    }
    report["dry_capture"] = call(
        "xeus/oracle-capture",
        {
            "arguments": {
                "content": "---\ntype: note\ntier: episodic\n---\nSynthetic dry validation only.",
                "slug": "cybergym/episodic/synthetic-dry-validation",
                "type": "note",
                "dry_run": True,
            }
        },
    )
    report["namespace_denial"] = call(
        "xeus/oracle-capture",
        {
            "arguments": {
                "content": "Synthetic dry validation only.",
                "slug": "cybergym/principle/denied",
                "type": "note",
                "dry_run": True,
            }
        },
    )
    (args.output / "writer-probe.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "evidence_file": str(args.output / "writer-probe.json"),
                "dry_capture": report["dry_capture"],
            }
        )
    )
