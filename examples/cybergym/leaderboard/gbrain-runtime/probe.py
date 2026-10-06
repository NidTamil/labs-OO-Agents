# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Run a controller-only live smoke check on generic, non-cohort memory queries."""

import argparse
import json
import os
from pathlib import Path

from nooa_cybergym.leaderboard.deepseek import SharedCampaignBudget
from nooa_cybergym.leaderboard.gbrain_bridge import GBrainControllerBridge


class DurableAudit:
    def __init__(self, path):
        self.path = path

    def record(self, event):
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event, sort_keys=True, allow_nan=False) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    command = args.command[1:] if args.command[0] == "--" else args.command
    budget = SharedCampaignBudget()
    with GBrainControllerBridge(
        command,
        budget=budget,
        audit=DurableAudit(args.output / "invocations.jsonl"),
        allowed_models={
            "openai:text-embedding-3-large": "embedding",
            "voyage:rerank-2.5": "rerank",
            "openai:gpt-5.6-luna": "chat",
        },
    ) as bridge:
        report = {"scope": "synthetic_live_native_gbrain", "evidence": bridge.inspection()}

        def call(method, params=None, request_id="probe"):
            return bridge.exchange(
                {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}},
                timeout_seconds=60,
            )

        report["initialize"] = call("initialize", {"protocolVersion": "2025-06-18"})
        bridge.notify({"jsonrpc": "2.0", "method": "notifications/initialized"})
        report["catalog"] = call("tools/list")
        report["auxiliary_certification"] = call(
            "xeus/certify-native-models", request_id="synthetic-auxiliary"
        )
        for role in ("automatic", "parent", "child"):
            report[role] = call(
                "tools/call",
                {
                    "name": "recall",
                    "arguments": {
                        "query": "generic buffer bounds validation",
                        "budget_tokens": 2000,
                        "limit": 12,
                    },
                },
                f"synthetic-{role}",
            )
        report["search"] = call(
            "tools/call",
            {
                "name": "search",
                "arguments": {
                    "query": "generic buffer bounds validation",
                    "source_id": "xeus-cybergym-workspace",
                    "limit": 12,
                    "types": ["note"],
                    "snippet_chars": 1000,
                },
            },
            "synthetic-search",
        )
        report["default_denial"] = call(
            "tools/call",
            {"name": "search", "arguments": {"query": "generic", "source_id": "default"}},
            "synthetic-deny-default",
        )
        report["write_denial"] = call(
            "tools/call",
            {"name": "capture", "arguments": {"content": "synthetic must not be saved"}},
            "synthetic-deny-write",
        )
        report["budget"] = budget.snapshot()
        (args.output / "probe.json").write_text(
            json.dumps(report, indent=2) + "\n", encoding="utf-8"
        )
        print(
            json.dumps(
                {
                    "evidence_file": str(args.output / "probe.json"),
                    "budget": report["budget"],
                    "source_ids": report["evidence"]["source_ids"],
                    "guard_bound": report["evidence"]["native_guard_bound"],
                }
            )
        )


if __name__ == "__main__":
    main()
