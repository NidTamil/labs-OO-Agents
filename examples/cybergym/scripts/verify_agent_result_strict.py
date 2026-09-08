#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Run CyberGym fixed-build verification and reject incomplete results."""

from __future__ import annotations

import argparse
import os
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import httpx

API_KEY_NAME = "X-API-Key"
NON_CRASH_EXIT_CODES = {0, 300}


def run_verify(
    agent_id: str,
    server: str,
    *,
    api_key: str,
    transport: httpx.BaseTransport | None = None,
) -> None:
    """Ask the verifier to replay an agent's PoCs and require HTTP success."""
    with httpx.Client(base_url=server, timeout=1200, transport=transport) as client:
        response = client.post(
            "/verify-agent-pocs",
            json={"agent_id": agent_id},
            headers={API_KEY_NAME: api_key},
        )
        response.raise_for_status()
        print(f"Verification response for agent {agent_id}: {response.status_code} {response.text}")


def require_complete_fix_results(records: Iterable[Any], *, agent_id: str) -> None:
    """Reject vulnerable-build crashes that have no fixed-build result."""
    missing = [
        record
        for record in records
        if record.vul_exit_code is not None
        and record.vul_exit_code not in NON_CRASH_EXIT_CODES
        and record.fix_exit_code is None
    ]
    if missing:
        raise RuntimeError(
            f"agent {agent_id} has {len(missing)} vulnerable crash(es) with a missing fixed-build result"
        )


def load_results(pocdb_path: Path, agent_id: str) -> list[Any]:
    """Load this agent's PoC rows through CyberGym's authoritative schema."""
    from cybergym.server.pocdb import PoCRecord, Session, init_engine

    engine = init_engine(pocdb_path)
    with Session(engine) as session:
        return list(session.query(PoCRecord).filter(PoCRecord.agent_id == agent_id).all())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True)
    parser.add_argument("--agent_id", required=True)
    parser.add_argument("--pocdb_path", type=Path, required=True)
    args = parser.parse_args()

    api_key = os.environ.get("CYBERGYM_API_KEY")
    if not api_key:
        raise SystemExit("CYBERGYM_API_KEY is required")

    run_verify(args.agent_id, args.server, api_key=api_key)
    records = load_results(args.pocdb_path, args.agent_id)
    require_complete_fix_results(records, agent_id=args.agent_id)
    for record in records:
        print(record.to_dict())


if __name__ == "__main__":
    main()
