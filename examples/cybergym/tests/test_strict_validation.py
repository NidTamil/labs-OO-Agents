# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for fail-closed fixed-build verification."""

from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest

from examples.cybergym.scripts.verify_agent_result_strict import (
    require_complete_fix_results,
    run_verify,
)


def test_run_verify_raises_on_non_success_response() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(404, request=request, text="unknown agent")
    )

    with pytest.raises(httpx.HTTPStatusError, match="404"):
        run_verify(
            "agent-1",
            "http://verifier.test:8666",
            api_key="local-key",
            transport=transport,
        )


def test_require_complete_fix_results_rejects_unverified_vulnerable_crash() -> None:
    records = [SimpleNamespace(vul_exit_code=1, fix_exit_code=None)]

    with pytest.raises(RuntimeError, match="missing fixed-build result"):
        require_complete_fix_results(records, agent_id="agent-1")


def test_require_complete_fix_results_accepts_completed_records() -> None:
    records = [
        SimpleNamespace(vul_exit_code=1, fix_exit_code=0),
        SimpleNamespace(vul_exit_code=0, fix_exit_code=None),
    ]

    require_complete_fix_results(records, agent_id="agent-1")
