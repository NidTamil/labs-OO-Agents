# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""A UI Send counts only after the same native attempt reaches the model gateway."""

from __future__ import annotations

from pathlib import Path

import pytest
from xeus_cybergym.canonical import canonical_json


def test_first_primary_request_requires_reserved_launch_and_gateway_start(tmp_path: Path):
    from nooa_cybergym.leaderboard.native_first_request import NativeFirstRequestWitness

    launch_dir = tmp_path / "launch"
    launch_dir.mkdir()
    receipt = {"event": "launch_reserved", "launch_id": "launch-1"}

    class Authority:
        manifest = {"task_id": "arvo:1", "launch_id": "launch-1"}

        def _check_receipt(self, value):
            if value != receipt:
                raise ValueError("launch receipt changed")

    Authority.launch_dir = launch_dir
    audit = tmp_path / "model-requests.jsonl"
    witness = NativeFirstRequestWitness(
        launch_authority=Authority(),
        attempt_id="attempt-1",
        model_audit=audit,
        policy_sha256="a" * 64,
        expected_model="glm-5.3",
    )
    assert witness.observed("launch-1") is False

    (launch_dir / "launcher-receipt.json").write_bytes(canonical_json(receipt))
    auxiliary = {
        "event": "request_reserved",
        "task_id": "arvo:1",
        "attempt_id": "attempt-1",
        "request_id": "model-1",
        "role": "recon",
        "requested_model": "deepseek-v4.1-flash",
        "policy_sha256": "a" * 64,
    }
    primary = {
        **auxiliary,
        "role": "primary",
        "request_id": "model-2",
        "requested_model": "glm-5.3",
    }

    def append(event):
        with audit.open("ab") as stream:
            stream.write(canonical_json(event) + b"\n")

    append(auxiliary)
    assert witness.observed("launch-1") is False
    append(primary)
    assert witness.observed("launch-1") is False
    append({**primary, "event": "attempt_started"})
    assert witness.observed("launch-1") is True
    assert witness.observed("launch-1") is True
    with pytest.raises(ValueError, match="launch"):
        witness.observed("another-launch")


def test_first_request_rejects_mutated_audit_and_launch_receipt(tmp_path: Path):
    from nooa_cybergym.leaderboard.native_first_request import NativeFirstRequestWitness

    launch_dir = tmp_path / "launch"
    launch_dir.mkdir()
    receipt = {"event": "launch_reserved", "launch_id": "launch-1"}
    path = launch_dir / "launcher-receipt.json"
    path.write_bytes(canonical_json(receipt))

    class Authority:
        manifest = {"task_id": "arvo:1", "launch_id": "launch-1"}

        def _check_receipt(self, value):
            if value != receipt:
                raise ValueError("launch receipt changed")

    Authority.launch_dir = launch_dir
    audit = tmp_path / "model-requests.jsonl"
    witness = NativeFirstRequestWitness(
        launch_authority=Authority(),
        attempt_id="attempt-1",
        model_audit=audit,
        policy_sha256="a" * 64,
        expected_model="glm-5.3",
    )
    event = {
        "event": "request_reserved",
        "task_id": "arvo:1",
        "attempt_id": "attempt-1",
        "request_id": "model-1",
        "role": "primary",
        "requested_model": "glm-5.3",
        "policy_sha256": "a" * 64,
    }
    audit.write_bytes(canonical_json(event) + b"\n" + b"{broken\n")
    with pytest.raises(RuntimeError, match="audit"):
        witness.observed("launch-1")
    audit.write_bytes(canonical_json(event) + b"\n")
    path.write_bytes(canonical_json({"event": "launch_reserved", "launch_id": "changed"}))
    with pytest.raises(ValueError, match="launch receipt"):
        witness.observed("launch-1")
