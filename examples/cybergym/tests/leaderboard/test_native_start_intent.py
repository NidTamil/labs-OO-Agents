# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Automatic model lanes stay gated until the verified campaign started event."""

from __future__ import annotations

import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nooa_cybergym.leaderboard.native_start_intent import (
    publish_start_intent,
    wait_start_intent,
)
from xeus_cybergym.ledger import Ed25519Signer, Ed25519Verifier


def test_signed_start_intent_is_idempotent_and_bound_to_exact_attempt(tmp_path):
    private = Ed25519PrivateKey.generate()
    signer = Ed25519Signer(private_key=private, key_id="controller")
    verifier = Ed25519Verifier({"controller": private.public_key()})
    digest = hashlib.sha256(b"verified started event").hexdigest()
    first = publish_start_intent(
        tmp_path,
        signer=signer,
        verifier=verifier,
        run_id="run-1",
        task_id="synthetic:chunk-table",
        attempt_id="attempt-1",
        launch_id="launch-1",
        started_event_sha256=digest,
    )
    assert (
        publish_start_intent(
            tmp_path,
            signer=signer,
            verifier=verifier,
            run_id="run-1",
            task_id="synthetic:chunk-table",
            attempt_id="attempt-1",
            launch_id="launch-1",
            started_event_sha256=digest,
        )
        == first
    )
    observed = wait_start_intent(
        tmp_path,
        verifier=verifier,
        run_id="run-1",
        task_id="synthetic:chunk-table",
        attempt_id="attempt-1",
        launch_id="launch-1",
        timeout_seconds=0,
    )
    assert observed["started_event_sha256"] == digest
    with pytest.raises(RuntimeError, match="differs"):
        wait_start_intent(
            tmp_path,
            verifier=verifier,
            run_id="run-1",
            task_id="synthetic:chunk-table",
            attempt_id="attempt-2",
            launch_id="launch-1",
            timeout_seconds=0,
        )
