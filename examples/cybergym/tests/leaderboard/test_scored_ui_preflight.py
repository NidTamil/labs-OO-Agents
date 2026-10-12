# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""The scored UI mailbox is bound before a durable campaign is created."""

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nooa_cybergym.leaderboard.campaign_runner import MailboxNativeUi
from nooa_cybergym.leaderboard.native_ui_mailbox import NativeUiMailbox
from nooa_cybergym.leaderboard.scored_campaign_inputs import (
    ScoredLaunchPreview,
    SignedCampaignInputs,
)
from nooa_cybergym.leaderboard.scored_launch_config import ScoredSignerPreflight
from nooa_cybergym.leaderboard.scored_ui_preflight import (
    ScoredUiPreflight,
    prepare_previewed_scored_ui,
    require_previewed_scored_ui_client,
)
from xeus_cybergym.ledger import Ed25519Signer, Ed25519Verifier, SignedEnvelope


def test_scored_ui_mailbox_is_ready_before_admission_and_bound_to_signed_run(tmp_path: Path):
    mailbox_root = tmp_path / "mailbox"
    mailbox_root.mkdir()
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    private = Ed25519PrivateKey.generate()
    signer = Ed25519Signer(private_key=private, key_id="controller-1")
    verifier = Ed25519Verifier({"controller-1": private.public_key()})
    config = {
        "run_id": "run-1",
        "epoch": "scored-epoch-1",
        "paths": {"mailbox_root": str(mailbox_root), "evidence_root": str(evidence_root)},
    }
    signers = ScoredSignerPreflight(config, object(), signer, verifier, signer, verifier)
    inputs = SignedCampaignInputs(b"decision", b"cert", b"lock", b"cohort", b"[]", {})

    class State:
        run_id = "run-1"
        epoch = "scored-epoch-1"

    authority = object()
    state = State()
    state.evidence_root = evidence_root
    state.authority = authority
    preview = ScoredLaunchPreview(inputs, authority, state, {"controller-1": private.public_key()})
    prepared = prepare_previewed_scored_ui(preview, signers)
    assert prepared.mailbox.run_id == "run-1"
    assert prepared.ui.mailbox is prepared.mailbox
    assert (mailbox_root / "native-ui-mailbox.sqlite").is_file()
    assert prepared.mailbox.pending() is None

    config["run_id"] = "other-run"
    with pytest.raises(RuntimeError, match="signed run"):
        prepare_previewed_scored_ui(preview, signers)


def test_scored_ui_client_probe_requires_fresh_completed_signed_status(tmp_path: Path, monkeypatch):
    key = Ed25519PrivateKey.generate()
    signer = Ed25519Signer(private_key=key, key_id="controller-1")
    verifier = Ed25519Verifier({"controller-1": key.public_key()})
    root = tmp_path / "mailbox"
    root.mkdir()
    mailbox = NativeUiMailbox(root, run_id="run-1", signer=signer, verifier=verifier)
    prepared = ScoredUiPreflight(mailbox, MailboxNativeUi(mailbox))
    original_wait = mailbox.wait_ack
    observed = []

    def acknowledge(command_id, *, timeout_seconds):
        pending = mailbox.pending()
        assert pending is not None
        payload = verifier.verify(SignedEnvelope.model_validate_json(pending))
        command = json.loads(payload)
        observed.append(command)
        assert command["command_id"] == command_id
        mailbox.acknowledge(command_id, status="completed")
        return original_wait(command_id, timeout_seconds=timeout_seconds)

    monkeypatch.setattr(mailbox, "wait_ack", acknowledge)
    require_previewed_scored_ui_client(prepared, timeout_seconds=1)
    require_previewed_scored_ui_client(prepared, timeout_seconds=1)
    assert len(observed) == 2
    assert observed[0]["command_id"] != observed[1]["command_id"]
    assert all(command["action"] == "status" for command in observed)
    assert mailbox.pending() is None
    monkeypatch.setattr(mailbox, "wait_ack", original_wait)
    with pytest.raises(TimeoutError, match="not acknowledged"):
        require_previewed_scored_ui_client(prepared, timeout_seconds=0.001)
