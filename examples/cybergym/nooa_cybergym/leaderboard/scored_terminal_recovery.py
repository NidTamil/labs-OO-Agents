# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Read-only reconciliation of one already-finished official native attempt.

This verifier has no Docker, UI or model dispatch path. A restarted controller
may use its output only for the same verified ledger ``started`` transition.
Missing or ambiguous evidence is a refusal, never a reason to retry Send.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from .campaign import CampaignAction, _terminal_receipt
from .native_first_request import NativeFirstRequestWitness
from .native_launcher import NativeLaunchAuthority
from .native_start_intent import wait_start_intent
from .practice_arvo_evaluator import _read_signed
from .practice_arvo_runner import official_raw_solved

_REQUEST_FIELDS = {
    "schema_version",
    "artifact_kind",
    "run_id",
    "epoch",
    "task_id",
    "final_sha256",
    "final_declaration_sha256",
    "parent_event_digest",
    "vulnerable_image_id",
    "fixed_image_id",
    "official_verifier_sha256",
}
_RESULT_FIELDS = {
    "schema_version",
    "artifact_kind",
    "run_id",
    "epoch",
    "task_id",
    "request_sha256",
    "vulnerable",
    "fixed",
    "official_scoring_form",
    "official_solved",
}


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def recover_scored_terminal(
    *,
    state,
    task_id: str,
    launch_authority: NativeLaunchAuthority,
    attempt_id: str,
    witness: NativeFirstRequestWitness,
    evidence_dir: Path,
    controller_verifier,
    evaluator_verifier,
) -> bytes:
    """Return an authentic terminal only after exact launch, Send and oracle proof."""
    if (
        state.next_action() != CampaignAction("observe_started", task_id)
        or type(launch_authority) is not NativeLaunchAuthority
        or launch_authority.manifest.get("scope") != "official"
        or launch_authority.manifest.get("run_id") != state.run_id
        or launch_authority.manifest.get("task_id") != task_id
        or type(attempt_id) is not str
        or not attempt_id
        or type(witness) is not NativeFirstRequestWitness
        or witness.launch is not launch_authority
        or witness.attempt_id != attempt_id
    ):
        raise RuntimeError("recovered native launch differs from verified started task")
    launch_id = launch_authority.manifest["launch_id"]
    started_digest = state.started_event_sha256(task_id, launch_id)
    root = Path(evidence_dir)
    if not root.is_absolute() or root.is_symlink() or not root.is_dir() or root.resolve() != root:
        raise RuntimeError("controller-owned scored recovery evidence required")
    intent = wait_start_intent(
        root,
        verifier=controller_verifier,
        run_id=state.run_id,
        task_id=task_id,
        attempt_id=attempt_id,
        launch_id=launch_id,
        timeout_seconds=0,
    )
    if intent["started_event_sha256"] != started_digest:
        raise RuntimeError("signed start intent differs from verified ledger")
    if witness.observed(launch_id) is not True:
        raise RuntimeError("recovered native first request was not observed")

    request_raw, request = _read_signed(
        root / "scored-evaluation-request.signed.json", controller_verifier
    )
    result_raw, result = _read_signed(
        root / "scored-evaluation-result.signed.json", evaluator_verifier
    )
    terminal_raw, terminal = _read_signed(
        root / "terminal-receipt.signed.json", controller_verifier
    )
    common = {"run_id": state.run_id, "epoch": state.epoch, "task_id": task_id}
    if (
        set(request) != _REQUEST_FIELDS
        or request.get("schema_version") != 1
        or request.get("artifact_kind") != "scored_official_evaluation_request"
        or any(request.get(key) != value for key, value in common.items())
        or request["vulnerable_image_id"] == request["fixed_image_id"]
        or set(result) != _RESULT_FIELDS
        or result.get("schema_version") != 1
        or result.get("artifact_kind") != "scored_official_evaluation_result"
        or any(result.get(key) != value for key, value in common.items())
        or result["request_sha256"] != _sha(request_raw)
        or result["official_scoring_form"] != "raw"
    ):
        raise RuntimeError("signed scored oracle request or result differs from attempt")
    for name, image_key in (("vulnerable", "vulnerable_image_id"), ("fixed", "fixed_image_id")):
        observed = result[name]
        if (
            type(observed) is not dict
            or observed.get("task_id") != task_id
            or observed.get("image_id") != request[image_key]
            or observed.get("candidate_sha256") != request["final_sha256"]
            or observed.get("snapshot_sha256") != request["final_sha256"]
            or observed.get("network_disabled") is not True
            or type(observed.get("raw_exit_code")) is not int
        ):
            raise RuntimeError("signed scored image observation differs from frozen final")
    solved = official_raw_solved(
        result["vulnerable"]["raw_exit_code"], result["fixed"]["raw_exit_code"]
    )
    if result["official_solved"] is not solved:
        raise RuntimeError("signed scored result differs from official raw verdict")
    expected_terminal = {
        "schema_version": 1,
        "artifact_kind": "terminal_receipt",
        **common,
        "status": "oracle_true" if solved else "oracle_false",
        "final_sha256": request["final_sha256"],
        "final_declaration_sha256": request["final_declaration_sha256"],
        "parent_event_digest": request["parent_event_digest"],
        "oracle_request_sha256": _sha(request_raw),
        "oracle_verdict_sha256": _sha(result_raw),
        "oracle_true": solved,
    }
    if terminal != expected_terminal:
        raise RuntimeError("signed scored terminal differs from oracle evidence")
    attested = state.authority.attest_signed("terminal_receipt", terminal_raw)
    if attested != terminal:
        raise RuntimeError("campaign authority rejected scored terminal signature")
    _terminal_receipt(terminal, state=state, task_id=task_id)
    return terminal_raw
