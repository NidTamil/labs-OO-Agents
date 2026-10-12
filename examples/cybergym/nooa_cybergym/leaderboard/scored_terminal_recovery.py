# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Read-only reconciliation of one already-finished official native attempt.

This verifier has no Docker, UI or model dispatch path. A restarted controller
may use its output only for the same verified ledger ``started`` transition.
Missing or ambiguous evidence is a refusal, never a reason to retry Send.
"""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Mapping
from pathlib import Path

from .campaign import CampaignAction, _terminal_receipt
from .native_first_request import NativeFirstRequestWitness
from .native_launcher import NativeLaunchAuthority
from .native_start_intent import wait_start_intent
from .practice_arvo_evaluator import _read_signed
from .practice_arvo_runner import official_raw_solved
from .synthetic_workspace import write_new

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


def persist_scored_launch(
    *,
    state,
    task_id: str,
    signed_envelope: bytes,
    public_keys: Mapping,
    evidence_dir: Path,
) -> NativeLaunchAuthority:
    """Durably bind one signed native launch before declaring it prepared.

    An existing file is never replaced or accepted as a fresh reservation. A
    crash after this write therefore blocks a second launch until the signed
    ledger and the original attempt are reconciled.
    """
    task_ids = getattr(state, "task_ids", None)
    run_id = getattr(state, "run_id", None)
    root = Path(evidence_dir)
    if (
        type(task_id) is not str
        or re.fullmatch(r"(?:arvo|oss-fuzz):[0-9]+", task_id) is None
        or type(task_ids) is not tuple
        or task_id not in task_ids
        or type(run_id) is not str
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", run_id) is None
        or state.next_action() != CampaignAction("prepare", task_id)
    ):
        raise RuntimeError("signed current cohort preparation required for native launch")
    if (
        not root.is_absolute()
        or root.is_symlink()
        or not root.is_dir()
        or root.resolve() != root
        or root.name != f"{run_id}-{task_id.replace(':', '-')}"
    ):
        raise RuntimeError("current scored task evidence directory required")
    launch = NativeLaunchAuthority.from_signed_envelope(signed_envelope, public_keys, root)
    manifest = launch.manifest
    if (
        manifest.get("scope") != "official"
        or manifest.get("run_id") != run_id
        or manifest.get("task_id") != task_id
        or manifest.get("ordinal") != task_ids.index(task_id) + 1
    ):
        raise RuntimeError("signed native launch differs from current cohort task")
    try:
        write_new(root / "native-launch.signed.json", signed_envelope)
    except FileExistsError:
        raise RuntimeError("scored native launch evidence already exists") from None
    if os.name == "posix":
        descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    return launch


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


class ScoredTerminalRecovery:
    """Reconstruct the verifier from durable controller-only attempt files."""

    def __init__(
        self,
        *,
        state,
        evidence_dir: Path,
        public_keys: Mapping,
        controller_verifier,
        evaluator_verifier,
        expected_policy_sha256: str,
        expected_model: str,
    ) -> None:
        root = Path(evidence_dir)
        if (
            not root.is_absolute()
            or root.is_symlink()
            or not root.is_dir()
            or root.resolve() != root
            or not isinstance(public_keys, Mapping)
            or not public_keys
            or not callable(getattr(controller_verifier, "verify", None))
            or not callable(getattr(evaluator_verifier, "verify", None))
            or type(expected_policy_sha256) is not str
            or re.fullmatch(r"[a-f0-9]{64}", expected_policy_sha256) is None
            or type(expected_model) is not str
            or not expected_model
        ):
            raise ValueError("frozen scored recovery inputs required")
        self.state = state
        self.root = root
        self.public_keys = public_keys
        self.controller_verifier = controller_verifier
        self.evaluator_verifier = evaluator_verifier
        self.policy_sha256 = expected_policy_sha256
        self.model = expected_model

    def __call__(self, task_id: str, request_id: str) -> bytes | None:
        terminal_path = self.root / "terminal-receipt.signed.json"
        if not terminal_path.exists() and not terminal_path.is_symlink():
            return None
        launch_raw, manifest = _read_signed(
            self.root / "native-launch.signed.json", self.controller_verifier
        )
        if (
            manifest.get("run_id") != self.state.run_id
            or manifest.get("task_id") != task_id
            or manifest.get("launch_id") != request_id
        ):
            raise RuntimeError("durable scored launch differs from verified request")
        launch = NativeLaunchAuthority.from_signed_envelope(launch_raw, self.public_keys, self.root)
        _, intent = _read_signed(
            self.root / "campaign-start-intent.signed.json", self.controller_verifier
        )
        attempt_id = intent.get("attempt_id")
        witness = NativeFirstRequestWitness(
            launch_authority=launch,
            attempt_id=attempt_id,
            model_audit=self.root / "model-requests.jsonl",
            policy_sha256=self.policy_sha256,
            expected_model=self.model,
        )
        return recover_scored_terminal(
            state=self.state,
            task_id=task_id,
            launch_authority=launch,
            attempt_id=attempt_id,
            witness=witness,
            evidence_dir=self.root,
            controller_verifier=self.controller_verifier,
            evaluator_verifier=self.evaluator_verifier,
        )


class CohortTerminalRecovery:
    """Choose one controller-owned attempt directory from the verified cohort state.

    The per-task verifier above intentionally takes an exact directory. This
    adapter supplies that directory without accepting a path from a mailbox,
    model, or resumed launch record. A missing prepared directory is an error;
    only a missing terminal inside an existing directory means still running.
    """

    def __init__(
        self,
        *,
        state,
        evidence_root: Path,
        public_keys: Mapping,
        controller_verifier,
        evaluator_verifier,
        expected_policy_sha256: str,
        expected_model: str,
    ) -> None:
        root = Path(evidence_root)
        run_id = getattr(state, "run_id", None)
        task_ids = getattr(state, "task_ids", None)
        if (
            not root.is_absolute()
            or root.is_symlink()
            or not root.is_dir()
            or root.resolve() != root
            or type(run_id) is not str
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", run_id) is None
            or type(task_ids) is not tuple
            or not task_ids
            or not callable(getattr(state, "next_action", None))
        ):
            raise ValueError("verified scored cohort and controller evidence root required")
        self.state = state
        self.root = root
        self.public_keys = public_keys
        self.controller_verifier = controller_verifier
        self.evaluator_verifier = evaluator_verifier
        self.policy_sha256 = expected_policy_sha256
        self.model = expected_model

    def __call__(self, task_id: str, request_id: str) -> bytes | None:
        if (
            type(task_id) is not str
            or re.fullmatch(r"(?:arvo|oss-fuzz):[0-9]+", task_id) is None
            or task_id not in self.state.task_ids
            or self.state.next_action() != CampaignAction("observe_started", task_id)
        ):
            raise RuntimeError("recovery is limited to the current signed cohort task")
        evidence = self.root / f"{self.state.run_id}-{task_id.replace(':', '-')}"
        if (
            evidence.is_symlink()
            or not evidence.is_dir()
            or evidence.resolve() != evidence
            or evidence.parent != self.root
        ):
            raise RuntimeError("current scored task evidence is missing or linked")
        recovery = ScoredTerminalRecovery(
            state=self.state,
            evidence_dir=evidence,
            public_keys=self.public_keys,
            controller_verifier=self.controller_verifier,
            evaluator_verifier=self.evaluator_verifier,
            expected_policy_sha256=self.policy_sha256,
            expected_model=self.model,
        )
        return recovery(task_id, request_id)
