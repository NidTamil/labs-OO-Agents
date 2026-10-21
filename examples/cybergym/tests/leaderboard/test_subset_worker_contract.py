# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Inert worker-boundary facts; no process, signing, host or provider effects."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path

import pytest
from nooa_cybergym.leaderboard.budgeted_subset_admission import BudgetedSubsetPreview
from nooa_cybergym.leaderboard.budgeted_subset_runner import PreparedSubsetLaunch
from nooa_cybergym.leaderboard.campaign_runner import UiTarget
from nooa_cybergym.leaderboard.subset_run_budget import VerifiedSubsetBudget
from nooa_cybergym.leaderboard.subset_worker_contract import (
    BoundSubsetTaskInputs,
    BoundSubsetTaskOutput,
    MaterialReference,
    WorkerContractError,
)

_A = "a" * 64
_B = "b" * 64
_C = "c" * 64
_D = "d" * 64
_E = "e" * 64
_F = "f" * 64
_ZERO = "0" * 64
_ONE = "1" * 64
_TWO = "2" * 64
_THREE = "3" * 64
_FOUR = "4" * 64
_FIVE = "5" * 64
_SIX = "6" * 64
_SEVEN = "7" * 64
_EIGHT = "8" * 64
_NINE = "9" * 64
_MANIFEST = (
    b'{"items":[{"delivery":"sealed_fd","name":"entrypoint","sha256":"'
    + _A.encode()
    + b'","size_bytes":128},{"delivery":"pinned_runtime","name":"interpreter",'
    b'"path":"/opt/cybergym/python","sha256":"'
    + _B.encode()
    + b'","size_bytes":100000}],"schema_version":1}'
)


def _inputs() -> BoundSubsetTaskInputs:
    return BoundSubsetTaskInputs(
        run_id="subset-run",
        epoch="epoch-1",
        task_id="arvo:47101",
        preparation_id="prep-101",
        attempt_id="attempt-101",
        preparation_started_event_sha256=_ZERO,
        source_commit="a" * 40,
        cohort_sha256=_ONE,
        admission_sha256=_TWO,
        freeze_sha256=_THREE,
        certification_sha256=_FOUR,
        budget_sha256=_FIVE,
        model_policy_sha256=_SIX,
        metering_policy_sha256=_SEVEN,
        launch_config_sha256=_EIGHT,
        material_manifest_sha256=hashlib.sha256(_MANIFEST).hexdigest(),
        aggregate_deadline_ns=2_200_000_000,
        manager_deadline_ns=2_000_000_000,
        stop_grace_ns=100_000_000,
        material=(
            MaterialReference("entrypoint", "sealed_fd", _A, 128, fd=7),
            MaterialReference(
                "interpreter", "pinned_runtime", _B, 100000, path="/opt/cybergym/python"
            ),
        ),
    )


def _preview() -> BudgetedSubsetPreview:
    budget = VerifiedSubsetBudget(
        run_id="subset-run",
        epoch="epoch-1",
        campaign_policy_sha256=_NINE,
        model_policy_sha256=_SIX,
        metering_policy_sha256=_SEVEN,
        max_elapsed_seconds=432000,
        max_spend_units=500000000,
        signed_envelope=b"synthetic budget bytes",
        envelope_sha256=_FIVE,
        payload_json=b"synthetic payload bytes",
        payload_sha256=_C,
    )
    return BudgetedSubsetPreview(
        run_id="subset-run",
        epoch="epoch-1",
        evidence_root=Path("/synthetic/evidence"),
        source_commit="a" * 40,
        cohort_sha256=_ONE,
        freeze_sha256=_THREE,
        certification_sha256=_FOUR,
        admission_sha256=_TWO,
        payload_sha256=_D,
        signed_admission=b"synthetic admission bytes",
        budget=budget,
    )


def _preparation() -> dict:
    return {
        "preparation_id": "prep-101",
        "preparation_started_event_sha256": _ZERO,
        "preparation_started": {
            "type": "preparation_started",
            "task_id": "arvo:47101",
            "preparation_id": "prep-101",
        },
        "prepared": None,
    }


def _resources() -> dict:
    return {
        "run_id": "subset-run",
        "epoch": "epoch-1",
        "budget_sha256": _FIVE,
        "started_at_ns": 900_000_000,
        "deadline_ns": 2_200_000_000,
        "last_observed_ns": 1_000_000_000,
        "stop": None,
    }


def _launch() -> PreparedSubsetLaunch:
    return PreparedSubsetLaunch(
        task_id="arvo:47101",
        preparation_id="prep-101",
        request_id="request-101",
        attempt_id="attempt-101",
        launch_sha256=_E,
        ui_target=UiTarget("cybergym-host", 2291),
    )


def test_exact_input_identity_and_material_manifest_are_bound_without_fd_number():
    first = _inputs()
    second = replace(
        first,
        material=(
            replace(first.material[0], fd=11),
            first.material[1],
        ),
    )
    assert first.material_manifest_sha256 == hashlib.sha256(_MANIFEST).hexdigest()
    assert first.identity_sha256 == second.identity_sha256
    first.require_existing_identity(
        preview=_preview(),
        preparation=_preparation(),
        resource_snapshot=_resources(),
        signed_launch_config_sha256=_EIGHT,
        expected_attempt_id="attempt-101",
    )


@pytest.mark.parametrize(
    "change",
    [
        {"run_id": "other-run"},
        {"epoch": "other-epoch"},
        {"task_id": "arvo:3938"},
        {"preparation_id": "other-prep"},
        {"attempt_id": ""},
        {"source_commit": "z" * 40},
        {"budget_sha256": _NINE},
        {"certification_sha256": _NINE},
        {"material_manifest_sha256": _NINE},
        {"manager_deadline_ns": 2_150_000_000},
        {"stop_grace_ns": 250_000_000},
    ],
)
def test_invalid_or_changed_input_identity_fails_closed(change):
    with pytest.raises(WorkerContractError):
        replace(_inputs(), **change).require_existing_identity(
            preview=_preview(),
            preparation=_preparation(),
            resource_snapshot=_resources(),
            signed_launch_config_sha256=_EIGHT,
            expected_attempt_id="attempt-101",
        )


@pytest.mark.parametrize(
    "change",
    [
        {"delivery": "sealed_fd", "fd": None},
        {"delivery": "sealed_fd", "path": "/tmp/entrypoint"},
        {"delivery": "pinned_runtime", "fd": 7},
        {"delivery": "pinned_runtime", "path": "relative/python", "fd": None},
        {"delivery": "pinned_runtime", "path": "/opt/../tmp/python", "fd": None},
    ],
)
def test_material_delivery_classes_reject_ambiguous_fallback(change):
    values = {
        "name": "entrypoint",
        "delivery": "sealed_fd",
        "sha256": _A,
        "size_bytes": 128,
        "fd": 7,
        "path": None,
    }
    values.update(change)
    with pytest.raises(WorkerContractError):
        MaterialReference(**values)


@pytest.mark.parametrize(
    "path",
    [
        pytest.param("/" + "a" * 4095, id="ascii-over-byte-limit"),
        pytest.param("/" + "é" * 2048, id="utf8-over-byte-limit"),
        pytest.param("/opt/runtime\npython", id="newline"),
        pytest.param("/opt/runtime\x7fpython", id="del-control"),
        pytest.param("/opt/runtime\x85python", id="c1-control"),
        pytest.param("/opt/runtime\ud800python", id="surrogate"),
    ],
)
def test_pinned_runtime_path_rejects_unbounded_bytes_controls_and_surrogates(path):
    with pytest.raises(WorkerContractError):
        MaterialReference("interpreter", "pinned_runtime", _B, 100000, path=path)


def test_pinned_runtime_path_accepts_bounded_utf8_path():
    path = "/" + "é" * 2047
    assert len(path.encode("utf-8")) == 4095
    assert MaterialReference("interpreter", "pinned_runtime", _B, 100000, path=path).path == path


def test_stopped_or_drifted_resource_snapshot_cannot_match_task():
    input_contract = _inputs()
    for change in (
        {"deadline_ns": 2_300_000_000},
        {"started_at_ns": 1_200_000_000},
        {"last_observed_ns": 2_000_000_000},
        {"stop": {"reason": "deadline"}},
        {"budget_sha256": _NINE},
    ):
        snapshot = {**_resources(), **change}
        with pytest.raises(WorkerContractError):
            input_contract.require_existing_identity(
                preview=_preview(),
                preparation=_preparation(),
                resource_snapshot=snapshot,
                signed_launch_config_sha256=_EIGHT,
                expected_attempt_id="attempt-101",
            )


def test_mutated_budget_and_preparation_events_cannot_match_preview():
    contract = _inputs()
    preview = _preview()
    altered_preview = replace(preview, budget=replace(preview.budget, run_id="other-run"))
    with pytest.raises(WorkerContractError):
        contract.require_existing_identity(
            preview=altered_preview,
            preparation=_preparation(),
            resource_snapshot=_resources(),
            signed_launch_config_sha256=_EIGHT,
            expected_attempt_id="attempt-101",
        )
    preparation = _preparation()
    preparation["preparation_started"]["type"] = "different_event"
    with pytest.raises(WorkerContractError):
        contract.require_existing_identity(
            preview=preview,
            preparation=preparation,
            resource_snapshot=_resources(),
            signed_launch_config_sha256=_EIGHT,
            expected_attempt_id="attempt-101",
        )


def test_unverified_output_bytes_require_exact_input_and_prepared_launch_binding():
    contract = _inputs()
    raw = b"synthetic signed-looking bytes without an attested signer"
    output = BoundSubsetTaskOutput(
        kind="terminal",
        inputs_sha256=contract.identity_sha256,
        task_id=contract.task_id,
        preparation_id=contract.preparation_id,
        attempt_id=contract.attempt_id,
        request_id="request-101",
        launch_sha256=_E,
        payload=raw,
        payload_sha256=hashlib.sha256(raw).hexdigest(),
    )
    assert output.require_binding(contract, _launch()) == raw
    for altered in (
        replace(output, inputs_sha256=_NINE),
        replace(output, attempt_id="attempt-102"),
        replace(output, launch_sha256=_NINE),
    ):
        with pytest.raises(WorkerContractError):
            altered.require_binding(contract, _launch())
    with pytest.raises(WorkerContractError):
        replace(output, payload_sha256=_NINE)
    with pytest.raises(WorkerContractError):
        output.require_binding(contract, replace(_launch(), request_id="other-request"))
