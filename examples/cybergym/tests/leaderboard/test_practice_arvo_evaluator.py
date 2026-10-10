# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""One locked final enters the private official ARVO verifier once."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from nooa_cybergym.leaderboard.practice_arvo_evaluator import PracticeArvoEvaluator
from xeus_cybergym.ledger import SignedEnvelope

from .test_native_task_executor import _evidence

VUL = "sha256:" + "a" * 64
FIX = "sha256:" + "b" * 64


@pytest.fixture
def fixture(tmp_path: Path):
    signed = _evidence(tmp_path)
    created = []
    source = tmp_path / "server_utils.py"
    source.write_bytes(b"pinned official verifier source")

    class Container:
        def __init__(self, image):
            self.image = image
            self.removed = False

        def start(self):
            pass

        def wait(self, timeout):
            assert timeout == 60
            return {"StatusCode": 42 if self.image == VUL else 0}

        def logs(self, **_):
            return iter((b"observed",))

        def remove(self, force):
            self.removed = force

    def create(**kwargs):
        assert (tmp_path / "practice-evaluation-request.signed.json").exists()
        container = Container(kwargs["image"])
        created.append((kwargs, container))
        return container

    docker = SimpleNamespace(
        images=SimpleNamespace(get=lambda image: SimpleNamespace(id=image)),
        containers=SimpleNamespace(create=create),
    )
    evaluator = PracticeArvoEvaluator(
        run_id="run-1",
        epoch="practice-1",
        task_id="arvo:1",
        evidence_dir=tmp_path,
        vulnerable_image_id=VUL,
        fixed_image_id=FIX,
        official_verifier_source=source,
        official_verifier_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        docker_client=docker,
        controller_signer=signed["controller_signer"],
        controller_verifier=signed["controller_verifier"],
        evaluator_signer=signed["evaluator_signer"],
        evaluator_verifier=signed["evaluator_verifier"],
    )
    return evaluator, signed, created, tmp_path


def test_practice_final_is_scored_once_with_signed_request_result_and_terminal(fixture):
    evaluator, signed, created, root = fixture
    first = evaluator.evaluate(signed["lock"], solver_stopped=lambda: True)
    second = evaluator.evaluate(signed["lock"], solver_stopped=lambda: True)
    assert first == second
    assert [call[0]["image"] for call in created] == [VUL, FIX]
    assert all(call[0]["network_mode"] == "none" and call[1].removed for call in created)
    request = json.loads(
        signed["controller_verifier"].verify(
            SignedEnvelope.model_validate_json(
                (root / "practice-evaluation-request.signed.json").read_bytes()
            )
        )
    )
    result = json.loads(
        signed["evaluator_verifier"].verify(
            SignedEnvelope.model_validate_json(
                (root / "practice-evaluation-result.signed.json").read_bytes()
            )
        )
    )
    terminal = json.loads(
        signed["controller_verifier"].verify(SignedEnvelope.model_validate_json(first))
    )
    assert request["final_sha256"] == signed["lock"].sha256
    assert result["vulnerable"]["raw_exit_code"] == 42
    assert result["fixed"]["raw_exit_code"] == 0
    assert result["official_solved"] is True
    assert terminal["status"] == "oracle_true"
    assert terminal["oracle_true"] is True


def test_practice_evaluation_never_retries_ambiguous_request(fixture):
    evaluator, signed, created, root = fixture
    evaluator.docker_client.containers.create = lambda **kwargs: (_ for _ in ()).throw(
        RuntimeError("synthetic image failure")
    )
    with pytest.raises(RuntimeError, match="synthetic image failure"):
        evaluator.evaluate(signed["lock"], solver_stopped=lambda: True)
    assert (root / "practice-evaluation-request.signed.json").exists()
    with pytest.raises(RuntimeError, match="ambiguous"):
        evaluator.evaluate(signed["lock"], solver_stopped=lambda: True)
    assert not created


def test_practice_evaluation_never_opens_fixed_image_while_solver_active(fixture):
    evaluator, signed, created, root = fixture
    with pytest.raises(RuntimeError, match="solver must be stopped"):
        evaluator.evaluate(signed["lock"], solver_stopped=lambda: False)
    assert not created
    assert not (root / "practice-evaluation-request.signed.json").exists()


def test_practice_evaluation_rejects_changed_official_verifier_source(fixture):
    evaluator, signed, created, root = fixture
    (root / "server_utils.py").write_bytes(b"changed")
    with pytest.raises(RuntimeError, match="official verifier"):
        evaluator.evaluate(signed["lock"], solver_stopped=lambda: True)
    assert not created
    assert not (root / "practice-evaluation-request.signed.json").exists()
