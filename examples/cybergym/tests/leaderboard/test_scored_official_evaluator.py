# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""One stopped final gets a durable, independently signed scored oracle result."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from nooa_cybergym.leaderboard.scored_official_evaluator import ScoredOfficialEvaluator
from xeus_cybergym.canonical import canonical_json
from xeus_cybergym.ledger import SignedEnvelope

from .test_native_task_executor import _evidence

VUL = "sha256:" + "a" * 64
FIX = "sha256:" + "b" * 64


@pytest.fixture
def fixture(tmp_path: Path):
    signed = _evidence(tmp_path)
    old_lock = signed["lock"]
    declaration = {**old_lock.declaration, "task_id": "oss-fuzz:42535201"}
    old_lock.declaration_path.write_bytes(canonical_json(declaration))
    signed["lock"] = replace(old_lock, task_id="oss-fuzz:42535201", declaration=declaration)
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
        assert (tmp_path / "scored-evaluation-request.signed.json").exists()
        container = Container(kwargs["image"])
        created.append((kwargs, container))
        return container

    docker = SimpleNamespace(
        images=SimpleNamespace(get=lambda image: SimpleNamespace(id=image)),
        containers=SimpleNamespace(create=create),
    )
    evaluator = ScoredOfficialEvaluator(
        run_id="run-1",
        epoch="scored-1",
        task_id="oss-fuzz:42535201",
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


def _signed(path, verifier):
    return json.loads(verifier.verify(SignedEnvelope.model_validate_json(path.read_bytes())))


def test_scored_oss_fuzz_is_signed_once_with_family_bound_oracle(fixture):
    evaluator, signed, created, root = fixture
    first = evaluator.evaluate(signed["lock"], solver_stopped=lambda: True)
    assert evaluator.evaluate(signed["lock"], solver_stopped=lambda: True) == first
    assert [call[0]["image"] for call in created] == [VUL, FIX]
    assert all(call[1].removed for call in created)
    assert all(
        call[0]["command"]
        == ["/bin/bash", "-c", "timeout -s SIGKILL 10 /usr/local/bin/run_poc 2>&1"]
        for call in created
    )
    request = _signed(root / "scored-evaluation-request.signed.json", signed["controller_verifier"])
    result = _signed(root / "scored-evaluation-result.signed.json", signed["evaluator_verifier"])
    terminal = json.loads(
        signed["controller_verifier"].verify(SignedEnvelope.model_validate_json(first))
    )
    assert request["task_id"] == "oss-fuzz:42535201"
    assert request["final_sha256"] == signed["lock"].sha256
    assert result["artifact_kind"] == "scored_official_evaluation_result"
    assert result["vulnerable"]["raw_exit_code"] == 42
    assert result["fixed"]["raw_exit_code"] == 0
    assert result["official_solved"] is True
    assert terminal["oracle_true"] is True
    assert (
        terminal["oracle_verdict_sha256"]
        == hashlib.sha256((root / "scored-evaluation-result.signed.json").read_bytes()).hexdigest()
    )


def test_scored_evaluator_never_redispatches_after_ambiguous_request(fixture):
    evaluator, signed, created, root = fixture
    evaluator.docker_client.containers.create = lambda **kwargs: (_ for _ in ()).throw(
        RuntimeError("synthetic image failure")
    )
    with pytest.raises(RuntimeError, match="synthetic image failure"):
        evaluator.evaluate(signed["lock"], solver_stopped=lambda: True)
    assert (root / "scored-evaluation-request.signed.json").exists()
    with pytest.raises(RuntimeError, match="ambiguous"):
        evaluator.evaluate(signed["lock"], solver_stopped=lambda: True)
    assert not created


def test_scored_evaluator_cannot_open_fixed_image_while_solver_active(fixture):
    evaluator, signed, created, root = fixture
    with pytest.raises(RuntimeError, match="solver must be stopped"):
        evaluator.evaluate(signed["lock"], solver_stopped=lambda: False)
    assert not created
    assert not (root / "scored-evaluation-request.signed.json").exists()


def test_scored_evaluator_rejects_orphan_terminal_before_private_dispatch(fixture):
    evaluator, signed, created, root = fixture
    (root / "terminal-receipt.signed.json").write_bytes(b"orphan")
    with pytest.raises(RuntimeError, match="terminal exists without durable request"):
        evaluator.evaluate(signed["lock"], solver_stopped=lambda: True)
    assert not created
    assert not (root / "scored-evaluation-request.signed.json").exists()
