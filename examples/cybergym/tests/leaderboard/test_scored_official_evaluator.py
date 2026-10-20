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
from nooa_cybergym.leaderboard.finalize import _primary_event_digest
from nooa_cybergym.leaderboard.native_task_executor import _locked_final
from nooa_cybergym.leaderboard.primary_takeover import PrimaryTakeoverPolicy
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
            log_path = tmp_path / f"{len(created)}.docker.log"
            log_path.touch()
            self.attrs = {"LogPath": str(log_path)}

        def reload(self):
            pass

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


def _schema2_lock(signed, *, fallback):
    policy = PrimaryTakeoverPolicy()
    route = policy.fallback if fallback else policy.initial
    old = signed["lock"]
    declaration = {
        **old.declaration,
        "schema_version": 2,
        "selected_by": "primary_parent",
        "provider": route.provider,
        "configured_model": route.model,
        "provider_model": route.wire_model,
        "takeover_policy_sha256": policy.digest,
        "provider_attempt_id": "provider-attempt-2" if fallback else "provider-attempt-1",
        "attempt_id": "attempt-1",
        "request_id": "request-1",
        "session_id": "session-1",
        "tool_id": "select-final-1",
    }
    old.declaration_path.write_bytes(canonical_json(declaration))
    signed["lock"] = replace(
        old, declaration=declaration, parent_event_digest=_primary_event_digest(declaration)
    )
    return policy


def _with_policy(evaluator, policy):
    args = dict(vars(evaluator))
    args.pop("takeover_policy", None)
    args["evidence_dir"] = args.pop("evidence")
    return ScoredOfficialEvaluator(**args, takeover_policy=policy)


@pytest.mark.parametrize("fallback", [False, True])
def test_explicit_schema2_policy_preserves_actual_primary_final_and_one_oracle(fixture, fallback):
    evaluator, signed, created, root = fixture
    policy = _schema2_lock(signed, fallback=fallback)
    candidate, declaration = _locked_final(
        root, evaluator.task_id, signed["lock"], lambda: True, takeover_policy=policy
    )
    assert candidate == signed["lock"].poc_path.read_bytes()
    assert json.loads(declaration) == signed["lock"].declaration
    evaluator = _with_policy(evaluator, policy)
    terminal = evaluator.evaluate(signed["lock"], solver_stopped=lambda: True)
    assert evaluator.evaluate(signed["lock"], solver_stopped=lambda: True) == terminal
    assert [call[0]["image"] for call in created] == [VUL, FIX]
    request = _signed(root / "scored-evaluation-request.signed.json", signed["controller_verifier"])
    assert request["parent_event_digest"] == _primary_event_digest(signed["lock"].declaration)
    assert request["final_declaration_sha256"] == hashlib.sha256(declaration).hexdigest()


@pytest.mark.parametrize("fallback", [False, True])
def test_legacy_default_rejects_schema2_even_when_attribution_is_valid(fixture, fallback):
    evaluator, signed, created, root = fixture
    _schema2_lock(signed, fallback=fallback)
    with pytest.raises(ValueError, match="fields"):
        evaluator.evaluate(signed["lock"], solver_stopped=lambda: True)
    assert created == []
    assert not (root / "scored-evaluation-request.signed.json").exists()


def test_explicit_takeover_policy_rejects_legacy_final_and_untyped_policy(fixture):
    evaluator, signed, created, root = fixture
    with pytest.raises(ValueError, match="takeover policy"):
        _with_policy(evaluator, object())
    evaluator = _with_policy(evaluator, PrimaryTakeoverPolicy())
    with pytest.raises(ValueError, match="fields"):
        evaluator.evaluate(signed["lock"], solver_stopped=lambda: True)
    assert created == []
    assert not (root / "scored-evaluation-request.signed.json").exists()


@pytest.mark.parametrize(
    "change",
    [
        {"takeover_policy_sha256": "a" * 64},
        {"configured_model": "glm-5.3[1m]"},
        {"selected_by": "glm_parent"},
        {"provider_attempt_id": "request-1"},
    ],
)
def test_schema2_attribution_mismatch_rejected_before_private_dispatch(fixture, change):
    evaluator, signed, created, root = fixture
    policy = _schema2_lock(signed, fallback=True)
    lock = signed["lock"]
    declaration = {**lock.declaration, **change}
    lock.declaration_path.write_bytes(canonical_json(declaration))
    changed_lock = replace(lock, declaration=declaration)
    evaluator = _with_policy(evaluator, policy)
    with pytest.raises((ValueError, RuntimeError)):
        evaluator.evaluate(changed_lock, solver_stopped=lambda: True)
    assert created == []
    assert not (root / "scored-evaluation-request.signed.json").exists()


def test_coherent_provider_substitution_cannot_reuse_original_parent_event(fixture):
    evaluator, signed, created, root = fixture
    policy = _schema2_lock(signed, fallback=False)
    lock = signed["lock"]
    declaration = {
        **lock.declaration,
        "provider": policy.fallback.provider,
        "configured_model": policy.fallback.model,
        "provider_model": policy.fallback.wire_model,
        "provider_attempt_id": "replacement-provider-attempt",
    }
    lock.declaration_path.write_bytes(canonical_json(declaration))
    changed_lock = replace(lock, declaration=declaration)
    with pytest.raises(RuntimeError, match="parent final"):
        _with_policy(evaluator, policy).evaluate(changed_lock, solver_stopped=lambda: True)
    assert created == []
    assert not (root / "scored-evaluation-request.signed.json").exists()


def test_schema2_post_dispatch_custody_recheck_preserves_failed_observations(fixture, monkeypatch):
    import nooa_cybergym.leaderboard.scored_official_evaluator as module

    evaluator, signed, created, root = fixture
    policy = _schema2_lock(signed, fallback=True)
    evaluator = _with_policy(evaluator, policy)
    observed = module.run_official_image

    def change_after_fixed(*args, **kwargs):
        result = observed(*args, **kwargs)
        if kwargs["image_id"] == FIX:
            signed["lock"].poc_path.write_bytes(b"changed after fixed synthetic observation")
        return result

    monkeypatch.setattr(module, "run_official_image", change_after_fixed)
    with pytest.raises(RuntimeError, match="locked parent final changed"):
        evaluator.evaluate(signed["lock"], solver_stopped=lambda: True)
    assert len(created) == 2
    assert (root / "scored-evaluation-request.signed.json").exists()
    assert not (root / "scored-evaluation-result.signed.json").exists()
    assert not (root / "terminal-receipt.signed.json").exists()
