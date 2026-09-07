from __future__ import annotations

import base64
import hashlib
import json
import os

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cybergym.server.pocdb import PoCRecord, Session, init_engine
from scripts.score_final import _strict_evidence_name, score_run
from xeus_cybergym.canonical import canonical_json
from xeus_cybergym.ledger import Ed25519Verifier, SignedEnvelope

_MISSING = object()


def _configure_signing(monkeypatch) -> None:
    seed = os.urandom(32)
    monkeypatch.setenv("SUNCHASER_EVIDENCE_SIGNING_SEED", base64.b64encode(seed).decode())
    monkeypatch.setenv("SUNCHASER_EVIDENCE_KEY_ID", "test-key")


def _write_run(
    run_dir,
    name: str,
    agent_id: str,
    task_id: str,
    *,
    cohort_id="heldout-v2",
    evaluation_mode="heldout",
    poc: bytes = b"official-final",
    selection=_MISSING,
    artifacts: bool = True,
) -> str:
    log_dir = run_dir / "logs" / name
    log_dir.mkdir(parents=True)
    args = {"agent_id": agent_id, "task": {"task_id": task_id}}
    if cohort_id is not _MISSING:
        args["cohort_id"] = cohort_id
    if evaluation_mode is not _MISSING:
        args["evaluation_mode"] = evaluation_mode
    (log_dir / "args.json").write_text(json.dumps(args))
    digest = hashlib.sha256(poc).hexdigest()
    if artifacts:
        final_dir = log_dir / "artifacts" / "final_submission"
        final_dir.mkdir(parents=True)
        (final_dir / "poc").write_bytes(poc)
        manifest = (
            {"submission_number": 1, "sha256": digest, "byte_length": len(poc)}
            if selection is _MISSING
            else selection
        )
        (final_dir / "selection.json").write_text(
            manifest if isinstance(manifest, str) else json.dumps(manifest)
        )
    return digest


def _write_db(path, rows: list[tuple[str, str, str]]) -> None:
    engine = init_engine(path)
    with Session(engine) as session:
        session.add_all(
            [
                PoCRecord(
                    agent_id=agent_id,
                    task_id=task_id,
                    poc_id=f"poc-{index}",
                    poc_hash=digest,
                    poc_length=14,
                    vul_exit_code=139,
                    fix_exit_code=0,
                )
                for index, (agent_id, task_id, digest) in enumerate(rows)
            ]
        )
        session.commit()


def test_score_run_preserves_legacy_single_run_and_verifiable_evidence(tmp_path, monkeypatch):
    _configure_signing(monkeypatch)
    run_dir = tmp_path / "run"
    digest = _write_run(
        run_dir,
        "task",
        "agent-1",
        "arvo:1",
        cohort_id=_MISSING,
        evaluation_mode=_MISSING,
    )
    db_path = tmp_path / "poc.db"
    _write_db(db_path, [("agent-1", "arvo:1", digest)])
    output_dir = run_dir / "official_evidence"

    summary = score_run(run_dir, db_path, output_dir)

    assert summary["official_solved"] == 1
    envelope = SignedEnvelope.model_validate_json((output_dir / "arvo_1.signed.json").read_bytes())
    keys = json.loads((output_dir / "verifiers.json").read_text())
    public = Ed25519PublicKey.from_public_bytes(base64.b64decode(keys["test-key"]))
    payload = Ed25519Verifier({"test-key": public}).verify(envelope)
    assert json.loads(payload)["official_solved"] is True
    assert canonical_json(SignedEnvelope.model_validate_json(canonical_json(envelope))) == canonical_json(
        envelope
    )


def test_score_run_rejects_duplicate_task_ids_before_output_mutation(tmp_path, monkeypatch):
    _configure_signing(monkeypatch)
    run_dir = tmp_path / "run"
    for attempt in ("attempt-a", "attempt-b"):
        _write_run(run_dir, attempt, attempt, "arvo:15", artifacts=False)
    output_dir = tmp_path / "official-evidence"
    with pytest.raises(RuntimeError, match="duplicate task_id"):
        score_run(run_dir, tmp_path / "poc.db", output_dir)
    assert not output_dir.exists()


def test_score_run_rejects_mixed_cohorts_before_output_mutation(tmp_path, monkeypatch):
    _configure_signing(monkeypatch)
    run_dir = tmp_path / "run"
    _write_run(run_dir, "task-15", "attempt-15", "arvo:15", cohort_id="a", artifacts=False)
    _write_run(run_dir, "task-16", "attempt-16", "arvo:16", cohort_id="b", artifacts=False)
    output_dir = tmp_path / "official-evidence"
    with pytest.raises(RuntimeError, match="mixed cohort_id"):
        score_run(run_dir, tmp_path / "poc.db", output_dir)
    assert not output_dir.exists()


@pytest.mark.parametrize("task_id", ["arvo:8", "arvo:13"])
def test_score_run_rejects_diagnostic_entries(tmp_path, monkeypatch, task_id):
    _configure_signing(monkeypatch)
    run_dir = tmp_path / "run"
    _write_run(run_dir, "heldout", "attempt-15", "arvo:15", artifacts=False)
    _write_run(
        run_dir,
        "diagnostic",
        "diagnostic-attempt",
        task_id,
        cohort_id="diagnostic-v2",
        evaluation_mode="diagnostic",
        artifacts=False,
    )
    output_dir = tmp_path / "official-evidence"
    with pytest.raises(RuntimeError, match="evaluation_mode.*diagnostic"):
        score_run(run_dir, tmp_path / "poc.db", output_dir)
    assert not output_dir.exists()


@pytest.mark.parametrize("partial", [False, True])
def test_score_run_requires_multi_entry_cohort_metadata(tmp_path, monkeypatch, partial):
    _configure_signing(monkeypatch)
    run_dir = tmp_path / "run"
    _write_run(
        run_dir,
        "task-15",
        "attempt-15",
        "arvo:15",
        cohort_id="heldout-v2" if partial else _MISSING,
        evaluation_mode="heldout" if partial else _MISSING,
        artifacts=False,
    )
    _write_run(
        run_dir,
        "task-16",
        "attempt-16",
        "arvo:16",
        cohort_id=_MISSING,
        evaluation_mode=_MISSING,
        artifacts=False,
    )
    output_dir = tmp_path / "official-evidence"
    with pytest.raises(RuntimeError, match="cohort_id and evaluation_mode"):
        score_run(run_dir, tmp_path / "poc.db", output_dir)
    assert not output_dir.exists()


def test_score_run_preflights_artifacts_before_key_or_output(tmp_path, monkeypatch):
    monkeypatch.delenv("SUNCHASER_EVIDENCE_SIGNING_SEED", raising=False)
    run_dir = tmp_path / "run"
    _write_run(run_dir, "task-15", "attempt-15", "arvo:15", artifacts=False)
    output_dir = tmp_path / "official-evidence"
    with pytest.raises(RuntimeError, match="final submission artifacts are missing"):
        score_run(run_dir, tmp_path / "poc.db", output_dir)
    assert not output_dir.exists()


def test_strict_evidence_name_resists_delimiter_shift_collision():
    first = ("a", "b__c", "d")
    second = ("a__b", "c", "d")
    assert "__".join(first) == "__".join(second)
    assert _strict_evidence_name(*first) != _strict_evidence_name(*second)


def test_later_malformed_selection_leaves_no_output_directory(tmp_path, monkeypatch):
    _configure_signing(monkeypatch)
    run_dir = tmp_path / "run"
    _write_run(run_dir, "task-15", "attempt-15", "arvo:15")
    _write_run(run_dir, "task-16", "attempt-16", "arvo:16", selection="{malformed")
    output_dir = tmp_path / "official-evidence"
    with pytest.raises(RuntimeError, match="cannot load final selection"):
        score_run(run_dir, tmp_path / "poc.db", output_dir)
    assert not output_dir.exists()


def test_later_db_mismatch_leaves_no_output_directory(tmp_path, monkeypatch):
    _configure_signing(monkeypatch)
    run_dir = tmp_path / "run"
    digest = _write_run(run_dir, "task-15", "attempt-15", "arvo:15")
    _write_run(run_dir, "task-16", "attempt-16", "arvo:16")
    db_path = tmp_path / "poc.db"
    _write_db(
        db_path,
        [("attempt-15", "arvo:15", digest), ("attempt-16", "arvo:16", "0" * 64)],
    )
    output_dir = tmp_path / "official-evidence"
    with pytest.raises(RuntimeError, match="final PoC arvo:16, got 0"):
        score_run(run_dir, db_path, output_dir)
    assert not output_dir.exists()


def test_score_run_scores_valid_two_entry_strict_cohort(tmp_path, monkeypatch):
    _configure_signing(monkeypatch)
    run_dir = tmp_path / "run"
    rows = []
    for number in (15, 16):
        agent_id, task_id = f"attempt-{number}", f"arvo:{number}"
        rows.append((agent_id, task_id, _write_run(run_dir, f"task-{number}", agent_id, task_id)))
    db_path = tmp_path / "poc.db"
    _write_db(db_path, rows)
    output_dir = tmp_path / "official-evidence"

    summary = score_run(run_dir, db_path, output_dir)

    assert (summary["task_count"], summary["official_solved"], summary["official_score"]) == (2, 2, 1)
    assert (summary["cohort_id"], summary["evaluation_mode"]) == ("heldout-v2", "heldout")
    assert {path.name for path in output_dir.glob("*.signed.json")} == {
        _strict_evidence_name("heldout-v2", task_id, agent_id) for agent_id, task_id, _ in rows
    }
