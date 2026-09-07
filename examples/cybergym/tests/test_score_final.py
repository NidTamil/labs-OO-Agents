from __future__ import annotations

import base64
import hashlib
import json
import os

import pytest
import scripts.score_final as score_final_module
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cybergym.server.pocdb import PoCRecord, Session, init_engine
from nooa_cybergym.cohort_commitment import canonical_json as commitment_json
from nooa_cybergym.cohort_commitment import commitment_payload
from scripts.score_final import (
    _strict_evidence_name,
    _validate_manifest_git_commitment,
    score_run,
)
from xeus_cybergym.canonical import canonical_json
from xeus_cybergym.ledger import Ed25519Verifier, SignedEnvelope
from xeus_cybergym.ledger.signing import SignatureVerificationError

_MISSING = object()
_DEFAULT_POLICY = {
    "harness_revision": "rev-1",
    "reviewer": {"enabled": True},
    "runner_image_id": "image@sha256:abc",
    "version": 2,
}
_DEFAULT_POLICY_SHA256 = hashlib.sha256(canonical_json(_DEFAULT_POLICY)).hexdigest()


@pytest.fixture(autouse=True)
def _committed_manifest_git(monkeypatch, tmp_path):
    repo_root = tmp_path.resolve()

    def run_git(_cwd, args):
        command = tuple(args)
        if command == ("rev-parse", "--show-toplevel"):
            return f"{repo_root}\n".encode()
        if command == ("rev-parse", "--verify", "HEAD"):
            return b"rev-1\n"
        if command == ("status", "--porcelain", "--untracked-files=all"):
            return b""
        if command[:1] == ("show",):
            relative = command[1].split(":", 1)[1]
            tracked = repo_root / relative
            return tracked.with_name(tracked.name + ".committed").read_bytes()
        raise AssertionError(f"unexpected git command: {command!r}")

    monkeypatch.setattr(score_final_module, "_run_git", run_git)


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
    harness_revision="rev-1",
    runner_image_id="image@sha256:abc",
    harness_policy_sha256=_DEFAULT_POLICY_SHA256,
    harness_policy=_DEFAULT_POLICY,
    cohort_manifest_sha256=_MISSING,
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
    if harness_revision is not _MISSING:
        args["harness_revision"] = harness_revision
    if runner_image_id is not _MISSING:
        args["runner_image_id"] = runner_image_id
    if harness_policy_sha256 is not _MISSING:
        args["harness_policy_sha256"] = harness_policy_sha256
    if harness_policy is not _MISSING:
        args["harness_policy"] = harness_policy
    if cohort_manifest_sha256 is not _MISSING:
        args["cohort_manifest_sha256"] = cohort_manifest_sha256
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


def _write_manifest(run_dir, task_ids: list[str], *, cohort_id="heldout-v2"):
    path = run_dir / "cohort.json"
    manifest = {
        "schema_version": 1,
        "cohort_id": cohort_id,
        "evaluation_mode": "heldout",
        "expected_task_ids": task_ids,
    }
    path.write_text(json.dumps(manifest))
    path.with_name(path.name + ".committed").write_bytes(path.read_bytes())
    digest = hashlib.sha256(canonical_json(manifest)).hexdigest()
    first_args_path = next(run_dir.rglob("args.json"))
    first_args = json.loads(first_args_path.read_text())
    payload = commitment_payload(
        cohort_id=cohort_id,
        cohort_manifest_sha256=digest,
        expected_task_ids=task_ids,
        harness_revision=first_args.get("harness_revision", "rev-1"),
        runner_image_id=first_args.get("runner_image_id", "image@sha256:abc"),
        harness_policy_sha256=first_args.get("harness_policy_sha256", _DEFAULT_POLICY_SHA256),
    )
    private = Ed25519PrivateKey.generate()
    payload_bytes = commitment_json(payload)
    envelope = {
        "algorithm": "Ed25519",
        "key_id": "cohort-authority-v1",
        "payload": base64.b64encode(payload_bytes).decode(),
        "signature": base64.b64encode(private.sign(payload_bytes)).decode(),
    }
    commitment_path = path.with_name(path.name + ".commitment.signed.json")
    authority_path = path.with_name(path.name + ".authority-keys.json")
    commitment_path.write_bytes(commitment_json(envelope))
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    authority_path.write_text(
        json.dumps({"cohort-authority-v1": base64.b64encode(public).decode()})
    )
    commitment_digest = hashlib.sha256(commitment_json(envelope)).hexdigest()
    for args_path in run_dir.rglob("args.json"):
        args = json.loads(args_path.read_text())
        args["cohort_manifest_sha256"] = digest
        args["cohort_commitment_sha256"] = commitment_digest
        args["cohort_authority_key_id"] = "cohort-authority-v1"
        args_path.write_text(json.dumps(args))
    return path


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


def test_score_run_rejects_metadata_free_single_run_by_default(tmp_path, monkeypatch):
    _configure_signing(monkeypatch)
    run_dir = tmp_path / "run"
    _write_run(
        run_dir,
        "task",
        "agent-1",
        "arvo:1",
        cohort_id=_MISSING,
        evaluation_mode=_MISSING,
        harness_revision=_MISSING,
        runner_image_id=_MISSING,
        harness_policy_sha256=_MISSING,
        harness_policy=_MISSING,
    )
    output_dir = run_dir / "official_evidence"

    with pytest.raises(RuntimeError, match="explicit cohort manifest"):
        score_run(run_dir, tmp_path / "poc.db", output_dir)

    assert not output_dir.exists()


def test_explicit_legacy_single_run_mode_produces_verifiable_evidence(tmp_path, monkeypatch):
    _configure_signing(monkeypatch)
    run_dir = tmp_path / "run"
    digest = _write_run(
        run_dir,
        "task",
        "agent-1",
        "arvo:1",
        cohort_id=_MISSING,
        evaluation_mode=_MISSING,
        harness_revision=_MISSING,
        runner_image_id=_MISSING,
        harness_policy_sha256=_MISSING,
        harness_policy=_MISSING,
    )
    db_path = tmp_path / "poc.db"
    _write_db(db_path, [("agent-1", "arvo:1", digest)])
    output_dir = run_dir / "official_evidence"

    summary = score_run(run_dir, db_path, output_dir, allow_legacy_single_run=True)

    assert summary["official_solved"] == 1
    envelope = SignedEnvelope.model_validate_json((output_dir / "arvo_1.signed.json").read_bytes())
    keys = json.loads((output_dir / "verifiers.json").read_text())
    public = Ed25519PublicKey.from_public_bytes(base64.b64decode(keys["test-key"]))
    payload = Ed25519Verifier({"test-key": public}).verify(envelope)
    assert json.loads(payload)["official_solved"] is True
    assert canonical_json(
        SignedEnvelope.model_validate_json(canonical_json(envelope))
    ) == canonical_json(envelope)


def test_manifest_rejects_duplicate_roster_and_duplicate_discovered_tasks(tmp_path, monkeypatch):
    _configure_signing(monkeypatch)
    run_dir = tmp_path / "run"
    _write_run(run_dir, "task", "agent", "arvo:15", artifacts=False)
    output_dir = tmp_path / "official-evidence"
    manifest = _write_manifest(run_dir, ["arvo:15", "arvo:15"])
    with pytest.raises(RuntimeError, match="task IDs must be unique"):
        score_run(run_dir, tmp_path / "poc.db", output_dir, cohort_manifest_path=manifest)

    _write_run(run_dir, "duplicate", "agent-2", "arvo:15", artifacts=False)
    manifest = _write_manifest(run_dir, ["arvo:15"])
    with pytest.raises(RuntimeError, match="duplicate task_id"):
        score_run(run_dir, tmp_path / "poc.db", output_dir, cohort_manifest_path=manifest)


def test_score_run_preflights_artifacts_before_key_or_output(tmp_path, monkeypatch):
    monkeypatch.delenv("SUNCHASER_EVIDENCE_SIGNING_SEED", raising=False)
    run_dir = tmp_path / "run"
    _write_run(run_dir, "task-15", "attempt-15", "arvo:15", artifacts=False)
    manifest = _write_manifest(run_dir, ["arvo:15"])
    output_dir = tmp_path / "official-evidence"
    with pytest.raises(RuntimeError, match="final submission artifacts are missing"):
        score_run(
            run_dir,
            tmp_path / "poc.db",
            output_dir,
            cohort_manifest_path=manifest,
        )
    assert not output_dir.exists()


def test_strict_evidence_name_resists_delimiter_shift_collision():
    first = ("a", "b__c", "d")
    second = ("a__b", "c", "d")
    assert "__".join(first) == "__".join(second)
    assert _strict_evidence_name(*first) != _strict_evidence_name(*second)


def test_manifest_git_commitment_requires_same_repo_revision_cleanliness_and_bytes(tmp_path):
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    manifest = repo_root / "cohort.json"
    manifest.write_bytes(b"committed roster")
    common = {
        "manifest_path": manifest,
        "repo_root": repo_root,
        "harness_revision": "rev-1",
        "head_revision": "rev-1",
        "status": b"",
        "committed_bytes": b"committed roster",
    }
    _validate_manifest_git_commitment(**common)

    with pytest.raises(RuntimeError, match="HEAD does not match"):
        _validate_manifest_git_commitment(**{**common, "head_revision": "rev-2"})
    with pytest.raises(RuntimeError, match="must be clean"):
        _validate_manifest_git_commitment(**{**common, "status": b"?? cohort.json\n"})
    with pytest.raises(RuntimeError, match="bytes do not match"):
        _validate_manifest_git_commitment(**{**common, "committed_bytes": b"other"})
    with pytest.raises(RuntimeError, match="inside the executing repository"):
        _validate_manifest_git_commitment(**{**common, "manifest_path": tmp_path / "outside.json"})


def test_later_malformed_selection_leaves_no_output_directory(tmp_path, monkeypatch):
    _configure_signing(monkeypatch)
    run_dir = tmp_path / "run"
    _write_run(run_dir, "task-15", "attempt-15", "arvo:15")
    _write_run(run_dir, "task-16", "attempt-16", "arvo:16", selection="{malformed")
    manifest = _write_manifest(run_dir, ["arvo:15", "arvo:16"])
    output_dir = tmp_path / "official-evidence"
    with pytest.raises(RuntimeError, match="cannot load final selection"):
        score_run(run_dir, tmp_path / "poc.db", output_dir, cohort_manifest_path=manifest)
    assert not output_dir.exists()


def test_later_db_mismatch_leaves_no_output_directory(tmp_path, monkeypatch):
    _configure_signing(monkeypatch)
    run_dir = tmp_path / "run"
    digest = _write_run(run_dir, "task-15", "attempt-15", "arvo:15")
    _write_run(run_dir, "task-16", "attempt-16", "arvo:16")
    manifest = _write_manifest(run_dir, ["arvo:15", "arvo:16"])
    db_path = tmp_path / "poc.db"
    _write_db(
        db_path,
        [("attempt-15", "arvo:15", digest), ("attempt-16", "arvo:16", "0" * 64)],
    )
    output_dir = tmp_path / "official-evidence"
    with pytest.raises(RuntimeError, match="final PoC arvo:16, got 0"):
        score_run(run_dir, db_path, output_dir, cohort_manifest_path=manifest)
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
    manifest = _write_manifest(run_dir, ["arvo:15", "arvo:16"])
    output_dir = tmp_path / "official-evidence"

    summary = score_run(run_dir, db_path, output_dir, cohort_manifest_path=manifest)

    assert (summary["task_count"], summary["official_solved"], summary["official_score"]) == (
        2,
        2,
        1,
    )
    assert (summary["cohort_id"], summary["evaluation_mode"]) == ("heldout-v2", "heldout")
    child_names = {
        _strict_evidence_name("heldout-v2", task_id, agent_id) for agent_id, task_id, _ in rows
    }
    assert {path.name for path in output_dir.glob("*.signed.json")} == child_names | {
        "cohort_manifest.signed.json"
    }

    keys = json.loads((output_dir / "verifiers.json").read_text())
    public = Ed25519PublicKey.from_public_bytes(base64.b64decode(keys["test-key"]))
    verifier = Ed25519Verifier({"test-key": public})
    signed = SignedEnvelope.model_validate_json(
        (output_dir / "cohort_manifest.signed.json").read_bytes()
    )
    payload = json.loads(verifier.verify(signed))
    assert payload == {
        "schema_version": 1,
        "cohort_id": "heldout-v2",
        "evaluation_mode": "heldout",
        "harness_revision": "rev-1",
        "runner_image_id": "image@sha256:abc",
        "harness_policy_sha256": _DEFAULT_POLICY_SHA256,
        "cohort_manifest_sha256": hashlib.sha256(
            canonical_json(json.loads(manifest.read_text()))
        ).hexdigest(),
        "cohort_commitment_sha256": hashlib.sha256(
            commitment_json(
                json.loads(
                    manifest.with_name(manifest.name + ".commitment.signed.json").read_text()
                )
            )
        ).hexdigest(),
        "cohort_authority_key_id": "cohort-authority-v1",
        "expected_task_ids": ["arvo:15", "arvo:16"],
        "task_count": 2,
        "children": [
            {
                "filename": name,
                "sha256": hashlib.sha256((output_dir / name).read_bytes()).hexdigest(),
            }
            for name in sorted(child_names)
        ],
    }

    signed = signed.model_copy(update={"payload": base64.b64encode(b"{}").decode()})
    with pytest.raises(SignatureVerificationError):
        verifier.verify(signed)


def test_manifest_rejects_unexpected_and_deleted_roster_tasks(tmp_path, monkeypatch):
    _configure_signing(monkeypatch)
    run_dir = tmp_path / "run"
    _write_run(run_dir, "listed", "agent-1", "arvo:15", artifacts=False)
    _write_run(run_dir, "unexpected", "agent-2", "arvo:16", artifacts=False)
    output_dir = tmp_path / "out"

    manifest = _write_manifest(run_dir, ["arvo:15"])
    with pytest.raises(RuntimeError, match="unexpected task IDs.*arvo:16"):
        score_run(run_dir, tmp_path / "poc.db", output_dir, cohort_manifest_path=manifest)

    manifest = _write_manifest(run_dir, ["arvo:15", "arvo:16"])
    (run_dir / "logs" / "unexpected" / "args.json").unlink()
    with pytest.raises(RuntimeError, match="missing task IDs.*arvo:16"):
        score_run(run_dir, tmp_path / "poc.db", output_dir, cohort_manifest_path=manifest)


def test_authority_commitment_rejects_post_result_roster_rewrite(tmp_path, monkeypatch):
    _configure_signing(monkeypatch)
    run_dir = tmp_path / "run"
    _write_run(run_dir, "success", "agent-1", "arvo:15", artifacts=False)
    _write_run(run_dir, "failure", "agent-2", "arvo:16", artifacts=False)
    manifest = _write_manifest(run_dir, ["arvo:15", "arvo:16"])

    (run_dir / "logs" / "failure" / "args.json").unlink()
    reduced = {
        "schema_version": 1,
        "cohort_id": "heldout-v2",
        "evaluation_mode": "heldout",
        "expected_task_ids": ["arvo:15"],
    }
    manifest.write_text(json.dumps(reduced))
    manifest.with_name(manifest.name + ".committed").write_bytes(manifest.read_bytes())
    args_path = run_dir / "logs" / "success" / "args.json"
    args = json.loads(args_path.read_text())
    args["cohort_manifest_sha256"] = hashlib.sha256(canonical_json(reduced)).hexdigest()
    args_path.write_text(json.dumps(args))

    with pytest.raises(RuntimeError, match="invalid pre-run cohort commitment"):
        score_run(
            run_dir,
            tmp_path / "poc.db",
            tmp_path / "out",
            cohort_manifest_path=manifest,
        )


def test_manifest_mutation_invalidates_recorded_hash(tmp_path, monkeypatch):
    _configure_signing(monkeypatch)
    run_dir = tmp_path / "run"
    _write_run(run_dir, "task", "agent", "arvo:15", artifacts=False)
    manifest = _write_manifest(run_dir, ["arvo:15"])
    changed = json.loads(manifest.read_text())
    changed["expected_task_ids"] = ["arvo:15", "arvo:16"]
    manifest.write_text(json.dumps(changed))

    with pytest.raises(RuntimeError, match="cohort_manifest_sha256 does not match"):
        score_run(
            run_dir,
            tmp_path / "poc.db",
            tmp_path / "out",
            cohort_manifest_path=manifest,
        )


def test_manifest_rejects_policy_mismatch(tmp_path, monkeypatch):
    _configure_signing(monkeypatch)
    run_dir = tmp_path / "run"
    _write_run(run_dir, "task-15", "agent-15", "arvo:15", artifacts=False)
    other_policy = {
        **_DEFAULT_POLICY,
        "reviewer": {"enabled": False},
    }
    _write_run(
        run_dir,
        "task-16",
        "agent-16",
        "arvo:16",
        harness_policy=other_policy,
        harness_policy_sha256=hashlib.sha256(canonical_json(other_policy)).hexdigest(),
        artifacts=False,
    )
    manifest = _write_manifest(run_dir, ["arvo:15", "arvo:16"])
    with pytest.raises(RuntimeError, match="harness policy identity mismatch"):
        score_run(
            run_dir,
            tmp_path / "poc.db",
            tmp_path / "out",
            cohort_manifest_path=manifest,
        )


def test_manifest_rejects_self_inconsistent_policy_hash(tmp_path, monkeypatch):
    _configure_signing(monkeypatch)
    run_dir = tmp_path / "run"
    _write_run(
        run_dir,
        "task",
        "agent",
        "arvo:15",
        harness_policy_sha256="0" * 64,
        artifacts=False,
    )
    manifest = _write_manifest(run_dir, ["arvo:15"])
    with pytest.raises(RuntimeError, match="does not match harness_policy"):
        score_run(
            run_dir,
            tmp_path / "poc.db",
            tmp_path / "out",
            cohort_manifest_path=manifest,
        )


def test_manifest_requires_complete_policy_identity(tmp_path, monkeypatch):
    _configure_signing(monkeypatch)
    run_dir = tmp_path / "run"
    _write_run(
        run_dir,
        "task",
        "agent",
        "arvo:15",
        harness_revision=_MISSING,
        artifacts=False,
    )
    manifest = _write_manifest(run_dir, ["arvo:15"])
    with pytest.raises(RuntimeError, match="harness_revision"):
        score_run(
            run_dir,
            tmp_path / "poc.db",
            tmp_path / "out",
            cohort_manifest_path=manifest,
        )


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"harness_revision": "rev-contradiction"}, "harness_revision contradicts"),
        ({"runner_image_id": "image@sha256:contradiction"}, "runner_image_id contradicts"),
    ],
)
def test_manifest_rejects_top_level_policy_contradiction(tmp_path, monkeypatch, override, message):
    _configure_signing(monkeypatch)
    run_dir = tmp_path / "run"
    _write_run(run_dir, "task", "agent", "arvo:15", artifacts=False, **override)
    manifest = _write_manifest(run_dir, ["arvo:15"])
    with pytest.raises(RuntimeError, match=message):
        score_run(
            run_dir,
            tmp_path / "poc.db",
            tmp_path / "out",
            cohort_manifest_path=manifest,
        )


def test_manifest_and_legacy_mode_are_mutually_exclusive(tmp_path, monkeypatch):
    _configure_signing(monkeypatch)
    run_dir = tmp_path / "run"
    _write_run(run_dir, "task", "agent", "arvo:15", artifacts=False)
    manifest = _write_manifest(run_dir, ["arvo:15"])
    with pytest.raises(RuntimeError, match="mutually exclusive"):
        score_run(
            run_dir,
            tmp_path / "poc.db",
            tmp_path / "out",
            cohort_manifest_path=manifest,
            allow_legacy_single_run=True,
        )
