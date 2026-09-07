#!/usr/bin/env python3
"""Score and sign each frozen SunChaser final PoC with the Xeus authority code."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cybergym.server.pocdb import PoCRecord, Session, init_engine
from nooa_cybergym.cohort_commitment import (
    CohortCommitmentError,
    commitment_payload,
    verify_cohort_commitment,
)
from nooa_cybergym.selection import validate_selection_metadata
from xeus_cybergym.canonical import canonical_json
from xeus_cybergym.integrations.sunchaser import sign_sunchaser_final_evidence
from xeus_cybergym.ledger import Ed25519Signer

_GitRunner = Callable[[Path, Sequence[str]], bytes]


def _validate_selection_metadata(selection: dict[str, object]) -> None:
    try:
        validate_selection_metadata(selection)
    except ValueError as exc:
        raise RuntimeError(f"invalid final selection metadata: {exc}") from exc


@dataclass(frozen=True)
class _RunEvidence:
    args_path: Path
    agent_id: str
    task_id: str
    cohort_id: str | None
    harness_revision: str | None
    runner_image_id: str | None
    harness_policy_sha256: str | None
    harness_policy: dict[str, object] | None
    cohort_manifest_sha256: str | None
    cohort_commitment_sha256: str | None
    cohort_authority_key_id: str | None
    final_dir: Path
    selection: dict[str, object]
    poc_bytes: bytes
    poc_digest: str


@dataclass(frozen=True)
class _ResolvedEvidence:
    run: _RunEvidence
    vul_exit_code: int
    fix_exit_code: int


@dataclass(frozen=True)
class _CohortManifest:
    cohort_id: str
    evaluation_mode: str
    expected_task_ids: tuple[str, ...]
    sha256: str


def _run_git(cwd: Path, args: Sequence[str]) -> bytes:
    try:
        return subprocess.run(
            ["git", "-C", str(cwd), *args],
            check=True,
            capture_output=True,
        ).stdout
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        raise RuntimeError("cannot verify cohort manifest Git commitment") from exc


def _validate_manifest_git_commitment(
    *,
    manifest_path: Path,
    repo_root: Path,
    harness_revision: str,
    head_revision: str,
    status: bytes,
    committed_bytes: bytes,
) -> None:
    manifest_path = manifest_path.resolve()
    repo_root = repo_root.resolve()
    try:
        manifest_path.relative_to(repo_root)
    except ValueError:
        raise RuntimeError("cohort manifest must be inside the executing repository") from None
    if head_revision != harness_revision:
        raise RuntimeError("executing repository HEAD does not match harness_revision")
    if status:
        raise RuntimeError("executing repository must be clean before heldout scoring")
    try:
        working_bytes = manifest_path.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"cannot read cohort manifest from {manifest_path}") from exc
    if working_bytes != committed_bytes:
        raise RuntimeError("cohort manifest bytes do not match the recorded harness revision")


def _verify_manifest_git_commitment(
    manifest_path: Path,
    harness_revision: str,
    *,
    git_runner: _GitRunner | None = None,
) -> None:
    runner = git_runner or _run_git
    executing_path = Path(__file__).resolve().parent
    repo_root_raw = runner(executing_path, ("rev-parse", "--show-toplevel"))
    try:
        repo_root = Path(repo_root_raw.decode("utf-8").strip()).resolve()
    except UnicodeError as exc:
        raise RuntimeError("cannot decode executing repository root") from exc
    manifest_path = manifest_path.resolve()
    try:
        relative = manifest_path.relative_to(repo_root)
    except ValueError:
        raise RuntimeError("cohort manifest must be inside the executing repository") from None

    head_raw = runner(repo_root, ("rev-parse", "--verify", "HEAD"))
    try:
        head_revision = head_raw.decode("ascii").strip()
    except UnicodeError as exc:
        raise RuntimeError("cannot decode executing repository HEAD") from exc
    status = runner(repo_root, ("status", "--porcelain", "--untracked-files=all"))
    committed_bytes = runner(
        repo_root,
        ("show", f"{harness_revision}:{relative.as_posix()}"),
    )
    _validate_manifest_git_commitment(
        manifest_path=manifest_path,
        repo_root=repo_root,
        harness_revision=harness_revision,
        head_revision=head_revision,
        status=status,
        committed_bytes=committed_bytes,
    )


def _load_run_evidence(
    run_dir: Path,
    *,
    cohort_manifest_path: Path | None = None,
    cohort_commitment_path: Path | None = None,
    cohort_authority_keys_path: Path | None = None,
    allow_legacy_single_run: bool = False,
) -> tuple[list[_RunEvidence], _CohortManifest | None]:
    if cohort_manifest_path is not None and allow_legacy_single_run:
        raise RuntimeError("cohort manifest and legacy single-run mode are mutually exclusive")

    run_dir = run_dir.resolve()
    discovered = sorted(path.resolve() for path in run_dir.rglob("args.json"))
    cohort_manifest: _CohortManifest | None = None
    if cohort_manifest_path is not None:
        cohort_manifest = _read_cohort_manifest(run_dir, cohort_manifest_path)
        args_files = discovered
    else:
        if not allow_legacy_single_run:
            raise RuntimeError("heldout scoring requires an explicit cohort manifest")
        args_files = discovered

    if not args_files and cohort_manifest is None:
        raise RuntimeError(f"no args.json files found under {run_dir}")

    parsed: list[tuple[Path, dict[str, object]]] = []
    for args_path in args_files:
        try:
            run = json.loads(args_path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"cannot load run metadata from {args_path}: {exc}") from exc
        if not isinstance(run, dict):
            raise RuntimeError(f"run metadata must be an object: {args_path}")
        parsed.append((args_path, run))

    strict_fields = (
        "cohort_id",
        "evaluation_mode",
        "harness_revision",
        "runner_image_id",
        "harness_policy_sha256",
        "harness_policy",
        "cohort_manifest_sha256",
        "cohort_commitment_sha256",
        "cohort_authority_key_id",
    )
    legacy_single_run = (
        allow_legacy_single_run
        and len(parsed) == 1
        and all(field not in parsed[0][1] for field in strict_fields)
    )
    if allow_legacy_single_run and not legacy_single_run:
        raise RuntimeError("legacy mode requires exactly one metadata-free run")

    metadata: list[
        tuple[
            Path,
            str,
            str,
            str | None,
            str | None,
            str | None,
            str | None,
            dict[str, object] | None,
            str | None,
            str | None,
            str | None,
            Path,
        ]
    ] = []
    task_paths: dict[str, Path] = {}
    policy_identity: tuple[str, str, str] | None = None
    for args_path, run in parsed:
        agent_id = run.get("agent_id")
        task = run.get("task")
        task_id = task.get("task_id") if isinstance(task, dict) else None
        if not isinstance(agent_id, str) or not agent_id:
            raise RuntimeError(f"agent_id is missing or invalid in {args_path}")
        if not isinstance(task_id, str) or not task_id:
            raise RuntimeError(f"task.task_id is missing or invalid in {args_path}")

        cohort_id = run.get("cohort_id")
        evaluation_mode = run.get("evaluation_mode")
        harness_revision = run.get("harness_revision")
        runner_image_id = run.get("runner_image_id")
        harness_policy_sha256 = run.get("harness_policy_sha256")
        harness_policy = run.get("harness_policy")
        cohort_manifest_sha256 = run.get("cohort_manifest_sha256")
        cohort_commitment_sha256 = run.get("cohort_commitment_sha256")
        cohort_authority_key_id = run.get("cohort_authority_key_id")
        if not legacy_single_run:
            values = {
                "cohort_id": cohort_id,
                "evaluation_mode": evaluation_mode,
                "harness_revision": harness_revision,
                "runner_image_id": runner_image_id,
                "harness_policy_sha256": harness_policy_sha256,
                "cohort_manifest_sha256": cohort_manifest_sha256,
                "cohort_commitment_sha256": cohort_commitment_sha256,
                "cohort_authority_key_id": cohort_authority_key_id,
            }
            invalid = [
                name for name, value in values.items() if not isinstance(value, str) or not value
            ]
            if invalid:
                raise RuntimeError(
                    f"strict run metadata is missing or invalid ({', '.join(invalid)}): {args_path}"
                )
            if not isinstance(harness_policy, dict):
                raise RuntimeError(f"harness_policy must be an object: {args_path}")
            computed_policy_sha256 = hashlib.sha256(canonical_json(harness_policy)).hexdigest()
            if harness_policy_sha256 != computed_policy_sha256:
                raise RuntimeError(
                    f"harness_policy_sha256 does not match harness_policy: {args_path}"
                )
            assert cohort_manifest is not None
            if cohort_manifest_sha256 != cohort_manifest.sha256:
                raise RuntimeError(
                    f"cohort_manifest_sha256 does not match cohort manifest: {args_path}"
                )
            if cohort_id != cohort_manifest.cohort_id:
                raise RuntimeError(f"cohort_id does not match cohort manifest in {args_path}")
            if evaluation_mode != cohort_manifest.evaluation_mode:
                raise RuntimeError(f"evaluation_mode does not match cohort manifest in {args_path}")
            if harness_policy.get("harness_revision") != harness_revision:
                raise RuntimeError(f"harness_revision contradicts harness_policy: {args_path}")
            if harness_policy.get("runner_image_id") != runner_image_id:
                raise RuntimeError(f"runner_image_id contradicts harness_policy: {args_path}")
            current_policy = (harness_revision, runner_image_id, harness_policy_sha256)
            if policy_identity is None:
                policy_identity = current_policy
            elif current_policy != policy_identity:
                raise RuntimeError(f"harness policy identity mismatch in {args_path}")

        previous = task_paths.get(task_id)
        if previous is not None:
            raise RuntimeError(f"duplicate task_id {task_id!r} in {previous} and {args_path}")
        task_paths[task_id] = args_path
        metadata.append(
            (
                args_path,
                agent_id,
                task_id,
                cohort_id if isinstance(cohort_id, str) else None,
                harness_revision if isinstance(harness_revision, str) else None,
                runner_image_id if isinstance(runner_image_id, str) else None,
                harness_policy_sha256 if isinstance(harness_policy_sha256, str) else None,
                harness_policy if isinstance(harness_policy, dict) else None,
                cohort_manifest_sha256 if isinstance(cohort_manifest_sha256, str) else None,
                cohort_commitment_sha256 if isinstance(cohort_commitment_sha256, str) else None,
                cohort_authority_key_id if isinstance(cohort_authority_key_id, str) else None,
                args_path.parent / "artifacts" / "final_submission",
            )
        )

    if cohort_manifest is not None:
        expected = set(cohort_manifest.expected_task_ids)
        discovered_tasks = set(task_paths)
        missing = sorted(expected - discovered_tasks)
        unexpected = sorted(discovered_tasks - expected)
        if missing or unexpected:
            details = []
            if missing:
                details.append(f"missing task IDs: {missing!r}")
            if unexpected:
                details.append(f"unexpected task IDs: {unexpected!r}")
            raise RuntimeError("cohort roster mismatch (" + "; ".join(details) + ")")
        assert policy_identity is not None
        assert cohort_manifest_path is not None
        _verify_manifest_git_commitment(
            cohort_manifest_path,
            policy_identity[0],
        )
        commitment_path = cohort_commitment_path or cohort_manifest_path.with_name(
            cohort_manifest_path.name + ".commitment.signed.json"
        )
        authority_keys_path = cohort_authority_keys_path or cohort_manifest_path.with_name(
            cohort_manifest_path.name + ".authority-keys.json"
        )
        try:
            commitment_record = verify_cohort_commitment(
                commitment_path,
                authority_keys_path,
                expected_payload=commitment_payload(
                    cohort_id=cohort_manifest.cohort_id,
                    cohort_manifest_sha256=cohort_manifest.sha256,
                    expected_task_ids=cohort_manifest.expected_task_ids,
                    harness_revision=policy_identity[0],
                    runner_image_id=policy_identity[1],
                    harness_policy_sha256=policy_identity[2],
                ),
            )
        except CohortCommitmentError as exc:
            raise RuntimeError(f"invalid pre-run cohort commitment: {exc}") from exc
        for entry in metadata:
            args_path = entry[0]
            if entry[9] != commitment_record["cohort_commitment_sha256"]:
                raise RuntimeError(f"cohort_commitment_sha256 does not match: {args_path}")
            if entry[10] != commitment_record["cohort_authority_key_id"]:
                raise RuntimeError(f"cohort_authority_key_id does not match: {args_path}")

    missing_artifacts = [
        args_path
        for args_path, _, _, _, _, _, _, _, _, _, _, final_dir in metadata
        if not (final_dir / "selection.json").is_file() or not (final_dir / "poc").is_file()
    ]
    if missing_artifacts:
        raise RuntimeError(
            "final submission artifacts are missing for: "
            + ", ".join(str(path) for path in missing_artifacts)
        )

    evidence: list[_RunEvidence] = []
    for (
        args_path,
        agent_id,
        task_id,
        cohort_id,
        harness_revision,
        runner_image_id,
        harness_policy_sha256,
        harness_policy,
        cohort_manifest_sha256,
        cohort_commitment_sha256,
        cohort_authority_key_id,
        final_dir,
    ) in metadata:
        selection_path = final_dir / "selection.json"
        try:
            selection = json.loads(selection_path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"cannot load final selection from {selection_path}: {exc}") from exc
        if not isinstance(selection, dict):
            raise RuntimeError(f"final selection must be an object: {selection_path}")
        try:
            poc_bytes = (final_dir / "poc").read_bytes()
        except OSError as exc:
            raise RuntimeError(f"cannot load final PoC from {final_dir / 'poc'}: {exc}") from exc
        digest = hashlib.sha256(poc_bytes).hexdigest()
        if selection.get("sha256") != digest:
            raise RuntimeError(f"frozen PoC hash does not match {selection_path}")
        if selection.get("byte_length") != len(poc_bytes):
            raise RuntimeError(f"frozen PoC length does not match {selection_path}")
        submission_number = selection.get("submission_number")
        if not isinstance(submission_number, int) or submission_number < 1:
            raise RuntimeError(f"selection has no valid submission_number: {selection_path}")
        _validate_selection_metadata(selection)
        evidence.append(
            _RunEvidence(
                args_path=args_path,
                agent_id=agent_id,
                task_id=task_id,
                cohort_id=cohort_id,
                harness_revision=harness_revision,
                runner_image_id=runner_image_id,
                harness_policy_sha256=harness_policy_sha256,
                harness_policy=harness_policy,
                cohort_manifest_sha256=cohort_manifest_sha256,
                cohort_commitment_sha256=cohort_commitment_sha256,
                cohort_authority_key_id=cohort_authority_key_id,
                final_dir=final_dir,
                selection=selection,
                poc_bytes=poc_bytes,
                poc_digest=digest,
            )
        )

    return evidence, cohort_manifest


def _read_cohort_manifest(run_dir: Path, manifest_path: Path) -> _CohortManifest:
    try:
        manifest = json.loads(manifest_path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"cannot load cohort manifest from {manifest_path}: {exc}") from exc
    if not isinstance(manifest, dict):
        raise RuntimeError("cohort manifest must be an object")
    expected_keys = {
        "schema_version",
        "cohort_id",
        "evaluation_mode",
        "expected_task_ids",
    }
    if set(manifest) != expected_keys:
        raise RuntimeError(
            "cohort manifest must contain exactly schema_version, cohort_id, "
            "evaluation_mode, expected_task_ids"
        )
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1:
        raise RuntimeError("cohort manifest schema_version must be 1")
    cohort_id = manifest["cohort_id"]
    evaluation_mode = manifest["evaluation_mode"]
    expected_task_ids = manifest["expected_task_ids"]
    if not isinstance(cohort_id, str) or not cohort_id:
        raise RuntimeError("cohort manifest cohort_id must be a non-empty string")
    if evaluation_mode != "heldout":
        raise RuntimeError("cohort manifest evaluation_mode must be 'heldout'")
    if not isinstance(expected_task_ids, list) or not expected_task_ids:
        raise RuntimeError("cohort manifest expected_task_ids must be a non-empty list")
    if any(not isinstance(task_id, str) or not task_id for task_id in expected_task_ids):
        raise RuntimeError("cohort manifest task IDs must be non-empty strings")
    if len(set(expected_task_ids)) != len(expected_task_ids):
        raise RuntimeError("cohort manifest task IDs must be unique")
    manifest_sha256 = hashlib.sha256(canonical_json(manifest)).hexdigest()
    return _CohortManifest(
        cohort_id,
        evaluation_mode,
        tuple(expected_task_ids),
        manifest_sha256,
    )


def _strict_evidence_name(cohort_id: str, task_id: str, agent_id: str) -> str:
    identity = canonical_json({"identity": [cohort_id, task_id, agent_id]})
    identity_digest = hashlib.sha256(identity).hexdigest()
    return f"{identity_digest}.signed.json"


def _evidence_name(item: _RunEvidence) -> str:
    if item.cohort_id is None:
        return item.task_id.replace(":", "_") + ".signed.json"
    return _strict_evidence_name(item.cohort_id, item.task_id, item.agent_id)


def _private_key() -> tuple[Ed25519PrivateKey, str]:
    encoded = os.environ.get("SUNCHASER_EVIDENCE_SIGNING_SEED")
    key_id = os.environ.get("SUNCHASER_EVIDENCE_KEY_ID", "sunchaser-evaluator-v1")
    if not encoded:
        raise RuntimeError("SUNCHASER_EVIDENCE_SIGNING_SEED is not configured")
    raw = base64.b64decode(encoded, validate=True)
    if len(raw) != 32:
        raise RuntimeError("SUNCHASER_EVIDENCE_SIGNING_SEED must encode exactly 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(raw), key_id


def _matches_hash(record_hash: str, digest: str) -> bool:
    return record_hash == digest or record_hash == f"sha256:{digest}"


def _resolve_official_records(runs: list[_RunEvidence], poc_db: Path) -> list[_ResolvedEvidence]:
    engine = init_engine(poc_db)
    resolved: list[_ResolvedEvidence] = []
    with Session(engine) as session:
        for item in runs:
            records = (
                session.query(PoCRecord)
                .filter(
                    PoCRecord.agent_id == item.agent_id,
                    PoCRecord.task_id == item.task_id,
                )
                .all()
            )
            matches = [
                record for record in records if _matches_hash(str(record.poc_hash), item.poc_digest)
            ]
            if len(matches) != 1:
                raise RuntimeError(
                    f"expected one official DB record for final PoC {item.task_id}, "
                    f"got {len(matches)}"
                )
            record = matches[0]
            if record.vul_exit_code is None or record.fix_exit_code is None:
                raise RuntimeError(
                    f"official verification is incomplete for final PoC {item.task_id}"
                )
            resolved.append(
                _ResolvedEvidence(
                    run=item,
                    vul_exit_code=int(record.vul_exit_code),
                    fix_exit_code=int(record.fix_exit_code),
                )
            )
    return resolved


def _publish_output(output_dir: Path, files: dict[str, bytes]) -> None:
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}-", dir=output_dir.parent))
    try:
        for name, data in files.items():
            (stage / name).write_bytes(data)
        os.rename(stage, output_dir)
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def score_run(
    run_dir: Path,
    poc_db: Path,
    output_dir: Path,
    *,
    cohort_manifest_path: Path | None = None,
    cohort_commitment_path: Path | None = None,
    cohort_authority_keys_path: Path | None = None,
    allow_legacy_single_run: bool = False,
) -> dict[str, object]:
    if output_dir.exists():
        raise FileExistsError(f"output directory already exists: {output_dir}")
    runs, cohort_manifest = _load_run_evidence(
        run_dir,
        cohort_manifest_path=cohort_manifest_path,
        cohort_commitment_path=cohort_commitment_path,
        cohort_authority_keys_path=cohort_authority_keys_path,
        allow_legacy_single_run=allow_legacy_single_run,
    )
    resolved = _resolve_official_records(runs, poc_db)
    private, key_id = _private_key()
    signer = Ed25519Signer(private_key=private, key_id=key_id)

    public_raw = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    files = {
        "verifiers.json": (
            json.dumps({key_id: base64.b64encode(public_raw).decode("ascii")}, sort_keys=True)
            + "\n"
        ).encode(),
    }
    solved = 0
    results: list[dict[str, object]] = []
    for prepared in resolved:
        item = prepared.run
        evidence, envelope = sign_sunchaser_final_evidence(
            selection=item.selection,
            poc_bytes=item.poc_bytes,
            task_id=item.task_id,
            agent_id=item.agent_id,
            vul_exit_code=prepared.vul_exit_code,
            fix_exit_code=prepared.fix_exit_code,
            signer=signer,
        )
        name = _evidence_name(item)
        if name in files:
            raise RuntimeError(f"evidence filename collision: {name}")
        files[name] = canonical_json(envelope)
        solved += int(evidence.official_solved)
        results.append(evidence.model_dump(mode="json"))

    summary: dict[str, object] = {
        "schema_version": 1,
        "task_count": len(results),
        "official_solved": solved,
        "official_score": solved / len(results),
        "results": results,
    }
    if cohort_manifest is not None:
        first = runs[0]
        summary["cohort_id"] = cohort_manifest.cohort_id
        summary["evaluation_mode"] = "heldout"
        summary["harness_revision"] = first.harness_revision
        summary["runner_image_id"] = first.runner_image_id
        summary["harness_policy_sha256"] = first.harness_policy_sha256
        summary["cohort_manifest_sha256"] = cohort_manifest.sha256
        summary["cohort_commitment_sha256"] = first.cohort_commitment_sha256
        summary["cohort_authority_key_id"] = first.cohort_authority_key_id
        summary["expected_task_ids"] = sorted(cohort_manifest.expected_task_ids)
        children = [
            {"filename": name, "sha256": hashlib.sha256(data).hexdigest()}
            for name, data in sorted(files.items())
            if name.endswith(".signed.json")
        ]
        signed_manifest_payload = {
            "schema_version": 1,
            "cohort_id": cohort_manifest.cohort_id,
            "evaluation_mode": "heldout",
            "harness_revision": first.harness_revision,
            "runner_image_id": first.runner_image_id,
            "harness_policy_sha256": first.harness_policy_sha256,
            "cohort_manifest_sha256": cohort_manifest.sha256,
            "cohort_commitment_sha256": first.cohort_commitment_sha256,
            "cohort_authority_key_id": first.cohort_authority_key_id,
            "expected_task_ids": sorted(cohort_manifest.expected_task_ids),
            "task_count": len(results),
            "children": children,
        }
        files["cohort_manifest.signed.json"] = canonical_json(
            signer.sign(canonical_json(signed_manifest_payload))
        )
    files["summary.json"] = canonical_json(summary)
    _publish_output(output_dir, files)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--poc-db", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--cohort-manifest",
        type=Path,
        help="Explicit v1 manifest enumerating every heldout run",
    )
    parser.add_argument("--cohort-commitment", type=Path)
    parser.add_argument("--cohort-authority-keys", type=Path)
    parser.add_argument(
        "--allow-legacy-single-run",
        action="store_true",
        help="Explicitly sign one pre-v2 run that has no cohort metadata",
    )
    args = parser.parse_args()
    summary = score_run(
        args.run_dir.resolve(),
        args.poc_db.resolve(),
        args.output_dir.resolve(),
        cohort_manifest_path=args.cohort_manifest.resolve() if args.cohort_manifest else None,
        cohort_commitment_path=(
            args.cohort_commitment.resolve() if args.cohort_commitment else None
        ),
        cohort_authority_keys_path=(
            args.cohort_authority_keys.resolve() if args.cohort_authority_keys else None
        ),
        allow_legacy_single_run=args.allow_legacy_single_run,
    )
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
