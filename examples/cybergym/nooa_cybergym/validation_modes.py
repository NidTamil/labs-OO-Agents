"""Preflight CyberGym validation metadata before verifier side effects."""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

try:
    from .cohort_commitment import (
        CohortCommitmentError,
        commitment_payload,
        verify_cohort_commitment,
    )
except ImportError:  # pragma: no cover - script mode
    from cohort_commitment import (  # type: ignore[no-redef]
        CohortCommitmentError,
        commitment_payload,
        verify_cohort_commitment,
    )

ValidationMode = Literal["legacy", "diagnostic", "heldout"]
_POLICY_FIELDS = (
    "harness_revision",
    "runner_image_id",
    "harness_policy_sha256",
    "harness_policy",
)


@dataclass(frozen=True)
class ValidationPlan:
    mode: ValidationMode
    args_files: tuple[Path, ...]
    cohort_id: str | None


@dataclass(frozen=True)
class _Manifest:
    cohort_id: str
    expected_task_ids: tuple[str, ...]
    sha256: str


def _read_json_object(path: Path, *, label: str) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load {label} from {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must be an object: {path}")
    return payload


def _canonical_json(value: object, *, label: str) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} is not canonical JSON: {exc}") from exc


def _read_manifest(manifest_path: Path) -> _Manifest:
    manifest = _read_json_object(manifest_path.resolve(), label="cohort manifest")
    expected = {"schema_version", "cohort_id", "evaluation_mode", "expected_task_ids"}
    if set(manifest) != expected:
        raise ValueError(
            "cohort manifest must contain exactly schema_version, cohort_id, "
            "evaluation_mode, expected_task_ids"
        )
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1:
        raise ValueError("cohort manifest schema_version must be 1")
    cohort_id = manifest["cohort_id"]
    if not isinstance(cohort_id, str) or not cohort_id:
        raise ValueError("cohort manifest cohort_id must be a non-empty string")
    if manifest["evaluation_mode"] != "heldout":
        raise ValueError("cohort manifest evaluation_mode must be 'heldout'")
    expected_task_ids = manifest["expected_task_ids"]
    if not isinstance(expected_task_ids, list) or not expected_task_ids:
        raise ValueError("cohort manifest expected_task_ids must be a non-empty list")
    if any(not isinstance(task_id, str) or not task_id for task_id in expected_task_ids):
        raise ValueError("cohort manifest task IDs must be non-empty strings")
    if len(set(expected_task_ids)) != len(expected_task_ids):
        raise ValueError("cohort manifest expected_task_ids must be unique")
    digest = hashlib.sha256(_canonical_json(manifest, label="cohort manifest")).hexdigest()
    return _Manifest(cohort_id, tuple(expected_task_ids), digest)


def _validate_policy_identity(payload: dict[str, object], args_path: Path) -> tuple[str, str, str]:
    revision = payload.get("harness_revision")
    image_id = payload.get("runner_image_id")
    policy_hash = payload.get("harness_policy_sha256")
    policy = payload.get("harness_policy")
    invalid = [
        name
        for name, value in (
            ("harness_revision", revision),
            ("runner_image_id", image_id),
            ("harness_policy_sha256", policy_hash),
        )
        if not isinstance(value, str) or not value
    ]
    if invalid:
        raise ValueError(
            f"harness identity is missing or invalid ({', '.join(invalid)}): {args_path}"
        )
    if not isinstance(policy, dict):
        raise ValueError(f"harness_policy must be an object: {args_path}")
    computed = hashlib.sha256(_canonical_json(policy, label="harness_policy")).hexdigest()
    if policy_hash != computed:
        raise ValueError(f"harness_policy_sha256 does not match harness_policy: {args_path}")
    if policy.get("harness_revision") != revision:
        raise ValueError(f"harness_revision contradicts harness_policy: {args_path}")
    if policy.get("runner_image_id") != image_id:
        raise ValueError(f"runner_image_id contradicts harness_policy: {args_path}")
    return cast(tuple[str, str, str], (revision, image_id, policy_hash))


def classify_validation_run(
    run_dir: Path,
    *,
    cohort_manifest: Path | None = None,
    cohort_commitment: Path | None = None,
    cohort_authority_keys: Path | None = None,
) -> ValidationPlan:
    """Return a fully preflighted plan containing the exact files to verify."""
    run_dir = run_dir.resolve()
    discovered = tuple(sorted(path.resolve() for path in run_dir.rglob("args.json")))
    if not discovered:
        raise ValueError(f"no args.json files found under {run_dir}")

    parsed = [(path, _read_json_object(path, label="run metadata")) for path in discovered]
    strict_fields = (
        "cohort_id",
        "evaluation_mode",
        "cohort_manifest_sha256",
        "cohort_commitment_sha256",
        "cohort_authority_key_id",
        *_POLICY_FIELDS,
    )
    legacy = len(parsed) == 1 and all(field not in parsed[0][1] for field in strict_fields)

    modes: set[str] = set()
    cohorts: set[str] = set()
    identities: set[tuple[str, str, str]] = set()
    task_paths: dict[str, Path] = {}
    manifest_hashes: set[str] = set()
    commitment_hashes: set[str] = set()
    authority_key_ids: set[str] = set()
    for args_path, payload in parsed:
        agent_id = payload.get("agent_id")
        task = payload.get("task")
        task_id = task.get("task_id") if isinstance(task, dict) else None
        if not isinstance(agent_id, str) or not agent_id:
            raise ValueError(f"agent_id is missing or invalid in {args_path}")
        if not isinstance(task_id, str) or not task_id:
            raise ValueError(f"task.task_id is missing or invalid in {args_path}")
        previous = task_paths.get(task_id)
        if previous is not None:
            raise ValueError(f"duplicate task_id {task_id!r} in {previous} and {args_path}")
        task_paths[task_id] = args_path

        if legacy:
            continue
        cohort_id = payload.get("cohort_id")
        evaluation_mode = payload.get("evaluation_mode")
        if not isinstance(cohort_id, str) or not cohort_id:
            raise ValueError(f"cohort_id is required and must be non-empty in {args_path}")
        if evaluation_mode not in {"diagnostic", "heldout"}:
            raise ValueError(
                "evaluation_mode must be 'diagnostic' or 'heldout' "
                f"in {args_path}, got {evaluation_mode!r}"
            )
        cohorts.add(cohort_id)
        modes.add(evaluation_mode)

        policy_fields_present = [field in payload for field in _POLICY_FIELDS]
        if evaluation_mode == "heldout" or any(policy_fields_present):
            if not all(policy_fields_present):
                raise ValueError(f"partial harness identity is not allowed: {args_path}")
            identities.add(_validate_policy_identity(payload, args_path))
        manifest_hash = payload.get("cohort_manifest_sha256")
        if evaluation_mode == "heldout":
            if not isinstance(manifest_hash, str) or not manifest_hash:
                raise ValueError(f"cohort_manifest_sha256 is missing or invalid: {args_path}")
            manifest_hashes.add(manifest_hash)
            commitment_hash = payload.get("cohort_commitment_sha256")
            authority_key_id = payload.get("cohort_authority_key_id")
            if not isinstance(commitment_hash, str) or not commitment_hash:
                raise ValueError(f"cohort_commitment_sha256 is missing or invalid: {args_path}")
            if not isinstance(authority_key_id, str) or not authority_key_id:
                raise ValueError(f"cohort_authority_key_id is missing or invalid: {args_path}")
            commitment_hashes.add(commitment_hash)
            authority_key_ids.add(authority_key_id)
        elif manifest_hash is not None:
            if not isinstance(manifest_hash, str) or not manifest_hash:
                raise ValueError(f"cohort_manifest_sha256 is invalid: {args_path}")
            manifest_hashes.add(manifest_hash)

    if legacy:
        if cohort_manifest is not None:
            raise ValueError("cohort manifest is only valid for heldout validation")
        return ValidationPlan("legacy", discovered, None)
    if len(modes) != 1:
        raise ValueError(f"mixed evaluation modes are not allowed: {sorted(modes)!r}")
    if len(cohorts) != 1:
        raise ValueError(f"mixed cohort_id values are not allowed: {sorted(cohorts)!r}")
    if len(identities) > 1:
        raise ValueError("harness policy identity mismatch across run metadata")

    mode = cast(ValidationMode, next(iter(modes)))
    cohort_id = next(iter(cohorts))
    if mode == "diagnostic":
        if cohort_manifest is not None:
            raise ValueError("cohort manifest is only valid for heldout validation")
        return ValidationPlan(mode, discovered, cohort_id)
    if cohort_manifest is None:
        raise ValueError("heldout validation requires an explicit cohort manifest")

    manifest = _read_manifest(cohort_manifest)
    if manifest.cohort_id != cohort_id:
        raise ValueError("cohort_id does not match cohort manifest")
    expected_task_ids = frozenset(manifest.expected_task_ids)
    actual_task_ids = frozenset(task_paths)
    if actual_task_ids != expected_task_ids:
        missing = sorted(expected_task_ids - actual_task_ids)
        unexpected = sorted(actual_task_ids - expected_task_ids)
        raise ValueError(
            f"cohort task roster mismatch; missing={missing!r}, unexpected={unexpected!r}"
        )
    if manifest_hashes != {manifest.sha256}:
        raise ValueError("cohort_manifest_sha256 does not match cohort manifest")
    if len(identities) != 1:
        raise ValueError("heldout validation requires one harness policy identity")
    identity = next(iter(identities))
    commitment_path = cohort_commitment or cohort_manifest.with_name(
        cohort_manifest.name + ".commitment.signed.json"
    )
    authority_keys_path = cohort_authority_keys or cohort_manifest.with_name(
        cohort_manifest.name + ".authority-keys.json"
    )
    try:
        commitment_record = verify_cohort_commitment(
            commitment_path,
            authority_keys_path,
            expected_payload=commitment_payload(
                cohort_id=manifest.cohort_id,
                cohort_manifest_sha256=manifest.sha256,
                expected_task_ids=manifest.expected_task_ids,
                harness_revision=identity[0],
                runner_image_id=identity[1],
                harness_policy_sha256=identity[2],
            ),
        )
    except CohortCommitmentError as exc:
        raise ValueError(f"invalid pre-run cohort commitment: {exc}") from exc
    if commitment_hashes != {commitment_record["cohort_commitment_sha256"]}:
        raise ValueError("cohort_commitment_sha256 does not match authority commitment")
    if authority_key_ids != {commitment_record["cohort_authority_key_id"]}:
        raise ValueError("cohort_authority_key_id does not match authority commitment")
    return ValidationPlan(mode, discovered, cohort_id)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--cohort-manifest", type=Path)
    parser.add_argument("--cohort-commitment", type=Path)
    parser.add_argument("--cohort-authority-keys", type=Path)
    args = parser.parse_args()
    try:
        plan = classify_validation_run(
            args.run_dir.resolve(),
            cohort_manifest=args.cohort_manifest,
            cohort_commitment=args.cohort_commitment,
            cohort_authority_keys=args.cohort_authority_keys,
        )
    except ValueError as exc:
        parser.error(str(exc))
    print(
        json.dumps(
            {
                "mode": plan.mode,
                "cohort_id": plan.cohort_id,
                "args_files": [str(path) for path in plan.args_files],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
