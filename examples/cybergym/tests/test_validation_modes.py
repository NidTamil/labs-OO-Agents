from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from examples.cybergym.nooa_cybergym import validation_modes
from examples.cybergym.nooa_cybergym.validation_modes import classify_validation_run


@pytest.fixture(autouse=True)
def _trusted_commitment(monkeypatch):
    monkeypatch.setattr(
        validation_modes,
        "verify_cohort_commitment",
        lambda *args, **kwargs: {
            "cohort_commitment_sha256": "commitment-hash",
            "cohort_authority_key_id": "authority-v1",
        },
    )


def _canonical_sha256(value: object) -> str:
    raw = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()
    return hashlib.sha256(raw).hexdigest()


def _args(root: Path, name: str, *, task_id: str | None = None, **metadata: object) -> Path:
    run = root / name
    run.mkdir(parents=True, exist_ok=True)
    payload = {"agent_id": f"agent-{name}", "task": {"task_id": task_id or name}, **metadata}
    path = run / "args.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _manifest(root: Path, task_ids: list[str], *, cohort_id: str = "cohort-a") -> tuple[Path, str]:
    payload = {
        "schema_version": 1,
        "cohort_id": cohort_id,
        "evaluation_mode": "heldout",
        "expected_task_ids": task_ids,
    }
    path = root / "cohort-manifest.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path, _canonical_sha256(payload)


def _heldout_metadata(manifest_hash: str, **overrides: object) -> dict[str, object]:
    policy = {
        "harness_revision": "rev-1",
        "runner_image_id": "sha256:image",
        "reviewer": {"enabled": True},
        "version": 2,
    }
    values: dict[str, object] = {
        "cohort_id": "cohort-a",
        "evaluation_mode": "heldout",
        "harness_revision": "rev-1",
        "runner_image_id": "sha256:image",
        "harness_policy": policy,
        "harness_policy_sha256": _canonical_sha256(policy),
        "cohort_manifest_sha256": manifest_hash,
        "cohort_commitment_sha256": "commitment-hash",
        "cohort_authority_key_id": "authority-v1",
    }
    values.update(overrides)
    return values


def test_exactly_one_metadata_free_run_is_legacy_and_validates_agent_task(tmp_path: Path) -> None:
    args_path = _args(tmp_path, "one")
    plan = classify_validation_run(tmp_path)
    assert plan.mode == "legacy"
    assert plan.cohort_id is None
    assert plan.args_files == (args_path.resolve(),)

    payload = json.loads(args_path.read_text())
    del payload["task"]
    args_path.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="task.task_id"):
        classify_validation_run(tmp_path)


def test_multiple_metadata_free_runs_are_rejected(tmp_path: Path) -> None:
    _args(tmp_path, "one")
    _args(tmp_path, "two")
    with pytest.raises(ValueError, match="cohort_id is required"):
        classify_validation_run(tmp_path)


def test_diagnostic_runs_need_no_policy_identity_and_return_exact_files(tmp_path: Path) -> None:
    first = _args(tmp_path, "one", cohort_id="cohort-a", evaluation_mode="diagnostic")
    second = _args(tmp_path, "two", cohort_id="cohort-a", evaluation_mode="diagnostic")
    plan = classify_validation_run(tmp_path)
    assert plan.mode == "diagnostic"
    assert plan.args_files == tuple(sorted((first.resolve(), second.resolve())))


def test_diagnostic_partial_policy_identity_is_rejected(tmp_path: Path) -> None:
    _args(
        tmp_path,
        "one",
        cohort_id="cohort-a",
        evaluation_mode="diagnostic",
        harness_revision="rev-1",
    )
    with pytest.raises(ValueError, match="partial harness identity"):
        classify_validation_run(tmp_path)


def test_heldout_manifest_and_full_identity_are_preflighted(tmp_path: Path) -> None:
    manifest, digest = _manifest(tmp_path, ["task-1", "task-2"])
    first = _args(tmp_path, "one", task_id="task-1", **_heldout_metadata(digest))
    second = _args(tmp_path, "two", task_id="task-2", **_heldout_metadata(digest))
    plan = classify_validation_run(tmp_path, cohort_manifest=manifest)
    assert plan.mode == "heldout"
    assert plan.args_files == tuple(sorted((first.resolve(), second.resolve())))


def test_heldout_requires_manifest_before_validation(tmp_path: Path) -> None:
    _, digest = _manifest(tmp_path, ["task-1"])
    _args(tmp_path, "one", task_id="task-1", **_heldout_metadata(digest))
    with pytest.raises(ValueError, match="requires an explicit cohort manifest"):
        classify_validation_run(tmp_path)


def test_manifest_rejects_duplicate_roster_and_task_set_mismatch(tmp_path: Path) -> None:
    duplicate_manifest, digest = _manifest(tmp_path, ["task-1", "task-1"])
    _args(tmp_path, "one", task_id="task-1", **_heldout_metadata(digest))
    with pytest.raises(ValueError, match="must be unique"):
        classify_validation_run(tmp_path, cohort_manifest=duplicate_manifest)

    manifest, digest = _manifest(tmp_path, ["task-1", "task-2"])
    args_path = tmp_path / "one" / "args.json"
    payload = json.loads(args_path.read_text())
    payload["cohort_manifest_sha256"] = digest
    args_path.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="cohort task roster mismatch"):
        classify_validation_run(tmp_path, cohort_manifest=manifest)


def test_heldout_rejects_manifest_hash_and_policy_hash_mismatches(tmp_path: Path) -> None:
    manifest, digest = _manifest(tmp_path, ["task-1"])
    args_path = _args(tmp_path, "one", task_id="task-1", **_heldout_metadata("0" * 64))
    with pytest.raises(ValueError, match="cohort_manifest_sha256"):
        classify_validation_run(tmp_path, cohort_manifest=manifest)

    payload = json.loads(args_path.read_text())
    payload["cohort_manifest_sha256"] = digest
    payload["harness_policy_sha256"] = "0" * 64
    args_path.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="does not match harness_policy"):
        classify_validation_run(tmp_path, cohort_manifest=manifest)

    payload["harness_policy_sha256"] = _canonical_sha256(payload["harness_policy"])
    payload["harness_revision"] = "contradictory-revision"
    args_path.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="harness_revision contradicts harness_policy"):
        classify_validation_run(tmp_path, cohort_manifest=manifest)


def test_partial_metadata_mixed_modes_cohorts_and_duplicate_tasks_are_rejected(
    tmp_path: Path,
) -> None:
    _args(tmp_path, "one", task_id="same", cohort_id="cohort-a")
    with pytest.raises(ValueError, match="evaluation_mode"):
        classify_validation_run(tmp_path)

    (tmp_path / "one" / "args.json").unlink()
    _args(tmp_path, "one", task_id="same", **_heldout_metadata("manifest-hash"))
    _args(tmp_path, "two", task_id="other", cohort_id="cohort-a", evaluation_mode="diagnostic")
    with pytest.raises(ValueError, match="mixed evaluation modes"):
        classify_validation_run(tmp_path)

    (tmp_path / "two" / "args.json").unlink()
    (tmp_path / "one" / "args.json").unlink()
    _args(tmp_path, "one", task_id="same", cohort_id="cohort-a", evaluation_mode="diagnostic")
    _args(tmp_path, "two", task_id="other", cohort_id="cohort-b", evaluation_mode="diagnostic")
    with pytest.raises(ValueError, match="mixed cohort_id"):
        classify_validation_run(tmp_path)

    (tmp_path / "two" / "args.json").unlink()
    _args(tmp_path, "two", task_id="same", cohort_id="cohort-a", evaluation_mode="diagnostic")
    with pytest.raises(ValueError, match="duplicate task_id"):
        classify_validation_run(tmp_path)
