from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace

import pytest
from nooa_cybergym import run
from nooa_cybergym.stagnation import StagnationConfig


def _stagnation_config(**overrides):
    values = {
        "model": "alternate-reviewer",
        "trigger_age_sec": 100,
        "quiet_window_sec": 20,
        "minimum_submissions": 2,
        "reviewer_timeout_sec": 10,
        "reviewer_max_output_tokens": 1024,
        "recovery_window_sec": 40,
    }
    values.update(overrides)
    return StagnationConfig(**values)


def test_missing_required_image_fails_before_run(monkeypatch):
    class Missing(Exception):
        pass

    client = SimpleNamespace(
        images=SimpleNamespace(get=lambda image: (_ for _ in ()).throw(Missing()))
    )
    monkeypatch.setattr(run, "ImageNotFound", Missing)

    with pytest.raises(RuntimeError, match="required runner image is not local"):
        run.require_local_image(client, "runner:tag", role="runner")


def test_internal_route_probe_uses_runner_image_and_real_network():
    calls = []

    class Containers:
        def run(self, image, **kwargs):
            calls.append((image, kwargs))

    client = SimpleNamespace(containers=Containers())
    env = {"HTTP_PROXY": "http://cybergym-proxy:3128"}

    run.preflight_internal_route(
        client,
        image="runner:tag",
        network="cybergym-internal",
        env=env,
        server="http://server:8666",
    )

    image, kwargs = calls[0]
    assert image == "runner:tag"
    assert kwargs["network"] == "cybergym-internal"
    assert kwargs["environment"] == env
    assert kwargs["remove"] is True
    assert "http://server:8666/docs" in kwargs["command"][2]


def test_timeout_budget_requires_finalization_and_shutdown_margin():
    with pytest.raises(ValueError, match="timeout budget is unsafe"):
        run.validate_timeout_budget(
            hard_timeout=1800,
            soft_timeout=1680,
            finalization_grace=120,
            tracing_shutdown_timeout=30,
            outer_margin=60,
        )

    run.validate_timeout_budget(
        hard_timeout=1800,
        soft_timeout=1560,
        finalization_grace=120,
        tracing_shutdown_timeout=30,
        outer_margin=60,
    )


@pytest.mark.parametrize(
    "field",
    [
        "trigger_age_sec",
        "quiet_window_sec",
        "minimum_submissions",
        "reviewer_timeout_sec",
        "reviewer_max_output_tokens",
        "recovery_window_sec",
    ],
)
@pytest.mark.parametrize("invalid", [0, -1])
def test_stagnation_preflight_requires_positive_values(field, invalid):
    with pytest.raises(ValueError, match=field):
        run.validate_stagnation_preflight(
            config=_stagnation_config(**{field: invalid}),
            soft_timeout=1_000,
            cohort_id="heldout-v2",
            evaluation_mode="heldout",
        )


def test_stagnation_preflight_rejects_inconsistent_reviewer_and_run_windows():
    with pytest.raises(ValueError, match="reviewer_timeout_sec.*recovery_window_sec"):
        run.validate_stagnation_preflight(
            config=_stagnation_config(reviewer_timeout_sec=41),
            soft_timeout=1_000,
            cohort_id="heldout-v2",
            evaluation_mode="heldout",
        )

    with pytest.raises(ValueError, match="trigger_age_sec.*recovery_window_sec.*soft_timeout"):
        run.validate_stagnation_preflight(
            config=_stagnation_config(trigger_age_sec=970, recovery_window_sec=40),
            soft_timeout=1_000,
            cohort_id="heldout-v2",
            evaluation_mode="heldout",
        )


@pytest.mark.parametrize(
    ("cohort_id", "evaluation_mode"),
    [("heldout-v2", None), (None, "heldout"), ("", "heldout")],
)
def test_cohort_and_evaluation_mode_must_be_supplied_together(cohort_id, evaluation_mode):
    with pytest.raises(ValueError, match="cohort_id and evaluation_mode"):
        run.validate_stagnation_preflight(
            config=_stagnation_config(model=""),
            soft_timeout=1_000,
            cohort_id=cohort_id,
            evaluation_mode=evaluation_mode,
        )


def test_enabled_v2_requires_explicit_cohort_metadata():
    with pytest.raises(ValueError, match="enabled v2 runs require"):
        run.validate_stagnation_preflight(
            config=_stagnation_config(),
            soft_timeout=1_000,
            cohort_id=None,
            evaluation_mode=None,
        )


def test_measurement_metadata_is_omitted_for_legacy_runs_and_recorded_when_explicit():
    assert run.measurement_args_record(None, None) == {}
    assert run.measurement_args_record("heldout-v2", "heldout") == {
        "cohort_id": "heldout-v2",
        "evaluation_mode": "heldout",
    }


def test_enabled_v2_metadata_failure_happens_before_docker_work(monkeypatch, tmp_path):
    monkeypatch.setattr(
        run.docker,
        "from_env",
        lambda: (_ for _ in ()).throw(AssertionError("Docker must not be touched")),
    )

    with pytest.raises(ValueError, match="enabled v2 runs require"):
        run.main(
            [
                "--task-id",
                "arvo:15",
                "--data-dir",
                str(tmp_path / "data"),
                "--server",
                "http://server:8666",
                "--log-dir",
                str(tmp_path / "logs"),
                "--tmp-dir",
                str(tmp_path / "tmp"),
                "--dotenv",
                str(tmp_path / "missing.env"),
                "--escalation-model",
                "reviewer",
            ]
        )


def test_runner_forwards_cli_overrides_and_records_all_effective_v2_settings():
    args = run.parse_args(
        [
            "--task-id",
            "arvo:15",
            "--data-dir",
            "data",
            "--server",
            "http://server:8666",
            "--log-dir",
            "logs",
            "--tmp-dir",
            "tmp",
            "--cohort-id",
            "heldout-v2",
            "--evaluation-mode",
            "heldout",
            "--escalation-model",
            "reviewer",
            "--escalation-trigger-age",
            "100",
            "--escalation-quiet-window",
            "20",
            "--escalation-min-submissions",
            "2",
            "--escalation-reviewer-timeout",
            "10",
            "--escalation-reviewer-max-output-tokens",
            "1024",
            "--escalation-recovery-window",
            "40",
        ]
    )
    env = {}

    config = run.resolve_stagnation_config(args, env)
    record = run.stagnation_args_record(config)

    assert env == {
        "NOOA_CYBERGYM_ESCALATION_MODEL": "reviewer",
        "NOOA_CYBERGYM_ESCALATION_TRIGGER_AGE_SEC": "100",
        "NOOA_CYBERGYM_ESCALATION_QUIET_WINDOW_SEC": "20",
        "NOOA_CYBERGYM_ESCALATION_MIN_SUBMISSIONS": "2",
        "NOOA_CYBERGYM_ESCALATION_REVIEWER_TIMEOUT_SEC": "10",
        "NOOA_CYBERGYM_ESCALATION_REVIEWER_MAX_OUTPUT_TOKENS": "1024",
        "NOOA_CYBERGYM_ESCALATION_RECOVERY_WINDOW_SEC": "40",
    }
    assert record == {
        "escalation_enabled": True,
        "escalation_model": "reviewer",
        "escalation_trigger_age_sec": 100,
        "escalation_quiet_window_sec": 20,
        "escalation_min_submissions": 2,
        "escalation_reviewer_timeout_sec": 10,
        "escalation_reviewer_max_output_tokens": 1024,
        "escalation_recovery_window_sec": 40,
    }


def test_escalation_cli_values_override_conflicting_environment_values():
    args = SimpleNamespace(
        escalation_model="cli-reviewer",
        escalation_trigger_age=100,
        escalation_quiet_window=20,
        escalation_min_submissions=2,
        escalation_reviewer_timeout=10,
        escalation_reviewer_max_output_tokens=1024,
        escalation_recovery_window=40,
    )
    env = {
        "NOOA_CYBERGYM_ESCALATION_MODEL": "environment-reviewer",
        "NOOA_CYBERGYM_ESCALATION_TRIGGER_AGE_SEC": "999",
        "NOOA_CYBERGYM_ESCALATION_QUIET_WINDOW_SEC": "998",
        "NOOA_CYBERGYM_ESCALATION_MIN_SUBMISSIONS": "997",
        "NOOA_CYBERGYM_ESCALATION_REVIEWER_TIMEOUT_SEC": "996",
        "NOOA_CYBERGYM_ESCALATION_REVIEWER_MAX_OUTPUT_TOKENS": "995",
        "NOOA_CYBERGYM_ESCALATION_RECOVERY_WINDOW_SEC": "994",
    }

    config = run.resolve_stagnation_config(args, env)

    assert config == _stagnation_config(model="cli-reviewer")


def test_omitted_v2_cli_uses_environment_defaults_without_enabling_escalation():
    args = run.parse_args(
        [
            "--task-id",
            "arvo:15",
            "--data-dir",
            "data",
            "--server",
            "http://server:8666",
            "--log-dir",
            "logs",
            "--tmp-dir",
            "tmp",
        ]
    )
    env = {}

    config = run.resolve_stagnation_config(args, env)

    assert config == StagnationConfig.from_environment({})
    assert config.enabled is False
    assert env == {}
    run.validate_stagnation_preflight(
        config=config,
        soft_timeout=1,
        cohort_id=None,
        evaluation_mode=None,
    )


def test_hard_timeout_recovers_smallest_persisted_verified_crash(tmp_path):
    artifacts = tmp_path / "artifacts"
    candidates = artifacts / "candidates"
    candidates.mkdir(parents=True)
    (candidates / "submission_1.poc").write_bytes(b"larger-crash")
    (candidates / "submission_2.poc").write_bytes(b"tiny")
    (candidates / "submission_3.poc").write_bytes(b"safe")
    records = [
        {
            "submission_number": 1,
            "status": "crashed",
            "source_agent": "finder-a",
            "source_model": "model-a",
            "hypothesis": "first crash",
            "kind": "crash",
            "cluster_key": "asan:a",
        },
        {
            "submission_number": 2,
            "status": "crashed",
            "source_agent": "finder-b",
            "source_model": "model-b",
            "hypothesis": "small deterministic crash",
            "kind": "crash",
            "cluster_key": "asan:b",
        },
        {
            "submission_number": 3,
            "status": "no_crash",
            "hypothesis": "safe",
            "kind": "no_crash",
            "cluster_key": "no-crash",
        },
    ]
    (artifacts / "submissions.jsonl").write_text(
        "".join(json.dumps(record) + "\n" for record in records)
    )

    recovered = run.recover_timeout_final(tmp_path)

    assert recovered is not None
    assert (artifacts / "final_submission" / "poc").read_bytes() == b"tiny"
    selection = json.loads((artifacts / "final_submission" / "selection.json").read_text())
    assert selection["submission_number"] == 2
    assert selection["sha256"] == hashlib.sha256(b"tiny").hexdigest()
    assert selection["cluster_key"] == "asan:b"
    assert "outer hard timeout" in selection["selection_reason"].lower()
    assert (artifacts / "output.txt").is_file()


def test_hard_timeout_recovery_ignores_noncrash_and_incomplete_records(tmp_path):
    artifacts = tmp_path / "artifacts"
    candidates = artifacts / "candidates"
    candidates.mkdir(parents=True)
    (candidates / "submission_1.poc").write_bytes(b"not-a-crash")
    (artifacts / "submissions.jsonl").write_text(
        json.dumps(
            {
                "submission_number": 1,
                "status": "no_crash",
                "kind": "no_crash",
                "cluster_key": "safe",
            }
        )
        + "\n"
        + "{interrupted-json"
    )

    assert run.recover_timeout_final(tmp_path) is None
    assert not (artifacts / "final_submission").exists()


def test_task_preflight_rejects_unresolved_git_lfs_pointer(tmp_path):
    pointer = tmp_path / "description.txt"
    pointer.write_text(
        "version https://git-lfs.github.com/spec/v1\noid sha256:0123456789abcdef\nsize 182\n"
    )

    with pytest.raises(RuntimeError, match="unresolved Git LFS pointer"):
        run.require_resolved_task_files(tmp_path)


def test_task_preflight_accepts_materialized_task_files(tmp_path):
    (tmp_path / "description.txt").write_text("A real vulnerability description.\n")
    (tmp_path / "repo-vul.tar.gz").write_bytes(b"\x1f\x8bmaterialized archive")

    run.require_resolved_task_files(tmp_path)
