from __future__ import annotations

import base64
import hashlib
import json
import subprocess
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nooa_cybergym import run
from nooa_cybergym.cohort_commitment import commitment_payload, verify_cohort_commitment
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


def test_local_image_identity_uses_immutable_docker_image_id():
    image = SimpleNamespace(id="sha256:deadbeef", tags=["runner:latest"])
    client = SimpleNamespace(images=SimpleNamespace(get=lambda reference: image))

    resolved = run.require_local_image(client, "runner:latest", role="runner")

    assert resolved is image
    assert run.immutable_image_id(resolved) == "sha256:deadbeef"


def test_harness_revision_cli_overrides_environment_and_blank_is_absent():
    env = {"NOOA_CYBERGYM_HARNESS_REVISION": "environment-revision"}

    assert (
        run.resolve_harness_revision(SimpleNamespace(harness_revision=" cli-revision "), env)
        == "cli-revision"
    )
    assert env["NOOA_CYBERGYM_HARNESS_REVISION"] == "environment-revision"
    assert (
        run.resolve_harness_revision(SimpleNamespace(harness_revision=None), env)
        == "environment-revision"
    )
    assert run.resolve_harness_revision(SimpleNamespace(harness_revision=None), {}) is None
    assert (
        run.resolve_harness_revision(
            SimpleNamespace(harness_revision="   "),
            {"NOOA_CYBERGYM_HARNESS_REVISION": "environment-revision"},
        )
        is None
    )

    parsed = run.parse_args(
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
            "--harness-revision",
            "parsed-cli-revision",
        ]
    )
    assert run.resolve_harness_revision(parsed, env) == "parsed-cli-revision"


def test_attributed_runs_require_nonblank_harness_revision():
    with pytest.raises(ValueError, match="heldout runs require.*harness revision"):
        run.validate_harness_identity_preflight(harness_revision=None, evaluation_mode="heldout")
    with pytest.raises(ValueError, match="heldout runs require.*harness revision"):
        run.validate_harness_identity_preflight(harness_revision="  ", evaluation_mode="heldout")

    with pytest.raises(ValueError, match="diagnostic runs require.*harness revision"):
        run.validate_harness_identity_preflight(harness_revision=None, evaluation_mode="diagnostic")
    run.validate_harness_identity_preflight(
        harness_revision="diagnostic-revision", evaluation_mode="diagnostic"
    )
    run.validate_harness_identity_preflight(harness_revision=None, evaluation_mode=None)


def test_heldout_manifest_is_canonical_validated_roster(tmp_path):
    payload = {
        "schema_version": 1,
        "cohort_id": "heldout-v2",
        "evaluation_mode": "heldout",
        "expected_task_ids": ["arvo:15", "arvo:16"],
    }
    path = tmp_path / "cohort.json"
    path.write_text(json.dumps(payload, indent=2))

    manifest, digest = run.load_heldout_cohort_manifest(
        path,
        cohort_id="heldout-v2",
        evaluation_mode="heldout",
        task_id="arvo:15",
    )

    assert manifest == payload
    assert digest == run.canonical_json_sha256(payload)
    assert digest == run.canonical_json_sha256(dict(reversed(list(payload.items()))))


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ({"schema_version": 2}, "schema_version"),
        ({"cohort_id": "other"}, "cohort_id"),
        ({"evaluation_mode": "diagnostic"}, "evaluation_mode"),
        ({"expected_task_ids": []}, "expected_task_ids"),
        ({"expected_task_ids": ["arvo:15", "arvo:15"]}, "unique"),
        ({"expected_task_ids": ["arvo:16"]}, "current task_id"),
        ({"extra": "field"}, "exactly"),
    ],
)
def test_heldout_manifest_rejects_invalid_or_mismatched_roster(mutation, message):
    payload = {
        "schema_version": 1,
        "cohort_id": "heldout-v2",
        "evaluation_mode": "heldout",
        "expected_task_ids": ["arvo:15"],
    }
    payload.update(mutation)

    with pytest.raises(ValueError, match=message):
        run.validate_heldout_cohort_manifest(
            payload,
            cohort_id="heldout-v2",
            evaluation_mode="heldout",
            task_id="arvo:15",
        )


def test_git_identity_parser_requires_exact_head_and_clean_source():
    head = "a" * 40
    assert run.parse_git_source_identity(head, head + "\n", "") == head

    with pytest.raises(ValueError, match="does not match.*HEAD"):
        run.parse_git_source_identity("b" * 40, head + "\n", "")
    with pytest.raises(ValueError, match="dirty or untracked"):
        run.parse_git_source_identity(head, head + "\n", " M source.py\n")


def test_git_identity_check_uses_repo_root_and_non_shell_subprocess_seam(tmp_path):
    calls = []
    head = "a" * 40

    def runner(command, **kwargs):
        calls.append((command, kwargs))
        stdout = head + "\n" if command[-2:] == ["rev-parse", "HEAD"] else ""
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    assert run.verify_git_source_identity(tmp_path, head, runner=runner) == head
    assert [call[0] for call in calls] == [
        ["git", "rev-parse", "HEAD"],
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
    ]
    assert all(call[1]["cwd"] == tmp_path for call in calls)
    assert all(call[1]["shell"] is False for call in calls)


def test_authority_commitment_binds_roster_revision_image_and_policy(tmp_path):
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    payload = commitment_payload(
        cohort_id="heldout-v2",
        cohort_manifest_sha256="a" * 64,
        expected_task_ids=["arvo:15", "arvo:16"],
        harness_revision="b" * 40,
        runner_image_id="sha256:image",
        harness_policy_sha256="c" * 64,
    )
    payload_bytes = run.json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    envelope = {
        "algorithm": "Ed25519",
        "key_id": "independent-authority-v1",
        "payload": base64.b64encode(payload_bytes).decode(),
        "signature": base64.b64encode(private.sign(payload_bytes)).decode(),
    }
    commitment = tmp_path / "commitment.json"
    keys = tmp_path / "keys.json"
    commitment.write_text(json.dumps(envelope))
    keys.write_text(json.dumps({"independent-authority-v1": base64.b64encode(public).decode()}))

    record = verify_cohort_commitment(commitment, keys, expected_payload=payload)
    assert record["cohort_authority_key_id"] == "independent-authority-v1"

    changed = {**payload, "expected_task_ids": ["arvo:15"]}
    with pytest.raises(ValueError, match="does not match"):
        verify_cohort_commitment(commitment, keys, expected_payload=changed)


def test_repo_root_is_derived_from_executing_source_path(tmp_path):
    repo = tmp_path / "repo"
    source = repo / "examples" / "cybergym" / "nooa_cybergym" / "run.py"
    source.parent.mkdir(parents=True)
    source.touch()
    (repo / ".git").write_text("gitdir: elsewhere\n")

    assert run.repo_root_for_source(source) == repo


def test_manifest_git_binding_accepts_exact_tracked_head_bytes(tmp_path):
    repo = tmp_path / "repo"
    manifest = repo / "cohorts" / "heldout.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_bytes(b'{"schema_version":1}\n')
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        stdout = manifest.read_bytes() if command[1] == "show" else b""
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr=b"")

    assert run.verify_manifest_at_git_head(repo, manifest, runner=runner) == (
        "cohorts/heldout.json"
    )
    assert calls == [
        ["git", "ls-files", "--error-unmatch", "--", "cohorts/heldout.json"],
        ["git", "show", "HEAD:cohorts/heldout.json"],
    ]


def test_manifest_git_binding_rejects_outside_untracked_and_mutated_files(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_bytes(b"outside")
    with pytest.raises(ValueError, match="within the harness repo"):
        run.verify_manifest_at_git_head(repo, outside)

    manifest = repo / "cohort.json"
    manifest.write_bytes(b"working")

    def untracked(command, **kwargs):
        raise subprocess.CalledProcessError(1, command)

    with pytest.raises(ValueError, match="tracked at Git HEAD"):
        run.verify_manifest_at_git_head(repo, manifest, runner=untracked)

    def mutated(command, **kwargs):
        stdout = b"committed" if command[1] == "show" else b""
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr=b"")

    with pytest.raises(ValueError, match="bytes differ"):
        run.verify_manifest_at_git_head(repo, manifest, runner=mutated)


def test_provider_endpoint_normalization_removes_secrets_and_prompt_changes_policy():
    endpoint = run.normalize_provider_endpoint(
        "HTTPS://user:secret@API.Example.COM:8443/v1/chat?api_key=secret#token"
    )
    assert endpoint == "https://api.example.com:8443/v1/chat"
    assert "user" not in endpoint
    assert "secret" not in endpoint

    base = run.harness_policy_record(
        harness_revision="a" * 40,
        runner_image_id="sha256:deadbeef",
        task_difficulty="level1",
        primary_model="model-a",
        reasoning_effort="max",
        prompt_sha256=run.text_sha256("prompt one"),
        provider_endpoint=endpoint,
        with_flag=False,
        mask_map_sha256=None,
        firewall_mode="none",
        firewall_domains=["api.example.com"],
        firewall_proxy_image_id=None,
        task_server_endpoint="http://server:8666",
        runtime={},
        v2={},
    )
    changed_prompt = {**base, "prompt_sha256": run.text_sha256("prompt two")}
    changed_endpoint = {**base, "provider_endpoint": "https://other.example/v1"}
    assert run.harness_policy_sha256(base) != run.harness_policy_sha256(changed_prompt)
    assert run.harness_policy_sha256(base) != run.harness_policy_sha256(changed_endpoint)
    for override in (
        {"with_flag": True},
        {"mask_map_sha256": "f" * 64},
        {"firewall_mode": "start"},
        {"firewall_domains": ["api.example.com", "packages.example"]},
        {"firewall_proxy_image_id": "sha256:proxy"},
        {"task_server_endpoint": "http://other-server:8666"},
    ):
        assert run.harness_policy_sha256(base) != run.harness_policy_sha256({**base, **override})


def test_firewall_domain_and_mask_map_policy_inputs_are_sanitized_and_hashed(tmp_path):
    assert run.sanitized_firewall_domains(
        " Packages.Example.,.PYPI.org,packages.example ", "API.Example.COM"
    ) == [".pypi.org", "api.example.com", "packages.example"]
    with pytest.raises(ValueError, match="only DNS names"):
        run.sanitized_firewall_domains("user:secret@example.com", "api.example.com")

    mask_map = tmp_path / "mask.json"
    mask_map.write_bytes(b"mask-map-v1")
    assert run.file_sha256(None) is None
    assert run.file_sha256(mask_map) == hashlib.sha256(b"mask-map-v1").hexdigest()


def test_harness_policy_fingerprint_is_canonical_and_change_sensitive():
    runtime = run.effective_runtime_policy(
        env={},
        hard_timeout=14_400,
        soft_timeout=13_920,
        finalization_grace=300,
        tracing_shutdown_timeout=30,
    )
    policy = run.harness_policy_record(
        harness_revision="abc123",
        runner_image_id="sha256:deadbeef",
        task_difficulty="level1",
        primary_model="model-a",
        reasoning_effort="max",
        prompt_sha256=run.text_sha256("prompt"),
        provider_endpoint="https://api.example/v1",
        with_flag=False,
        mask_map_sha256=None,
        firewall_mode="none",
        firewall_domains=["api.example"],
        firewall_proxy_image_id=None,
        task_server_endpoint="http://server:8666",
        runtime=runtime,
        v2=run.stagnation_args_record(_stagnation_config()),
    )
    same_policy_different_order = dict(reversed(list(policy.items())))

    digest = run.harness_policy_sha256(policy)

    assert digest == run.harness_policy_sha256(same_policy_different_order)
    assert len(digest) == 64
    assert runtime == {
        "hard_timeout_sec": 14_400,
        "soft_timeout_sec": 13_920,
        "finalization_grace_sec": 300,
        "tracing_shutdown_timeout_sec": 30,
        "outer_margin_sec": 60,
        "max_iterations": 300,
        "max_output_tokens": 384_000,
        "control_max_output_tokens": 16_384,
        "request_timeout_sec": 3_900,
        "output_token_margin": 64_000,
        "reasoning_output_floor": 8_192,
        "summary_max_output_tokens": 16_384,
        "min_exploration_sec": 1_200,
        "max_concurrent_expanders": 2,
        "submission_timeout_sec": 300.0,
        "submission_rate_limit": 15,
        "submission_rate_window_sec": 60.0,
    }
    assert set(policy["v2"]) == {
        "escalation_enabled",
        "escalation_model",
        "escalation_trigger_age_sec",
        "escalation_quiet_window_sec",
        "escalation_min_submissions",
        "escalation_reviewer_timeout_sec",
        "escalation_reviewer_max_output_tokens",
        "escalation_recovery_window_sec",
    }
    changed = json.loads(json.dumps(policy))
    changed["runtime"]["max_concurrent_expanders"] = 3
    assert run.harness_policy_sha256(changed) != digest

    identity = run.harness_identity_args_record(
        harness_revision="abc123",
        runner_image_id="sha256:deadbeef",
        policy=policy,
    )
    assert identity == {
        "harness_revision": "abc123",
        "runner_image_id": "sha256:deadbeef",
        "harness_policy_sha256": digest,
        "harness_policy": policy,
    }
    assert run.harness_policy_sha256(identity["harness_policy"]) == digest

    unicode_policy = {"model": "reviewer-β"}
    expected = hashlib.sha256(
        json.dumps(
            unicode_policy,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    assert run.harness_policy_sha256(unicode_policy) == expected


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


def test_agent_container_launch_uses_resolved_immutable_image_id(monkeypatch, tmp_path):
    calls = []

    class Container:
        def logs(self, **kwargs):
            return []

        def wait(self):
            return {"StatusCode": 0}

        def remove(self, **kwargs):
            return None

    class Containers:
        def run(self, image, **kwargs):
            calls.append((image, kwargs))
            return Container()

    monkeypatch.setattr(run.docker, "from_env", lambda: SimpleNamespace(containers=Containers()))
    task_dir = tmp_path / "task"
    log_dir = tmp_path / "logs"
    task_dir.mkdir()
    (task_dir / "submit.sh").write_text("exit 0\n")
    (log_dir / "agent").mkdir(parents=True)
    (log_dir / "artifacts").mkdir()
    args = SimpleNamespace(
        timeout=10,
        model="model-a",
        prompt="",
        reasoning_effort=None,
        container_name="test-container",
        keep_container=False,
    )

    assert (
        run.run_container(
            args,
            task_dir,
            log_dir,
            {},
            None,
            "sha256:immutable-runner",
        )
        == 0
    )
    assert calls[0][0] == "sha256:immutable-runner"


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


def test_heldout_harness_identity_failure_happens_before_docker_work(monkeypatch, tmp_path):
    monkeypatch.delenv("NOOA_CYBERGYM_HARNESS_REVISION", raising=False)
    monkeypatch.setattr(
        run.docker,
        "from_env",
        lambda: (_ for _ in ()).throw(AssertionError("Docker must not be touched")),
    )

    with pytest.raises(ValueError, match="heldout runs require.*harness revision"):
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
                "--cohort-id",
                "heldout-v2",
                "--evaluation-mode",
                "heldout",
            ]
        )


def test_heldout_manifest_failure_happens_before_docker_work(monkeypatch, tmp_path):
    monkeypatch.setattr(
        run.docker,
        "from_env",
        lambda: (_ for _ in ()).throw(AssertionError("Docker must not be touched")),
    )

    with pytest.raises(ValueError, match="heldout runs require --cohort-manifest"):
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
                "--cohort-id",
                "heldout-v2",
                "--evaluation-mode",
                "heldout",
                "--harness-revision",
                "a" * 40,
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
