# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Config validation uses synthetic local artifacts and never launches a service."""

import hashlib
import json
import os
import shutil
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def hashed(path):
    return {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


@pytest.fixture
def prepared(tmp_path):
    from nooa_cybergym.leaderboard.capabilities import CapabilityRegistry

    repo = tmp_path / "repo"
    repo.mkdir()
    evidence, staging, private = (tmp_path / name for name in ("evidence", "staging", "private"))
    for root in (evidence, staging, private):
        root.mkdir(mode=0o700)
    bundled = Path(__file__).resolve().parents[2] / "leaderboard"
    shutil.copytree(
        bundled / "certification/fixtures",
        repo / "examples/cybergym/leaderboard/certification/fixtures",
    )
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    artifact_map = {}
    for name, filename in (
        ("certification_policy", "certification-policy.json"),
        ("campaign_policy", "campaign-policy.json"),
        ("alternate_policy", "alternate-model.json"),
        ("network_policy", "network-policy.json"),
    ):
        target = artifact_dir / filename
        shutil.copyfile(bundled / "config" / filename, target)
        artifact_map[name] = hashed(target)
    # An inventory can be empty/pending during load; it grants no capability.
    registry = artifact_dir / "capabilities.json"
    registry.write_text(CapabilityRegistry(()).manifest_json)
    artifact_map["capability_registry"] = hashed(registry)
    source = repo / "frozen-driver.py"
    source.write_bytes(b"# explicitly synthetic fixture\n")
    manifest = artifact_dir / "harness.json"
    manifest.write_bytes(
        canonical(
            {
                "schema_version": 1,
                "file_hashes": {
                    "frozen-driver.py": hashlib.sha256(source.read_bytes()).hexdigest()
                },
            }
        )
    )
    artifact_map["harness_manifest"] = hashed(manifest)
    native = artifact_dir / "native-runtime.json"
    native.write_bytes(
        canonical(
            {
                "schema_version": 1,
                "vscode_commit": "07f806f999227108933c2e30515b26eecc1fda74",
                "vscode_server_sha256": "1f65ee7af2ede2152b4f1bedf781ea28233438173eb9831a0f3f721c5d7dd6ac",
                "claude_vsix_sha256": "4d52576e7fe83a01b908e04ea8742192d432e79e2c1ee17f10d423eaf68e21ce",
                **dict.fromkeys(
                    (
                        "claude_extension_sha256",
                        "claude_binary_sha256",
                        "launcher_vsix_sha256",
                        "managed_settings_sha256",
                        "managed_mcp_sha256",
                    ),
                    "a" * 64,
                ),
            }
        )
    )
    artifact_map["native_runtime"] = hashed(native)
    credentials = {}
    for name in ("zai", "deepseek", "gbrain_read", "gbrain_write"):
        path = private / (name + ".secret")
        path.write_text("synthetic-private-" + name)
        path.chmod(0o600)
        credentials[name] = {"path": str(path)}
    key = Ed25519PrivateKey.generate()
    key_path = private / "signing.pem"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    public_hash = hashlib.sha256(
        key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).hexdigest()
    bun = artifact_dir / "bun"
    bun.write_bytes(b"synthetic executable fixture")
    bun.chmod(0o700)
    script = artifact_dir / "runtime.ts"
    script.write_bytes(b"// synthetic sidecar fixture")
    config = {
        "schema_version": 1,
        "scope": "synthetic_native",
        "epoch": "synthetic-epoch-1",
        "run_ids": ["synthetic-run-a", "synthetic-run-b"],
        "repo_root": str(repo),
        "staging_root": str(staging),
        "evidence_root": str(evidence),
        "image_id": "sha256:" + "b" * 64,
        "artifacts": artifact_map,
        "credentials": credentials,
        "signing": {
            "key_id": "synthetic-key",
            "private_key_path": str(key_path),
            "public_key_sha256": public_hash,
        },
        "gbrain": {
            "bun": hashed(bun),
            "runtime": hashed(script),
            "allowed_models": {
                "openai:text-embedding-3-large": "embedding",
                "voyage:rerank-2.5": "rerank",
                "openai:gpt-5.6-luna": "chat",
            },
        },
    }
    path = tmp_path / "runtime-config.json"

    def save():
        path.write_bytes(canonical(config))
        return path

    return config, save, path


def load(prepared):
    from nooa_cybergym.leaderboard.runtime_config import load_runtime_config

    _, save, _ = prepared
    return load_runtime_config(save())


def test_loads_two_runs_with_same_frozen_fixtures_without_readiness_claim(prepared):
    config = load(prepared)
    assert config.run_ids == ("synthetic-run-a", "synthetic-run-b")
    assert len(config.runs) == 2
    assert all(
        run.fixture_ids == ("synthetic:length-header", "synthetic:chunk-table")
        for run in config.runs
    )
    assert len(config.fixtures) == 2
    assert config.budgets.max_model_requests_per_task == 600
    assert config.budgets.glm_and_memory_auxiliary_max_requests == 564
    assert config.budgets.deepseek_max_requests == 36
    assert config.versions.vscode == "1.140.0"
    assert config.versions.claude_extension == "2.1.289"
    assert config.model_policy.primary == "glm-5.3[1m]"
    assert config.model_policy.approved_zai_coding_plan_url == "https://api.z.ai/api/anthropic"
    summary = config.safe_summary()
    assert not {"ready", "passed", "certified", "official_launch_authorised"} & set(summary)
    assert "synthetic-private" not in repr(config) + json.dumps(summary)
    assert str(config.credentials.zai.path) not in repr(config.credentials)
    assert config.credentials.zai.read_text() == "synthetic-private-zai"
    assert config.signing.load_private_key().public_key() is not None
    assert config.gbrain.command(config.credentials.gbrain_read)[-1] == str(
        config.credentials.gbrain_read.path
    )
    assert config.gbrain.command(config.credentials.gbrain_read)[:2] == (
        "/usr/bin/env",
        f"GBRAIN_HOME={config.credentials.gbrain_read.path.parent.parent}",
    )
    config.verify_unchanged()


def test_nested_config_is_immutable_and_policy_mutation_is_not_retained(prepared):
    config = load(prepared)
    with pytest.raises(FrozenInstanceError):
        config.epoch = "changed"
    with pytest.raises(TypeError):
        config.native_identity["vscode_commit"] = "changed"
    with pytest.raises(TypeError):
        config.gbrain.allowed_models["unknown"] = "chat"
    policy = config.certification_policy
    policy.alternate_max_requests_by_role["independent_recon"] = 999
    assert config.certification_policy.alternate_max_requests_by_role["independent_recon"] == 12


@pytest.mark.parametrize(
    "mutate",
    [
        lambda c: c.update(scope="official"),
        lambda c: c.update(ready=True),
        lambda c: c.update(schema_version=True),
        lambda c: c.update(run_ids=["one", "one"]),
        lambda c: c.update(run_ids=["one"]),
        lambda c: c.update(image_id="sunchaser/cybergym-native:local"),
        lambda c: c.update(fixture_ids=["arvo:1065"]),
        lambda c: c["gbrain"]["allowed_models"].update({"other": "chat"}),
    ],
)
def test_unapproved_execution_or_model_settings_are_rejected(prepared, mutate):
    mutate(prepared[0])
    with pytest.raises(ValueError):
        load(prepared)


def test_hash_drift_and_policy_budget_change_are_rejected(prepared):
    config, _, _ = prepared
    path = Path(config["artifacts"]["campaign_policy"]["path"])
    policy = json.loads(path.read_bytes())
    policy["max_model_requests_per_task"] = 601
    path.write_bytes(canonical(policy))
    with pytest.raises(ValueError, match="digest|hash"):
        load(prepared)
    config["artifacts"]["campaign_policy"] = hashed(path)
    with pytest.raises(ValueError, match="policy|budget"):
        load(prepared)


def test_vendor_drift_is_rejected_even_when_manifest_hash_is_updated(prepared):
    config, _, _ = prepared
    path = Path(config["artifacts"]["native_runtime"]["path"])
    value = json.loads(path.read_bytes())
    value["claude_vsix_sha256"] = "c" * 64
    path.write_bytes(canonical(value))
    config["artifacts"]["native_runtime"] = hashed(path)
    with pytest.raises(ValueError, match="native|pinned"):
        load(prepared)


def test_changed_frozen_source_or_fixture_blocks_revalidation(prepared):
    config = load(prepared)
    (config.repo_root / "frozen-driver.py").write_text("changed")
    with pytest.raises(ValueError, match="digest|hash|changed"):
        config.verify_unchanged()
    with pytest.raises(ValueError, match="digest|hash|changed"):
        load(prepared)


def test_freeze_identity_changes_when_fixture_bytes_change_without_config_change(prepared):
    before = load(prepared)
    original_config_hash = before.source.sha256
    before.fixtures[0].vulnerable.path.write_text("changed synthetic source")
    with pytest.raises(ValueError, match="digest|changed"):
        before.verify_unchanged()
    after = load(prepared)
    assert before.source.sha256 == after.source.sha256 == original_config_hash
    assert before.freeze_sha256 != after.freeze_sha256
    assert after.safe_summary()["configuration_sha256"] == after.freeze_sha256


@pytest.mark.parametrize("name", [".local-evidence/log.json", "state.sqlite", "events.jsonl"])
def test_mutable_runtime_state_cannot_be_part_of_harness_tree(prepared, name):
    raw = prepared[0]
    manifest = Path(raw["artifacts"]["harness_manifest"]["path"])
    target = Path(raw["repo_root"]) / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("state")
    manifest.write_bytes(
        canonical({"schema_version": 1, "file_hashes": {name: hashed(target)["sha256"]}})
    )
    raw["artifacts"]["harness_manifest"] = hashed(manifest)
    with pytest.raises(ValueError, match="mutable|harness"):
        load(prepared)


def test_changed_secret_and_signing_key_are_rejected_without_value_leak(prepared):
    config = load(prepared)
    config.credentials.zai.path.write_text("changed-credential-do-not-print")
    with pytest.raises(ValueError) as error:
        config.credentials.zai.read_text()
    assert "changed-credential-do-not-print" not in str(error.value)
    prepared[0]["signing"]["public_key_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="signing|key"):
        load(prepared)


def test_secret_ref_cannot_be_embedded_in_staging_or_repo(prepared):
    raw = prepared[0]
    path = Path(raw["staging_root"]) / "provider-key"
    path.write_text("synthetic-private-key")
    path.chmod(0o600)
    raw["credentials"]["zai"] = {"path": str(path)}
    with pytest.raises(ValueError, match="private|overlap|secret"):
        load(prepared)


def test_harness_manifest_rejects_escape_and_mutable_files(prepared):
    raw = prepared[0]
    path = Path(raw["artifacts"]["harness_manifest"]["path"])
    path.write_bytes(
        canonical({"schema_version": 1, "file_hashes": {"../private/signing.pem": "a" * 64}})
    )
    raw["artifacts"]["harness_manifest"] = hashed(path)
    with pytest.raises(ValueError, match="harness|path"):
        load(prepared)


def test_duplicate_json_and_plaintext_secret_fields_never_enter_config(prepared):
    from nooa_cybergym.leaderboard.runtime_config import load_runtime_config

    raw, save, path = prepared
    save()
    path.write_bytes(b'{"scope":"synthetic_native","scope":"official"}')
    with pytest.raises(ValueError):
        load_runtime_config(path)
    raw["credentials"]["zai"] = {"value": "synthetic-value-must-not-be-printed"}
    with pytest.raises(ValueError) as error:
        load(prepared)
    assert "synthetic-value-must-not-be-printed" not in str(error.value)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions and symlinks")
def test_public_or_linked_private_files_are_rejected(prepared):
    raw = prepared[0]
    path = Path(raw["credentials"]["zai"]["path"])
    path.chmod(0o644)
    with pytest.raises(ValueError, match="private|permission"):
        load(prepared)
    path.chmod(0o600)
    alias = path.with_name("alias")
    alias.symlink_to(path)
    raw["credentials"]["zai"]["path"] = str(alias)
    with pytest.raises(ValueError, match="link|path"):
        load(prepared)
