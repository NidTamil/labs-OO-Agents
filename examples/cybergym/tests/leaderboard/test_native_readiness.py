"""The static native harness audit never stands in for live certification."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

from nooa_cybergym.leaderboard.native_readiness import (
    REQUIRED_LIVE_INTERFACES,
    VerifiedNativeIntegration,
    audit_native_readiness,
    main,
)


def _fixture(tmp_path: Path) -> tuple[Path, Path, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    extension = tmp_path / "anthropic.claude-code-2.1.289"
    extension.mkdir()
    (extension / "package.json").write_text(
        json.dumps(
            {
                "name": "claude-code",
                "version": "2.1.289",
                "contributes": {
                    "commands": [{"command": "claude-vscode.editor.open"}],
                },
            }
        )
    )
    (extension / "extension.js").write_text(
        'commands.registerCommand("claude-vscode.editor.open",'
        "async(session,prompt,column,group,full,options)=>{"
        "return panels.createPanel(session,prompt,column,group,full,options)})"
    )
    version_output = "1.140.0\n" + "a" * 40 + "\nx64\n"
    return repo, extension, version_output


def test_audit_observes_native_command_but_blocks_unwired_runtime(
    tmp_path: Path, monkeypatch
) -> None:
    repo, extension, version_output = _fixture(tmp_path)
    secret = "never-print-controller-provider-key"
    monkeypatch.setenv("ZAI_API_KEY", secret)
    with (extension / "extension.js").open("a") as stream:
        stream.write(f"/* {secret} */")

    report = audit_native_readiness(
        repo_root=repo,
        extension_dir=extension,
        vscode_version_output=version_output,
    )

    assert report.gate == "blocked"
    assert report.observed["vscode_version"] == "1.140.0"
    assert report.observed["vscode_commit"] == "a" * 40
    assert report.observed["claude_extension_version"] == "2.1.289"
    assert report.observed["native_command_contract_observed"] is True
    assert (
        report.observed["extension_js_sha256"]
        == hashlib.sha256((extension / "extension.js").read_bytes()).hexdigest()
    )
    assert "workspace_native_launcher" in report.missing_interfaces
    assert "native_parent_child_tool_trace" in report.missing_interfaces
    assert "host_gateway_boundary" in report.missing_interfaces
    assert "live host-gateway canary listener" in report.missing_contracts["host_gateway_boundary"]
    assert "authenticated_model_connection" in report.missing_interfaces
    assert "guarded_gbrain_bridge" in report.missing_interfaces
    assert "start, result, failure" in report.missing_contracts["native_parent_child_tool_trace"]
    assert set(REQUIRED_LIVE_INTERFACES) <= set(report.missing_interfaces)
    assert secret not in report.to_json()


def test_audit_rejects_command_signature_drift_and_bad_live_attestation(tmp_path: Path) -> None:
    repo, extension, version_output = _fixture(tmp_path)
    (extension / "extension.js").write_text(
        'commands.registerCommand("claude-vscode.editor.open",'
        "async(session,ignored,prompt)=>panels.createPanel(session,prompt))"
    )
    report = audit_native_readiness(
        repo_root=repo,
        extension_dir=extension,
        vscode_version_output=version_output,
        signed_live_evidence=b"not-an-attested-native-run",
        attest_live=lambda _: None,
        expected_run_id="synthetic-run",
        expected_task_id="synthetic-task",
        expected_container_id="synthetic-container",
    )
    assert report.gate == "blocked"
    assert report.observed["native_command_contract_observed"] is False
    assert "version_locked_native_command" in report.missing_interfaces
    assert "signed_live_integration_evidence" in report.missing_interfaces


def test_complete_synthetic_attestor_exercises_future_gate_without_live_claim(
    tmp_path: Path,
) -> None:
    repo, extension, version_output = _fixture(tmp_path)
    controller = repo / "examples" / "cybergym" / "nooa_cybergym" / "leaderboard"
    controller.mkdir(parents=True)
    for name in (
        "campaign.py",
        "workspace.py",
        "container.py",
        "host_boundary.py",
        "model_service.py",
        "preflight.py",
        "memory_transport.py",
        "capabilities.py",
    ):
        (controller / name).write_text("# synthetic fixture only\n")
    launcher = repo / "examples" / "cybergym" / "vscode-launcher"
    launcher.mkdir(parents=True)
    (launcher / "extension.js").write_text("// synthetic fixture only\n")
    (launcher / "package.json").write_text("{}")
    signed = b"synthetic signed run fixture"
    digest = "b" * 64
    attested = VerifiedNativeIntegration(
        envelope_sha256=hashlib.sha256(signed).hexdigest(),
        signature_key_id="synthetic-key",
        scope="live_native",
        execution_source="native-vscode-extension",
        run_id="synthetic-run",
        task_id="synthetic-task",
        container_id="synthetic-container",
        vscode_version="1.140.0",
        vscode_commit="a" * 40,
        claude_extension_version="2.1.289",
        interface_evidence=dict.fromkeys(REQUIRED_LIVE_INTERFACES, digest),
        credential_exposure_surfaces=(),
    )

    report = audit_native_readiness(
        repo_root=repo,
        extension_dir=extension,
        vscode_version_output=version_output,
        signed_live_evidence=signed,
        attest_live=lambda _: attested,
        expected_run_id="synthetic-run",
        expected_task_id="synthetic-task",
        expected_container_id="synthetic-container",
    )
    assert report.gate == "interfaces-attested"
    assert report.missing_interfaces == ()
    assert report.observed["signature_key_id"] == "synthetic-key"

    missing_gateway = audit_native_readiness(
        repo_root=repo,
        extension_dir=extension,
        vscode_version_output=version_output,
        signed_live_evidence=signed,
        attest_live=lambda _: replace(
            attested,
            interface_evidence={
                name: value
                for name, value in attested.interface_evidence.items()
                if name != "host_gateway_boundary"
            },
        ),
        expected_run_id="synthetic-run",
        expected_task_id="synthetic-task",
        expected_container_id="synthetic-container",
    )
    assert missing_gateway.gate == "blocked"
    assert "host_gateway_boundary" in missing_gateway.missing_interfaces

    malformed = audit_native_readiness(
        repo_root=repo,
        extension_dir=extension,
        vscode_version_output=version_output,
        signed_live_evidence=signed,
        attest_live=lambda _: replace(attested, signature_key_id=42),
        expected_run_id="synthetic-run",
        expected_task_id="synthetic-task",
        expected_container_id="synthetic-container",
    )
    assert malformed.gate == "blocked"
    assert "signed_live_integration_evidence" in malformed.missing_interfaces


def test_command_line_reports_blocked_without_loading_credentials(tmp_path: Path, capsys) -> None:
    repo, extension, _ = _fixture(tmp_path)
    status = main(["--repo-root", str(repo), "--extension-dir", str(extension)])
    printed = json.loads(capsys.readouterr().out)
    assert status == 1
    assert printed["gate"] == "blocked"
    assert "native_parent_child_tool_trace" in printed["missing_interfaces"]
