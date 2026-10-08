# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Safe immutable vendor archive extraction without running Claude or VS Code."""

from __future__ import annotations

import gzip
import importlib.util
import io
import json
import tarfile
from pathlib import Path
from zipfile import ZipFile

import pytest

ROOT = Path(__file__).resolve().parents[2] / "leaderboard/agent-image"


def test_native_base_declares_clang_compiler_rt_for_fuzzing():
    """The promised Clang ASan/libFuzzer workflow needs the matching runtime archives."""
    dockerfile = (ROOT / "Dockerfile").read_text()
    assert "libclang-rt-14-dev" in dockerfile


@pytest.fixture
def subject():
    spec = importlib.util.spec_from_file_location("install_native", ROOT / "install-native.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_native_managed_bypass_keeps_controller_pretool_hook(subject, tmp_path):
    launcher = tmp_path / "launcher"
    launcher.mkdir()
    (launcher / "hooks-settings.json").write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {"hooks": [{"type": "command", "command": "template", "timeout": 20}]}
                    ]
                }
            }
        )
    )

    managed = subject.build_managed_settings(launcher)

    assert managed["permissions"]["defaultMode"] == "bypassPermissions"
    assert "disableBypassPermissionsMode" not in managed["permissions"]
    assert managed["allowManagedHooksOnly"] is True
    assert managed["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == (
        "/usr/local/bin/node " + str(launcher / "native-hook.js")
    )
    assert "Agent(Explore)" in managed["permissions"]["deny"]


@pytest.mark.parametrize(
    "name", ["root/../outside", "root/a/./b", "root//absolute", "other/file", "root/a\\b"]
)
def test_native_archive_rejects_noncanonical_or_escaping_paths(subject, name):
    with pytest.raises(ValueError):
        subject.relative_path(name, "root")


def test_vendor_digest_mismatch_is_rejected(subject, tmp_path):
    source = tmp_path / "vendor"
    source.write_bytes(b"wrong vendor")
    with pytest.raises(ValueError, match="digest mismatch"):
        subject.require_digest(source, "a" * 64)


def test_server_extraction_preserves_executable_and_rejects_device(subject, tmp_path):
    source = tmp_path / "server.tar.gz"
    with tarfile.open(source, "w:gz") as archive:
        file = tarfile.TarInfo("vscode-server/bin/server")
        file.size = 3
        file.mode = 0o755
        archive.addfile(file, io.BytesIO(b"abc"))
    subject.extract_server(source, tmp_path / "server")
    assert (tmp_path / "server/bin/server").read_bytes() == b"abc"
    with tarfile.open(source, "w:gz") as archive:
        device = tarfile.TarInfo("vscode-server/device")
        device.type = tarfile.CHRTYPE
        archive.addfile(device)
    with pytest.raises(ValueError, match="special device"):
        subject.extract_server(source, tmp_path / "unsafe-server")


def test_extension_extraction_refuses_zip_slip(subject, tmp_path):
    archive_path = tmp_path / "extension.vsix"
    with ZipFile(archive_path, "w") as archive:
        archive.writestr("extension/../../outside", "no")
    with pytest.raises(ValueError):
        subject.extract_extension(archive_path, tmp_path / "extension")
    assert not (tmp_path / "outside").exists()


def wrapped_vsix():
    stream = io.BytesIO()
    with ZipFile(stream, "w") as archive:
        archive.writestr("extension/package.json", '{"name":"claude-code","version":"2.1.289"}')
        archive.writestr("extension/resources/native-binary/claude", b"native fixture" * 1000)
    return gzip.compress(stream.getvalue())


def test_official_gzip_wrapped_vsix_extracts_only_after_complete_crc_validation(subject, tmp_path):
    source = tmp_path / "extension.vsix"
    wrapped = wrapped_vsix()
    source.write_bytes(wrapped)
    assert subject.extract_extension(source, tmp_path / "valid")["version"] == "2.1.289"
    assert (
        tmp_path / "valid/resources/native-binary/claude"
    ).read_bytes() == b"native fixture" * 1000
    damaged = bytearray(wrapped)
    damaged[-8] ^= 0x80  # The gzip trailer CRC fails only after reading the whole stream.
    source.write_bytes(damaged)
    with pytest.raises((OSError, ValueError)):
        subject.extract_extension(source, tmp_path / "corrupt")
    assert not (tmp_path / "corrupt").exists()


def test_gzip_vsix_expansion_and_inner_zip_integrity_are_bounded(subject, tmp_path, monkeypatch):
    source = tmp_path / "extension.vsix"
    source.write_bytes(wrapped_vsix())
    monkeypatch.setattr(subject, "MAX_VSIX_CONTAINER_BYTES", 256)
    with pytest.raises(ValueError, match="bounded"):
        subject.extract_extension(source, tmp_path / "oversized")
    assert not (tmp_path / "oversized").exists()
    source.write_bytes(gzip.compress(b"not a zip"))
    with pytest.raises(ValueError, match="ZIP"):
        subject.extract_extension(source, tmp_path / "notzip")
    assert not (tmp_path / "notzip").exists()


def test_frozen_child_definitions_have_no_command_write_or_nested_agent_tools():
    definitions = list((ROOT / "native-agents").glob("*.md"))
    assert len(definitions) == 3
    for definition in definitions:
        content = definition.read_text()
        tools = next(line for line in content.splitlines() if line.startswith("tools: "))
        assert set(tools.removeprefix("tools: ").split(", ")) == {
            "Read",
            "Grep",
            "Glob",
            "mcp__gbrain__recall",
            "mcp__gbrain__search",
            "mcp__clangd__document_symbols",
            "mcp__clangd__hover",
            "mcp__clangd__definition",
            "mcp__clangd__references",
            "mcp__documentation__fetch",
        }
        assert "model: inherit\n" in content
        assert "permissionMode: bypassPermissions\n" in content
        assert "maxTurns:" not in content
    settings = json.loads((ROOT.parent / "native-launcher/machine-settings.json").read_bytes())
    assert settings["claudeCode.allowDangerouslySkipPermissions"] is True
    environment = {
        entry["name"]: entry["value"] for entry in settings["claudeCode.environmentVariables"]
    }
    assert environment["ANTHROPIC_AUTH_TOKEN"] == "xeus-container-peer-auth"
    assert environment["ANTHROPIC_BASE_URL"] == "http://model-gateway"
    assert environment["ENABLE_TOOL_SEARCH"] == "false"
    assert all(
        value == "glm-5.3[1m]" for key, value in environment.items() if key.endswith("_MODEL")
    )


def test_managed_mcp_is_exact_public_peer_bound_frozen_roster():
    config = json.loads((ROOT / "native-mcp.json").read_bytes())
    assert config == {
        "mcpServers": {
            "gbrain": {"type": "http", "url": "http://gbrain-read-gateway/mcp"},
            "clangd": {"type": "http", "url": "http://registered-tool-gateway/mcp/clangd"},
            "documentation": {
                "type": "http",
                "url": "http://registered-tool-gateway/mcp/documentation",
            },
            "advisor": {
                "type": "http",
                "url": "http://registered-tool-gateway/advisor/mcp",
                "timeout": 3600000,
            },
            "finalizer": {"type": "http", "url": "http://registered-tool-gateway/mcp/finalizer"},
            "vulnerable": {"type": "http", "url": "http://cybergym-submit/mcp"},
        }
    }


def test_build_context_shell_scripts_are_lf_normalized(tmp_path):
    spec = importlib.util.spec_from_file_location(
        "prepare_native", ROOT / "prepare-native-build.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    source = tmp_path / "source.sh"
    source.write_bytes(b"#!/bin/bash\r\nset -e\r\n")
    target = tmp_path / "target.sh"
    module.copy_build_source(source, target)
    assert target.read_bytes() == b"#!/bin/bash\nset -e\n"
