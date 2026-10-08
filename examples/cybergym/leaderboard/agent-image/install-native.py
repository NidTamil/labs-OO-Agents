# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Verify vendor archives and install immutable native artifacts during image build."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import posixpath
import re
import shutil
import tarfile
import tempfile
from contextlib import ExitStack, contextmanager
from pathlib import Path, PurePosixPath
from zipfile import ZipFile

SERVER_SHA256 = "1f65ee7af2ede2152b4f1bedf781ea28233438173eb9831a0f3f721c5d7dd6ac"
CLAUDE_SHA256 = "4d52576e7fe83a01b908e04ea8742192d432e79e2c1ee17f10d423eaf68e21ce"
SERVER_COMMIT = "07f806f999227108933c2e30515b26eecc1fda74"
MAX_VSIX_CONTAINER_BYTES = 2 * 1024 * 1024 * 1024
MAX_VSIX_EXTRACTED_BYTES = 4 * 1024 * 1024 * 1024


def sha256_file(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def require_digest(path: Path, expected: str) -> None:
    if not re.fullmatch(r"[a-f0-9]{64}", expected) or sha256_file(path) != expected:
        raise ValueError("native vendor archive digest mismatch")


def relative_path(name: str, prefix: str) -> Path:
    if not name.startswith(prefix + "/") or "\\" in name:
        raise ValueError("native archive path is outside expected prefix")
    relative = name.removeprefix(prefix + "/").rstrip("/")
    parts = PurePosixPath(relative).parts
    if (
        not parts
        or PurePosixPath(relative).is_absolute()
        or any(p in {".", "..", ""} for p in relative.split("/"))
    ):
        raise ValueError("native archive path is unsafe")
    return Path(*parts)


def extract_server(archive_path: Path, destination: Path) -> None:
    """Extract bounded regular artifacts; defer confined relative links until last."""
    destination.mkdir(parents=True)
    with tarfile.open(archive_path, "r:gz") as archive:
        members = archive.getmembers()
        roots = {PurePosixPath(member.name).parts[0] for member in members if member.name}
        if len(roots) != 1:
            raise ValueError("native server archive must have one root")
        prefix = roots.pop()
        links = []
        for member in members:
            if member.name.rstrip("/") == prefix:
                continue
            relative = relative_path(member.name, prefix)
            target = destination / relative
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    raise ValueError("native archive regular file unreadable")
                with source, target.open("xb") as output:
                    shutil.copyfileobj(source, output)
                target.chmod(0o755 if member.mode & 0o111 else 0o644)
            elif member.issym() or member.islnk():
                links.append((member, relative))
            else:
                raise ValueError("native archive special device is forbidden")
        for member, relative in links:
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if member.issym():
                normalized = posixpath.normpath(
                    posixpath.join(relative.parent.as_posix(), member.linkname)
                )
                if (
                    member.linkname.startswith("/")
                    or normalized == ".."
                    or normalized.startswith("../")
                ):
                    raise ValueError("native archive symbolic link escapes destination")
                target.symlink_to(member.linkname)
            else:
                source = destination / relative_path(member.linkname, prefix)
                if source.is_symlink() or not source.is_file():
                    raise ValueError("native archive hardlink is unsafe")
                os.link(source, target)


@contextmanager
def extension_zip(archive_path: Path):
    """Open a pinned VSIX, including the vendor's gzip transport wrapper.

    main() verifies the original downloaded bytes before calling this helper.
    Stream to a bounded temporary file, reaching gzip EOF/CRC before touching
    the destination. Never substitute an inner checksum for the vendor pin.
    """
    with ExitStack() as stack:
        raw = stack.enter_context(archive_path.open("rb"))
        magic = raw.read(2)
        raw.seek(0)
        if magic == b"\x1f\x8b":
            source = stack.enter_context(gzip.GzipFile(fileobj=raw, mode="rb"))
            container = stack.enter_context(tempfile.TemporaryFile(mode="w+b"))
            total = 0
            while chunk := source.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_VSIX_CONTAINER_BYTES:
                    raise ValueError("native gzip VSIX exceeds bounded container size")
                container.write(chunk)
            container.seek(0)
        else:
            if os.fstat(raw.fileno()).st_size > MAX_VSIX_CONTAINER_BYTES:
                raise ValueError("native VSIX exceeds bounded container size")
            container = raw
        if container.read(4) != b"PK\x03\x04":
            raise ValueError("native VSIX container is not a ZIP archive")
        container.seek(0)
        archive = stack.enter_context(ZipFile(container))
        entries = archive.infolist()
        if (
            len(entries) > 50000
            or any(len(entry.filename) > 4096 for entry in entries)
            or sum(entry.file_size for entry in entries) > MAX_VSIX_EXTRACTED_BYTES
        ):
            raise ValueError("native VSIX exceeds bounded extraction size")
        if archive.testzip() is not None:
            raise ValueError("native VSIX ZIP integrity check failed")
        yield archive


def extract_extension(archive_path: Path, destination: Path) -> dict:
    with extension_zip(archive_path) as archive:
        destination.mkdir(parents=True)
        for entry in archive.infolist():
            if not entry.filename.startswith("extension/") or entry.filename == "extension/":
                continue
            target = destination / relative_path(entry.filename, "extension")
            if entry.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if (entry.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError("native extension symbolic link is forbidden")
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(entry) as source, target.open("xb") as output:
                shutil.copyfileobj(source, output)
            target.chmod(0o644)
    return json.loads((destination / "package.json").read_bytes())


def build_managed_settings(launcher_dir: Path) -> dict:
    """Bind immutable native hooks while removing interactive permission prompts."""
    managed = json.loads((launcher_dir / "hooks-settings.json").read_bytes())
    for entries in managed["hooks"].values():
        for entry in entries:
            for hook in entry["hooks"]:
                hook["command"] = "/usr/local/bin/node " + str(launcher_dir / "native-hook.js")
    managed.update(
        {
            "model": "glm-5.3[1m]",
            "alwaysThinkingEnabled": True,
            "enableWorkflows": True,
            "ultracode": True,
            "allowManagedHooksOnly": True,
            "allowedMcpServers": [],
            "permissions": {
                "defaultMode": "bypassPermissions",
                "deny": [
                    f"{tool}({kind})"
                    for tool in ("Agent", "Task")
                    for kind in (
                        "Explore",
                        "Plan",
                        "general-purpose",
                        "Bash",
                        "statusline-setup",
                        "claude-code-guide",
                    )
                ],
            },
        }
    )
    return managed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vendor", type=Path, required=True)
    parser.add_argument("--launcher-sha256", required=True)
    args = parser.parse_args()
    server = args.vendor / "vscode-server-linux-x64.tar.gz"
    claude = args.vendor / "claude-code-linux-x64.vsix"
    launcher = args.vendor / "sunchaser-cybergym-launcher.vsix"
    require_digest(server, SERVER_SHA256)
    require_digest(claude, CLAUDE_SHA256)
    require_digest(launcher, args.launcher_sha256)
    root = Path("/opt/sunchaser")
    extract_server(server, root / "vscode-server")
    product = json.loads((root / "vscode-server/product.json").read_bytes())
    if product.get("commit") != SERVER_COMMIT:
        raise ValueError("native server commit differs from frozen workstation")
    claude_dir = root / "vscode-extensions/anthropic.claude-code-2.1.289-linux-x64"
    claude_package = extract_extension(claude, claude_dir)
    if claude_package.get("name") != "claude-code" or claude_package.get("version") != "2.1.289":
        raise ValueError("Claude native extension version mismatch")
    binary = claude_dir / "resources/native-binary/claude"
    if not binary.is_file():
        raise ValueError("Linux native Claude binary missing")
    binary.chmod(0o755)
    launcher_dir = root / "vscode-extensions/xeus.sunchaser-cybergym-launcher-0.1.0"
    launcher_package = extract_extension(launcher, launcher_dir)
    if launcher_package.get("version") != "0.1.0" or launcher_package.get("extensionKind") != [
        "workspace"
    ]:
        raise ValueError("native launcher identity mismatch")
    managed = build_managed_settings(launcher_dir)
    managed_path = Path("/etc/claude-code/managed-settings.json")
    managed_path.parent.mkdir(parents=True, exist_ok=True)
    managed_path.write_text(json.dumps(managed, sort_keys=True), encoding="utf8")
    managed_path.chmod(0o444)
    managed_mcp = managed_path.with_name("managed-mcp.json")
    managed_mcp.chmod(0o444)
    identity = {
        "schema_version": 1,
        "vscode_commit": SERVER_COMMIT,
        "vscode_server_sha256": SERVER_SHA256,
        "claude_vsix_sha256": CLAUDE_SHA256,
        "claude_extension_sha256": sha256_file(claude_dir / "extension.js"),
        "claude_binary_sha256": sha256_file(binary),
        "launcher_vsix_sha256": args.launcher_sha256,
        "managed_settings_sha256": sha256_file(managed_path),
        "managed_mcp_sha256": sha256_file(managed_mcp),
    }
    (root / "native-runtime.json").write_text(json.dumps(identity, sort_keys=True), encoding="utf8")
    print(json.dumps(identity, sort_keys=True))


if __name__ == "__main__":
    main()
