# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Provision the pinned per-task VS Code SSH profile before native UI open."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import shutil
from pathlib import Path

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9:_.-]{0,127}\Z")
_ALIAS = re.compile(r"[a-z][a-z0-9-]{1,63}\Z")
_SHA = re.compile(r"[a-f0-9]{64}\Z")


def _tree_hash(root: Path) -> str:
    rows = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("linked VS Code extension source is forbidden")
        if path.is_file():
            rows.append(
                (path.relative_to(root).as_posix(), hashlib.sha256(path.read_bytes()).hexdigest())
            )
    if not rows:
        raise ValueError("pinned VS Code extension source is empty")
    return hashlib.sha256(
        json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _write_exact(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        if path.is_symlink() or not path.is_file() or path.read_bytes() != content:
            raise RuntimeError("existing native practice profile differs from pinned bytes")
        return
    with path.open("xb") as stream:
        stream.write(content)


def _rebased_extension_manifest(source: Path, target: Path) -> bytes:
    """Replace stale donor absolute locations with this run's D: profile paths."""
    raw = (source / "extensions.json").read_bytes()
    try:
        entries = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise ValueError("pinned VS Code extension manifest is malformed") from None
    if type(entries) is not list or not entries:
        raise ValueError("pinned VS Code extension manifest is empty")
    for entry in entries:
        if type(entry) is not dict or type(entry.get("relativeLocation")) is not str:
            raise ValueError("pinned VS Code extension location differs")
        relative = entry["relativeLocation"]
        if re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,127}", relative) is None:
            raise ValueError("pinned VS Code extension location escapes profile")
        if not (source / relative).is_dir():
            raise ValueError("pinned VS Code extension directory is absent")
        destination = target / relative
        entry["location"] = {
            "$mid": 1,
            "fsPath": str(destination),
            "_sep": 1,
            "path": "/" + destination.as_posix(),
            "scheme": "file",
        }
    return json.dumps(entries, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class PracticeHostProfilePreparer:
    """Only static remote-SSH settings and a controller-observed host key enter D:."""

    def __init__(
        self,
        *,
        profiles_dir: Path,
        identity_file: Path,
        extension_source: Path,
        expected_extension_sha256: str | None = None,
    ) -> None:
        profiles, identity, extensions = (
            Path(profiles_dir),
            Path(identity_file),
            Path(extension_source),
        )
        if (
            not profiles.is_absolute()
            or profiles.is_symlink()
            or not identity.is_absolute()
            or identity.is_symlink()
            or not identity.is_file()
            or not extensions.is_absolute()
            or extensions.is_symlink()
            or not extensions.is_dir()
            or (
                expected_extension_sha256 is not None
                and _SHA.fullmatch(expected_extension_sha256) is None
            )
        ):
            raise ValueError("absolute pinned D: native profile inputs required")
        observed = _tree_hash(extensions)
        if expected_extension_sha256 is not None and observed != expected_extension_sha256:
            raise RuntimeError("VS Code remote extension tree differs from freeze")
        self.profiles = profiles
        self.identity = identity
        self.extensions = extensions
        self.extension_sha256 = observed

    def profile_root(self, run_id: str, task_id: str) -> Path:
        if (
            type(run_id) is not str
            or _ID.fullmatch(run_id) is None
            or type(task_id) is not str
            or _ID.fullmatch(task_id) is None
        ):
            raise ValueError("bounded native practice profile identity required")
        run_key = hashlib.sha256(run_id.encode()).hexdigest()[:24]
        task_key = hashlib.sha256(task_id.encode()).hexdigest()[:24]
        return self.profiles / f"cybergym-{run_key}-{task_key}"

    def prepare(
        self,
        *,
        run_id: str,
        task_id: str,
        remote_host: str,
        port: int,
        known_hosts: bytes,
    ) -> Path:
        if (
            type(remote_host) is not str
            or _ALIAS.fullmatch(remote_host) is None
            or type(port) is not int
            or not 1024 <= port <= 65535
            or type(known_hosts) is not bytes
            or len(known_hosts) > 4096
        ):
            raise ValueError("bounded native practice host and port required")
        try:
            line = known_hosts.decode("ascii")
            match = re.fullmatch(
                rf"\[127\.0\.0\.1\]:{port} ssh-ed25519 ([A-Za-z0-9+/]+={{0,2}})\n",
                line,
            )
            if match is None:
                raise ValueError()
            key = base64.b64decode(match[1], validate=True)
            if (
                len(key) != 51
                or key[:4] != (11).to_bytes(4, "big")
                or key[4:15] != b"ssh-ed25519"
                or key[15:19] != (32).to_bytes(4, "big")
                or base64.b64encode(key).decode("ascii") != match[1]
            ):
                raise ValueError()
        except (UnicodeDecodeError, ValueError, binascii.Error):
            raise ValueError("controller-observed practice SSH host key differs") from None
        root = self.profile_root(run_id, task_id)
        if root.is_symlink():
            raise RuntimeError("native practice profile root is linked")
        root.mkdir(parents=True, exist_ok=True)
        host_file = root / "known_hosts"
        ssh_config = root / "ssh-config"
        _write_exact(host_file, known_hosts)
        config = (
            f"Host {remote_host}\n"
            "    HostName 127.0.0.1\n"
            f"    Port {port}\n"
            "    User agent\n"
            f"    IdentityFile {self.identity.as_posix()}\n"
            f"    UserKnownHostsFile {host_file.as_posix()}\n"
            "    StrictHostKeyChecking yes\n"
            "    IdentitiesOnly yes\n"
            "    BatchMode yes\n"
        ).encode("ascii")
        _write_exact(ssh_config, config)
        settings = {
            "telemetry.telemetryLevel": "off",
            "remote.SSH.useExecServer": False,
            "extensions.autoCheckUpdates": False,
            "remote.SSH.connectTimeout": 60,
            "security.workspace.trust.enabled": False,
            "extensions.autoUpdate": "off",
            "remote.SSH.configFile": str(ssh_config),
            "remote.SSH.remotePlatform": {remote_host: "linux"},
            "remote.SSH.useLocalServer": True,
            "remote.SSH.lockfilesInTmp": True,
        }
        _write_exact(
            root / "user-data/User/settings.json",
            json.dumps(settings, sort_keys=True, separators=(",", ":")).encode(),
        )
        target = root / "extensions"
        rebased = _rebased_extension_manifest(self.extensions, target)
        copied = False
        if not target.exists() and not target.is_symlink():
            shutil.copytree(self.extensions, target)
            copied = True
        if target.is_symlink() or not target.is_dir():
            raise RuntimeError("copied VS Code remote extension tree differs")
        manifest = target / "extensions.json"
        if copied:
            manifest.write_bytes(rebased)
        elif manifest.is_symlink() or manifest.read_bytes() != rebased:
            raise RuntimeError("rebased VS Code extension manifest differs")
        source_files = {
            path.relative_to(self.extensions).as_posix(): path
            for path in self.extensions.rglob("*")
            if path.is_file() and not path.is_symlink()
        }
        copied_files = {
            path.relative_to(target).as_posix(): path
            for path in target.rglob("*")
            if path.is_file() and not path.is_symlink()
        }
        if source_files.keys() != copied_files.keys() or any(
            hashlib.sha256(copied_files[name].read_bytes()).digest()
            != hashlib.sha256(
                rebased if name == "extensions.json" else source.read_bytes()
            ).digest()
            for name, source in source_files.items()
        ):
            raise RuntimeError("copied VS Code remote extension tree differs")
        return root


class ProvisioningPracticeUi:
    """Fetch the current container host key before invoking the owned UI open."""

    def __init__(self, *, preparer, fetch_known_hosts, ui):
        if (
            not callable(getattr(preparer, "prepare", None))
            or not callable(fetch_known_hosts)
            or not all(callable(getattr(ui, name, None)) for name in ("open", "close", "reap"))
        ):
            raise ValueError("native practice UI provisioning inputs required")
        self.preparer = preparer
        self.fetch_known_hosts = fetch_known_hosts
        self.ui = ui

    def open(self, run_id: str, task_id: str, remote_host: str, port: int) -> None:
        self.preparer.prepare(
            run_id=run_id,
            task_id=task_id,
            remote_host=remote_host,
            port=port,
            known_hosts=self.fetch_known_hosts(task_id, port),
        )
        self.ui.open(run_id, task_id, remote_host, port)

    def close(self, run_id: str, task_id: str, remote_host: str) -> None:
        self.ui.close(run_id, task_id, remote_host)

    def reap(self, run_id: str) -> None:
        self.ui.reap(run_id)
