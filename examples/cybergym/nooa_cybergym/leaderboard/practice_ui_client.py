# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Pinned Windows Claude Code UI client for the two-task native practice run."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from xeus_cybergym.canonical import canonical_json
from xeus_cybergym.ledger import Ed25519Verifier

from .campaign_runner import PowerShellNativeUi
from .native_ui_client import NativeUiClient, PowerShellNativeSubmit
from .practice_host_material import PinnedPracticeHostMaterial, PinnedPracticeUiTransport
from .practice_host_profile import PracticeHostProfilePreparer, ProvisioningPracticeUi

_FIELDS = frozenset(
    {
        "schema_version",
        "scope",
        "run_id",
        "controller_key_id",
        "controller_public_key_pem",
        "ssh_exe",
        "ssh_config",
        "tunnel_known_hosts",
        "outer_ssh_alias",
        "mailbox_remote_argv",
        "host_material_remote_argv",
        "ui_script",
        "send_script",
        "code_exe",
        "identity_file",
        "extension_source",
        "extension_tree_sha256",
        "profiles_dir",
        "custody_dir",
        "poll_interval_seconds",
    }
)
_PINNED_CODE = Path("D:/GLM/bin/VSCode-1.140.0/Code.exe")
_PINNED_CODE_SHA = "96851792952c34ead53462ad36d973356af2e737b5ed4e433e23c4647e0d6318"


def _verified(ref: dict) -> Path:
    if type(ref) is not dict or set(ref) != {"path", "sha256"}:
        raise ValueError("one pinned Windows file reference required")
    path = Path(ref["path"])
    if (
        not path.is_absolute()
        or path.is_symlink()
        or not path.is_file()
        or hashlib.sha256(path.read_bytes()).hexdigest() != ref["sha256"]
    ):
        raise RuntimeError("pinned Windows file differs")
    return path


def client_from_practice_config(path: Path, expected_sha256: str) -> tuple[NativeUiClient, float]:
    source = Path(path)
    if not source.is_absolute() or source.is_symlink() or not source.is_file():
        raise ValueError("absolute regular practice UI configuration required")
    raw = source.read_bytes()
    if not 0 < len(raw) <= 16384 or hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise RuntimeError("practice UI configuration digest differs")
    try:
        config = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise ValueError("practice UI configuration is malformed") from None
    if (
        type(config) is not dict
        or set(config) != _FIELDS
        or canonical_json(config) != raw
        or config["schema_version"] != 1
        or config["scope"] != "native_practice_level1"
        or type(config["run_id"]) is not str
        or not config["run_id"]
        or type(config["controller_key_id"]) is not str
        or not config["controller_key_id"]
        or type(config["poll_interval_seconds"]) not in {int, float}
        or not 0.1 <= config["poll_interval_seconds"] <= 60
        or type(config["mailbox_remote_argv"]) is not list
        or type(config["host_material_remote_argv"]) is not list
    ):
        raise ValueError("exact practice-only Windows UI configuration required")
    public = load_pem_public_key(_verified(config["controller_public_key_pem"]).read_bytes())
    if not isinstance(public, Ed25519PublicKey):
        raise ValueError("Ed25519 controller public key required")
    ssh_exe = _verified(config["ssh_exe"])
    ssh_config = _verified(config["ssh_config"])
    tunnel_known_hosts = _verified(config["tunnel_known_hosts"])
    code_exe = _verified(config["code_exe"])
    if code_exe != _PINNED_CODE or config["code_exe"]["sha256"] != _PINNED_CODE_SHA:
        raise RuntimeError("practice requires pinned D: VS Code 1.140.0")
    identity = Path(config["identity_file"])
    if not identity.is_absolute() or identity.is_symlink() or not identity.is_file():
        raise RuntimeError("dedicated native container SSH identity unavailable")
    route = PinnedPracticeHostMaterial(
        ssh_exe=ssh_exe,
        ssh_config=ssh_config,
        ssh_config_sha256=config["ssh_config"]["sha256"],
        tunnel_known_hosts=tunnel_known_hosts,
        tunnel_known_hosts_sha256=config["tunnel_known_hosts"]["sha256"],
        ssh_alias=config["outer_ssh_alias"],
        remote_argv=tuple(config["host_material_remote_argv"]),
        run_id=config["run_id"],
    )
    profiles = Path(config["profiles_dir"])
    preparer = PracticeHostProfilePreparer(
        profiles_dir=profiles,
        identity_file=identity,
        extension_source=Path(config["extension_source"]),
        expected_extension_sha256=config["extension_tree_sha256"],
    )
    ui = ProvisioningPracticeUi(
        preparer=preparer,
        fetch_known_hosts=route,
        ui=PowerShellNativeUi(
            str(_verified(config["ui_script"])),
            code_exe=str(code_exe),
            tunnel_known_hosts=str(tunnel_known_hosts),
        ),
    )
    client = NativeUiClient(
        run_id=config["run_id"],
        verifier=Ed25519Verifier({config["controller_key_id"]: public}),
        transport=PinnedPracticeUiTransport(
            route=route, remote_argv=tuple(config["mailbox_remote_argv"])
        ),
        ui=ui,
        custody_dir=Path(config["custody_dir"]),
        profiles_dir=profiles,
        submit=PowerShellNativeSubmit(_verified(config["send_script"])),
    )
    return client, config["poll_interval_seconds"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--config-sha256", required=True)
    args = parser.parse_args(argv)
    client, interval = client_from_practice_config(args.config, args.config_sha256)
    client.run_forever(poll_interval_seconds=interval)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
