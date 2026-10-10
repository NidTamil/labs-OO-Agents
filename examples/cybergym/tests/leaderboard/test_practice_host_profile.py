# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Native practice profile must be ready before the owned window opens."""

import base64
import json

import pytest
from nooa_cybergym.leaderboard.practice_host_profile import (
    PracticeHostProfilePreparer,
    ProvisioningPracticeUi,
)


def _identity(tmp_path):
    key = tmp_path / "agent-key"
    key.write_bytes(b"private key is never read by the preparer")
    extensions = tmp_path / "extensions-source"
    extension = extensions / "ms-vscode-remote.remote-ssh-0.128.0"
    extension.mkdir(parents=True)
    (extension / "package.json").write_bytes(b"{}")
    (extensions / "extensions.json").write_bytes(
        json.dumps(
            [
                {
                    "identifier": {"id": "ms-vscode-remote.remote-ssh"},
                    "version": "0.128.0",
                    "relativeLocation": "ms-vscode-remote.remote-ssh-0.128.0",
                    "location": {"fsPath": "D:\\stale\\profile"},
                }
            ]
        ).encode()
    )
    return key, extensions


def test_profile_is_created_on_d_before_owned_window_opens(tmp_path):
    key, extensions = _identity(tmp_path)
    blob = (11).to_bytes(4, "big") + b"ssh-ed25519" + (32).to_bytes(4, "big") + b"x" * 32
    known_hosts = b"[127.0.0.1]:22514 ssh-ed25519 " + base64.b64encode(blob) + b"\n"
    preparer = PracticeHostProfilePreparer(
        profiles_dir=tmp_path / "profiles",
        identity_file=key,
        extension_source=extensions,
    )

    class Ui:
        def __init__(self):
            self.calls = []

        def open(self, run_id, task_id, remote_host, port):
            self.calls.append(("open", run_id, task_id, remote_host, port))
            assert preparer.profile_root(run_id, task_id).joinpath("ssh-config").is_file()

        def close(self, *args):
            self.calls.append(("close", *args))

        def reap(self, *args):
            self.calls.append(("reap", *args))

    ui = Ui()
    owned = ProvisioningPracticeUi(
        preparer=preparer,
        fetch_known_hosts=lambda task_id, port: known_hosts,
        ui=ui,
    )
    owned.open("practice-1", "arvo:47101", "cybergym-practice-1", 22514)
    root = preparer.profile_root("practice-1", "arvo:47101")
    settings = json.loads((root / "user-data/User/settings.json").read_bytes())
    assert settings["remote.SSH.configFile"] == str(root / "ssh-config")
    assert settings["remote.SSH.remotePlatform"] == {"cybergym-practice-1": "linux"}
    assert "IdentityFile " + str(key).replace("\\", "/") in (root / "ssh-config").read_text()
    assert (root / "known_hosts").read_bytes() == known_hosts
    assert (root / "extensions/ms-vscode-remote.remote-ssh-0.128.0/package.json").is_file()
    manifest = json.loads((root / "extensions/extensions.json").read_bytes())
    assert manifest[0]["location"]["fsPath"] == str(
        root / "extensions/ms-vscode-remote.remote-ssh-0.128.0"
    )
    preparer.prepare(
        run_id="practice-1",
        task_id="arvo:47101",
        remote_host="cybergym-practice-1",
        port=22514,
        known_hosts=known_hosts,
    )
    assert ui.calls[0][0] == "open"
    owned.close("practice-1", "arvo:47101", "cybergym-practice-1")
    owned.reap("practice-1")


def test_profile_rejects_swapped_host_key_and_does_not_open(tmp_path):
    key, extensions = _identity(tmp_path)
    preparer = PracticeHostProfilePreparer(
        profiles_dir=tmp_path / "profiles", identity_file=key, extension_source=extensions
    )

    class Ui:
        def open(self, *args):
            raise AssertionError("must not open")

        def close(self, *args):
            pass

        def reap(self, *args):
            pass

    owned = ProvisioningPracticeUi(
        preparer=preparer,
        fetch_known_hosts=lambda task_id, port: b"[127.0.0.1]:9999 ssh-ed25519 AAAA\n",
        ui=Ui(),
    )
    with pytest.raises(ValueError, match="host key"):
        owned.open("practice-1", "arvo:47101", "cybergym-practice-1", 22514)
