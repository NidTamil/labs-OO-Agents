# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Initialize only a fresh task tmpfs home; never copy workstation/personal state."""

from __future__ import annotations

import json
import os
import pwd
from pathlib import Path

COMMIT = "07f806f999227108933c2e30515b26eecc1fda74"


def initialize(home: Path = Path("/home/agent"), runtime: Path = Path("/opt/sunchaser")) -> None:
    if os.getuid() != 0 or home.is_symlink() or not home.is_dir() or any(home.iterdir()):
        raise RuntimeError("native runtime requires fresh root-initialized task home")
    account = pwd.getpwnam("agent")
    server = home / ".vscode-server"
    for folder in (
        server / "bin",
        server / "data/Machine",
        server / "extensions",
        home / ".claude/agents",
    ):
        folder.mkdir(parents=True, exist_ok=True)
    (server / "bin" / COMMIT).symlink_to(runtime / "vscode-server", target_is_directory=True)
    for extension in sorted((runtime / "vscode-extensions").iterdir()):
        if extension.is_symlink() or not extension.is_dir():
            raise RuntimeError("immutable native extension directory malformed")
        (server / "extensions" / extension.name).symlink_to(extension, target_is_directory=True)
    launcher = runtime / "vscode-extensions/xeus.sunchaser-cybergym-launcher-0.1.0"
    (server / "data/Machine/settings.json").symlink_to(launcher / "machine-settings.json")
    # Onboarding acknowledgement is task-local and contains no credentials/sessions.
    # Native Slr() joins CLAUDE_CONFIG_DIR with .claude.json when explicitly set.
    (home / ".claude/.claude.json").write_text(
        json.dumps({"hasCompletedOnboarding": True}), encoding="utf8"
    )
    for agent in sorted((runtime / "native-agents").glob("*.md")):
        (home / ".claude/agents" / agent.name).symlink_to(agent)
    home.chmod(0o700)
    # The unchanged base entrypoint must still chmod the root-owned tmpfs mount
    # before it transfers the mount directory to the agent.
    for entry in home.rglob("*"):
        os.chown(entry, account.pw_uid, account.pw_gid, follow_symlinks=False)


if __name__ == "__main__":
    initialize()
