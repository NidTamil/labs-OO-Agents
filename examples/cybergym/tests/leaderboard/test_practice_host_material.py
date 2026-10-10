# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Windows receives only the current task container's observed public host key."""

import base64
import hashlib
from types import SimpleNamespace

import pytest
from nooa_cybergym.leaderboard.practice_host_material import (
    PinnedPracticeHostMaterial,
    read_practice_host_material,
)
from xeus_cybergym.canonical import canonical_json


def test_current_connection_yields_only_bounded_host_key(tmp_path):
    evidence = tmp_path / "run-1-arvo-47101"
    evidence.mkdir()
    known = evidence / "known_hosts"
    known.write_bytes(b"public host key\n")
    connection = {
        "scope": "native_practice_level1",
        "run_id": "run-1",
        "task_id": "arvo:47101",
        "ssh_host_port": 22514,
        "known_hosts": str(known),
        "status": "awaiting_signed_practice_start_intent",
    }
    (evidence / "connection.json").write_bytes(canonical_json(connection))
    value = read_practice_host_material(
        evidence_root=tmp_path, run_id="run-1", task_id="arvo:47101", port=22514
    )
    assert value["run_id"] == "run-1"
    assert value["task_id"] == "arvo:47101"
    assert value["port"] == 22514
    assert value["known_hosts_base64"] == "cHVibGljIGhvc3Qga2V5Cg=="
    with pytest.raises(RuntimeError, match="connection"):
        read_practice_host_material(
            evidence_root=tmp_path, run_id="run-1", task_id="arvo:47101", port=22515
        )


def test_material_rejects_task_swap_and_linked_key(tmp_path):
    evidence = tmp_path / "run-1-arvo-47101"
    evidence.mkdir()
    outside = tmp_path / "outside"
    outside.write_bytes(b"host key")
    (evidence / "known_hosts").symlink_to(outside)
    connection = {
        "scope": "native_practice_level1",
        "run_id": "run-1",
        "task_id": "arvo:3938",
        "ssh_host_port": 22514,
        "known_hosts": str(evidence / "known_hosts"),
        "status": "awaiting_signed_practice_start_intent",
    }
    (evidence / "connection.json").write_bytes(canonical_json(connection))
    with pytest.raises(RuntimeError, match="connection"):
        read_practice_host_material(
            evidence_root=tmp_path, run_id="run-1", task_id="arvo:47101", port=22514
        )


def test_pinned_fetch_uses_only_sunchaser_alias_and_validates_task(tmp_path):
    ssh = tmp_path / "ssh.exe"
    ssh.write_bytes(b"ssh")
    config = tmp_path / "ssh-config"
    alias = "cybergym-tunnel-" + "a" * 24
    config.write_text(
        f"Host {alias}\n"
        "    HostName sunchaser-20260905.cinnamon-gamut.ts.net\n"
        "    HostKeyAlias sunchaser-20260905.cinnamon-gamut.ts.net.\n"
        '    ProxyCommand "C:/Program Files/Tailscale/tailscale.exe" nc %h %p\n'
        "    StrictHostKeyChecking yes\n"
        "    BatchMode yes\n"
    )
    hosts = tmp_path / "tailscale-known-hosts"
    hosts.write_bytes(b"pinned public key")
    material = b"[127.0.0.1]:22514 ssh-ed25519 AAAA\n"
    calls = []

    def invoke(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(
            stdout=canonical_json(
                {
                    "schema_version": 1,
                    "run_id": "practice-1",
                    "task_id": "arvo:47101",
                    "port": 22514,
                    "known_hosts_base64": base64.b64encode(material).decode(),
                }
            )
            + b"\n"
        )

    fetch = PinnedPracticeHostMaterial(
        ssh_exe=ssh,
        ssh_config=config,
        ssh_config_sha256=hashlib.sha256(config.read_bytes()).hexdigest(),
        tunnel_known_hosts=hosts,
        tunnel_known_hosts_sha256=hashlib.sha256(hosts.read_bytes()).hexdigest(),
        ssh_alias=alias,
        remote_argv=("python", "-m", "practice_host_material", "--run-id", "practice-1"),
        run_id="practice-1",
        run_command=invoke,
    )
    assert fetch("arvo:47101", 22514) == material
    assert calls[0][0][7] == alias
    assert "--task-id arvo:47101 --port 22514" in calls[0][0][-1]
    with pytest.raises(ValueError, match="current practice task"):
        fetch("oss-fuzz:1", 22514)
