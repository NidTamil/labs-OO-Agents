# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Disposable Docker/SSH proof; no benchmark task or model is contacted."""

from __future__ import annotations

import io
import json
import shutil
import subprocess
import tarfile
import time
import uuid
from pathlib import Path

import pytest
from nooa_cybergym.leaderboard.container import start_task_container

pytestmark = pytest.mark.docker
IMAGE_CONTEXT = Path(__file__).resolve().parents[2] / "leaderboard" / "agent-image"


def _docker_client():
    docker = pytest.importorskip("docker")
    try:
        client = docker.from_env()
        client.ping()
    except Exception:
        pytest.skip("disposable Docker daemon is unavailable")
    return client


def _ssh(private_key: Path, known_hosts: Path, port: int, user: str, command: str):
    return subprocess.run(
        [
            "ssh",
            "-F",
            "none",
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={known_hosts}",
            "-o",
            "ConnectTimeout=2",
            "-i",
            str(private_key),
            "-p",
            str(port),
            f"{user}@127.0.0.1",
            command,
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )


def _wait_for_ssh(private_key: Path, known_hosts: Path, port: int):
    deadline = time.monotonic() + 15
    while True:
        result = _ssh(private_key, known_hosts, port, "agent", "id -u")
        if result.returncode == 0:
            return result
        if time.monotonic() >= deadline:
            pytest.fail(f"task SSH never accepted its authorized key: {result.stderr}")
        time.sleep(0.25)


def _make_bundle(workspace: Path) -> None:
    workspace.mkdir()
    (workspace / "src").mkdir()
    (workspace / "output").mkdir()
    (workspace / "description.txt").write_text("synthetic task\n")
    (workspace / "README.md").write_text("synthetic fixture\n")
    (workspace / "submit.sh").write_text("#!/bin/sh\nexit 0\n")
    with tarfile.open(workspace / "repo-vul.tar.gz", "w:gz") as archive:
        for name, content in (
            ("repo/.git/config", b"must disappear\n"),
            ("repo/hello.c", b"int main(void) { return 0; }\n"),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(content))


def test_disposable_network_without_scoped_firewall_sentinel_is_blocked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _docker_client()
    network = client.networks.create(
        f"cybergym-disposable-{uuid.uuid4().hex[:12]}",
        driver="bridge",
        internal=True,
        labels={"org.xeus.cybergym.boundary": "task-v1"},
    )
    workspace = tmp_path / "workspace"
    _make_bundle(workspace)

    def unexpected_run(**_kwargs: object) -> None:
        pytest.fail("container was started without host-gateway boundary evidence")

    try:
        monkeypatch.setattr(client.containers, "run", unexpected_run)
        with pytest.raises(RuntimeError, match="host gateway boundary attestation required"):
            start_task_container(
                workspace,
                tmp_path / "evidence",
                network.name,
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockFixtureKey fixture",
                expected_network_id=network.id,
                image="synthetic-unbuilt:image",
                docker_client=client,
            )
    finally:
        network.remove()


@pytest.mark.skip(reason="requires live scoped firewall sentinel and gateway probes")
def test_task_image_ssh_identity_is_nonroot_and_mounts_are_disposable(tmp_path: Path) -> None:
    if shutil.which("ssh") is None or shutil.which("ssh-keygen") is None:
        pytest.skip("OpenSSH client tools are unavailable")
    client = _docker_client()
    tag = f"cybergym-agent-test:{uuid.uuid4().hex[:12]}"
    image, _logs = client.images.build(path=str(IMAGE_CONTEXT), tag=tag, rm=True)
    network = None
    workspace = tmp_path / "workspace"
    _make_bundle(workspace)
    private_key = tmp_path / "id_ed25519"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(private_key)],
        check=True,
        capture_output=True,
    )
    ssh_public_key = private_key.with_suffix(".pub").read_text().strip()
    created = []
    first_host_key: str | None = None
    try:
        network = client.networks.create(
            f"cybergym-disposable-{uuid.uuid4().hex[:12]}",
            driver="bridge",
            internal=True,
            labels={"org.xeus.cybergym.boundary": "task-v1"},
        )
        for index in range(2):
            evidence = tmp_path / f"evidence-{index}"
            task = start_task_container(
                workspace,
                evidence,
                network.name,
                ssh_public_key,
                expected_network_id=network.id,
                image=tag,
                docker_client=client,
            )
            container = client.containers.get(task.container_id)
            created.append(container)
            known_hosts = evidence / "known_hosts"
            login = _wait_for_ssh(private_key, known_hosts, task.host_ssh_port)
            assert int(login.stdout.strip()) > 0

            details = container.attrs["HostConfig"]
            assert details["Privileged"] is False
            assert details["ReadonlyRootfs"] is True
            assert details["NetworkMode"] == network.name
            assert details["PidMode"] in ("", None)
            assert details["CapDrop"] == ["ALL"]
            assert set(details["CapAdd"]) == {
                "CHOWN",
                "SETUID",
                "SETGID",
                "DAC_OVERRIDE",
                "SYS_CHROOT",
            }
            assert not details.get("PortBindings")
            assert container.attrs["NetworkSettings"]["Ports"].get("2222/tcp") is None
            assert all("docker.sock" not in bind for bind in details["Binds"])

            probe = _ssh(
                private_key,
                known_hosts,
                task.host_ssh_port,
                "agent",
                "id -un; node -e 'console.log(process.getuid())'; "
                "awk '/^CapEff:/ {print $2}' /proc/self/status; "
                "test ! -e /var/run/docker.sock && test ! -e /srv && test ! -e /root && "
                "test ! -e /tmp/poc && test ! -e /workspace/src/repo/.git && "
                "test -f /workspace/src/repo/hello.c && "
                "test ! -r /run/ssh/ssh_host_ed25519_key && "
                "! command -v sudo && ! command -v docker && "
                "command -v git && command -v clang && command -v clangd && command -v gdb && command -v python3 && "
                "test ! -w /workspace/description.txt",
            )
            assert probe.returncode == 0, probe.stderr
            lines = probe.stdout.splitlines()
            assert lines[0] == "agent"
            assert int(lines[1]) == int(login.stdout.strip())
            assert lines[2] == "0000000000000000"

            root_login = _ssh(private_key, known_hosts, task.host_ssh_port, "root", "id -u")
            assert root_login.returncode != 0
            public_evidence = json.loads((evidence / "ssh-host-key.json").read_text())
            assert public_evidence["public_key"].startswith("ssh-ed25519 ")
            assert public_evidence["fingerprint"].startswith("SHA256:")

            if index == 1:
                assert first_host_key is not None
                assert public_evidence["public_key"] != first_host_key
                fresh = _ssh(
                    private_key,
                    known_hosts,
                    task.host_ssh_port,
                    "agent",
                    "test ! -e /workspace/src/repo/transient && test ! -e /home/agent/transient",
                )
                assert fresh.returncode == 0, fresh.stderr
            else:
                first_host_key = public_evidence["public_key"]
                write = _ssh(
                    private_key,
                    known_hosts,
                    task.host_ssh_port,
                    "agent",
                    "touch /workspace/src/repo/transient && touch /home/agent/transient "
                    "&& touch /workspace/output/poc.bin",
                )
                assert write.returncode == 0, write.stderr
            task.close_relay()
            container.remove(force=True)
            created.pop()
    finally:
        for container in created:
            container.remove(force=True)
        if network is not None:
            network.remove()
        image.remove(force=True)
