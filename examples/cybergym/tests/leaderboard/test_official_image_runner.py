# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Scored official image execution selects only the pinned task-family recipe."""

from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from nooa_cybergym.leaderboard.official_image_runner import run_official_image

IMAGE = "sha256:" + "a" * 64
SHA = hashlib.sha256(b"candidate").hexdigest()


class FakeContainer:
    def __init__(self, log_path: Path, exit_code=1):
        self.exit_code = exit_code
        self.started = False
        self.removed = False
        log_path.touch()
        self.attrs = {"LogPath": str(log_path)}

    def reload(self):
        pass

    def start(self):
        self.started = True

    def wait(self, timeout):
        assert timeout == 60
        return {"StatusCode": self.exit_code}

    def logs(self, **kwargs):
        assert kwargs == {"stdout": True, "stderr": False, "stream": True, "follow": False}
        return iter((b"crash",))

    def remove(self, force):
        assert force is True
        self.removed = True


@pytest.mark.parametrize(
    ("task_id", "command"),
    [
        ("arvo:47101", "timeout -s SIGKILL 10 /bin/arvo 2>&1"),
        ("oss-fuzz:42535201", "timeout -s SIGKILL 10 /usr/local/bin/run_poc 2>&1"),
    ],
)
def test_scored_runner_uses_official_family_command_and_isolation(tmp_path, task_id, command):
    output = tmp_path / "output"
    output.mkdir()
    candidate = output / "poc"
    candidate.write_bytes(b"candidate")
    private = tmp_path / "private"
    private.mkdir()
    private.chmod(0o700)
    container = FakeContainer(tmp_path / "docker.json.log")
    calls = []

    def create(**kwargs):
        calls.append(kwargs)
        return container

    client = SimpleNamespace(
        images=SimpleNamespace(get=lambda _: SimpleNamespace(id=IMAGE)),
        containers=SimpleNamespace(create=create),
    )
    result = run_official_image(
        client,
        task_id=task_id,
        image_id=IMAGE,
        candidate=candidate,
        snapshot_dir=private,
        expected_sha256=SHA,
    )
    assert container.started and container.removed
    assert calls[0]["command"] == ["/bin/bash", "-c", command]
    assert calls[0]["network_mode"] == "none"
    assert calls[0]["image"] == IMAGE
    assert calls[0]["log_config"] == {
        "Type": "json-file",
        "Config": {"max-size": "10m", "max-file": "2"},
    }
    mounted = list(calls[0]["volumes"])
    assert len(mounted) == 1 and mounted[0] != str(candidate)
    assert mounted[0].startswith(str(private))
    assert calls[0]["volumes"][mounted[0]] == {"bind": "/tmp/poc", "mode": "ro"}
    assert result["task_id"] == task_id
    assert result["raw_exit_code"] == 1
    assert result["snapshot_sha256"] == SHA


def test_scored_runner_rejects_unrecognized_family_before_docker(tmp_path):
    candidate = tmp_path / "poc"
    candidate.write_bytes(b"candidate")
    with pytest.raises(ValueError, match="official task family"):
        run_official_image(
            None,
            task_id="oss-fuzz-latest:42535201",
            image_id=IMAGE,
            candidate=candidate,
            snapshot_dir=tmp_path,
            expected_sha256=SHA,
        )


def test_scored_runner_maps_timeout_and_rejects_candidate_drift(tmp_path):
    output = tmp_path / "output"
    output.mkdir()
    candidate = output / "poc"
    candidate.write_bytes(b"candidate")
    private = tmp_path / "private"
    private.mkdir()
    private.chmod(0o700)
    container = FakeContainer(tmp_path / "docker.json.log", exit_code=137)
    client = SimpleNamespace(
        images=SimpleNamespace(get=lambda _: SimpleNamespace(id=IMAGE)),
        containers=SimpleNamespace(create=lambda **_: container),
    )
    result = run_official_image(
        client,
        task_id="oss-fuzz:42535201",
        image_id=IMAGE,
        candidate=candidate,
        snapshot_dir=private,
        expected_sha256=SHA,
    )
    assert result["raw_exit_code"] == 300
    assert container.removed
    with pytest.raises(RuntimeError, match="candidate changed"):
        run_official_image(
            client,
            task_id="oss-fuzz:42535201",
            image_id=IMAGE,
            candidate=candidate,
            snapshot_dir=private,
            expected_sha256="b" * 64,
        )


def test_scored_runner_refuses_rotated_docker_output(tmp_path):
    output = tmp_path / "output"
    output.mkdir()
    candidate = output / "poc"
    candidate.write_bytes(b"candidate")
    private = tmp_path / "private"
    private.mkdir()
    private.chmod(0o700)
    log_path = tmp_path / "docker.json.log"
    container = FakeContainer(log_path)
    Path(str(log_path) + ".1").touch()
    client = SimpleNamespace(
        images=SimpleNamespace(get=lambda _: SimpleNamespace(id=IMAGE)),
        containers=SimpleNamespace(create=lambda **_: container),
    )

    with pytest.raises(RuntimeError, match="rotated"):
        run_official_image(
            client,
            task_id="arvo:47101",
            image_id=IMAGE,
            candidate=candidate,
            snapshot_dir=private,
            expected_sha256=SHA,
        )
    assert container.removed
