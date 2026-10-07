# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Correlate a native hook's gateway socket with its Linux process."""

from __future__ import annotations

import importlib
import importlib.util
import os
from pathlib import Path

import pytest


def _subject():
    name = "nooa_cybergym.leaderboard.native_process"
    assert importlib.util.find_spec(name) is not None, "native process observer is missing"
    return importlib.import_module(name)


def _tcp_row(port: int, inode: int, *, state: str = "01") -> str:
    return (
        f"   0: 02001EAC:{port:04X} 01001EAC:0050 {state} "
        f"00000000:00000000 00:00000000 00000000 1001 0 {inode} 1"
    )


def test_linux_tcp_lookup_requires_one_established_socket_inode():
    subject = _subject()
    table = (
        "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
    )
    table += _tcp_row(42424, 555) + "\n"
    table += _tcp_row(42425, 556, state="0A") + "\n"
    assert subject.tcp_socket_inode(table, "172.30.0.2", 42424) == "555"
    with pytest.raises(ValueError, match="socket"):
        subject.tcp_socket_inode(table, "172.30.0.2", 42425)
    with pytest.raises(ValueError, match="socket"):
        subject.tcp_socket_inode(table + _tcp_row(42424, 557) + "\n", "172.30.0.2", 42424)


@pytest.mark.skipif(os.name != "posix", reason="Linux procfs symlinks required")
def test_process_observer_binds_socket_to_one_container_descendant(tmp_path: Path):
    subject = _subject()
    (tmp_path / "100/net").mkdir(parents=True)
    (tmp_path / "100/net/tcp").write_text(
        "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
        + _tcp_row(42424, 555)
        + "\n"
    )
    for pid, ppid in ((100, 1), (150, 100), (200, 150), (300, 1)):
        folder = tmp_path / str(pid)
        folder.mkdir(exist_ok=True)
        (folder / "status").write_text(f"Name:\tnode\nPid:\t{pid}\nPPid:\t{ppid}\n")
    (tmp_path / "200/fd").mkdir()
    (tmp_path / "200/fd/4").symlink_to("socket:[555]")
    observed = subject.observe_socket_process(
        tmp_path, container_init_host_pid=100, source_ip="172.30.0.2", source_port=42424
    )
    assert observed.host_pid == 200
    assert observed.parent_pid == 150
    assert observed.socket_inode == "555"

    (tmp_path / "300/fd").mkdir()
    (tmp_path / "300/fd/5").symlink_to("socket:[555]")
    with pytest.raises(ValueError, match="socket"):
        subject.observe_socket_process(
            tmp_path, container_init_host_pid=100, source_ip="172.30.0.2", source_port=42424
        )
    (tmp_path / "300/fd/5").unlink()
    (tmp_path / "200/status").write_text("Name:\tnode\nPid:\t200\nPPid:\t300\n")
    with pytest.raises(ValueError, match="ancestry"):
        subject.observe_socket_process(
            tmp_path, container_init_host_pid=100, source_ip="172.30.0.2", source_port=42424
        )
