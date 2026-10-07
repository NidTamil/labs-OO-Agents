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


@pytest.mark.skipif(os.name != "posix", reason="Linux procfs symlinks required")
def test_native_hook_identity_requires_frozen_executable_and_container_namespaces(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    import hashlib

    subject = _subject()
    proc = tmp_path / "proc"
    container = tmp_path / "container"
    hook = (
        container
        / "opt/sunchaser/vscode-extensions/xeus.sunchaser-cybergym-launcher-0.1.0/native-hook.js"
    )
    hook.parent.mkdir(parents=True)
    hook.write_bytes(b"frozen native hook")
    node = container / "usr/local/bin/node"
    node.parent.mkdir(parents=True)
    node.write_bytes(b"frozen node")
    for pid, ppid in ((100, 1), (150, 100), (200, 150)):
        folder = proc / str(pid)
        (folder / "ns").mkdir(parents=True)
        (folder / "status").write_text(
            f"Name:\tnode\nPid:\t{pid}\nPPid:\t{ppid}\nUid:\t1001\t1001\t1001\t1001\n"
        )
        (folder / "root").symlink_to(container)
        for name in ("pid", "mnt", "net"):
            (folder / "ns" / name).symlink_to(f"{name}:[1234]")
    (proc / "200/exe").symlink_to(node)
    original_readlink = subject.os.readlink
    monkeypatch.setattr(
        subject.os,
        "readlink",
        lambda path: (
            "/usr/local/bin/node" if Path(path) == proc / "200/exe" else original_readlink(path)
        ),
    )
    (proc / "200/cmdline").write_bytes(
        b"/usr/local/bin/node\0"
        b"/opt/sunchaser/vscode-extensions/xeus.sunchaser-cybergym-launcher-0.1.0/native-hook.js\0"
    )
    (proc / "200/fd").mkdir()
    (proc / "200/fd/4").symlink_to("socket:[555]")
    observed = subject.NativeSocketProcess(200, 150, "555")
    kwargs = {
        "container_init_host_pid": 100,
        "process": observed,
        "expected_hook_sha256": hashlib.sha256(hook.read_bytes()).hexdigest(),
        "expected_node_sha256": hashlib.sha256(node.read_bytes()).hexdigest(),
    }
    assert subject.verify_native_hook_process(proc, **kwargs) is None

    (proc / "200/cmdline").write_bytes(b"/usr/local/bin/node\0/tmp/fake-hook.js\0")
    with pytest.raises(ValueError, match="command"):
        subject.verify_native_hook_process(proc, **kwargs)
    (proc / "200/cmdline").write_bytes(
        b"/usr/local/bin/node\0"
        b"/opt/sunchaser/vscode-extensions/xeus.sunchaser-cybergym-launcher-0.1.0/native-hook.js\0"
    )
    (proc / "200/ns/net").unlink()
    (proc / "200/ns/net").symlink_to("net:[9999]")
    with pytest.raises(ValueError, match="namespace"):
        subject.verify_native_hook_process(proc, **kwargs)
    (proc / "200/ns/net").unlink()
    (proc / "200/ns/net").symlink_to("net:[1234]")
    (proc / "200/status").write_text("Name:\tnode\nPid:\t200\nPPid:\t150\nUid:\t0\t0\t0\t0\n")
    with pytest.raises(ValueError, match="user"):
        subject.verify_native_hook_process(proc, **kwargs)
    (proc / "200/status").write_text(
        "Name:\tnode\nPid:\t200\nPPid:\t150\nUid:\t1001\t1001\t1001\t1001\n"
    )
    node.write_bytes(b"changed executable")
    with pytest.raises(ValueError, match="digest"):
        subject.verify_native_hook_process(proc, **kwargs)
    node.write_bytes(b"frozen node")
    (proc / "200/fd/4").unlink()
    with pytest.raises(ValueError, match="socket"):
        subject.verify_native_hook_process(proc, **kwargs)
    (proc / "200/fd/4").symlink_to("socket:[555]")
    hook.write_bytes(b"mutated hook")
    with pytest.raises(ValueError, match="digest"):
        subject.verify_native_hook_process(proc, **kwargs)
