# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Read-only Linux procfs correlation for a live gateway TCP connection.

This establishes which host PID holds an observed socket while the HTTP
request remains open. A matching PID alone is not native-hook certification:
callers must also verify the process executable, ancestry and frozen hook
source before admitting a preflight report.
"""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class NativeSocketProcess:
    host_pid: int
    parent_pid: int
    socket_inode: str


def tcp_socket_inode(table: str, source_ip: str, source_port: int) -> str:
    """Find exactly one established IPv4 socket in its network namespace."""
    if type(table) is not str or type(source_port) is not int or not 1 <= source_port <= 65535:
        raise ValueError("observed TCP socket input is invalid")
    try:
        address = ipaddress.IPv4Address(source_ip)
    except ipaddress.AddressValueError:
        raise ValueError("observed TCP source address is invalid") from None
    endpoint = f"{address.packed[::-1].hex().upper()}:{source_port:04X}"
    matches = []
    for line in table.splitlines()[1:]:
        fields = line.split()
        if len(fields) > 9 and fields[1].upper() == endpoint and fields[3] == "01":
            inode = fields[9]
            if re.fullmatch(r"[1-9][0-9]*", inode) is None:
                raise ValueError("observed TCP socket inode is invalid")
            matches.append(inode)
    if len(matches) != 1:
        raise ValueError("observed TCP socket is absent or ambiguous")
    return matches[0]


def _parent_pid(proc_root: Path, pid: int) -> int:
    try:
        status = (proc_root / str(pid) / "status").read_text(encoding="ascii")
    except (OSError, UnicodeError):
        raise ValueError("observed process status is unavailable") from None
    matches = re.findall(r"^PPid:\s*([0-9]+)\s*$", status, re.MULTILINE)
    if len(matches) != 1:
        raise ValueError("observed process parent is ambiguous")
    return int(matches[0])


def observe_socket_process(
    proc_root: Path, *, container_init_host_pid: int, source_ip: str, source_port: int
) -> NativeSocketProcess:
    """Map gateway source port to one descendant of the task container init."""
    proc_root = Path(proc_root)
    if (
        proc_root.is_symlink()
        or not proc_root.is_dir()
        or type(container_init_host_pid) is not int
        or container_init_host_pid <= 1
    ):
        raise ValueError("trusted procfs root and container init PID are required")
    try:
        table = (proc_root / str(container_init_host_pid) / "net" / "tcp").read_text(
            encoding="ascii"
        )
    except (OSError, UnicodeError):
        raise ValueError("container TCP table is unavailable") from None
    inode = tcp_socket_inode(table, source_ip, source_port)
    socket_link = f"socket:[{inode}]"
    holders = set()
    for process in proc_root.iterdir():
        if not process.name.isdecimal():
            continue
        try:
            for descriptor in (process / "fd").iterdir():
                try:
                    if os.readlink(descriptor) == socket_link:
                        holders.add(int(process.name))
                except OSError:
                    continue
        except OSError:
            continue
    if len(holders) != 1:
        raise ValueError("observed TCP socket process is absent or ambiguous")
    host_pid = holders.pop()
    if host_pid == container_init_host_pid:
        raise ValueError("native hook socket cannot belong to container init")
    parent_pid = _parent_pid(proc_root, host_pid)
    current = parent_pid
    seen = {host_pid}
    while current != container_init_host_pid:
        if current <= 1 or current in seen:
            raise ValueError("socket process is outside task container ancestry")
        seen.add(current)
        current = _parent_pid(proc_root, current)
    try:
        if not any(
            os.readlink(descriptor) == socket_link
            for descriptor in (proc_root / str(host_pid) / "fd").iterdir()
        ):
            raise ValueError("observed TCP socket closed during process verification")
    except OSError:
        raise ValueError("observed TCP socket closed during process verification") from None
    return NativeSocketProcess(host_pid, parent_pid, inode)
