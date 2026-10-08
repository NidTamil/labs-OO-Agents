# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Read-only Linux procfs correlation for a live gateway TCP connection.

This establishes which host PID holds an observed socket while the HTTP
request remains open. A matching PID alone is not native-hook certification:
callers must also verify the process executable, ancestry and frozen hook
source before admitting a preflight report.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class NativeSocketProcess:
    host_pid: int
    parent_pid: int
    socket_inode: str


_NODE_PATH = "/usr/local/bin/node"
_HOOK_PATH = (
    "/opt/sunchaser/vscode-extensions/xeus.sunchaser-cybergym-launcher-0.1.0/native-hook.js"
)
_PARENT_NODE_PATH = "/opt/sunchaser/vscode-server/node"
_LAUNCHER_PATH = (
    "/opt/sunchaser/vscode-extensions/xeus.sunchaser-cybergym-launcher-0.1.0/extension.js"
)
_EXTENSION_HOST_COMMAND = (
    _PARENT_NODE_PATH,
    "--dns-result-order=ipv4first",
    "/opt/sunchaser/vscode-server/out/bootstrap-fork",
    "--type=extensionHost",
    "--transformURIs",
    "--useHostProxy=false",
)
FROZEN_NATIVE_IMAGE_ID = "sha256:80db89a5dfc81a55308d801063bffd413999d56de339d7735ba7a43c113fbf4b"
FROZEN_HOOK_SHA256 = "79599794a427a44a89ca09f19e6daec5917a5c4c55daeb9c731a2a830140d8c1"
FROZEN_NODE_SHA256 = "fde6a4bf8d0562f7751d1a2d6cb9b417c4cfe107bbcb0aa3e9a24e125e348f48"
FROZEN_PARENT_NODE_SHA256 = "e7bb5f506b21993b0192ae9086aaa2fb99593b35ece1512e83364d2feb5172a5"
FROZEN_LAUNCHER_SHA256 = "c05a1466ad0739b0931002d366d919b64e1a50868036781328e5b7892e0c6043"


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


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_native_hook_process(
    proc_root: Path,
    *,
    container_init_host_pid: int,
    process: NativeSocketProcess,
    expected_hook_sha256: str,
    expected_node_sha256: str,
) -> None:
    """Fail closed unless the socket holder is the frozen hook in this container."""
    proc_root = Path(proc_root)
    if (
        proc_root.is_symlink()
        or not proc_root.is_dir()
        or type(container_init_host_pid) is not int
        or container_init_host_pid <= 1
        or type(process) is not NativeSocketProcess
        or any(
            re.fullmatch(r"[a-f0-9]{64}", value) is None
            for value in (expected_hook_sha256, expected_node_sha256)
        )
    ):
        raise ValueError("trusted native process inputs required")
    folder = proc_root / str(process.host_pid)
    init = proc_root / str(container_init_host_pid)
    try:
        if _parent_pid(proc_root, process.host_pid) != process.parent_pid:
            raise ValueError("native hook ancestry changed")
        status = (folder / "status").read_text(encoding="ascii")
        uid = re.findall(
            r"^Uid:\s*([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s*$",
            status,
            re.MULTILINE,
        )
        if uid != [("1001",) * 4]:
            raise ValueError("native hook user differs from task agent")
        for name in ("pid", "mnt", "net"):
            if os.readlink(folder / "ns" / name) != os.readlink(init / "ns" / name):
                raise ValueError("native hook namespace differs from task container")
        if (folder / "cmdline").read_bytes() != (_NODE_PATH + "\0" + _HOOK_PATH + "\0").encode():
            raise ValueError("native hook command differs from frozen managed settings")
        executable = folder / "exe"
        if os.readlink(executable) != _NODE_PATH:
            raise ValueError("native hook executable differs from frozen Node")
        hook = folder / "root" / _HOOK_PATH.lstrip("/")
        metadata = hook.stat()
        if (
            hook.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_mode & 0o022
        ):
            raise ValueError("native hook source is not root-owned immutable image content")
        if (
            _sha256_file(hook) != expected_hook_sha256
            or _sha256_file(executable) != expected_node_sha256
        ):
            raise ValueError("native hook or Node digest differs from frozen image")
        socket_link = f"socket:[{process.socket_inode}]"
        if not any(os.readlink(fd) == socket_link for fd in (folder / "fd").iterdir()):
            raise ValueError("native hook socket closed during verification")
        if _parent_pid(proc_root, process.host_pid) != process.parent_pid:
            raise ValueError("native hook ancestry changed")
    except (OSError, UnicodeError):
        raise ValueError("native hook process identity unavailable") from None


def verify_native_parent_process(
    proc_root: Path,
    *,
    container_init_host_pid: int,
    process: NativeSocketProcess,
    receipt_observed: dict,
    expected_launcher_sha256: str,
    expected_node_sha256: str,
) -> None:
    """Bind a gateway socket to the extension host that reserved the launch."""
    proc_root = Path(proc_root)
    if (
        proc_root.is_symlink()
        or not proc_root.is_dir()
        or type(container_init_host_pid) is not int
        or container_init_host_pid <= 1
        or type(process) is not NativeSocketProcess
        or type(receipt_observed) is not dict
        or any(
            type(receipt_observed.get(key)) is not int or receipt_observed[key] <= 1
            for key in ("pid", "ppid")
        )
        or any(
            re.fullmatch(r"[a-f0-9]{64}", value) is None
            for value in (expected_launcher_sha256, expected_node_sha256)
        )
    ):
        raise ValueError("trusted native parent process inputs required")
    folder = proc_root / str(process.host_pid)
    parent = proc_root / str(process.parent_pid)
    init = proc_root / str(container_init_host_pid)
    try:
        if _parent_pid(proc_root, process.host_pid) != process.parent_pid:
            raise ValueError("native parent ancestry changed")
        status = (folder / "status").read_text(encoding="ascii")
        uid = re.findall(
            r"^Uid:\s*([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s*$",
            status,
            re.MULTILINE,
        )
        if uid != [("1001",) * 4]:
            raise ValueError("native parent user differs from task agent")
        for name in ("pid", "mnt", "net"):
            if os.readlink(folder / "ns" / name) != os.readlink(init / "ns" / name):
                raise ValueError("native parent namespace differs from task container")

        def nested_pid(path: Path) -> int:
            matches = re.findall(
                r"^NSpid:\s*([0-9]+(?:\s+[0-9]+)*)\s*$",
                path.read_text(encoding="ascii"),
                re.MULTILINE,
            )
            if len(matches) != 1:
                raise ValueError("native parent nested PID unavailable")
            return int(matches[0].split()[-1])

        if (
            nested_pid(folder / "status") != receipt_observed["pid"]
            or nested_pid(parent / "status") != receipt_observed["ppid"]
        ):
            raise ValueError("native parent PID differs from launch receipt")
        if (folder / "cmdline").read_bytes() != (
            "\0".join(_EXTENSION_HOST_COMMAND) + "\0"
        ).encode():
            raise ValueError("native parent command is not the frozen extension host")
        executable = folder / "exe"
        if os.readlink(executable) != _PARENT_NODE_PATH:
            raise ValueError("native parent executable differs from frozen VS Code Node")
        launcher = folder / "root" / _LAUNCHER_PATH.lstrip("/")
        metadata = launcher.stat()
        if (
            launcher.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_mode & 0o022
        ):
            raise ValueError("native launcher source is not root-owned immutable image content")
        if (
            _sha256_file(launcher) != expected_launcher_sha256
            or _sha256_file(executable) != expected_node_sha256
        ):
            raise ValueError("native launcher or Node digest differs from frozen image")
        socket_link = f"socket:[{process.socket_inode}]"
        if not any(os.readlink(fd) == socket_link for fd in (folder / "fd").iterdir()):
            raise ValueError("native parent socket closed during verification")
        if _parent_pid(proc_root, process.host_pid) != process.parent_pid:
            raise ValueError("native parent ancestry changed")
    except (OSError, UnicodeError):
        raise ValueError("native parent process identity unavailable") from None


class NativeHookRequestVerifier:
    """Bind a hook gateway request to a verified task-container process."""

    def __init__(
        self,
        *,
        peer,
        container_init_host_pid: int,
        expected_hook_sha256: str,
        expected_node_sha256: str,
        audit,
        proc_root: Path = Path("/proc"),
    ):
        from .host_boundary_runtime import AdmittedPeer

        if (
            type(peer) is not AdmittedPeer
            or type(container_init_host_pid) is not int
            or container_init_host_pid <= 1
            or any(
                re.fullmatch(r"[a-f0-9]{64}", value) is None
                for value in (expected_hook_sha256, expected_node_sha256)
            )
            or not callable(getattr(audit, "record", None))
            or Path(proc_root).is_symlink()
            or not Path(proc_root).is_dir()
        ):
            raise ValueError("trusted native hook verifier configuration required")
        self.peer = peer
        self.container_init_host_pid = container_init_host_pid
        self.expected_hook_sha256 = expected_hook_sha256
        self.expected_node_sha256 = expected_node_sha256
        self.audit = audit
        self.proc_root = Path(proc_root)

    def __call__(self, request):
        from .host_boundary_runtime import GatewayRequest

        if type(request) is not GatewayRequest or request.peer != self.peer:
            raise ValueError("native hook peer differs from task container")
        if type(request.source_port) is not int or not 1 <= request.source_port <= 65535:
            raise ValueError("native hook source port is unavailable")
        process = observe_socket_process(
            self.proc_root,
            container_init_host_pid=self.container_init_host_pid,
            source_ip=request.peer.source_ip,
            source_port=request.source_port,
        )
        verify_native_hook_process(
            self.proc_root,
            container_init_host_pid=self.container_init_host_pid,
            process=process,
            expected_hook_sha256=self.expected_hook_sha256,
            expected_node_sha256=self.expected_node_sha256,
        )
        self.audit.record(
            {
                "event": "native_hook_process_verified",
                "container_id": request.peer.container_id,
                "source_ip": request.peer.source_ip,
                "source_port": request.source_port,
                "host_pid": process.host_pid,
                "parent_pid": process.parent_pid,
                "socket_inode": process.socket_inode,
                "hook_sha256": self.expected_hook_sha256,
                "node_sha256": self.expected_node_sha256,
            }
        )
        return process


class NativeParentRequestVerifier:
    """Require the reserved launch's extension-host PID on this TCP request."""

    def __init__(
        self,
        *,
        peer,
        container_init_host_pid: int,
        launch_authority,
        expected_launcher_sha256: str,
        expected_node_sha256: str,
        audit,
        proc_root: Path = Path("/proc"),
    ):
        from .host_boundary_runtime import AdmittedPeer
        from .native_launcher import NativeLaunchAuthority

        if (
            type(peer) is not AdmittedPeer
            or type(launch_authority) is not NativeLaunchAuthority
            or type(container_init_host_pid) is not int
            or container_init_host_pid <= 1
            or any(
                re.fullmatch(r"[a-f0-9]{64}", value) is None
                for value in (expected_launcher_sha256, expected_node_sha256)
            )
            or not callable(getattr(audit, "record", None))
            or Path(proc_root).is_symlink()
            or not Path(proc_root).is_dir()
        ):
            raise ValueError("trusted native parent verifier configuration required")
        self.peer, self.container_init_host_pid = peer, container_init_host_pid
        self.launch_authority = launch_authority
        self.expected_launcher_sha256 = expected_launcher_sha256
        self.expected_node_sha256 = expected_node_sha256
        self.audit, self.proc_root = audit, Path(proc_root)

    def __call__(self, request):
        from .host_boundary_runtime import GatewayRequest
        from .native_launcher import _canonical

        if type(request) is not GatewayRequest or request.peer != self.peer:
            raise ValueError("native parent peer differs from task container")
        if type(request.source_port) is not int or not 1 <= request.source_port <= 65535:
            raise ValueError("native parent source port is unavailable")
        receipt_path = self.launch_authority.launch_dir / "launcher-receipt.json"
        if receipt_path.is_symlink() or not receipt_path.is_file():
            raise ValueError("native parent launch receipt unavailable")
        try:
            raw = receipt_path.read_bytes()
            receipt = json.loads(raw)
            self.launch_authority._check_receipt(receipt)
            if _canonical(receipt) != raw:
                raise ValueError("native parent launch receipt changed")
        except (OSError, UnicodeError, json.JSONDecodeError):
            raise ValueError("native parent launch receipt unavailable") from None
        process = observe_socket_process(
            self.proc_root,
            container_init_host_pid=self.container_init_host_pid,
            source_ip=request.peer.source_ip,
            source_port=request.source_port,
        )
        verify_native_parent_process(
            self.proc_root,
            container_init_host_pid=self.container_init_host_pid,
            process=process,
            receipt_observed=receipt["observed"],
            expected_launcher_sha256=self.expected_launcher_sha256,
            expected_node_sha256=self.expected_node_sha256,
        )
        if (
            self.audit.record(
                {
                    "event": "native_parent_process_verified",
                    "container_id": request.peer.container_id,
                    "source_ip": request.peer.source_ip,
                    "source_port": request.source_port,
                    "host_pid": process.host_pid,
                    "parent_pid": process.parent_pid,
                    "socket_inode": process.socket_inode,
                    "launcher_sha256": self.expected_launcher_sha256,
                    "node_sha256": self.expected_node_sha256,
                }
            )
            is not True
        ):
            raise ValueError("native parent process audit unavailable")
        return process


def frozen_parent_verifier(
    *, inspect: dict, peer, launch_authority, audit, proc_root: Path = Path("/proc")
):
    """Construct the parent verifier only for the pinned running image."""
    from .host_boundary_runtime import AdmittedPeer
    from .native_launcher import NativeLaunchAuthority

    if (
        type(inspect) is not dict
        or type(peer) is not AdmittedPeer
        or type(launch_authority) is not NativeLaunchAuthority
        or launch_authority.manifest.get("container_id") != peer.container_id
        or inspect.get("Id") != peer.container_id
        or inspect.get("Image") != FROZEN_NATIVE_IMAGE_ID
        or type(inspect.get("State")) is not dict
        or inspect["State"].get("Running") is not True
        or type(inspect["State"].get("Pid")) is not int
        or inspect["State"]["Pid"] <= 1
    ):
        raise ValueError("running pinned image and signed parent launch required")
    return NativeParentRequestVerifier(
        peer=peer,
        container_init_host_pid=inspect["State"]["Pid"],
        launch_authority=launch_authority,
        expected_launcher_sha256=FROZEN_LAUNCHER_SHA256,
        expected_node_sha256=FROZEN_PARENT_NODE_SHA256,
        audit=audit,
        proc_root=proc_root,
    )


def frozen_hook_verifier(*, inspect: dict, peer, audit, proc_root: Path = Path("/proc")):
    """Build a verifier only for the inspected, running pinned native image."""
    from .host_boundary_runtime import AdmittedPeer

    if (
        type(inspect) is not dict
        or type(peer) is not AdmittedPeer
        or inspect.get("Id") != peer.container_id
        or inspect.get("Image") != FROZEN_NATIVE_IMAGE_ID
        or type(inspect.get("State")) is not dict
        or inspect["State"].get("Running") is not True
        or type(inspect["State"].get("Pid")) is not int
        or inspect["State"]["Pid"] <= 1
    ):
        raise ValueError("running pinned image and daemon container identity required")
    return NativeHookRequestVerifier(
        peer=peer,
        container_init_host_pid=inspect["State"]["Pid"],
        expected_hook_sha256=FROZEN_HOOK_SHA256,
        expected_node_sha256=FROZEN_NODE_SHA256,
        audit=audit,
        proc_root=proc_root,
    )
