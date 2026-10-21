# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Bounded observations of pinned local Python source; never material authority.

Parsing source does not execute or import it. Static imports and lexical lookup
signals are leads for a later, independently checked dependency graph, not an
exhaustive graph or immutable delivery proof. This module cannot release a
worker, authorize staging, or grant any other effect.
"""

from __future__ import annotations

import ast
import hashlib
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

MAX_SOURCE_FILES = 64
MAX_SOURCE_BYTES = 1_048_576
MAX_TOTAL_BYTES = 4_194_304
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SEGMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_WINDOWS_DEVICE_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{number}" for number in range(1, 10)}
    | {f"LPT{number}" for number in range(1, 10)}
)
_UNRESOLVED = (
    "recursive_import_graph_unproven",
    "dynamic_import_unproven",
    "native_library_lookup_unproven",
    "package_resource_lookup_unproven",
    "subprocess_and_path_lookup_unproven",
    "environment_lookup_unproven",
    "external_cybergym_graph_unproven",
    "immutable_bytes_through_use_unproven",
    "source_path_custody_unproven",
)


class MaterialInventoryError(ValueError):
    """A requested local source observation is malformed or cannot be pinned."""


@dataclass(frozen=True, slots=True)
class LocalPythonSource:
    relative_path: str
    sha256: str
    size_bytes: int
    static_imports: tuple[str, ...]
    signals: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class LocalSourceInventory:
    sources: tuple[LocalPythonSource, ...]

    @property
    def status(self) -> str:
        return "NON_AUTHORITATIVE"

    @property
    def unresolved(self) -> tuple[str, ...]:
        return _UNRESOLVED


def _relative_parts(name: str) -> tuple[str, ...]:
    if (
        type(name) is not str
        or not name
        or len(name) > 240
        or "\\" in name
        or ":" in name
        or "\x00" in name
        or not name.endswith(".py")
    ):
        raise MaterialInventoryError("canonical relative Python source path required")
    parts = tuple(name.split("/"))
    if len(parts) > 16 or any(part in {"", ".", ".."} for part in parts):
        raise MaterialInventoryError("canonical relative Python source path required")
    for index, part in enumerate(parts):
        stem = part[:-3] if index == len(parts) - 1 else part
        if _SEGMENT.fullmatch(stem) is None or stem.upper() in _WINDOWS_DEVICE_NAMES:
            raise MaterialInventoryError("canonical relative Python source path required")
    return parts


def _checked_path(root: Path, parts: tuple[str, ...]) -> Path:
    current = root
    for index, part in enumerate(parts):
        current = current / part
        try:
            info = current.lstat()
        except OSError as error:
            raise MaterialInventoryError("source path unavailable") from error
        if stat.S_ISLNK(info.st_mode) or current.is_junction():
            raise MaterialInventoryError("source path links are not accepted")
        if index < len(parts) - 1 and not stat.S_ISDIR(info.st_mode):
            raise MaterialInventoryError("source parent must be a directory")
        if index == len(parts) - 1 and not stat.S_ISREG(info.st_mode):
            raise MaterialInventoryError("source must be a regular file")
    return current


def _read_source(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_SOURCE_BYTES:
                raise MaterialInventoryError("source is not a bounded regular file")
            data = stream.read(MAX_SOURCE_BYTES + 1)
            after = os.fstat(stream.fileno())
    except OSError as error:
        raise MaterialInventoryError("source read failed") from error
    if (
        len(data) > MAX_SOURCE_BYTES
        or len(data) != before.st_size
        or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    ):
        raise MaterialInventoryError("source size or identity changed during read")
    return data


def _name(node: ast.expr, aliases: Mapping[str, str]) -> str:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        base = _name(node.value, aliases)
        return f"{base}.{node.attr}" if base else ""
    return ""


def _static_imports_and_signals(
    source: bytes, name: str
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    try:
        tree = ast.parse(source, filename=name)
    except (SyntaxError, ValueError, RecursionError, MemoryError) as error:
        raise MaterialInventoryError("source cannot be parsed as Python") from error
    imports: set[str] = set()
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(f"import {alias.name}")
                if alias.asname:
                    aliases[alias.asname] = alias.name
                else:
                    root_name = alias.name.split(".")[0]
                    aliases[root_name] = root_name
        elif isinstance(node, ast.ImportFrom):
            module = "." * node.level + (node.module or "")
            imports.add(f"from {module} import {', '.join(alias.name for alias in node.names)}")
            if node.level == 0:
                for alias in node.names:
                    aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    signals: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            called = _name(node.func, aliases)
            if called in {
                "__import__",
                "eval",
                "exec",
                "importlib.import_module",
                "importlib.util.spec_from_file_location",
                "importlib.util.module_from_spec",
            }:
                signals.add("dynamic_import")
            if called.startswith(("ctypes.", "cffi.")) or called.endswith(".dlopen"):
                signals.add("native_library_lookup")
            if called.startswith(("importlib.resources.", "pkg_resources.", "pkgutil.get_data")):
                signals.add("package_resource_lookup")
            if (
                called.startswith("subprocess.")
                or called
                in {
                    "os.system",
                    "os.popen",
                    "os.posix_spawn",
                    "os.posix_spawnp",
                }
                or called.startswith(("os.exec", "os.spawn"))
            ):
                signals.add("subprocess_command")
            if called in {"shutil.which", "os.get_exec_path", "os.execvp", "os.execvpe"}:
                signals.add("path_lookup")
            if called in {"os.getenv", "os.getenvb", "os.environ.get", "os.environb.get"}:
                signals.add("environment_lookup")
        if isinstance(node, (ast.Name, ast.Attribute)):
            lexical = _name(node, aliases)
            if lexical in {"os.environ", "os.environb", "__file__"}:
                signals.add(
                    "environment_lookup" if lexical != "__file__" else "package_resource_lookup"
                )
        if isinstance(node, ast.Subscript) and _name(node.value, aliases) in {
            "os.environ",
            "os.environb",
        }:
            signals.add("environment_lookup")
            if isinstance(node.slice, ast.Constant) and node.slice.value in {"PATH", b"PATH"}:
                signals.add("path_lookup")
    return tuple(sorted(imports)), tuple(sorted(signals))


def inventory_local_python_sources(
    root: Path, expected_sha256_by_path: Mapping[str, str]
) -> LocalSourceInventory:
    """Read explicitly pinned source bytes, without importing or executing them.

    The caller's pin provenance and path custody are not authenticated here.
    Runtime dependencies and post-read mutation remain unresolved even on a
    successful observation.
    """
    if (
        not isinstance(root, Path)
        or not root.is_absolute()
        or not isinstance(expected_sha256_by_path, Mapping)
        or not 1 <= len(expected_sha256_by_path) <= MAX_SOURCE_FILES
    ):
        raise MaterialInventoryError("absolute root and bounded source pins required")
    try:
        root_info = root.lstat()
    except OSError as error:
        raise MaterialInventoryError("source root unavailable") from error
    if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode) or root.is_junction():
        raise MaterialInventoryError("source root must be a real directory")
    if any(type(name) is not str for name in expected_sha256_by_path):
        raise MaterialInventoryError("canonical relative Python source path required")
    observed: list[LocalPythonSource] = []
    total_bytes = 0
    for name, expected in sorted(expected_sha256_by_path.items()):
        if type(expected) is not str or _SHA256.fullmatch(expected) is None:
            raise MaterialInventoryError("canonical expected SHA-256 required")
        path = _checked_path(root, _relative_parts(name))
        source = _read_source(path)
        total_bytes += len(source)
        if total_bytes > MAX_TOTAL_BYTES:
            raise MaterialInventoryError("aggregate source byte limit exceeded")
        digest = hashlib.sha256(source).hexdigest()
        if digest != expected:
            raise MaterialInventoryError("source bytes differ from caller pin")
        imports, signals = _static_imports_and_signals(source, name)
        observed.append(LocalPythonSource(name, digest, len(source), imports, signals))
    return LocalSourceInventory(tuple(observed))
