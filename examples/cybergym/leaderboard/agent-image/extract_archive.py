# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Extract a task's source archive into its disposable tmpfs, without escapes.

This uses only Python's standard library so the pinned Debian image does not
depend on a newer tarfile.data_filter implementation. SSH starts only after
this command has completed successfully.
"""

from __future__ import annotations

import os
import shutil
import sys
import tarfile
from pathlib import Path


def _parts(name: str) -> tuple[str, ...]:
    if not name or name.startswith("/") or "\\" in name or "\x00" in name:
        raise ValueError("archive path is outside source root")
    parts = tuple(part for part in name.split("/") if part not in ("", "."))
    if not parts or ".." in parts:
        raise ValueError("archive path is outside source root")
    return parts


def _link_parts(base: tuple[str, ...], target: str) -> tuple[str, ...]:
    if not target or target.startswith("/") or "\\" in target or "\x00" in target:
        raise ValueError("archive link is outside source root")
    parts = list(base)
    for part in target.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if not parts:
                raise ValueError("archive link is outside source root")
            parts.pop()
        else:
            parts.append(part)
    if not parts:
        raise ValueError("archive link is outside source root")
    return tuple(parts)


def extract_archive(archive: Path, destination: Path) -> None:
    if destination.is_symlink() or not destination.is_dir() or any(destination.iterdir()):
        raise ValueError("source destination must be a fresh directory")
    with tarfile.open(archive, "r:gz") as source:
        members = source.getmembers()
        paths: dict[tuple[str, ...], tarfile.TarInfo] = {}
        links: dict[tuple[str, ...], tuple[str, ...]] = {}
        for member in members:
            if member.isdir() and member.name in {".", "./"}:
                continue
            parts = _parts(member.name)
            if not (member.isdir() or member.isfile() or member.issym() or member.islnk()):
                raise ValueError("special archive member is forbidden")
            if parts in paths and not (paths[parts].isdir() and member.isdir()):
                raise ValueError("duplicate archive member is forbidden")
            paths[parts] = member
            if member.issym():
                links[parts] = _link_parts(parts[:-1], member.linkname)
            elif member.islnk():
                links[parts] = _link_parts((), member.linkname)

        for parts, member in paths.items():
            for depth in range(1, len(parts)):
                ancestor = paths.get(parts[:depth])
                if ancestor is not None and not ancestor.isdir():
                    raise ValueError("archive member descends through a non-directory")
            if member.islnk():
                target_member = paths.get(links[parts])
                if target_member is None or not target_member.isfile():
                    raise ValueError("archive hardlink target is not a regular file")

        for parts, member in sorted(paths.items(), key=lambda item: len(item[0])):
            if member.isdir():
                path = destination.joinpath(*parts)
                path.mkdir(parents=True, exist_ok=True)
                path.chmod(0o755)

        for parts, member in paths.items():
            if not member.isfile():
                continue
            path = destination.joinpath(*parts)
            path.parent.mkdir(parents=True, exist_ok=True)
            stream = source.extractfile(member)
            if stream is None:
                raise ValueError("archive regular file has no content stream")
            with stream, path.open("xb") as target:
                shutil.copyfileobj(stream, target, length=1024 * 1024)
            if path.stat().st_size != member.size:
                raise ValueError("archive regular file length changed")
            path.chmod(0o755 if member.mode & 0o111 else 0o644)

        for parts, member in paths.items():
            if not member.islnk():
                continue
            path = destination.joinpath(*parts)
            path.parent.mkdir(parents=True, exist_ok=True)
            os.link(destination.joinpath(*links[parts]), path)

        for parts, member in paths.items():
            if not member.issym():
                continue
            path = destination.joinpath(*parts)
            path.parent.mkdir(parents=True, exist_ok=True)
            os.symlink(member.linkname, path)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: extract_archive.py ARCHIVE DESTINATION")
    extract_archive(Path(sys.argv[1]), Path(sys.argv[2]))
