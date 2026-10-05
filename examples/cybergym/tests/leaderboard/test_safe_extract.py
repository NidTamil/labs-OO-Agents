"""The image's archive extractor runs against real tar inputs without Docker."""

from __future__ import annotations

import io
import os
import subprocess
import sys
import tarfile
from pathlib import Path

EXTRACTOR = (
    Path(__file__).resolve().parents[2] / "leaderboard" / "agent-image" / "extract_archive.py"
)


def _archive(path: Path, entries: list[tuple[str, bytes | str, str]]) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name, value, kind in entries:
            info = tarfile.TarInfo(name)
            if kind == "file":
                assert isinstance(value, bytes)
                info.size = len(value)
                info.mode = 0o755 if name.endswith(".sh") else 0o644
                archive.addfile(info, io.BytesIO(value))
            elif kind == "symlink":
                assert isinstance(value, str)
                info.type = tarfile.SYMTYPE
                info.linkname = value
                archive.addfile(info)
            elif kind == "device":
                info.type = tarfile.CHRTYPE
                archive.addfile(info)
            elif kind == "dir":
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            else:
                raise AssertionError(kind)


def _extract(archive: Path, destination: Path) -> subprocess.CompletedProcess[str]:
    destination.mkdir()
    return subprocess.run(
        [sys.executable, str(EXTRACTOR), str(archive), str(destination)],
        capture_output=True,
        text=True,
    )


def test_safe_extract_keeps_executable_source_and_internal_symlink(tmp_path: Path) -> None:
    archive = tmp_path / "source.tar.gz"
    _archive(
        archive,
        [
            ("repo/build.sh", b"#!/bin/sh\nexit 0\n", "file"),
            ("repo/src/file.c", b"int main(void) { return 0; }\n", "file"),
            ("repo/current.c", "src/file.c", "symlink"),
        ],
    )
    root = tmp_path / "src"
    result = _extract(archive, root)
    assert result.returncode == 0, result.stderr
    assert (root / "repo" / "src" / "file.c").read_bytes() == b"int main(void) { return 0; }\n"
    if os.name != "nt":
        assert (root / "repo" / "build.sh").stat().st_mode & 0o111
        assert (root / "repo" / "current.c").read_bytes() == b"int main(void) { return 0; }\n"


def test_safe_extract_rejects_parent_traversal_without_touching_outside(tmp_path: Path) -> None:
    archive = tmp_path / "source.tar.gz"
    _archive(archive, [("../outside.txt", b"wrong", "file")])
    result = _extract(archive, tmp_path / "src")
    assert result.returncode != 0
    assert not (tmp_path / "outside.txt").exists()


def test_safe_extract_accepts_root_dot_directory_entry(tmp_path: Path) -> None:
    archive = tmp_path / "source.tar.gz"
    _archive(archive, [("./", "", "dir"), ("./repo/file.c", b"int x;\n", "file")])
    root = tmp_path / "src"
    result = _extract(archive, root)
    assert result.returncode == 0, result.stderr
    assert (root / "repo" / "file.c").read_bytes() == b"int x;\n"


def test_safe_extract_rejects_symlink_ancestor_and_special_file(tmp_path: Path) -> None:
    archive = tmp_path / "source.tar.gz"
    _archive(
        archive,
        [
            ("repo/link", "src", "symlink"),
            ("repo/link/child.c", b"int x;", "file"),
        ],
    )
    result = _extract(archive, tmp_path / "src")
    assert result.returncode != 0
    assert not (tmp_path / "src" / "repo" / "link" / "child.c").exists()

    unsafe = tmp_path / "device.tar.gz"
    _archive(unsafe, [("repo/fake-device", "", "device")])
    result = _extract(unsafe, tmp_path / "src2")
    assert result.returncode != 0
    assert not (tmp_path / "src2" / "repo" / "fake-device").exists()
