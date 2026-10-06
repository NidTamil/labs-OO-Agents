# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Prepare a new Docker context using only the already-downloaded frozen artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def copy_build_source(source: Path, target: Path) -> None:
    if source.suffix == ".sh":
        target.write_bytes(source.read_bytes().replace(b"\r\n", b"\n"))
        if b"\r" in target.read_bytes():
            raise ValueError("native shell build input contains a bare carriage return")
    else:
        shutil.copyfile(source, target)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vendor-dir", type=Path, required=True)
    parser.add_argument("--launcher-vsix", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    inputs = {
        "vscode-server-linux-x64.tar.gz": (
            args.vendor_dir / "vscode-server-linux-x64.tar.gz",
            "1f65ee7af2ede2152b4f1bedf781ea28233438173eb9831a0f3f721c5d7dd6ac",
        ),
        "claude-code-linux-x64.vsix": (
            args.vendor_dir / "claude-code-linux-x64.vsix",
            "4d52576e7fe83a01b908e04ea8742192d432e79e2c1ee17f10d423eaf68e21ce",
        ),
        "sunchaser-cybergym-launcher.vsix": (args.launcher_vsix, None),
    }
    hashes = {}
    for name, (source, expected) in inputs.items():
        if source.is_symlink() or not source.is_file():
            raise ValueError("native build input is not a regular file")
        hashes[name] = digest(source)
        if expected is not None and hashes[name] != expected:
            raise ValueError("native build vendor digest mismatch")
    if (
        not args.output_dir.is_absolute()
        or args.output_dir.parent.resolve() != args.output_dir.parent
    ):
        raise ValueError("native build output requires an absolute canonical parent")
    args.output_dir.mkdir(mode=0o700)
    source_root = Path(__file__).resolve().parent
    for name in (
        "Dockerfile.native",
        "install-native.py",
        "native-entrypoint.sh",
        "native-home.py",
        "native-mcp.json",
    ):
        copy_build_source(source_root / name, args.output_dir / name)
    shutil.copytree(source_root / "native-agents", args.output_dir / "native-agents")
    for name, (source, _) in inputs.items():
        shutil.copyfile(source, args.output_dir / name)
    (args.output_dir / "artifact-hashes.json").write_text(
        json.dumps(hashes, sort_keys=True), encoding="utf8"
    )
    print(
        json.dumps(
            {
                "context": str(args.output_dir),
                "launcher_sha256": hashes["sunchaser-cybergym-launcher.vsix"],
            }
        )
    )


if __name__ == "__main__":
    main()
