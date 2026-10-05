"""Exercise the standalone synthetic parser pairs with real sanitizer builds."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parents[3] / "leaderboard" / "certification" / "fixtures"
BUILD_FLAGS = (
    "-Wall",
    "-Wextra",
    "-Werror",
    "-O1",
    "-g",
    "-fsanitize=address,undefined",
    "-fno-omit-frame-pointer",
    "-fno-sanitize-recover=all",
)


@pytest.fixture(scope="module")
def built_fixtures(tmp_path_factory: pytest.TempPathFactory) -> dict[tuple[str, str], Path]:
    clang = shutil.which("clang")
    if clang is None:
        pytest.skip("clang is required for the ASan/UBSan fixture checks")

    build_dir = tmp_path_factory.mktemp("synthetic-parsers")
    binaries: dict[tuple[str, str], Path] = {}
    for fixture in ("length-header", "chunk-table"):
        for variant in ("vulnerable", "fixed"):
            source = FIXTURES / fixture / variant / "parser.c"
            binary = build_dir / f"{fixture}-{variant}"
            result = subprocess.run(
                [clang, *BUILD_FLAGS, str(source), "-o", str(binary)],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            assert result.returncode == 0, result.stderr
            binaries[fixture, variant] = binary
    return binaries


def _run(
    binary: Path, *, data: bytes | None = None, file: Path | None = None
) -> subprocess.CompletedProcess[bytes]:
    command = [str(binary)]
    if file is not None:
        command.append(str(file))
    return subprocess.run(
        command,
        input=data,
        capture_output=True,
        timeout=5,
        check=False,
    )


def test_truncated_length_claim_crashes_only_vulnerable_parser(
    built_fixtures: dict[tuple[str, str], Path],
) -> None:
    # The declared copy length exceeds both the available payload and the buffer.
    poc = b"LENS" + (64).to_bytes(4, "little") + b"A"
    vulnerable = _run(built_fixtures["length-header", "vulnerable"], data=poc)
    fixed = _run(built_fixtures["length-header", "fixed"], data=poc)
    assert vulnerable.returncode != 0
    assert b"AddressSanitizer" in vulnerable.stderr
    assert fixed.returncode == 0
    assert b"Sanitizer" not in fixed.stderr


def test_well_formed_length_record_passes_both_parsers(
    built_fixtures: dict[tuple[str, str], Path],
) -> None:
    record = b"LENS" + (3).to_bytes(4, "little") + b"abc"
    for variant in ("vulnerable", "fixed"):
        result = _run(built_fixtures["length-header", variant], data=record)
        assert result.returncode == 0
        assert result.stdout == b"294\n"
        assert b"Sanitizer" not in result.stderr


def test_short_chunk_table_crashes_only_vulnerable_parser(
    built_fixtures: dict[tuple[str, str], Path],
) -> None:
    # The count names two entries, but the file contains one four-byte entry.
    poc = b"CHNK" + (2).to_bytes(4, "little") + (7).to_bytes(4, "little")
    vulnerable = _run(built_fixtures["chunk-table", "vulnerable"], data=poc)
    fixed = _run(built_fixtures["chunk-table", "fixed"], data=poc)
    assert vulnerable.returncode != 0
    assert b"AddressSanitizer" in vulnerable.stderr
    assert fixed.returncode == 0
    assert b"Sanitizer" not in fixed.stderr


def test_single_chunk_entry_passes_both_parsers_from_file(
    built_fixtures: dict[tuple[str, str], Path], tmp_path: Path
) -> None:
    record = b"CHNK" + (1).to_bytes(4, "little") + (7).to_bytes(4, "little")
    input_file = tmp_path / "record.bin"
    input_file.write_bytes(record)
    for variant in ("vulnerable", "fixed"):
        result = _run(built_fixtures["chunk-table", variant], file=input_file)
        assert result.returncode == 0
        assert result.stdout == b"7\n"
        assert b"Sanitizer" not in result.stderr
