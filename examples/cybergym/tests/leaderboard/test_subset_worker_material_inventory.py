# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Local source observations only; no worker import, staging or release."""

import hashlib
from importlib import import_module, util

import pytest


def _api():
    name = "nooa_cybergym.leaderboard.subset_worker_material_inventory"
    assert util.find_spec(name) is not None, "local source inventory is missing"
    return import_module(name)


def _pinned(path, contents):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(contents)
    return hashlib.sha256(contents).hexdigest()


def test_reads_pinned_bytes_and_static_imports_without_executing_source(tmp_path):
    api = _api()
    source = (
        b"import os as operating_system\n"
        b"from .helper import item\n"
        b"from .. import sibling\n"
        b"raise AssertionError('source was executed')\n"
    )
    digest = _pinned(tmp_path / "pkg" / "worker.py", source)

    result = api.inventory_local_python_sources(tmp_path, {"pkg/worker.py": digest})

    assert result.status == "NON_AUTHORITATIVE"
    assert len(result.sources) == 1
    observed = result.sources[0]
    assert (observed.relative_path, observed.sha256, observed.size_bytes) == (
        "pkg/worker.py",
        digest,
        len(source),
    )
    assert observed.static_imports == (
        "from .. import sibling",
        "from .helper import item",
        "import os",
    )
    assert "immutable_bytes_through_use_unproven" in result.unresolved
    assert "recursive_import_graph_unproven" in result.unresolved
    assert "external_cybergym_graph_unproven" in result.unresolved
    assert not hasattr(result, "release_allowed")


def test_detects_lexical_dynamic_and_external_lookup_signals(tmp_path):
    api = _api()
    source = (
        b"import importlib, ctypes, subprocess, os, shutil\n"
        b"from importlib import resources\n"
        b"__import__('plugin')\n"
        b"importlib.import_module('plugin')\n"
        b"ctypes.CDLL('libdemo.so')\n"
        b"resources.files('pkg').joinpath('data.txt')\n"
        b"subprocess.run(['tool'])\n"
        b"shutil.which('tool')\n"
        b"os.environ['PATH']\n"
    )
    digest = _pinned(tmp_path / "worker.py", source)

    observed = api.inventory_local_python_sources(tmp_path, {"worker.py": digest}).sources[0]

    assert observed.signals == (
        "dynamic_import",
        "environment_lookup",
        "native_library_lookup",
        "package_resource_lookup",
        "path_lookup",
        "subprocess_command",
    )


def test_dotted_import_without_alias_keeps_python_root_binding(tmp_path):
    api = _api()
    source = (
        b"import os.path\n"
        b"import importlib.resources\n"
        b"import importlib.util\n"
        b"os.environ['PATH']\n"
        b"importlib.resources.files('pkg')\n"
        b"importlib.util.spec_from_file_location('plugin', '/tmp/plugin.py')\n"
    )
    digest = _pinned(tmp_path / "worker.py", source)

    observed = api.inventory_local_python_sources(tmp_path, {"worker.py": digest}).sources[0]

    assert observed.signals == (
        "dynamic_import",
        "environment_lookup",
        "package_resource_lookup",
        "path_lookup",
    )


def test_unknown_runtime_categories_stay_unresolved_even_when_no_call_is_seen(tmp_path):
    api = _api()
    digest = _pinned(tmp_path / "worker.py", b"VALUE = 1\n")

    result = api.inventory_local_python_sources(tmp_path, {"worker.py": digest})

    assert result.sources[0].signals == ()
    assert {
        "dynamic_import_unproven",
        "native_library_lookup_unproven",
        "package_resource_lookup_unproven",
        "subprocess_and_path_lookup_unproven",
        "environment_lookup_unproven",
        "external_cybergym_graph_unproven",
    }.issubset(set(result.unresolved))


def test_rejects_changed_bytes_and_invalid_python(tmp_path):
    api = _api()
    path = tmp_path / "worker.py"
    digest = _pinned(path, b"VALUE = 1\n")
    path.write_bytes(b"VALUE = 2\n")
    with pytest.raises(api.MaterialInventoryError):
        api.inventory_local_python_sources(tmp_path, {"worker.py": digest})

    digest = _pinned(path, b"def broken(:\n")
    with pytest.raises(api.MaterialInventoryError):
        api.inventory_local_python_sources(tmp_path, {"worker.py": digest})


def test_rejects_non_string_pin_path_before_sorting(tmp_path):
    api = _api()
    with pytest.raises(api.MaterialInventoryError):
        api.inventory_local_python_sources(tmp_path, {1: "a" * 64, "worker.py": "a" * 64})


@pytest.mark.parametrize("name", ["../outside.py", "/absolute.py", "a\\b.py", "./a.py"])
def test_rejects_noncanonical_or_escaping_path(tmp_path, name):
    api = _api()
    with pytest.raises(api.MaterialInventoryError):
        api.inventory_local_python_sources(tmp_path, {name: "a" * 64})


@pytest.mark.parametrize(
    "name",
    [
        ".. /outside.py",
        "pkg./worker.py",
        "pkg /worker.py",
        "worker .py",
        "CON.py",
        "aux/worker.py",
        "LPT9.py",
    ],
)
def test_rejects_windows_noncanonical_segments_before_lookup(tmp_path, name):
    api = _api()
    root = tmp_path / "root"
    root.mkdir()
    source = b"VALUE = 1\n"
    digest = _pinned(tmp_path / "outside.py", source)
    _pinned(root / "pkg" / "worker.py", source)

    with pytest.raises(api.MaterialInventoryError, match="canonical relative Python source path"):
        api.inventory_local_python_sources(root, {name: digest})


def test_rejects_file_symlink(tmp_path):
    api = _api()
    target = tmp_path / "target.py"
    digest = _pinned(target, b"VALUE = 1\n")
    link = tmp_path / "link.py"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation unavailable")

    with pytest.raises(api.MaterialInventoryError):
        api.inventory_local_python_sources(tmp_path, {"link.py": digest})


def test_rejects_intermediate_directory_symlink(tmp_path):
    api = _api()
    digest = _pinned(tmp_path / "real" / "worker.py", b"VALUE = 1\n")
    link = tmp_path / "linked"
    try:
        link.symlink_to(tmp_path / "real", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlink creation unavailable")

    with pytest.raises(api.MaterialInventoryError):
        api.inventory_local_python_sources(tmp_path, {"linked/worker.py": digest})


def test_caller_cannot_construct_completion_or_remove_unresolved_caveats():
    api = _api()
    with pytest.raises(TypeError):
        api.LocalSourceInventory((), status="COMPLETE")
    with pytest.raises(TypeError):
        api.LocalSourceInventory((), unresolved=())


def test_rejects_file_count_and_byte_bounds(tmp_path):
    api = _api()
    too_many = {}
    for i in range(api.MAX_SOURCE_FILES + 1):
        name = f"source_{i}.py"
        too_many[name] = _pinned(tmp_path / name, b"X = 1\n")
    with pytest.raises(api.MaterialInventoryError):
        api.inventory_local_python_sources(tmp_path, too_many)

    large = b"#" * (api.MAX_SOURCE_BYTES + 1)
    digest = _pinned(tmp_path / "large.py", large)
    with pytest.raises(api.MaterialInventoryError):
        api.inventory_local_python_sources(tmp_path, {"large.py": digest})

    content = b"#" * api.MAX_SOURCE_BYTES
    pins = {
        f"total_{i}.py": _pinned(tmp_path / f"total_{i}.py", content)
        for i in range(api.MAX_TOTAL_BYTES // api.MAX_SOURCE_BYTES + 1)
    }
    with pytest.raises(api.MaterialInventoryError):
        api.inventory_local_python_sources(tmp_path, pins)
