# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""A pinned raw inventory is byte custody, never a readiness gate."""

from __future__ import annotations

import hashlib
import json
import time
from copy import deepcopy
from types import SimpleNamespace

import nooa_cybergym.leaderboard.subset_readiness_inventory as inventory_module
import pytest
from nooa_cybergym.leaderboard.raw_pair_manifest import build_raw_pair_manifest
from nooa_cybergym.leaderboard.subset_readiness_inventory import (
    load_subset_readiness_inventory as _load_inventory,
)

_FIXTURES = ("synthetic:length-header", "synthetic:chunk-table")
_CONTROLS = (
    "primary_takeover",
    "interruption_reconnection",
    "timeout_failure",
    "version_drift",
    "memory_write_denial",
)


def load_subset_readiness_inventory(*args, deadline_monotonic=None, **kwargs):
    """Give synthetic tests an operation deadline without relaxing production API."""
    if deadline_monotonic is None:
        deadline_monotonic = time.monotonic() + 60
    return _load_inventory(*args, deadline_monotonic=deadline_monotonic, **kwargs)


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _bundle(tmp_path):
    repetitions = []
    manifests = {}
    paths = {}
    for run_id in ("repeat-one", "repeat-two"):
        run_root = tmp_path / run_id
        run_root.mkdir()
        fixtures = {}
        for index, fixture in enumerate(_FIXTURES):
            root = run_root / f"fixture-{index}"
            root.mkdir()
            (root / "result.json").write_bytes(_json({"run_id": f"{run_id}-{index}"}))
            fixtures[fixture] = root
            paths[(run_id, fixture)] = root
        manifest = _json(build_raw_pair_manifest(run_id, fixtures))
        manifests[run_id] = manifest
        note = _json({"run_id": run_id})
        (run_root / "note.json").write_bytes(note)
        files = [
            {
                "path": f"fixture-{index}/result.json",
                "bytes": len((fixtures[fixture] / "result.json").read_bytes()),
                "sha256": _sha((fixtures[fixture] / "result.json").read_bytes()),
            }
            for index, fixture in enumerate(_FIXTURES)
        ]
        files.append({"path": "note.json", "bytes": len(note), "sha256": _sha(note)})
        repetitions.append(
            {
                "run_id": run_id,
                "root": str(run_root),
                "pair_manifest_sha256": _sha(manifest),
                "fixtures": {fixture: str(fixtures[fixture]) for fixture in _FIXTURES},
                "files": files,
            }
        )
    controls = []
    for kind in _CONTROLS:
        root = tmp_path / f"control-{kind}"
        root.mkdir()
        data = _json({"control_id": kind})
        (root / "control.json").write_bytes(data)
        paths[kind] = root
        controls.append(
            {
                "kind": kind,
                "control_id": f"control-{kind}",
                "root": str(root),
                "files": [{"path": "control.json", "bytes": len(data), "sha256": _sha(data)}],
            }
        )
    descriptor = {
        "schema_version": 1,
        "scope": "subset_raw_readiness_inventory",
        "repetitions": repetitions,
        "controls": controls,
    }
    raw = _json(descriptor)
    return raw, _sha(raw), manifests, paths


def test_pinned_inventory_keeps_custody_facts_without_gate_claims(tmp_path):
    raw, pin, manifests, paths = _bundle(tmp_path)

    inventory = load_subset_readiness_inventory(raw, expected_sha256=pin, pair_manifests=manifests)

    assert inventory.descriptor_sha256 == pin
    assert inventory.repetition_ids == ("repeat-one", "repeat-two")
    assert inventory.control_kinds == _CONTROLS
    assert inventory.repetition_root("repeat-one") == paths[("repeat-one", _FIXTURES[0])].parent
    assert inventory.fixture_root("repeat-one", _FIXTURES[0]) == paths[("repeat-one", _FIXTURES[0])]
    assert inventory.control_root("version_drift") == paths["version_drift"]
    inventory.recheck()
    assert not hasattr(inventory, "verified")
    assert not hasattr(inventory, "gates")


def test_inventory_does_not_resolve_unlisted_evidence_root(tmp_path):
    raw, pin, manifests, _ = _bundle(tmp_path)
    inventory = load_subset_readiness_inventory(raw, expected_sha256=pin, pair_manifests=manifests)
    with pytest.raises(ValueError, match="not inventoried"):
        inventory.fixture_root("repeat-three", _FIXTURES[0])
    with pytest.raises(ValueError, match="not inventoried"):
        inventory.repetition_root("repeat-three")
    with pytest.raises(ValueError, match="not inventoried"):
        inventory.control_root("undeclared_control")


def test_pinned_inventory_exposes_only_typed_control_id(tmp_path):
    raw, pin, manifests, _ = _bundle(tmp_path)
    inventory = load_subset_readiness_inventory(raw, expected_sha256=pin, pair_manifests=manifests)

    assert inventory.control_id("timeout_failure") == "control-timeout_failure"
    with pytest.raises(ValueError, match="not inventoried"):
        inventory.control_id("undeclared_control")


def test_descriptor_requires_independent_pin_and_canonical_bytes(tmp_path):
    raw, pin, manifests, _ = _bundle(tmp_path)
    with pytest.raises(ValueError):
        load_subset_readiness_inventory(raw, expected_sha256="0" * 64, pair_manifests=manifests)

    noncanonical = json.dumps(json.loads(raw), indent=2).encode()
    with pytest.raises(ValueError, match="canonical"):
        load_subset_readiness_inventory(
            noncanonical, expected_sha256=_sha(noncanonical), pair_manifests=manifests
        )


def test_pair_manifest_bytes_must_match_descriptor_pin(tmp_path):
    raw, pin, manifests, _ = _bundle(tmp_path)
    manifests["repeat-one"] += b" "
    with pytest.raises(ValueError, match="manifest"):
        load_subset_readiness_inventory(raw, expected_sha256=pin, pair_manifests=manifests)


def test_repetitions_must_have_distinct_ids_and_nonoverlapping_roots(tmp_path):
    raw, _, manifests, _ = _bundle(tmp_path)
    descriptor = json.loads(raw)
    descriptor["repetitions"][1] = deepcopy(descriptor["repetitions"][0])
    duplicate = _json(descriptor)
    with pytest.raises(ValueError, match="repetition"):
        load_subset_readiness_inventory(
            duplicate, expected_sha256=_sha(duplicate), pair_manifests=manifests
        )

    descriptor = json.loads(raw)
    descriptor["repetitions"][1]["root"] = descriptor["repetitions"][0]["root"]
    overlapping = _json(descriptor)
    with pytest.raises(ValueError, match="repetition"):
        load_subset_readiness_inventory(
            overlapping, expected_sha256=_sha(overlapping), pair_manifests=manifests
        )


def test_exact_typed_controls_are_required(tmp_path):
    raw, _, manifests, _ = _bundle(tmp_path)
    descriptor = json.loads(raw)
    descriptor["controls"].pop()
    incomplete = _json(descriptor)
    with pytest.raises(ValueError, match="control"):
        load_subset_readiness_inventory(
            incomplete, expected_sha256=_sha(incomplete), pair_manifests=manifests
        )

    descriptor = json.loads(raw)
    descriptor["controls"][1]["kind"] = descriptor["controls"][0]["kind"]
    duplicated = _json(descriptor)
    with pytest.raises(ValueError, match="control"):
        load_subset_readiness_inventory(
            duplicated, expected_sha256=_sha(duplicated), pair_manifests=manifests
        )


def test_control_cannot_reuse_a_fixture_root(tmp_path):
    raw, _, manifests, paths = _bundle(tmp_path)
    descriptor = json.loads(raw)
    fixture = paths[("repeat-one", _FIXTURES[0])]
    data = (fixture / "result.json").read_bytes()
    descriptor["controls"][0]["root"] = str(fixture)
    descriptor["controls"][0]["files"] = [
        {"path": "result.json", "bytes": len(data), "sha256": _sha(data)}
    ]
    overlapping = _json(descriptor)
    with pytest.raises(ValueError, match="overlap"):
        load_subset_readiness_inventory(
            overlapping, expected_sha256=_sha(overlapping), pair_manifests=manifests
        )


def test_control_symlink_is_rejected_even_when_target_bytes_match(tmp_path):
    raw, _, manifests, paths = _bundle(tmp_path)
    root = paths[_CONTROLS[0]]
    try:
        (root / "linked.json").symlink_to(root / "control.json")
    except OSError:
        pytest.skip("platform does not allow synthetic symlink creation")
    descriptor = json.loads(raw)
    data = (root / "control.json").read_bytes()
    descriptor["controls"][0]["files"].append(
        {"path": "linked.json", "bytes": len(data), "sha256": _sha(data)}
    )
    linked = _json(descriptor)
    with pytest.raises(ValueError, match="linked"):
        load_subset_readiness_inventory(
            linked, expected_sha256=_sha(linked), pair_manifests=manifests
        )


def test_recheck_rejects_changed_or_new_control_file(tmp_path):
    raw, pin, manifests, paths = _bundle(tmp_path)
    inventory = load_subset_readiness_inventory(raw, expected_sha256=pin, pair_manifests=manifests)
    root = paths[_CONTROLS[0]]
    (root / "control.json").write_bytes(b"changed")
    with pytest.raises(ValueError, match="changed"):
        inventory.recheck()

    original = _json({"control_id": _CONTROLS[0]})
    (root / "control.json").write_bytes(original)
    (root / "new.json").write_bytes(b"{}")
    with pytest.raises(ValueError, match="changed"):
        inventory.recheck()


def test_interpretation_bracket_rechecks_after_reader_mutation(tmp_path):
    raw, pin, manifests, paths = _bundle(tmp_path)
    inventory = load_subset_readiness_inventory(raw, expected_sha256=pin, pair_manifests=manifests)

    with pytest.raises(ValueError, match="changed"):
        with inventory.observed_bytes():
            fixture = paths[("repeat-two", _FIXTURES[1])]
            (fixture / "result.json").write_bytes(b"{}")


def test_recheck_rejects_deleted_control_file(tmp_path):
    raw, pin, manifests, paths = _bundle(tmp_path)
    inventory = load_subset_readiness_inventory(raw, expected_sha256=pin, pair_manifests=manifests)
    (paths[_CONTROLS[4]] / "control.json").unlink()
    with pytest.raises(ValueError, match="changed"):
        inventory.recheck()


def test_control_inventory_rejects_noncanonical_relative_file_path(tmp_path):
    raw, _, manifests, _ = _bundle(tmp_path)
    descriptor = json.loads(raw)
    descriptor["controls"][0]["files"][0]["path"] = "../control.json"
    malformed = _json(descriptor)
    with pytest.raises(ValueError, match="control file"):
        load_subset_readiness_inventory(
            malformed, expected_sha256=_sha(malformed), pair_manifests=manifests
        )


def test_file_size_bound_is_checked_before_reading(tmp_path, monkeypatch):
    raw, pin, manifests, _ = _bundle(tmp_path)
    monkeypatch.setattr(inventory_module, "_MAX_FILE_BYTES", 1)
    with pytest.raises(ValueError, match="file inventory"):
        load_subset_readiness_inventory(raw, expected_sha256=pin, pair_manifests=manifests)


def test_empty_control_directories_still_consume_an_entry_bound(tmp_path, monkeypatch):
    raw, pin, manifests, paths = _bundle(tmp_path)
    control = paths[_CONTROLS[0]]
    (control / "empty-a").mkdir()
    (control / "empty-b").mkdir()
    monkeypatch.setattr(inventory_module, "_MAX_ENTRIES", 2, raising=False)
    with pytest.raises(ValueError, match="entry bound"):
        load_subset_readiness_inventory(raw, expected_sha256=pin, pair_manifests=manifests)


def test_repetition_root_files_outside_fixture_pair_are_not_ignored(tmp_path):
    raw, pin, manifests, _ = _bundle(tmp_path)
    inventory = load_subset_readiness_inventory(raw, expected_sha256=pin, pair_manifests=manifests)
    (tmp_path / "repeat-one" / "note.json").write_bytes(b'{"run_id":"changed"}')
    with pytest.raises(ValueError, match="repetition bytes changed"):
        inventory.recheck()


def test_bounded_repetition_scan_trips_on_entry_limit(tmp_path, monkeypatch):
    raw, pin, manifests, _ = _bundle(tmp_path)
    inventory = load_subset_readiness_inventory(raw, expected_sha256=pin, pair_manifests=manifests)

    monkeypatch.setattr(inventory_module, "_MAX_REPETITION_ENTRIES", 1)
    with pytest.raises(ValueError, match="entry bound"):
        load_subset_readiness_inventory(raw, expected_sha256=pin, pair_manifests=manifests)
    with pytest.raises(ValueError, match="entry bound"):
        inventory.recheck()


def test_pair_manifest_projection_rejects_mismatch_without_rescanning(tmp_path):
    raw, _, manifests, _ = _bundle(tmp_path)
    descriptor = json.loads(raw)
    pair = json.loads(manifests["repeat-one"])
    pair["files"][_FIXTURES[0]][0]["sha256"] = "0" * 64
    manifests["repeat-one"] = _json(pair)
    descriptor["repetitions"][0]["pair_manifest_sha256"] = _sha(manifests["repeat-one"])
    pinned = _json(descriptor)

    with pytest.raises(ValueError, match="pair manifest bytes changed"):
        load_subset_readiness_inventory(
            pinned, expected_sha256=_sha(pinned), pair_manifests=manifests
        )


def test_pair_projection_matches_legacy_path_ordering(tmp_path):
    raw, _, manifests, paths = _bundle(tmp_path)
    fixture_root = paths[("repeat-one", _FIXTURES[0])]
    for name in ("B.json", "a.json"):
        (fixture_root / name).write_bytes(name.encode())
    roots = {fixture: paths[("repeat-one", fixture)] for fixture in _FIXTURES}
    manifests["repeat-one"] = _json(build_raw_pair_manifest("repeat-one", roots))
    descriptor = json.loads(raw)
    repetition = descriptor["repetitions"][0]
    repetition["pair_manifest_sha256"] = _sha(manifests["repeat-one"])
    for name in ("B.json", "a.json"):
        repetition["files"].append(
            {
                "path": f"fixture-0/{name}",
                "bytes": len(name),
                "sha256": _sha(name.encode()),
            }
        )
    repetition["files"].sort(key=lambda row: row["path"])
    pinned = _json(descriptor)

    load_subset_readiness_inventory(pinned, expected_sha256=_sha(pinned), pair_manifests=manifests)


def test_repetition_scan_stops_at_pinned_aggregate_bytes(tmp_path):
    raw, pin, manifests, _ = _bundle(tmp_path)
    (tmp_path / "repeat-one" / "rogue.bin").write_bytes(b"x" * 1024)

    with pytest.raises(ValueError, match="pinned byte total"):
        load_subset_readiness_inventory(raw, expected_sha256=pin, pair_manifests=manifests)


def test_repetition_scan_fails_closed_on_unreadable_extra_directory(tmp_path, monkeypatch):
    raw, pin, manifests, _ = _bundle(tmp_path)
    blocked = tmp_path / "repeat-one" / "blocked"
    blocked.mkdir()
    original = inventory_module.os.scandir

    def denied(path):
        if str(path) == str(blocked):
            raise PermissionError("synthetic unreadable directory")
        return original(path)

    monkeypatch.setattr(inventory_module.os, "scandir", denied)
    with pytest.raises(ValueError, match="scan failed"):
        load_subset_readiness_inventory(raw, expected_sha256=pin, pair_manifests=manifests)


def test_caller_narrower_aggregate_cap_rejects_before_disk_walk(tmp_path, monkeypatch):
    raw, pin, manifests, _ = _bundle(tmp_path)
    descriptor = json.loads(raw)
    declared = sum(
        file["bytes"]
        for item in (*descriptor["repetitions"], *descriptor["controls"])
        for file in item["files"]
    )

    def forbidden_walk(*_args, **_kwargs):
        raise AssertionError("disk walk preceded aggregate policy check")

    monkeypatch.setattr(inventory_module, "_inventory_files", forbidden_walk)
    with pytest.raises(ValueError, match="aggregate byte cap"):
        load_subset_readiness_inventory(
            raw,
            expected_sha256=pin,
            pair_manifests=manifests,
            max_aggregate_bytes=declared - 1,
        )


def test_provisional_hard_cap_rejects_before_disk_walk(tmp_path, monkeypatch):
    raw, _, manifests, _ = _bundle(tmp_path)
    descriptor = json.loads(raw)
    for row in descriptor["repetitions"][0]["files"]:
        row["bytes"] = 512 * 1024 * 1024
    pinned = _json(descriptor)

    def forbidden_walk(*_args, **_kwargs):
        raise AssertionError("disk walk preceded hard ceiling check")

    monkeypatch.setattr(inventory_module, "_inventory_files", forbidden_walk)
    with pytest.raises(ValueError, match="aggregate byte cap"):
        load_subset_readiness_inventory(
            pinned, expected_sha256=_sha(pinned), pair_manifests=manifests
        )


def test_expired_deadline_rejects_before_disk_walk(tmp_path, monkeypatch):
    raw, pin, manifests, _ = _bundle(tmp_path)

    def forbidden_walk(*_args, **_kwargs):
        raise AssertionError("disk walk preceded deadline check")

    monkeypatch.setattr(inventory_module, "_inventory_files", forbidden_walk)
    with pytest.raises(ValueError, match="deadline"):
        load_subset_readiness_inventory(
            raw,
            expected_sha256=pin,
            pair_manifests=manifests,
            deadline_monotonic=time.monotonic() - 1,
        )


def test_deadline_expiring_during_scan_fails_closed(tmp_path, monkeypatch):
    raw, pin, manifests, _ = _bundle(tmp_path)
    original_scan = inventory_module.os.scandir
    expired = False

    def expire_after_open(path):
        nonlocal expired
        scan = original_scan(path)
        if str(path) == str(tmp_path / "repeat-one"):
            expired = True
        return scan

    monkeypatch.setattr(inventory_module.os, "scandir", expire_after_open)
    monkeypatch.setattr(
        inventory_module,
        "time",
        SimpleNamespace(monotonic=lambda: 101.0 if expired else 99.0),
    )
    with pytest.raises(ValueError, match="deadline expired"):
        _load_inventory(
            raw,
            expected_sha256=pin,
            pair_manifests=manifests,
            deadline_monotonic=100.0,
        )
