# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Two-task practice admission and signed-ledger replay are distinct from scored go-live."""

from __future__ import annotations

import base64
import hashlib

import pytest
from nooa_cybergym.leaderboard.campaign import CampaignAction
from nooa_cybergym.leaderboard.campaign_runner import UiTarget, run_campaign
from nooa_cybergym.leaderboard.practice_campaign import (
    PRACTICE_TASK_IDS,
    admit_practice,
    selected_assets_sha256,
    verify_practice_assets,
)


class Authority:
    def __init__(self, admission):
        self.admission = admission
        self.events = []
        self.receipts = {}

    def attest_signed(self, kind, envelope):
        if kind == "practice_admission" and envelope == b"signed-admission":
            return self.admission
        if kind == "terminal_receipt":
            return self.receipts.get(envelope)
        return None

    def create_campaign_once(self, _root, _run_id, event):
        if self.events:
            return False
        self.events.append(dict(event))
        return True

    def read_verified_events(self, _root, _run_id):
        return tuple(dict(event) for event in self.events)

    def append_event(self, _root, _run_id, event, expected_revision):
        if expected_revision != len(self.events):
            return False
        self.events.append(dict(event))
        return True


def admission():
    return {
        "schema_version": 1,
        "artifact_kind": "practice_admission",
        "scope": "native_practice_level1",
        "run_id": "practice-1",
        "epoch": "v26q",
        "task_ids": list(PRACTICE_TASK_IDS),
        "max_parallel_tasks": 1,
        "freeze_sha256": "a" * 64,
        "asset_hashes_sha256": "b" * 64,
        "selected_assets_sha256": "e" * 64,
        "host_key_sha256": "c" * 64,
        "vscode_exe_sha256": "f" * 64,
        "vscode_version": "1.140.0",
        "claude_extension_version": "2.1.289",
        "remote_host": "sunchaser-20260905.cinnamon-gamut.ts.net",
    }


def admit(tmp_path, authority):
    return admit_practice(
        signed_admission=b"signed-admission",
        authority=authority,
        run_id="practice-1",
        epoch="v26q",
        evidence_root=tmp_path,
        expected_freeze_sha256="a" * 64,
        expected_asset_hashes_sha256="b" * 64,
        expected_selected_assets_sha256="e" * 64,
        expected_host_key_sha256="c" * 64,
        expected_vscode_exe_sha256="f" * 64,
    )


def receipt(authority, task_id):
    raw = f"signed-receipt:{task_id}".encode()
    authority.receipts[raw] = {
        "schema_version": 1,
        "artifact_kind": "terminal_receipt",
        "run_id": "practice-1",
        "epoch": "v26q",
        "task_id": task_id,
        "status": "timeout",
        "evidence_sha256": "d" * 64,
    }
    return raw


def test_practice_replays_exact_two_tasks_and_signed_terminal_receipts(tmp_path):
    authority = Authority(admission())
    state = admit(tmp_path, authority)
    assert state.next_action() == CampaignAction("prepare", "arvo:47101")
    state.mark_prepared("arvo:47101")
    state.mark_started("arvo:47101", request_id="request-1")
    with pytest.raises(RuntimeError, match="task order"):
        state.mark_prepared("arvo:3938")
    state.mark_terminal("arvo:47101", receipt(authority, "arvo:47101"))
    assert state.next_action() == CampaignAction("prepare", "arvo:3938")
    state.mark_prepared("arvo:3938")
    state.mark_started("arvo:3938", request_id="request-2")
    state.mark_terminal("arvo:3938", receipt(authority, "arvo:3938"))
    assert state.next_action() == CampaignAction("complete", None)
    assert admit(tmp_path, authority).next_action() == CampaignAction("complete", None)
    assert [event["task_id"] for event in authority.events[1::3]] == list(PRACTICE_TASK_IDS)


@pytest.mark.parametrize(
    "mutation",
    [
        "task_ids",
        "max_parallel_tasks",
        "remote_host",
        "freeze_sha256",
        "asset_hashes_sha256",
        "selected_assets_sha256",
        "host_key_sha256",
        "vscode_exe_sha256",
        "vscode_version",
        "claude_extension_version",
    ],
)
def test_practice_admission_rejects_wrong_scope_before_ledger_creation(tmp_path, mutation):
    payload = admission()
    payload[mutation] = {
        "task_ids": ["arvo:3938", "arvo:47101"],
        "max_parallel_tasks": 2,
        "remote_host": "other.example",
        "freeze_sha256": "d" * 64,
        "asset_hashes_sha256": "e" * 64,
        "selected_assets_sha256": "a" * 64,
        "host_key_sha256": "f" * 64,
        "vscode_exe_sha256": "b" * 64,
        "vscode_version": "1.141.0",
        "claude_extension_version": "2.1.287",
    }[mutation]
    authority = Authority(payload)
    with pytest.raises(RuntimeError, match="practice admission"):
        admit(tmp_path, authority)
    assert authority.events == []


def test_practice_rejects_unsigned_or_wrong_task_receipt(tmp_path):
    authority = Authority(admission())
    state = admit(tmp_path, authority)
    state.mark_prepared("arvo:47101")
    state.mark_started("arvo:47101", request_id="request-1")
    with pytest.raises(RuntimeError, match="signed terminal"):
        state.mark_terminal("arvo:47101", b"unsigned")
    with pytest.raises(RuntimeError, match="identity"):
        state.mark_terminal("arvo:47101", receipt(authority, "arvo:3938"))
    assert state.next_action() == CampaignAction("observe_started", "arvo:47101")


def test_practice_rejects_tampered_verified_ledger(tmp_path):
    authority = Authority(admission())
    state = admit(tmp_path, authority)
    authority.events.append(
        {
            "type": "terminal",
            "task_id": "arvo:47101",
            "receipt_sha256": hashlib.sha256(b"fake").hexdigest(),
            "receipt_envelope_b64": base64.b64encode(b"fake").decode(),
        }
    )
    with pytest.raises(RuntimeError, match="practice ledger"):
        state.next_action()


def test_selected_practice_assets_are_checked_without_fixed_side_access(tmp_path):
    from nooa_cybergym.leaderboard.cohort import FrozenTaskInput, VulnerableArchive

    expected = {}
    for task_id in PRACTICE_TASK_IDS:
        family, number = task_id.split(":")
        folder = tmp_path / family / number
        folder.mkdir(parents=True)
        description = f"task {task_id}".encode()
        vulnerable = f"vulnerable {task_id}".encode()
        (folder / "description.txt").write_bytes(description)
        (folder / "repo-vul.tar.gz").write_bytes(vulnerable)
        (folder / "repo-fix.tar.gz").write_bytes(b"fixed side must remain unread")
        expected[task_id] = FrozenTaskInput(
            task_id=task_id,
            description_sha256=hashlib.sha256(description).hexdigest(),
            description_bytes=len(description),
            vulnerable_archive=VulnerableArchive(
                hashlib.sha256(vulnerable).hexdigest(), len(vulnerable)
            ),
            description_lfs_pointer=True,
            vulnerable_archive_lfs_pointer=True,
        )

    class SelectedRegistry:
        def inputs_for(self, task_id):
            assert task_id in PRACTICE_TASK_IDS
            return expected[task_id]

    observed = verify_practice_assets(registry=SelectedRegistry(), data_dir=tmp_path)
    assert list(observed) == list(PRACTICE_TASK_IDS)
    assert (
        observed["arvo:47101"]["vulnerable_archive_sha256"]
        == expected["arvo:47101"].vulnerable_archive.sha256
    )
    digest = selected_assets_sha256(observed)
    assert len(digest) == 64
    with pytest.raises(ValueError, match="exactly two"):
        selected_assets_sha256({"arvo:47101": observed["arvo:47101"]})
    with pytest.raises(ValueError, match="selected asset"):
        selected_assets_sha256(
            {**observed, "arvo:3938": {**observed["arvo:3938"], "description_bytes": -1}}
        )

    (tmp_path / "arvo" / "3938" / "repo-vul.tar.gz").write_bytes(b"changed")
    with pytest.raises(RuntimeError, match="selected practice asset"):
        verify_practice_assets(registry=SelectedRegistry(), data_dir=tmp_path)


def test_signed_practice_state_runs_serially_through_native_ui_owner(tmp_path):
    authority = Authority(admission())
    state = admit(tmp_path, authority)
    actions = []

    class Executor:
        def prepare(self, task_id):
            actions.append(("prepare", task_id))

        def ui_target(self, task_id):
            return UiTarget("cybergym-practice", 22511)

        def first_request_id(self, task_id):
            return f"request:{task_id}"

        def start(self, task_id, request_id):
            assert request_id == f"request:{task_id}"
            actions.append(("start", task_id))

        def await_terminal(self, task_id):
            actions.append(("terminal", task_id))
            return receipt(authority, task_id)

    class Ui:
        opened = None

        def reap(self, _run_id):
            self.opened = None
            actions.append(("reap", None))

        def open(self, _run_id, task_id, _host, _port):
            assert self.opened is None
            self.opened = task_id
            actions.append(("open", task_id))

        def close(self, _run_id, task_id, _host):
            assert self.opened == task_id
            self.opened = None
            actions.append(("close", task_id))

    ui = Ui()
    run_campaign(state, Executor(), ui, action_for_state=lambda current: current.next_action())
    assert ui.opened is None
    assert state.next_action() == CampaignAction("complete", None)
    assert [item for item in actions if item[0] == "open"] == [
        ("open", "arvo:47101"),
        ("open", "arvo:3938"),
    ]
    assert actions.index(("close", "arvo:47101")) < actions.index(("open", "arvo:3938"))
