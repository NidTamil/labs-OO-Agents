# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""The serial campaign runner drives the signed ledger and owns native-UI teardown.

These tests exercise the real ``campaign.next_action`` ledger replay (through the
same signed-authority test double used by ``test_campaign``) and assert that the
runner opens exactly one native VS Code window + tunnel per task, closes it on the
signed terminal receipt, and reaps on completion or on any failure. The per-task
Docker/oracle work and the Windows-side window control are injected seams, so the
loop is verified without a real container, a real oracle, or a real VS Code.
"""

import base64
import hashlib
import json
from pathlib import Path

import pytest
from nooa_cybergym.leaderboard.campaign import CampaignAction, check_go_live, next_action
from nooa_cybergym.leaderboard.campaign_runner import (
    MailboxNativeUi,
    NativeUiController,
    PowerShellNativeUi,
    TaskExecutor,
    UiTarget,
    run_campaign,
)
from nooa_cybergym.leaderboard.deepseek import AlternateModelPolicy

CONFIG = Path(__file__).resolve().parents[2] / "leaderboard/config/campaign-policy.json"
ALTERNATE = CONFIG.with_name("alternate-model.json")
IDS = tuple(f"arvo:{index}" for index in range(1, 1508))


def test_powershell_ui_opens_with_pinned_client_and_tunnel_host_key(monkeypatch):
    calls = []

    def invoke(argv, *, check):
        calls.append((argv, check))

    monkeypatch.setattr("nooa_cybergym.leaderboard.campaign_runner.subprocess.run", invoke)
    ui = PowerShellNativeUi(
        script="D:/GLM/cybergym-windows.ps1",
        code_exe="D:/GLM/bin/VSCode-1.140.0/Code.exe",
        tunnel_known_hosts="D:/GLM/secrets/tunnel-known-hosts",
    )
    ui.open("run-1", "arvo:1", "cybergym-task-1", 32355)
    argv, check = calls[0]
    assert check is True
    assert argv[:4] == ["pwsh", "-NoProfile", "-File", "D:/GLM/cybergym-windows.ps1"]
    assert argv[-4:] == [
        "-CodeExe",
        "D:/GLM/bin/VSCode-1.140.0/Code.exe",
        "-TunnelKnownHosts",
        "D:/GLM/secrets/tunnel-known-hosts",
    ]


def test_owned_tunnel_config_uses_pinned_tailscale_host_key_alias():
    script = (Path(__file__).resolve().parents[2] / "scripts/cybergym-windows.ps1").read_text()
    assert "HostKeyAlias $RemoteHostFqdn.cinnamon-gamut.ts.net." in script
    assert "UserKnownHostsFile $($sshKnown.Replace('\\','/'))" in script
    assert "StrictHostKeyChecking yes" in script
    assert "'-F', $tunnelConfig" in script
    assert "[regex]::Escape((Get-TunnelConfig $key))" in script


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def failure_receipt(task_id, *, status="timeout"):
    return {
        "schema_version": 1,
        "artifact_kind": "terminal_receipt",
        "run_id": "run-1",
        "epoch": "epoch-1",
        "task_id": task_id,
        "status": status,
        "evidence_sha256": "f" * 64,
    }


class Authority:
    """Reuses the signed-attestation + durable-ledger double from test_campaign."""

    def __init__(self, payloads):
        self.payloads = payloads
        self.invalid = set()
        self.events = []
        self.created_root = None
        self.append_calls = []
        self.signed_receipts = {}

    def attest_signed(self, kind, envelope):
        if kind in self.invalid:
            return None
        if kind == "terminal_receipt" and envelope in self.signed_receipts:
            return self.signed_receipts[envelope]
        return self.payloads.get(kind) if envelope == f"signed:{kind}".encode() else None

    def create_campaign_once(self, evidence_root, run_id, event):
        if self.created_root is not None:
            return False
        self.created_root = evidence_root
        self.events.append(event)
        return True

    def read_verified_events(self, evidence_root, run_id):
        assert evidence_root == self.created_root
        return tuple(dict(event) for event in self.events)

    def append_event(self, evidence_root, run_id, event, expected_revision):
        self.append_calls.append((event, expected_revision))
        if len(self.events) != expected_revision:
            return False
        self.events.append(dict(event))
        return True


def _state(tmp_path):
    policy = json.loads(CONFIG.read_text())
    alternate = AlternateModelPolicy.model_validate_json(ALTERNATE.read_text())
    tasks_json = canonical([{"task_id": task_id} for task_id in IDS])
    envelopes = {
        kind: f"signed:{kind}".encode()
        for kind in ("decision", "certification", "harness_lock", "cohort")
    }
    policy_sha = sha(canonical(policy))
    payloads = {
        "cohort": {
            "schema_version": 1,
            "task_ids": list(IDS),
            "tasks_json_sha256": sha(tasks_json),
            "asset_hashes_sha256": "d" * 64,
            "benchmark_commit": "1" * 40,
            "dataset_commit": "2" * 40,
            "mask_map_sha256": "e" * 64,
            "generator_sha256": "f" * 64,
            "harness_manifest_sha256": "0" * 64,
        },
        "harness_lock": {
            "schema_version": 1,
            "epoch": "epoch-1",
            "campaign_policy_sha256": policy_sha,
            "alternate_policy_sha256": alternate.digest,
            "capability_registry_sha256": "b" * 64,
            "memory_policy_sha256": "c" * 64,
        },
        "certification": {
            "schema_version": 1,
            "status": "accepted",
            "scope": "live_native",
            "epoch": "epoch-1",
            "harness_sha256": sha(envelopes["harness_lock"]),
            "cohort_sha256": sha(envelopes["cohort"]),
            "campaign_policy_sha256": policy_sha,
            "alternate_policy_sha256": alternate.digest,
            "capability_registry_sha256": "b" * 64,
            "memory_policy_sha256": "c" * 64,
            "capability_coverage": "all_enabled_exercised",
            "memory_mode": "audited_hybrid",
            "controller_writes_after_true_oracle": True,
            "deepseek": {
                "status": "active",
                "provider": "https://api.deepseek.com",
                "model": "deepseek-flash",
                "thinking": {"type": "enabled"},
                "reasoning_effort": "max",
                "api": "chat_completions",
                "context_tokens": 1048576,
                "max_output_tokens": 128000,
                "max_requests": 36,
                "role_tokens": {
                    "independent_recon": 12582912,
                    "conditional_debug_recovery": 16777216,
                    "final_adversarial_critic": 8388608,
                },
                "role_seconds": {
                    "independent_recon": 3600,
                    "conditional_debug_recovery": 3600,
                    "final_adversarial_critic": 1800,
                },
                "role_requests": {
                    "independent_recon": 12,
                    "conditional_debug_recovery": 16,
                    "final_adversarial_critic": 8,
                },
            },
        },
        "decision": {
            "schema_version": 1,
            "run_id": "run-1",
            "official_launch_authorised": True,
            "epoch": "epoch-1",
            "certification_sha256": sha(envelopes["certification"]),
            "harness_sha256": sha(envelopes["harness_lock"]),
            "cohort_sha256": sha(envelopes["cohort"]),
            "campaign_policy_sha256": policy_sha,
        },
    }
    authority = Authority(payloads)
    inputs = {
        "decision": envelopes["decision"],
        "certification": envelopes["certification"],
        "harness_lock": envelopes["harness_lock"],
        "cohort": envelopes["cohort"],
        "campaign_policy": policy,
        "tasks_json": tasks_json,
        "authority": authority,
        "run_id": "run-1",
        "evidence_root": tmp_path / "evidence",
    }
    return check_go_live(**inputs), authority


def _seed_terminal_prefix(authority, upto):
    """Pre-seed the ledger with completed tasks IDS[:upto] so only the tail runs."""
    for task_id in IDS[:upto]:
        receipt = f"signed:terminal_receipt:{task_id}".encode()
        authority.signed_receipts[receipt] = failure_receipt(task_id)
        authority.events.extend(
            (
                {"type": "prepared", "task_id": task_id},
                {"type": "started", "task_id": task_id, "request_id": f"req:{task_id}"},
                {
                    "type": "terminal",
                    "task_id": task_id,
                    "status": "timeout",
                    "receipt_sha256": sha(receipt),
                    "receipt_envelope_b64": base64.b64encode(receipt).decode(),
                    "evidence_sha256": "f" * 64,
                },
            )
        )


class RecordingUi(NativeUiController):
    def __init__(self):
        self.calls = []
        self.open_hosts = []

    def reap(self, run_id):
        self.calls.append(("reap", run_id))
        self.open_hosts.clear()

    def open(self, run_id, task_id, remote_host, ssh_port):
        # Serial invariant: never two windows live at once.
        assert not self.open_hosts, f"opened {remote_host} while {self.open_hosts} still live"
        self.calls.append(("open", run_id, task_id, remote_host, ssh_port))
        self.open_hosts.append(remote_host)

    def close(self, run_id, task_id, remote_host):
        self.calls.append(("close", run_id, task_id, remote_host))
        if remote_host in self.open_hosts:
            self.open_hosts.remove(remote_host)


class FakeExecutor(TaskExecutor):
    def __init__(self, authority, *, fail_on=None):
        self.authority = authority
        self.fail_on = fail_on
        self.events = []
        self.submitted = set()
        self._port = 38350

    def prepare(self, task_id):
        self.events.append(("prepare", task_id))
        self._port += 1

    def ui_target(self, task_id):
        self.events.append(("ui_target", task_id))
        alias = "cybergym-syn-" + task_id.split(":")[1]
        return UiTarget(remote_host=alias, ssh_port=self._port)

    def first_request_id(self, task_id):
        self.events.append(("first_request_id", task_id))
        return f"req:{task_id}"

    def start(self, task_id, request_id):
        assert request_id == f"req:{task_id}"
        assert any(
            event.get("type") == "started"
            and event.get("task_id") == task_id
            and event.get("request_id") == request_id
            for event in self.authority.events
        ), "model request submitted before durable started intent"
        self.events.append(("start", task_id, request_id))
        self.submitted.add((task_id, request_id))

    def await_terminal(self, task_id):
        self.events.append(("await_terminal", task_id))
        if self.fail_on == task_id:
            raise RuntimeError("oracle lane exploded")
        receipt = f"signed:terminal_receipt:{task_id}".encode()
        self.authority.signed_receipts[receipt] = failure_receipt(task_id)
        return receipt


def test_runner_drives_one_task_and_owns_window_lifecycle(tmp_path):
    state, authority = _state(tmp_path)
    _seed_terminal_prefix(authority, 1506)  # leave only the final task to run
    ui = RecordingUi()
    executor = FakeExecutor(authority)

    run_campaign(state, executor, ui)

    last = IDS[-1]
    alias = "cybergym-syn-" + last.split(":")[1]
    # Executor walked the full per-task path in order.
    assert [name for name, *_ in executor.events] == [
        "prepare",
        "ui_target",
        "first_request_id",
        "start",
        "await_terminal",
    ]
    # UI: initial reap, open before start, close after terminal, final reap on complete.
    assert ui.calls == [
        ("reap", "run-1"),
        ("open", "run-1", last, alias, executor._port),
        ("close", "run-1", last, alias),
        ("reap", "run-1"),
    ]
    # Ledger reached completion.
    assert next_action(state).kind == "complete"
    assert [e["type"] for e in authority.events[-3:]] == ["prepared", "started", "terminal"]


def test_runner_is_serial_across_two_tasks_without_overlapping_windows(tmp_path):
    state, authority = _state(tmp_path)
    _seed_terminal_prefix(authority, 1505)  # leave the final two tasks
    ui = RecordingUi()
    executor = FakeExecutor(authority)

    run_campaign(state, executor, ui)

    opens = [c for c in ui.calls if c[0] == "open"]
    closes = [c for c in ui.calls if c[0] == "close"]
    assert len(opens) == 2 and len(closes) == 2
    # RecordingUi.open asserts no overlap; reaching here proves serial execution.
    assert next_action(state).kind == "complete"


def test_runner_drives_two_task_practice_state_without_scored_cohort(tmp_path):
    """Practice scheduling must use the same owned UI teardown without a 1,507-task state."""

    class Authority:
        def __init__(self):
            self.events = []
            self.signed_receipts = {}

        def read_verified_events(self, _root, _run_id):
            return tuple(self.events)

    class PracticeState:
        run_id = "practice-1"
        evidence_root = tmp_path
        task_ids = ("arvo:47101", "arvo:3938")

        def __init__(self):
            self.authority = Authority()
            self.actions = [
                *(
                    CampaignAction(kind, task_id)
                    for task_id in self.task_ids
                    for kind in ("prepare", "observe_prepared", "observe_started")
                ),
                CampaignAction("complete", None),
            ]

        def next_action(self):
            return self.actions[0]

        def mark_prepared(self, task_id):
            assert self.actions[0] == CampaignAction("prepare", task_id)
            self.authority.events.append({"type": "prepared", "task_id": task_id})
            self.actions.pop(0)

        def mark_started(self, task_id, *, request_id):
            assert self.actions[0] == CampaignAction("observe_prepared", task_id)
            self.authority.events.append(
                {"type": "started", "task_id": task_id, "request_id": request_id}
            )
            self.actions.pop(0)

        def mark_terminal(self, task_id, receipt):
            assert self.actions[0] == CampaignAction("observe_started", task_id)
            assert receipt in self.authority.signed_receipts
            self.authority.events.append({"type": "terminal", "task_id": task_id})
            self.actions.pop(0)

    state = PracticeState()
    executor = FakeExecutor(state.authority)
    ui = RecordingUi()

    run_campaign(state, executor, ui, action_for_state=lambda current: current.next_action())

    assert [
        event["task_id"] for event in state.authority.events if event["type"] == "terminal"
    ] == [
        "arvo:47101",
        "arvo:3938",
    ]
    assert [call[2] for call in ui.calls if call[0] == "open"] == list(state.task_ids)
    assert [call[2] for call in ui.calls if call[0] == "close"] == list(state.task_ids)
    assert ui.calls[-1] == ("reap", "practice-1")


def test_runner_reaps_and_reraises_when_a_task_fails(tmp_path):
    state, authority = _state(tmp_path)
    _seed_terminal_prefix(authority, 1506)
    ui = RecordingUi()
    last = IDS[-1]
    executor = FakeExecutor(authority, fail_on=last)

    with pytest.raises(RuntimeError, match="oracle lane exploded"):
        run_campaign(state, executor, ui)

    # A window was opened for the failing task; the runner must reap before propagating.
    assert ("open", "run-1", last, "cybergym-syn-" + last.split(":")[1], executor._port) in ui.calls
    assert ui.calls[-1] == ("reap", "run-1")
    # The task never advanced to terminal.
    assert next_action(state).kind == "observe_started"


def test_runner_requires_serial_policy(tmp_path):
    state, authority = _state(tmp_path)
    with pytest.raises(ValueError, match="serial"):
        run_campaign(state, FakeExecutor(authority), RecordingUi(), max_parallel_tasks=2)


def test_runner_does_not_submit_when_started_intent_append_is_unacknowledged(tmp_path):
    state, authority = _state(tmp_path)
    _seed_terminal_prefix(authority, 1506)
    executor = FakeExecutor(authority)
    ui = RecordingUi()
    original_append = authority.append_event

    def reject_started(root, run_id, event, expected_revision):
        if event["type"] == "started":
            return False
        return original_append(root, run_id, event, expected_revision)

    authority.append_event = reject_started
    with pytest.raises(RuntimeError, match="ledger append acknowledgement unavailable"):
        run_campaign(state, executor, ui)

    assert not executor.submitted
    assert next_action(state).kind == "observe_prepared"
    assert ui.calls[-1] == ("reap", "run-1")


def test_runner_resumes_started_intent_with_ledger_request_id(tmp_path):
    state, authority = _state(tmp_path)
    _seed_terminal_prefix(authority, 1506)
    last = IDS[-1]
    authority.events.extend(
        (
            {"type": "prepared", "task_id": last},
            {"type": "started", "task_id": last, "request_id": f"req:{last}"},
        )
    )
    executor = FakeExecutor(authority)

    ui = RecordingUi()
    run_campaign(state, executor, ui)

    assert (last, f"req:{last}") in executor.submitted
    assert [event["type"] for event in authority.events[-3:]] == ["prepared", "started", "terminal"]
    # The previous runner may have completed the native Send. Recovery must
    # reconcile that command without reaping its live Claude window first.
    assert ui.calls[0][0] == "open"


def test_mailbox_ui_uses_stable_task_keys_and_requires_completed_host_ack():
    from types import SimpleNamespace

    class Box:
        run_id = "run-1"

        def __init__(self):
            self.calls = []
            self.status = "completed"

        def publish(self, **kwargs):
            self.calls.append(kwargs)
            return SimpleNamespace(command_id="a" * 32)

        def wait_ack(self, command_id, *, timeout_seconds):
            assert command_id == "a" * 32
            assert timeout_seconds == 30
            return {"status": self.status}

    box = Box()
    ui = MailboxNativeUi(box, timeout_seconds=30)
    ui.open("run-1", "arvo:1507", "cybergym-task-1", 32355)
    ui.open("run-1", "arvo:1507", "cybergym-task-1", 32355)
    assert box.calls[0]["operation_key"] == box.calls[1]["operation_key"]
    box.status = "ambiguous"
    with pytest.raises(RuntimeError, match="not completed"):
        ui.close("run-1", "arvo:1507", "cybergym-task-1")
