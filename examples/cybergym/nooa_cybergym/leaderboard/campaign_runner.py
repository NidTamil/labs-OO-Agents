# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Serial campaign runner that drives the signed ledger and owns native-UI teardown.

``campaign.py`` decides the next action from a replayed signed ledger; it never
launches anything. The per-task work (stage a container, submit the frozen prompt,
run the signed oracle) and the Windows-side native VS Code window + SSH tunnel are
environment-specific, so they are injected here as the ``TaskExecutor`` and
``NativeUiController`` seams. This module is the thin, deterministic loop that ties
them to the ledger and, critically, **guarantees the window/tunnel are torn down**:
opened once per task before the first model request, closed on the signed terminal
receipt, and reaped on completion or on any failure. It mirrors the campaign plan's
"one prepared/running/terminal task at a time ... on terminal, stop the tunnel".

The loop never signs or fabricates a receipt. It records first-request intent
before dispatch and asks the executor to ensure that request exists by its
ledger ID. Repeated calls after a crash must not submit a second model request.
The only in-memory state is which window is currently open; run-scoped
``reap()`` clears it on recovery.
"""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from .campaign import CampaignState, next_action


@dataclass(frozen=True, slots=True)
class UiTarget:
    """Where the native window + tunnel should attach for a task."""

    remote_host: str
    ssh_port: int


@runtime_checkable
class TaskExecutor(Protocol):
    """Per-task side effects the runner delegates (Docker, prompt, oracle, signing).

    ``first_request_id`` reserves a stable identity without submitting a request.
    ``start`` must be idempotent across process restarts for that identity: on
    recovery the runner invokes it again with the ID in the verified ledger.
    An adapter cannot implement this by blindly resubmitting the model prompt.
    """

    def prepare(self, task_id: str) -> None:
        """Stage the container and emit the task's signed launch + connection."""

    def ui_target(self, task_id: str) -> UiTarget:
        """Return the SSH remote-host alias and forwarded port to attach the UI."""

    def first_request_id(self, task_id: str) -> str:
        """Return a durable, stable identity without submitting a model request."""

    def start(self, task_id: str, request_id: str) -> None:
        """Ensure the frozen prompt was submitted once under this request ID."""

    def await_terminal(self, task_id: str) -> bytes:
        """Block until the signed terminal receipt (oracle verdict or failure)."""


@runtime_checkable
class NativeUiController(Protocol):
    """Owns the host-side native VS Code window + SSH tunnel for one task at a time."""

    def reap(self, run_id: str) -> None:
        """Close only windows and tunnels owned by this campaign run."""

    def open(self, run_id: str, task_id: str, remote_host: str, ssh_port: int) -> None:
        """Open one owned window + tunnel for this task."""

    def close(self, run_id: str, task_id: str, remote_host: str) -> None:
        """Close only this run/task's window + tunnel (no-op if absent)."""


class PowerShellNativeUi:
    """Default controller: shells out to the operational launcher/reaper script.

    The script path is taken from ``CYBERGYM_NATIVE_UI_SCRIPT`` (or the constructor)
    so the repo carries no machine-specific path. See the reviewed
    ``examples/cybergym/scripts/cybergym-windows.ps1``:
    ``-Reap -RunId <r>`` / ``-Open -RunId <r> -TaskId <t>
    -RemoteHost <h> -Port <n>`` / ``-Close -RunId <r> -TaskId <t>
    -RemoteHost <h>``.
    """

    def __init__(
        self,
        script: str | None = None,
        *,
        pwsh: str = "pwsh",
        code_exe: str | None = None,
        tunnel_known_hosts: str | None = None,
    ) -> None:
        resolved = script or os.environ.get("CYBERGYM_NATIVE_UI_SCRIPT")
        if not resolved:
            raise ValueError(
                "native UI script path required (pass script= or set CYBERGYM_NATIVE_UI_SCRIPT)"
            )
        self._script = resolved
        self._pwsh = pwsh
        if any(
            value is not None and (type(value) is not str or not value)
            for value in (code_exe, tunnel_known_hosts)
        ):
            raise ValueError("pinned native UI paths must be nonempty strings")
        self._code_exe = code_exe
        self._tunnel_known_hosts = tunnel_known_hosts

    def _run(self, *args: str) -> None:
        subprocess.run(
            [self._pwsh, "-NoProfile", "-File", self._script, *args],
            check=True,
        )

    def reap(self, run_id: str) -> None:
        self._run("-Reap", "-RunId", run_id)

    def open(self, run_id: str, task_id: str, remote_host: str, ssh_port: int) -> None:
        args = [
            "-Open",
            "-RunId",
            run_id,
            "-TaskId",
            task_id,
            "-RemoteHost",
            remote_host,
            "-Port",
            str(ssh_port),
        ]
        if self._code_exe is not None:
            args.extend(("-CodeExe", self._code_exe))
        if self._tunnel_known_hosts is not None:
            args.extend(("-TunnelKnownHosts", self._tunnel_known_hosts))
        self._run(*args)

    def close(self, run_id: str, task_id: str, remote_host: str) -> None:
        self._run(
            "-Close",
            "-RunId",
            run_id,
            "-TaskId",
            task_id,
            "-RemoteHost",
            remote_host,
        )


def _started_request_id(state: CampaignState, task_id: str) -> str:
    """Read the first-request identity from the verified durable ledger."""
    events = state.authority.read_verified_events(state.evidence_root, state.run_id)
    for event in reversed(events):
        if event.get("type") == "started" and event.get("task_id") == task_id:
            request_id = event.get("request_id")
            if type(request_id) is str and request_id:
                return request_id
            break
    raise RuntimeError("started task lacks a verified first-request identity")


def run_campaign(
    state: CampaignState,
    executor: TaskExecutor,
    ui: NativeUiController,
    *,
    max_parallel_tasks: int = 1,
    log: Callable[[str], None] = print,
) -> None:
    """Drive the signed campaign to completion, one task at a time.

    Raises on the first failure after reaping the UI; the ledger is durable, so a
    re-invocation resumes at the same task. ``max_parallel_tasks`` must be 1: the
    frozen campaign policy pins serial execution and the scheduler is strictly serial.
    """
    if max_parallel_tasks != 1:
        raise ValueError("campaign scheduling is serial; max_parallel_tasks must be 1")

    open_host: str | None = None
    open_task_id: str | None = None
    # Clear only resources owned by this run from an earlier interrupted process.
    ui.reap(state.run_id)
    try:
        while True:
            action = next_action(state)
            if action.kind == "complete":
                # Final sweep: each task self-closes at terminal, but a crashed-then-
                # resumed task can leave an untracked orphan, so end on a clean slate.
                ui.reap(state.run_id)
                log("campaign complete")
                return
            task_id = action.task_id
            assert task_id is not None  # non-complete actions always name a task

            if action.kind == "prepare":
                log(f"prepare {task_id}")
                executor.prepare(task_id)
                state.mark_prepared(task_id)

            elif action.kind == "observe_prepared":
                target = executor.ui_target(task_id)
                if open_host is not None and open_task_id != task_id:
                    # Serial invariant: never leave a prior task's UI alive.
                    assert open_task_id is not None
                    ui.close(state.run_id, open_task_id, open_host)
                ui.open(state.run_id, task_id, target.remote_host, target.ssh_port)
                open_host = target.remote_host
                open_task_id = task_id
                log(f"opening {task_id} on {target.remote_host}:{target.ssh_port}")
                request_id = executor.first_request_id(task_id)
                state.mark_started(task_id, request_id=request_id)

            elif action.kind == "observe_started":
                if open_task_id != task_id:
                    target = executor.ui_target(task_id)
                    ui.open(state.run_id, task_id, target.remote_host, target.ssh_port)
                    open_host = target.remote_host
                    open_task_id = task_id
                executor.start(task_id, _started_request_id(state, task_id))
                receipt = executor.await_terminal(task_id)
                state.mark_terminal(task_id, receipt)
                if open_host is not None:
                    ui.close(state.run_id, task_id, open_host)
                    open_host = None
                    open_task_id = None
                log(f"terminal {task_id}")

            else:  # pragma: no cover - campaign.next_action yields no other kind
                raise RuntimeError(f"unsupported campaign action: {action.kind!r}")
    except BaseException:
        # Never leak a window or tunnel across a failure or interrupt.
        ui.reap(state.run_id)
        raise


def main(argv: list[str] | None = None) -> int:  # pragma: no cover - thin CLI shell
    """CLI shell: the signed authority, cohort inputs, and executor are wired by the
    operator's launch environment (no committed fallback exists for the authority).
    This entrypoint only documents the required inputs and refuses to invent them."""
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-ui-script", help="path to cybergym-windows.ps1")
    parser.add_argument(
        "--print-contract",
        action="store_true",
        help="print the inputs a real launcher must supply, then exit",
    )
    args = parser.parse_args(argv)
    if args.print_contract:
        print(
            json.dumps(
                {
                    "state": "campaign.check_go_live(signed decision/certification/"
                    "harness_lock/cohort, frozen policy, tasks.json, trusted authority)",
                    "executor": "TaskExecutor (prepare/ui_target/first_request_id/start/await_terminal; start idempotent by request_id)",
                    "ui": "NativeUiController (PowerShellNativeUi by default)",
                    "native_ui_script_env": "CYBERGYM_NATIVE_UI_SCRIPT",
                },
                indent=2,
            )
        )
        return 0
    parser.error("no committed authority/executor fallback; import run_campaign and inject them")
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
