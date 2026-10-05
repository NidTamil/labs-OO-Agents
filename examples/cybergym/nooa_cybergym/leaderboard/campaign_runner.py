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

The loop never signs, never fabricates a receipt, and never retries a started
attempt: it only calls the ledger transitions, which reject anything out of order.
Because every step is ledger-replayed, a crash is resumed by re-reading the ledger;
the only in-memory state is which window is currently open, which ``reap()`` clears.
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

    Every method is keyed only by ``task_id`` so the runner can resume after a crash
    by re-reading the ledger; the executor is responsible for reattaching to a task
    it already prepared or started (e.g. by reading its ``connection.json``).
    """

    def prepare(self, task_id: str) -> None:
        """Stage the container and emit the task's signed launch + connection."""

    def ui_target(self, task_id: str) -> UiTarget:
        """Return the SSH remote-host alias and forwarded port to attach the UI."""

    def start(self, task_id: str) -> str:
        """Submit the frozen prompt once and return the first model request id."""

    def await_terminal(self, task_id: str) -> bytes:
        """Block until the signed terminal receipt (oracle verdict or failure)."""


@runtime_checkable
class NativeUiController(Protocol):
    """Owns the host-side native VS Code window + SSH tunnel for one task at a time."""

    def reap(self) -> None:
        """Kill every cybergym window + tunnel, whoever opened them (orphan safety)."""

    def open(self, remote_host: str, ssh_port: int) -> None:
        """Open exactly one window + tunnel for ``remote_host`` on ``ssh_port``."""

    def close(self, remote_host: str) -> None:
        """Tear down the window + tunnel for ``remote_host`` (no-op if absent)."""


class PowerShellNativeUi:
    """Default controller: shells out to the operational launcher/reaper script.

    The script path is taken from ``CYBERGYM_NATIVE_UI_SCRIPT`` (or the constructor)
    so the repo carries no machine-specific path. See ``cybergym-windows.ps1``:
    ``-Reap`` / ``-Open -RemoteHost <h> -Port <n> -Force`` / ``-Close -RemoteHost <h>``.
    """

    def __init__(self, script: str | None = None, *, pwsh: str = "pwsh") -> None:
        resolved = script or os.environ.get("CYBERGYM_NATIVE_UI_SCRIPT")
        if not resolved:
            raise ValueError(
                "native UI script path required (pass script= or set CYBERGYM_NATIVE_UI_SCRIPT)"
            )
        self._script = resolved
        self._pwsh = pwsh

    def _run(self, *args: str) -> None:
        subprocess.run(
            [self._pwsh, "-NoProfile", "-File", self._script, *args],
            check=True,
        )

    def reap(self) -> None:
        self._run("-Reap")

    def open(self, remote_host: str, ssh_port: int) -> None:
        self._run("-Open", "-RemoteHost", remote_host, "-Port", str(ssh_port), "-Force")

    def close(self, remote_host: str) -> None:
        self._run("-Close", "-RemoteHost", remote_host)


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
    # Clear any window/tunnel orphaned by a prior aborted or manual run before starting.
    ui.reap()
    try:
        while True:
            action = next_action(state)
            if action.kind == "complete":
                # Final sweep: each task self-closes at terminal, but a crashed-then-
                # resumed task can leave an untracked orphan, so end on a clean slate.
                ui.reap()
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
                if open_host is not None and open_host != target.remote_host:
                    # Serial invariant: never leave a prior task's UI alive.
                    ui.close(open_host)
                ui.open(target.remote_host, target.ssh_port)
                open_host = target.remote_host
                log(f"started {task_id} on {target.remote_host}:{target.ssh_port}")
                request_id = executor.start(task_id)
                state.mark_started(task_id, request_id=request_id)

            elif action.kind == "observe_started":
                receipt = executor.await_terminal(task_id)
                state.mark_terminal(task_id, receipt)
                if open_host is not None:
                    ui.close(open_host)
                    open_host = None
                log(f"terminal {task_id}")

            else:  # pragma: no cover - campaign.next_action yields no other kind
                raise RuntimeError(f"unsupported campaign action: {action.kind!r}")
    except BaseException:
        # Never leak a window or tunnel across a failure or interrupt.
        ui.reap()
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
                    "executor": "TaskExecutor (prepare/ui_target/start/await_terminal)",
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
