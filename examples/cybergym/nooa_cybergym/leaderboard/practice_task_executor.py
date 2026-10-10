# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Bind a prepared native practice worker to the serial signed campaign runner.

The worker owns its isolated task container and evaluator. This adapter does
not start a second model request: it binds the verified ledger start event to
one durable start intent, then uses the existing one-shot Windows UI mailbox.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .campaign import CampaignAction
from .campaign_runner import UiTarget
from .practice_campaign import PRACTICE_TASK_IDS

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9:_.-]{0,127}\Z")


def _publish_intent(*args, **kwargs):
    from .native_start_intent import publish_start_intent

    return publish_start_intent(*args, **kwargs)


def _submitter(**kwargs):
    from .native_task_executor import MailboxNativeSubmitter

    return MailboxNativeSubmitter(**kwargs)


class NativePracticeTaskExecutor:
    """Controller-only TaskExecutor over one durable prepared worker per task."""

    def __init__(
        self,
        *,
        state,
        worker,
        mailbox,
        signer,
        verifier,
        remote_alias: str,
        publish_intent: Callable[..., bytes] = _publish_intent,
        submitter_factory: Callable[..., Any] = _submitter,
    ) -> None:
        if (
            type(getattr(state, "run_id", None)) is not str
            or state.run_id != getattr(mailbox, "run_id", None)
            or not all(
                callable(getattr(state, name, None))
                for name in ("next_action", "started_event_sha256")
            )
            or not all(
                callable(getattr(worker, name, None))
                for name in ("ensure_prepared", "await_terminal")
            )
            or type(remote_alias) is not str
            or re.fullmatch(r"[a-z][a-z0-9-]{1,63}", remote_alias) is None
            or not callable(publish_intent)
            or not callable(submitter_factory)
        ):
            raise ValueError("verified practice state, worker and pinned UI route required")
        self.state = state
        self.worker = worker
        self.mailbox = mailbox
        self.signer = signer
        self.verifier = verifier
        self.remote_alias = remote_alias
        self.publish_intent = publish_intent
        self.submitter_factory = submitter_factory
        self._launches: dict[str, Any] = {}

    def _prepared(self, task_id: str):
        if task_id not in PRACTICE_TASK_IDS:
            raise ValueError("task is outside authorized practice pair")
        launch = self.worker.ensure_prepared(task_id)
        evidence = Path(getattr(launch, "evidence", ""))
        authority = getattr(launch, "launch_authority", None)
        manifest = getattr(authority, "manifest", None)
        if (
            getattr(launch, "task_id", None) != task_id
            or type(getattr(launch, "launch_id", None)) is not str
            or _ID.fullmatch(launch.launch_id) is None
            or type(getattr(launch, "attempt_id", None)) is not str
            or _ID.fullmatch(launch.attempt_id) is None
            or getattr(launch, "remote_alias", None) != self.remote_alias
            or type(getattr(launch, "ssh_port", None)) is not int
            or not 1024 <= launch.ssh_port <= 65535
            or not evidence.is_absolute()
            or evidence.is_symlink()
            or not evidence.is_dir()
            or type(manifest) is not dict
            or manifest.get("run_id") != self.state.run_id
            or manifest.get("task_id") != task_id
            or manifest.get("launch_id") != launch.launch_id
            or not callable(getattr(authority, "_check_receipt", None))
            or not callable(getattr(getattr(launch, "witness", None), "observed", None))
        ):
            raise RuntimeError("prepared practice launch identity differs")
        prior = self._launches.get(task_id)
        if prior is not None and prior.launch_id != launch.launch_id:
            raise RuntimeError("prepared practice launch changed during campaign")
        self._launches[task_id] = launch
        return launch

    def prepare(self, task_id: str) -> None:
        self._prepared(task_id)

    def ui_target(self, task_id: str) -> UiTarget:
        launch = self._prepared(task_id)
        return UiTarget(launch.remote_alias, launch.ssh_port)

    def first_request_id(self, task_id: str) -> str:
        return self._prepared(task_id).launch_id

    def start(self, task_id: str, request_id: str) -> None:
        launch = self._prepared(task_id)
        if request_id != launch.launch_id:
            raise RuntimeError("practice launch identity differs from verified request")
        if self.state.next_action() != CampaignAction("observe_started", task_id):
            raise RuntimeError("verified practice started state required before native Send")
        digest = self.state.started_event_sha256(task_id, request_id)
        intent = self.publish_intent(
            Path(launch.evidence),
            signer=self.signer,
            verifier=self.verifier,
            run_id=self.state.run_id,
            task_id=task_id,
            attempt_id=launch.attempt_id,
            launch_id=request_id,
            started_event_sha256=digest,
        )
        if type(intent) is not bytes or not intent:
            raise RuntimeError("signed practice start intent unavailable")

        def started_intent(candidate_id: str) -> bool:
            return (
                candidate_id == request_id
                and self.state.started_event_sha256(task_id, candidate_id) == digest
            )

        submitter = self.submitter_factory(
            launch_authority=launch.launch_authority,
            mailbox=self.mailbox,
            witness=launch.witness,
            remote_alias=self.remote_alias,
            started_intent=started_intent,
        )
        if submitter.submit_once(request_id) is not True:
            raise RuntimeError("native practice first request was not observed")

    def await_terminal(self, task_id: str) -> bytes:
        self._prepared(task_id)
        receipt = self.worker.await_terminal(task_id)
        if type(receipt) is not bytes or not receipt:
            raise RuntimeError("signed practice terminal receipt unavailable")
        return receipt
