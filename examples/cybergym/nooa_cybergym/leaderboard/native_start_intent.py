# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Signed, durable campaign-start gate for automatic native model lanes."""

from __future__ import annotations

import json
import os
import re
import time
from collections.abc import Callable
from pathlib import Path

from xeus_cybergym.canonical import canonical_json
from xeus_cybergym.ledger import SignedEnvelope

_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9:_.-]{0,127}\Z")
_SHA256 = re.compile(r"[a-f0-9]{64}\Z")
_FILE = "campaign-start-intent.signed.json"


def _root(value: Path) -> Path:
    root = Path(value)
    if not root.is_absolute() or root.is_symlink() or not root.is_dir() or root.resolve() != root:
        raise ValueError("controller-owned start-intent directory required")
    return root


def _identity(*values: str) -> None:
    if any(type(value) is not str or _IDENTITY.fullmatch(value) is None for value in values):
        raise ValueError("bounded campaign start identity required")


def _verified(
    raw: bytes,
    *,
    verifier,
    run_id: str,
    task_id: str,
    attempt_id: str,
    launch_id: str,
) -> dict:
    if type(raw) is not bytes or not 0 < len(raw) <= 16384:
        raise RuntimeError("bounded signed campaign start intent required")
    payload = verifier.verify(SignedEnvelope.model_validate_json(raw))
    value = json.loads(payload)
    if (
        type(value) is not dict
        or canonical_json(value) != payload
        or set(value)
        != {
            "schema_version",
            "artifact_kind",
            "run_id",
            "task_id",
            "attempt_id",
            "launch_id",
            "started_event_sha256",
        }
        or value["schema_version"] != 1
        or value["artifact_kind"] != "campaign_start_intent"
        or value["run_id"] != run_id
        or value["task_id"] != task_id
        or value["attempt_id"] != attempt_id
        or value["launch_id"] != launch_id
        or type(value["started_event_sha256"]) is not str
        or _SHA256.fullmatch(value["started_event_sha256"]) is None
    ):
        raise RuntimeError("signed campaign start intent differs from exact attempt")
    return value


def publish_start_intent(
    evidence_dir: Path,
    *,
    signer,
    verifier,
    run_id: str,
    task_id: str,
    attempt_id: str,
    launch_id: str,
    started_event_sha256: str,
) -> bytes:
    root = _root(evidence_dir)
    _identity(run_id, task_id, attempt_id, launch_id)
    if (
        type(started_event_sha256) is not str
        or _SHA256.fullmatch(started_event_sha256) is None
        or not callable(getattr(signer, "sign", None))
        or not callable(getattr(verifier, "verify", None))
    ):
        raise ValueError("verified started ledger event and signing authority required")
    payload = canonical_json(
        {
            "schema_version": 1,
            "artifact_kind": "campaign_start_intent",
            "run_id": run_id,
            "task_id": task_id,
            "attempt_id": attempt_id,
            "launch_id": launch_id,
            "started_event_sha256": started_event_sha256,
        }
    )
    target = root / _FILE
    if target.exists() or target.is_symlink():
        if target.is_symlink() or not target.is_file():
            raise RuntimeError("campaign start intent custody changed")
        prior = target.read_bytes()
        observed = _verified(
            prior,
            verifier=verifier,
            run_id=run_id,
            task_id=task_id,
            attempt_id=attempt_id,
            launch_id=launch_id,
        )
        if canonical_json(observed) != payload:
            raise RuntimeError("campaign start intent differs from verified ledger")
        return prior
    envelope = signer.sign(payload)
    if verifier.verify(envelope) != payload:
        raise RuntimeError("campaign start intent signature failed self-verification")
    raw = canonical_json(envelope.model_dump())
    try:
        with target.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError:
        return publish_start_intent(
            root,
            signer=signer,
            verifier=verifier,
            run_id=run_id,
            task_id=task_id,
            attempt_id=attempt_id,
            launch_id=launch_id,
            started_event_sha256=started_event_sha256,
        )
    if os.name == "posix":
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    return raw


def wait_start_intent(
    evidence_dir: Path,
    *,
    verifier,
    run_id: str,
    task_id: str,
    attempt_id: str,
    launch_id: str,
    timeout_seconds: float,
    stopped: Callable[[], bool] | None = None,
) -> dict:
    root = _root(evidence_dir)
    _identity(run_id, task_id, attempt_id, launch_id)
    if (
        not callable(getattr(verifier, "verify", None))
        or type(timeout_seconds) not in {int, float}
        or not 0 <= timeout_seconds <= 43200
        or (stopped is not None and not callable(stopped))
    ):
        raise ValueError("bounded native campaign start wait required")
    deadline = time.monotonic() + timeout_seconds
    target = root / _FILE
    while True:
        if target.exists() or target.is_symlink():
            if target.is_symlink() or not target.is_file():
                raise RuntimeError("campaign start intent custody changed")
            return _verified(
                target.read_bytes(),
                verifier=verifier,
                run_id=run_id,
                task_id=task_id,
                attempt_id=attempt_id,
                launch_id=launch_id,
            )
        if stopped is not None and stopped():
            raise RuntimeError("native task stopped before campaign start intent")
        if time.monotonic() >= deadline:
            raise TimeoutError("campaign started intent was not published")
        time.sleep(min(0.25, deadline - time.monotonic()))
