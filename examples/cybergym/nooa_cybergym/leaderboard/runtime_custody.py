# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Controller-owned, durable task start and redacted service audit custody.

One process owns an attempt. A controller restart may inspect its records, but
must not resume an attempt with a reset in-memory model budget.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import threading
from contextlib import contextmanager
from dataclasses import asdict, is_dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from .deepseek import SharedCampaignBudget
from .model_gateway import _hex_forms, _redact, _secret_forms


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _private_path(path: Path):
    if (
        not path.is_absolute()
        or path.parent.resolve() != path.parent
        or not path.parent.is_dir()
        or (os.name == "posix" and path.parent.stat().st_mode & 0o022)
        or path.is_symlink()
        or (path.exists() and (not path.is_file() or path.stat().st_nlink != 1))
    ):
        raise ValueError("private, unlinked controller evidence path required")


class AttemptStart:
    """Durably mark the first actual model admission, including GBrain auxiliaries."""

    def __init__(self, path: Path, *, task_id: str, attempt_id: str):
        self.path = Path(path)
        _private_path(self.path)
        if any(type(v) is not str or not v or len(v) > 128 for v in (task_id, attempt_id)):
            raise ValueError("task and attempt identity required")
        self.task_id, self.attempt_id = task_id, attempt_id
        self._owner = uuid4().hex
        with self._connect() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS owner(id INTEGER PRIMARY KEY CHECK(id=1), task TEXT, attempt TEXT, nonce TEXT);
                CREATE TABLE IF NOT EXISTS started(id INTEGER PRIMARY KEY CHECK(id=1), timestamp TEXT NOT NULL);
            """)
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute("SELECT count(*) FROM owner").fetchone()[0]:
                raise RuntimeError(
                    "attempt already owned; budget reset or automatic resume forbidden"
                )
            connection.execute(
                "INSERT INTO owner VALUES(1,?,?,?)", (task_id, attempt_id, self._owner)
            )

    @contextmanager
    def _connect(self):
        for suffix in ("", "-journal", "-wal", "-shm"):
            _private_path(self.path.with_name(self.path.name + suffix))
        connection = sqlite3.connect(self.path, timeout=15)
        try:
            connection.execute("PRAGMA synchronous=FULL")
            with connection:
                yield connection
        finally:
            connection.close()

    def mark_started(self, task_id: str, attempt_id: str) -> bool:
        if (task_id, attempt_id) != (self.task_id, self.attempt_id):
            return False
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute("SELECT task,attempt,nonce FROM owner WHERE id=1").fetchone() != (
                task_id,
                attempt_id,
                self._owner,
            ):
                raise RuntimeError("attempt owner changed")
            connection.execute(
                "INSERT OR IGNORE INTO started VALUES(1,?)", (datetime.now(UTC).isoformat(),)
            )
        return True

    @property
    def started(self):
        with self._connect() as connection:
            return bool(connection.execute("SELECT count(*) FROM started").fetchone()[0])


class RuntimeAudit:
    """Fsync each record before acknowledging a service effect.

    Files are per-attempt and exclusive. This is a local hash chain, not a
    replacement for the Xeus authority's signed certification or oracle ledger.
    """

    def __init__(self, path: Path, *, secrets: tuple[str, ...], start: AttemptStart):
        self.path = Path(path)
        _private_path(self.path)
        if (
            not isinstance(start, AttemptStart)
            or not secrets
            or any(type(value) is not str or not value for value in secrets)
        ):
            raise ValueError("attempt owner and controller secret redaction required")
        self._secret_forms = _secret_forms(secrets)
        self._hex_forms = _hex_forms(secrets)
        self.start = start
        self._lock = threading.Lock()
        self._previous = "0" * 64
        self._sequence = 0
        self._failed = False
        self._descriptor = os.open(
            self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600
        )
        self._identity = os.fstat(self._descriptor)
        try:
            if os.name == "posix":
                directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        except BaseException:
            os.close(self._descriptor)
            self._descriptor = None
            raise

    def _check_destination(self):
        try:
            _private_path(self.path)
            current = self.path.stat(follow_symlinks=False)
            if not stat.S_ISREG(current.st_mode) or (current.st_dev, current.st_ino) != (
                self._identity.st_dev,
                self._identity.st_ino,
            ):
                raise ValueError("destination changed")
        except (OSError, ValueError) as error:
            raise RuntimeError("runtime audit destination unavailable") from error

    @property
    def available(self):
        with self._lock:
            if self._failed or self._descriptor is None:
                return False
            try:
                self._check_destination()
            except RuntimeError:
                self._failed = True
                return False
            return True

    def redact(self, value):
        return _redact(value, self._secret_forms, self._hex_forms)

    def record(self, event) -> bool:
        with self._lock:
            if self._failed or self._descriptor is None:
                raise RuntimeError("runtime audit unavailable")
            try:
                self._check_destination()
                if is_dataclass(event):
                    event = asdict(event)
                if not isinstance(event, dict):
                    event = dict(event)
                if event.get("event") == "memory_model_admitted":
                    if not self.start.mark_started(self.start.task_id, self.start.attempt_id):
                        raise RuntimeError("memory first request was not durably admitted")
                body = {
                    "sequence": self._sequence + 1,
                    "previous_sha256": self._previous,
                    "timestamp": datetime.now(UTC).isoformat(),
                    "task_id": self.start.task_id,
                    "attempt_id": self.start.attempt_id,
                    "event": self.redact(event),
                }
                digest = hashlib.sha256(_canonical(body)).hexdigest()
                remaining = memoryview(_canonical({**body, "sha256": digest}) + b"\n")
                while remaining:
                    written = os.write(self._descriptor, remaining)
                    if written <= 0:
                        raise OSError("audit short write")
                    remaining = remaining[written:]
                os.fsync(self._descriptor)
                self._sequence += 1
                self._previous = digest
                return True
            except BaseException:
                self._failed = True
                raise

    def close(self):
        with self._lock:
            if self._descriptor is not None:
                os.close(self._descriptor)
                self._descriptor = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class _ContextBudget(SharedCampaignBudget):
    """One clock and allocation ledger; halt never discards consumed reservations."""

    def __init__(self, audit: RuntimeAudit):
        super().__init__()
        self._audit = audit
        self._halted = threading.Event()

    def remaining_seconds(self):
        if self._halted.is_set() or not self._audit.available:
            return 0.0
        return super().remaining_seconds()

    def halt(self):
        # Serialize with reservation admission, without affecting terminal audit writes.
        with self._lock:
            self._halted.set()


class TaskRuntimeContext:
    """Outer-driver custody shared by capability admission and every model lane.

    Construct before CapabilityRuntime and pass its audit there. Services may
    halt this context, but the outer owner closes it after cancellation, final
    locking, and terminal evidence. Existing attempt ownership forbids resume
    with a reset in-memory budget.
    """

    def __init__(self, evidence: Path, *, task_id: str, attempt_id: str, secrets: tuple[str, ...]):
        self.evidence = Path(evidence)
        self.start = AttemptStart(
            self.evidence / "attempt-start.sqlite", task_id=task_id, attempt_id=attempt_id
        )
        self.audit = RuntimeAudit(
            self.evidence / "runtime-events.jsonl", secrets=secrets, start=self.start
        )
        self.budget = _ContextBudget(self.audit)

    @property
    def active(self):
        return self.budget.remaining_seconds() > 0

    def halt(self):
        self.budget.halt()

    def close(self):
        self.halt()
        self.audit.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
