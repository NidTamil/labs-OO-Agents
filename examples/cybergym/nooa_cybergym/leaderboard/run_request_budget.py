# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Durable, append-only request debits for one controller-owned ten-task run.

Reserve immediately before every provider dispatch, using a fresh dispatch ID.
Every committed debit counts, including failures, cancellations and ambiguous
outcomes. There is deliberately no refund operation. The caller owns allocation
selection; this module must never be exposed as a solver tool. Opening the ledger
does not authorize restarting or resending a native attempt, nor does this
request-only component grant run admission.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import stat
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

Allocation = Literal["primary_and_memory", "deepseek_advisory"]
RUN_REQUEST_LIMIT = 15_000
TASK_REQUEST_LIMIT = 1_500
PRIMARY_AND_MEMORY_LIMIT = 1_410
DEEPSEEK_ADVISORY_LIMIT = 90
_ALLOCATION_LIMITS = {
    "primary_and_memory": PRIMARY_AND_MEMORY_LIMIT,
    "deepseek_advisory": DEEPSEEK_ADVISORY_LIMIT,
}
_SCHEMA_VERSION = 1
_APPLICATION_ID = 0x4E525142
_SCHEMA = (
    """CREATE TABLE identity (
        id INTEGER PRIMARY KEY CHECK(id=1),
        run_id TEXT NOT NULL,
        epoch TEXT NOT NULL,
        policy_sha256 TEXT NOT NULL,
        ordered_task_ids TEXT NOT NULL
    ) STRICT""",
    """CREATE TABLE reservations (
        run_ordinal INTEGER PRIMARY KEY CHECK(run_ordinal BETWEEN 1 AND 15000),
        task_id TEXT NOT NULL CHECK(length(task_id) BETWEEN 1 AND 256),
        attempt_id TEXT NOT NULL CHECK(length(attempt_id) BETWEEN 1 AND 256),
        request_id TEXT NOT NULL UNIQUE CHECK(length(request_id) BETWEEN 1 AND 256),
        allocation TEXT NOT NULL CHECK(allocation IN ('primary_and_memory','deepseek_advisory')),
        task_ordinal INTEGER NOT NULL CHECK(task_ordinal BETWEEN 1 AND 1500),
        allocation_ordinal INTEGER NOT NULL CHECK(
            allocation_ordinal BETWEEN 1 AND CASE allocation
                WHEN 'primary_and_memory' THEN 1410 ELSE 90 END),
        UNIQUE(task_id, task_ordinal),
        UNIQUE(task_id, allocation, allocation_ordinal)
    ) STRICT""",
    """CREATE TRIGGER reservations_no_update BEFORE UPDATE ON reservations
        BEGIN SELECT RAISE(ABORT, 'request reservations are immutable'); END""",
    """CREATE TRIGGER reservations_no_delete BEFORE DELETE ON reservations
        BEGIN SELECT RAISE(ABORT, 'request reservations cannot be refunded'); END""",
    """CREATE TRIGGER identity_no_update BEFORE UPDATE ON identity
        BEGIN SELECT RAISE(ABORT, 'run identity is immutable'); END""",
    """CREATE TRIGGER identity_no_delete BEFORE DELETE ON identity
        BEGIN SELECT RAISE(ABORT, 'run identity is immutable'); END""",
)


class RunRequestBudgetError(RuntimeError):
    """The ledger cannot safely authorize a provider dispatch."""


class RequestBudgetExceeded(RunRequestBudgetError):
    """The fixed run, task or allocation request ceiling was reached."""


class DuplicateRequestReservation(RunRequestBudgetError):
    """A dispatch ID already consumed a request; it cannot be admitted twice."""


@dataclass(frozen=True, slots=True)
class RequestReservation:
    run_id: str
    task_id: str
    attempt_id: str
    request_id: str
    allocation: Allocation
    run_ordinal: int
    task_ordinal: int
    allocation_ordinal: int


def _identifier(value: str, label: str) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= 256
        or value != value.strip()
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError(f"invalid {label} identity")
    return value


def _identity(
    run_id: str, epoch: str, policy_sha256: str, ordered_task_ids: Sequence[str]
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    _identifier(run_id, "run")
    _identifier(epoch, "epoch")
    if type(policy_sha256) is not str or re.fullmatch("[0-9a-f]{64}", policy_sha256) is None:
        raise ValueError("policy_sha256 must be a lowercase SHA-256 digest")
    if not isinstance(ordered_task_ids, (list, tuple)) or len(ordered_task_ids) != 10:
        raise ValueError("exactly ten ordered task identities required")
    tasks = tuple(_identifier(task, "task") for task in ordered_task_ids)
    if len(set(tasks)) != 10:
        raise ValueError("exactly ten unique ordered task identities required")
    return (run_id, epoch, policy_sha256, json.dumps(tasks, separators=(",", ":"))), tasks


def _private_path(path: Path, *, required: bool) -> os.stat_result | None:
    if (
        not path.is_absolute()
        or not path.parent.is_dir()
        or path.parent.resolve() != path.parent
        or path.is_symlink()
        or (os.name == "posix" and path.parent.stat().st_mode & 0o022)
    ):
        raise RunRequestBudgetError("controller-private ledger path required")
    try:
        info = path.stat()
    except FileNotFoundError:
        if required:
            raise RunRequestBudgetError("request budget store is missing") from None
        return None
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or (os.name == "posix" and info.st_mode & 0o077)
    ):
        raise RunRequestBudgetError("controller-private, unlinked ledger file required")
    return info


@dataclass(frozen=True, slots=True)
class RunRequestBudget:
    """Validated handle; all authority remains in the database, never cached counts."""

    _path: Path
    _bound_identity: tuple[str, ...]
    _task_ids: tuple[str, ...]
    _file_identity: tuple[int, int]
    _write_failed: bool = field(default=False, init=False, repr=False, compare=False)

    @classmethod
    def create(
        cls,
        path: str | Path,
        *,
        run_id: str,
        epoch: str,
        policy_sha256: str,
        ordered_task_ids: Sequence[str],
    ) -> RunRequestBudget:
        """Exclusively create a fresh ledger; never overwrite or repair a store."""
        identity, tasks = _identity(run_id, epoch, policy_sha256, ordered_task_ids)
        path = Path(path)
        try:
            _private_path(path, required=False)
            for suffix in ("-journal", "-wal", "-shm"):
                if path.with_name(path.name + suffix).exists():
                    raise RunRequestBudgetError("existing SQLite sidecar prevents creation")
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
            info = path.stat()
            ledger = cls(path, identity, tasks, (info.st_dev, info.st_ino))
            with ledger._transaction(write=True) as connection:
                for statement in _SCHEMA:
                    connection.execute(statement)
                connection.execute(f"PRAGMA application_id={_APPLICATION_ID}")
                connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
                connection.execute("INSERT INTO identity VALUES(1,?,?,?,?)", identity)
            # SQLite syncs database/journal files; persist the directory entry too.
            if os.name == "posix":
                directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            return ledger
        except OSError as error:
            # Keep even a partially initialized store: never silently grant a reset.
            raise RunRequestBudgetError("cannot exclusively create request budget store") from error

    @classmethod
    def open(
        cls,
        path: str | Path,
        *,
        run_id: str,
        epoch: str,
        policy_sha256: str,
        ordered_task_ids: Sequence[str],
    ) -> RunRequestBudget:
        """Inspect/reuse the exact ledger without granting native attempt custody."""
        identity, tasks = _identity(run_id, epoch, policy_sha256, ordered_task_ids)
        path = Path(path)
        try:
            info = _private_path(path, required=True)
            assert info is not None
            ledger = cls(path, identity, tasks, (info.st_dev, info.st_ino))
            ledger.snapshot()
            return ledger
        except OSError as error:
            raise RunRequestBudgetError("cannot open request budget store") from error

    @contextmanager
    def _transaction(self, *, write: bool) -> Iterator[sqlite3.Connection]:
        connection = None
        try:
            if write and self._write_failed:
                raise RunRequestBudgetError("request budget handle has a prior write failure")
            info = _private_path(self._path, required=True)
            assert info is not None
            if (info.st_dev, info.st_ino) != self._file_identity:
                raise RunRequestBudgetError("request budget store identity changed")
            for suffix in ("-journal", "-wal", "-shm"):
                _private_path(self._path.with_name(self._path.name + suffix), required=False)
            # mode=rw is essential: a deleted file must never become a fresh budget.
            connection = sqlite3.connect(
                self._path.as_uri() + "?mode=rw", uri=True, timeout=30, isolation_level=None
            )
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            if write and self._write_failed:
                raise RunRequestBudgetError("request budget handle has a prior write failure")
            yield connection
            connection.commit()
        except (OSError, sqlite3.Error) as error:
            if write:
                object.__setattr__(self, "_write_failed", True)
            raise RunRequestBudgetError("request budget store operation failed") from error
        finally:
            if connection is not None:
                # Closing rolls back only an uncommitted transaction. A commit with a
                # lost acknowledgement stays charged; the caller must not dispatch.
                connection.close()

    def _snapshot(self, connection: sqlite3.Connection) -> dict:
        actual_schema = {
            row[0]
            for row in connection.execute("SELECT sql FROM sqlite_schema WHERE sql IS NOT NULL")
        }
        if (
            actual_schema != set(_SCHEMA)
            or connection.execute("PRAGMA user_version").fetchone()[0] != _SCHEMA_VERSION
            or connection.execute("PRAGMA application_id").fetchone()[0] != _APPLICATION_ID
        ):
            raise RunRequestBudgetError("request budget schema mismatch")
        # Duplicate admission relies on the unique request-ID index. quick_check
        # does not verify that indexes match table rows, so it cannot guard this.
        if connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise RunRequestBudgetError("corrupt request budget store")
        if connection.execute(
            "SELECT run_id,epoch,policy_sha256,ordered_task_ids FROM identity ORDER BY id"
        ).fetchall() != [self._bound_identity]:
            raise RunRequestBudgetError("request budget identity mismatch")
        counts = {
            task: {"requests": 0, "primary_and_memory": 0, "deepseek_advisory": 0}
            for task in self._task_ids
        }
        total = 0
        attempts: dict[str, str] = {}
        for row in connection.execute("SELECT * FROM reservations ORDER BY run_ordinal"):
            run_ordinal, task, attempt, request, allocation, task_ordinal, allocation_ordinal = row
            if task not in counts or allocation not in _ALLOCATION_LIMITS:
                raise RunRequestBudgetError("invalid request budget history identity")
            try:
                _identifier(attempt, "attempt")
                _identifier(request, "request")
            except ValueError as error:
                raise RunRequestBudgetError("invalid request budget history identity") from error
            if attempts.setdefault(attempt, task) != task:
                raise RunRequestBudgetError("request budget history changed attempt task")
            total += 1
            counts[task]["requests"] += 1
            counts[task][allocation] += 1
            if (
                run_ordinal != total
                or task_ordinal != counts[task]["requests"]
                or allocation_ordinal != counts[task][allocation]
                or total > RUN_REQUEST_LIMIT
                or task_ordinal > TASK_REQUEST_LIMIT
                or allocation_ordinal > _ALLOCATION_LIMITS[allocation]
            ):
                raise RunRequestBudgetError("invalid request budget history ordinals or limits")
        return {"requests": total, "tasks": counts}

    def snapshot(self) -> dict:
        """Return authoritative consumed counts, including all failed dispatches."""
        with self._transaction(write=False) as connection:
            return self._snapshot(connection)

    def reserve(
        self,
        *,
        task_id: str,
        attempt_id: str,
        request_id: str,
        allocation: Allocation,
    ) -> RequestReservation:
        """Commit one irreversible debit before the controller invokes its provider."""
        _identifier(task_id, "task")
        _identifier(attempt_id, "attempt")
        _identifier(request_id, "request")
        if task_id not in self._task_ids:
            raise ValueError("task identity is outside this run")
        if type(allocation) is not str or allocation not in _ALLOCATION_LIMITS:
            raise ValueError("unknown controller request allocation")
        with self._transaction(write=True) as connection:
            snapshot = self._snapshot(connection)
            if connection.execute(
                "SELECT 1 FROM reservations WHERE request_id=?", (request_id,)
            ).fetchone():
                raise DuplicateRequestReservation("request ID already reserved")
            if connection.execute(
                "SELECT 1 FROM reservations WHERE attempt_id=? AND task_id<>?",
                (attempt_id, task_id),
            ).fetchone():
                raise RunRequestBudgetError("attempt identity belongs to another task")
            counts = snapshot["tasks"][task_id]
            if snapshot["requests"] >= RUN_REQUEST_LIMIT:
                raise RequestBudgetExceeded("run request budget exhausted")
            if counts["requests"] >= TASK_REQUEST_LIMIT:
                raise RequestBudgetExceeded("task request budget exhausted")
            if counts[allocation] >= _ALLOCATION_LIMITS[allocation]:
                raise RequestBudgetExceeded("allocation request budget exhausted")
            reservation = RequestReservation(
                run_id=self._bound_identity[0],
                task_id=task_id,
                attempt_id=attempt_id,
                request_id=request_id,
                allocation=allocation,
                run_ordinal=snapshot["requests"] + 1,
                task_ordinal=counts["requests"] + 1,
                allocation_ordinal=counts[allocation] + 1,
            )
            connection.execute(
                "INSERT INTO reservations VALUES(?,?,?,?,?,?,?)",
                (
                    reservation.run_ordinal,
                    task_id,
                    attempt_id,
                    request_id,
                    allocation,
                    reservation.task_ordinal,
                    reservation.allocation_ordinal,
                ),
            )
        return reservation
