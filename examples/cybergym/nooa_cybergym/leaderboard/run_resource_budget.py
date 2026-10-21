# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Durable request, elapsed-time and conservative spend enforcement for a subset.

This is an explicit new ledger format. The historical request-only ledger is
unchanged. Create before the first preparation; do not create again on recovery.
Every permitted dispatch atomically consumes request and conservative spend.
There is no refund. A run stop is not a task terminal verdict. Owned cleanup is
allowed after stop, and signed quiescence must be independently verified by the
controller before close_task. This component itself never signs or launches.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .campaign import CampaignAuthority, _json_bytes
from .pinned_metering import VerifiedMeteringPolicy, _digest
from .run_request_budget import (
    _ALLOCATION_LIMITS,
    Allocation,
    DuplicateRequestReservation,
    RequestBudgetExceeded,
    RequestReservation,
    RunRequestBudgetError,
    _identifier,
    _private_path,
)
from .subset_run_budget import VerifiedSubsetBudget

_NS = 1_000_000_000
_APPLICATION_ID = 0x4E525342
_MAX_HISTORY_EVENTS = 15000 + 10 + 1
_MAX_EVENT_BODY_BYTES = 4096
_MAX_HISTORY_BODY_BYTES = 64 * 1024 * 1024
_MAX_INVENTORY_BYTES = 8 * 1024 * 1024
_SCHEMA = (
    """CREATE TABLE identity (
        id INTEGER PRIMARY KEY CHECK(id=1),
        binding TEXT NOT NULL,
        started_at_ns INTEGER NOT NULL CHECK(started_at_ns>0),
        deadline_ns INTEGER NOT NULL CHECK(deadline_ns>started_at_ns)
    ) STRICT""",
    """CREATE TABLE events (
        ordinal INTEGER PRIMARY KEY CHECK(ordinal>0),
        kind TEXT NOT NULL CHECK(kind IN ('reserve','stop','close')),
        observed_ns INTEGER NOT NULL CHECK(observed_ns>0),
        body TEXT NOT NULL
    ) STRICT""",
    """CREATE TABLE clock (
        id INTEGER PRIMARY KEY CHECK(id=1),
        observed_ns INTEGER NOT NULL CHECK(observed_ns>0)
    ) STRICT""",
    """CREATE TRIGGER clock_no_regression BEFORE UPDATE ON clock
        WHEN NEW.observed_ns < OLD.observed_ns
        BEGIN SELECT RAISE(ABORT, 'resource clock cannot regress'); END""",
    """CREATE TRIGGER clock_no_delete BEFORE DELETE ON clock
        BEGIN SELECT RAISE(ABORT, 'resource clock cannot be reset'); END""",
    """CREATE TRIGGER clock_no_replace BEFORE INSERT ON clock
        WHEN EXISTS(SELECT 1 FROM clock WHERE id=NEW.id)
        BEGIN SELECT RAISE(ABORT, 'resource clock cannot be replaced'); END""",
    """CREATE TRIGGER events_no_update BEFORE UPDATE ON events
        BEGIN SELECT RAISE(ABORT, 'resource history is immutable'); END""",
    """CREATE TRIGGER events_no_delete BEFORE DELETE ON events
        BEGIN SELECT RAISE(ABORT, 'resource reservations cannot be refunded'); END""",
    """CREATE TRIGGER events_no_replace BEFORE INSERT ON events
        WHEN EXISTS(SELECT 1 FROM events WHERE ordinal=NEW.ordinal)
        BEGIN SELECT RAISE(ABORT, 'resource event cannot be replaced'); END""",
    """CREATE TRIGGER identity_no_update BEFORE UPDATE ON identity
        BEGIN SELECT RAISE(ABORT, 'resource identity is immutable'); END""",
    """CREATE TRIGGER identity_no_delete BEFORE DELETE ON identity
        BEGIN SELECT RAISE(ABORT, 'resource identity is immutable'); END""",
    """CREATE TRIGGER identity_no_replace BEFORE INSERT ON identity
        WHEN EXISTS(SELECT 1 FROM identity WHERE id=NEW.id)
        BEGIN SELECT RAISE(ABORT, 'resource identity cannot be replaced'); END""",
)
_SCHEMA_V2 = (
    """CREATE TABLE identity (
        id INTEGER PRIMARY KEY CHECK(id=1),
        binding TEXT NOT NULL,
        boot_domain_sha256 TEXT NOT NULL,
        started_at_ns INTEGER NOT NULL CHECK(started_at_ns>0),
        deadline_ns INTEGER NOT NULL CHECK(deadline_ns>started_at_ns)
    ) STRICT""",
    *_SCHEMA[1:],
)
_STOP_REASONS = frozenset(
    {
        "elapsed_limit",
        "spend_limit",
        "request_limit",
        "clock_regression",
        "operator_stop",
        "controller_failure",
    }
)
_STOP_REASONS_V2 = _STOP_REASONS | {"clock_untrusted"}


class ResourceBudgetError(RunRequestBudgetError):
    """Resource history cannot safely authorize a dispatch or closure."""


class ResourceBudgetStopped(ResourceBudgetError):
    """The run is durably stopped; cleanup remains allowed."""


def _now_ns() -> int:
    return time.time_ns()


def _clock() -> int:
    now = _now_ns()
    if type(now) is not int or not 0 < now < 2**63 - 1:
        raise ResourceBudgetError("invalid controller clock")
    return now


@dataclass(frozen=True, slots=True)
class BootUptimeSample:
    """Provisional caller sample; this type does not authenticate a boot or clock.

    The caller must independently prove that the digest identifies this boot
    and that the uptime nanoseconds include suspend time. This component only
    checks the sample's shape and continuity, and grants no effect permission.
    """

    boot_domain_sha256: str
    uptime_ns: int


def _boot_sample(source: Callable[[], BootUptimeSample]) -> BootUptimeSample:
    try:
        sample = source()
    except Exception as error:
        raise ResourceBudgetError("boot clock source failed") from error
    if (
        type(sample) is not BootUptimeSample
        or not _digest(sample.boot_domain_sha256)
        or type(sample.uptime_ns) is not int
        or not 0 < sample.uptime_ns < 2**63 - 1
    ):
        raise ResourceBudgetError("invalid boot clock sample")
    return sample


def _binding(budget, authority, metering) -> str:
    if type(budget) is not VerifiedSubsetBudget or type(metering) is not VerifiedMeteringPolicy:
        raise ResourceBudgetError("verified signed budget and metering required")
    budget.reverify(authority)
    metering.reverify()
    if (
        budget.metering_policy_sha256 != metering.sha256
        or budget.model_policy_sha256 != metering.model_policy_sha256
    ):
        raise ResourceBudgetError("signed budget and metering binding mismatch")
    return _json_bytes(
        {
            "budget_envelope_sha256": budget.envelope_sha256,
            "budget_payload": json.loads(budget.payload_json),
            "metering_policy": json.loads(metering.policy_json),
            "required_dispatch_bounds": [
                asdict(bound) for bound in metering.required_dispatch_bounds
            ],
        }
    ).decode()


@dataclass(frozen=True, slots=True)
class RunResourceBudget:
    _path: Path
    _budget: VerifiedSubsetBudget
    _metering: VerifiedMeteringPolicy
    _bound_identity: str
    _file_identity: tuple[int, int]
    _schema_version: int = field(default=1, repr=False, compare=False)
    _boot_clock_source: Callable[[], BootUptimeSample] | None = field(
        default=None, repr=False, compare=False
    )
    _write_failed: bool = field(default=False, init=False, repr=False, compare=False)

    @classmethod
    def create(
        cls,
        path: str | Path,
        *,
        budget: VerifiedSubsetBudget,
        authority: CampaignAuthority,
        metering: VerifiedMeteringPolicy,
    ) -> RunResourceBudget:
        """Persist the clock before preparation, without overwriting any prior state."""
        binding = _binding(budget, authority, metering)
        path = Path(path)
        started = _clock()
        deadline = started + budget.max_elapsed_seconds * _NS
        if deadline >= 2**63 - 1:
            raise ResourceBudgetError("aggregate deadline exceeds supported clock range")
        try:
            _private_path(path, required=False)
            for suffix in ("-journal", "-wal", "-shm"):
                if path.with_name(path.name + suffix).exists():
                    raise ResourceBudgetError("existing SQLite sidecar prevents creation")
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
            info = path.stat()
            ledger = cls(path, budget, metering, binding, (info.st_dev, info.st_ino))
            with ledger._transaction(write=True) as connection:
                for statement in _SCHEMA:
                    connection.execute(statement)
                connection.execute(f"PRAGMA application_id={_APPLICATION_ID}")
                connection.execute("PRAGMA user_version=1")
                connection.execute(
                    "INSERT INTO identity VALUES(1,?,?,?)", (binding, started, deadline)
                )
                connection.execute("INSERT INTO clock VALUES(1,?)", (started,))
            if os.name == "posix":
                directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            return ledger
        except OSError as error:
            raise ResourceBudgetError("cannot exclusively create resource budget store") from error

    @classmethod
    def open(
        cls,
        path: str | Path,
        *,
        budget: VerifiedSubsetBudget,
        authority: CampaignAuthority,
        metering: VerifiedMeteringPolicy,
    ) -> RunResourceBudget:
        """Re-attest immutable inputs and retained history; never reset the clock."""
        binding = _binding(budget, authority, metering)
        path = Path(path)
        try:
            info = _private_path(path, required=True)
            assert info is not None
            ledger = cls(path, budget, metering, binding, (info.st_dev, info.st_ino))
            ledger.snapshot()
            return ledger
        except OSError as error:
            raise ResourceBudgetError("cannot open resource budget store") from error

    @classmethod
    def create_v2(
        cls,
        path: str | Path,
        *,
        budget: VerifiedSubsetBudget,
        authority: CampaignAuthority,
        metering: VerifiedMeteringPolicy,
        clock_source: Callable[[], BootUptimeSample],
    ) -> RunResourceBudget:
        """Create a separate boot-uptime schema before preparation.

        ``clock_source`` is a provisional input, not independent boot authority.
        No provider, worker or remote effect may be authorized by this method.
        """
        binding = _binding(budget, authority, metering)
        if not callable(clock_source):
            raise ResourceBudgetError("boot clock source required")
        path = Path(path)
        try:
            _private_path(path, required=False)
            for suffix in ("-journal", "-wal", "-shm"):
                if path.with_name(path.name + suffix).exists():
                    raise ResourceBudgetError("existing SQLite sidecar prevents creation")
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
            info = path.stat()
            ledger = cls(
                path, budget, metering, binding, (info.st_dev, info.st_ino), 2, clock_source
            )
            with ledger._transaction(write=True) as connection:
                sample = _boot_sample(clock_source)
                deadline = sample.uptime_ns + budget.max_elapsed_seconds * _NS
                if deadline >= 2**63 - 1:
                    raise ResourceBudgetError("aggregate deadline exceeds supported clock range")
                for statement in _SCHEMA_V2:
                    connection.execute(statement)
                connection.execute(f"PRAGMA application_id={_APPLICATION_ID}")
                connection.execute("PRAGMA user_version=2")
                connection.execute(
                    "INSERT INTO identity VALUES(1,?,?,?,?)",
                    (binding, sample.boot_domain_sha256, sample.uptime_ns, deadline),
                )
                connection.execute("INSERT INTO clock VALUES(1,?)", (sample.uptime_ns,))
            if os.name == "posix":
                directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            return ledger
        except OSError as error:
            raise ResourceBudgetError("cannot exclusively create resource budget store") from error

    @classmethod
    def open_v2(
        cls,
        path: str | Path,
        *,
        budget: VerifiedSubsetBudget,
        authority: CampaignAuthority,
        metering: VerifiedMeteringPolicy,
        clock_source: Callable[[], BootUptimeSample],
    ) -> RunResourceBudget:
        """Open v2 for read or accounting; permission calls resample inside writes."""
        binding = _binding(budget, authority, metering)
        if not callable(clock_source):
            raise ResourceBudgetError("boot clock source required")
        path = Path(path)
        try:
            info = _private_path(path, required=True)
            assert info is not None
            ledger = cls(
                path, budget, metering, binding, (info.st_dev, info.st_ino), 2, clock_source
            )
            # This is historical attestation only. It deliberately does not
            # sample the current boot, so evidence remains readable after a
            # boot change or clock-source failure. Mutations must sample.
            ledger.snapshot()
            return ledger
        except OSError as error:
            raise ResourceBudgetError("cannot open resource budget store") from error

    @contextmanager
    def _transaction(self, *, write: bool) -> Iterator[sqlite3.Connection]:
        connection = None
        try:
            if write and self._write_failed:
                raise ResourceBudgetError("resource budget handle has a prior write failure")
            info = _private_path(self._path, required=True)
            assert info is not None
            if (info.st_dev, info.st_ino) != self._file_identity:
                raise ResourceBudgetError("resource budget store identity changed")
            for suffix in ("-journal", "-wal", "-shm"):
                _private_path(self._path.with_name(self._path.name + suffix), required=False)
            connection = sqlite3.connect(
                self._path.as_uri() + "?mode=rw", uri=True, timeout=30, isolation_level=None
            )
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            if write and self._write_failed:
                raise ResourceBudgetError("resource budget handle has a prior write failure")
            yield connection
            connection.commit()
        except (OSError, sqlite3.Error) as error:
            if write:
                object.__setattr__(self, "_write_failed", True)
            raise ResourceBudgetError("resource budget store operation failed") from error
        except RunRequestBudgetError as error:
            if isinstance(
                error, (ResourceBudgetError, RequestBudgetExceeded, DuplicateRequestReservation)
            ):
                raise
            raise ResourceBudgetError(str(error)) from error
        finally:
            if connection is not None:
                connection.close()

    def _validate_store(self, connection: sqlite3.Connection) -> tuple[int, int, int, str | None]:
        schema = {
            row[0]
            for row in connection.execute("SELECT sql FROM sqlite_schema WHERE sql IS NOT NULL")
        }
        if (
            schema != set(_SCHEMA_V2 if self._schema_version == 2 else _SCHEMA)
            or connection.execute("PRAGMA user_version").fetchone()[0] != self._schema_version
            or connection.execute("PRAGMA application_id").fetchone()[0] != _APPLICATION_ID
        ):
            raise ResourceBudgetError("resource budget schema mismatch")
        if connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise ResourceBudgetError("corrupt resource budget store")
        if self._schema_version == 2:
            identity = connection.execute(
                "SELECT binding,boot_domain_sha256,started_at_ns,deadline_ns "
                "FROM identity ORDER BY id"
            ).fetchall()
        else:
            identity = connection.execute(
                "SELECT binding,started_at_ns,deadline_ns FROM identity ORDER BY id"
            ).fetchall()
        if len(identity) != 1 or identity[0][0] != self._bound_identity:
            raise ResourceBudgetError("resource budget identity mismatch")
        if self._schema_version == 2:
            _, boot_domain_sha256, started, deadline = identity[0]
            if not _digest(boot_domain_sha256):
                raise ResourceBudgetError("invalid resource boot identity")
        else:
            _, started, deadline = identity[0]
            boot_domain_sha256 = None
        if deadline != started + self._budget.max_elapsed_seconds * _NS:
            raise ResourceBudgetError("resource budget deadline mismatch")
        clocks = connection.execute("SELECT observed_ns FROM clock ORDER BY id").fetchall()
        if len(clocks) != 1 or clocks[0][0] < started:
            raise ResourceBudgetError("invalid resource clock high-watermark")
        return started, deadline, clocks[0][0], boot_domain_sha256

    def _snapshot(self, connection: sqlite3.Connection) -> dict:
        started, deadline, observed_clock, boot_domain_sha256 = self._validate_store(connection)
        state = {
            "run_id": self._budget.run_id,
            "epoch": self._budget.epoch,
            "budget_sha256": self._budget.envelope_sha256,
            "metering_policy_sha256": self._metering.sha256,
            "requests": 0,
            "spend_units": 0,
            "max_spend_units": self._budget.max_spend_units,
            "started_at_ns": started,
            "deadline_ns": deadline,
            "last_observed_ns": started,
            "tasks": {
                task: {"requests": 0, "primary_and_memory": 0, "deepseek_advisory": 0}
                for task in self._budget.task_ids
            },
            "attempts": {},
            "closures": {},
            "stop": None,
            "event_ordinal": 0,
        }
        if self._schema_version == 2:
            state.update(
                {
                    "schema_version": 2,
                    "clock_basis": "suspend_aware_uptime_ns",
                    "boot_domain_sha256": boot_domain_sha256,
                }
            )
        history = hashlib.sha256(self._bound_identity.encode()).digest()
        request_ids = set()
        attempt_tasks = {}
        for ordinal, kind, observed, body_json in connection.execute(
            "SELECT * FROM events ORDER BY ordinal"
        ):
            try:
                body = json.loads(body_json)
                if type(body) is not dict or _json_bytes(body).decode() != body_json:
                    raise ValueError("noncanonical event")
                if ordinal != state["event_ordinal"] + 1 or observed < state["last_observed_ns"]:
                    raise ValueError("event order or clock regression")
                if kind == "reserve":
                    if state["stop"] is not None or observed >= deadline:
                        raise ValueError("dispatch after stop or deadline")
                    fields = {
                        "run_id",
                        "task_id",
                        "attempt_id",
                        "request_id",
                        "allocation",
                        "run_ordinal",
                        "task_ordinal",
                        "allocation_ordinal",
                        "charge_units",
                    }
                    if set(body) != fields:
                        raise ValueError("reservation fields")
                    task, attempt, request, allocation = (
                        body[key] for key in ("task_id", "attempt_id", "request_id", "allocation")
                    )
                    _identifier(attempt, "attempt")
                    _identifier(request, "request")
                    if (
                        task not in state["tasks"]
                        or task in state["closures"]
                        or request in request_ids
                        or allocation not in _ALLOCATION_LIMITS
                        or body["run_id"] != self._budget.run_id
                        or state["attempts"].get(task, attempt) != attempt
                        or attempt_tasks.get(attempt, task) != task
                    ):
                        raise ValueError("reservation identity")
                    counts = state["tasks"][task]
                    expected = {
                        "run_ordinal": state["requests"] + 1,
                        "task_ordinal": counts["requests"] + 1,
                        "allocation_ordinal": counts[allocation] + 1,
                        "charge_units": self._metering.charge(allocation),
                    }
                    if (
                        any(
                            type(body[key]) is not int or body[key] != value
                            for key, value in expected.items()
                        )
                        or expected["run_ordinal"] > 15000
                        or expected["task_ordinal"] > 1500
                        or expected["allocation_ordinal"] > _ALLOCATION_LIMITS[allocation]
                        or state["spend_units"] + body["charge_units"]
                        > self._budget.max_spend_units
                    ):
                        raise ValueError("reservation limits or ordinals")
                    state["requests"] += 1
                    state["spend_units"] += body["charge_units"]
                    counts["requests"] += 1
                    counts[allocation] += 1
                    state["attempts"][task] = attempt
                    attempt_tasks[attempt] = task
                    request_ids.add(request)
                    history = hashlib.sha256(history + _json_bytes(body)).digest()
                elif kind == "stop":
                    if (
                        set(body) != {"reason"}
                        or body["reason"]
                        not in (_STOP_REASONS_V2 if self._schema_version == 2 else _STOP_REASONS)
                        or state["stop"] is not None
                    ):
                        raise ValueError("invalid stop history")
                    state["stop"] = body | {"observed_ns": observed, "event_ordinal": ordinal}
                elif kind == "close":
                    fields = {
                        "task_id",
                        "attempt_id",
                        "completion_sha256",
                        "accounting_sha256",
                        "run_ordinal",
                        "task_ordinal",
                        "spend_units",
                    }
                    if set(body) != fields:
                        raise ValueError("closure fields")
                    task, attempt = body["task_id"], body["attempt_id"]
                    _identifier(attempt, "attempt")
                    if (
                        task not in state["tasks"]
                        or task in state["closures"]
                        or state["attempts"].get(task, attempt) != attempt
                        or attempt_tasks.get(attempt, task) != task
                        or not _digest(body["completion_sha256"])
                        or body["accounting_sha256"] != history.hex()
                        or any(
                            type(body[key]) is not int
                            for key in ("run_ordinal", "task_ordinal", "spend_units")
                        )
                        or body["run_ordinal"] != state["requests"]
                        or body["task_ordinal"] != state["tasks"][task]["requests"]
                        or body["spend_units"] != state["spend_units"]
                    ):
                        raise ValueError("closure accounting or identity")
                    state["closures"][task] = body
                    state["attempts"][task] = attempt
                    attempt_tasks[attempt] = task
                else:
                    raise ValueError("unknown event")
            except (ValueError, TypeError, KeyError) as error:
                raise ResourceBudgetError("invalid resource budget history") from error
            state["event_ordinal"] = ordinal
            state["last_observed_ns"] = observed
        state["accounting_sha256"] = history.hex()
        if observed_clock < state["last_observed_ns"]:
            raise ResourceBudgetError("resource clock precedes immutable history")
        state["last_observed_ns"] = observed_clock
        return state

    def snapshot(self) -> dict:
        """Read authoritative accounting; this read alone grants no dispatch permission."""
        with self._transaction(write=False) as connection:
            return self._snapshot(connection)

    def read_attempt_debits(self, *, task_id: str, attempt_id: str) -> bytes:
        """Inventory durable debits; never infer dispatch, usage, or settlement.

        An empty inventory proves only that this resource store has no reservation
        for the supplied identity. It does not prove that no provider effect occurred.
        The accounting watermark and rows come from one validated read transaction.
        """
        if type(task_id) is not str or task_id not in self._budget.task_ids:
            raise ValueError("task is outside this resource budget")
        _identifier(attempt_id, "attempt")
        with self._transaction(write=False) as connection:
            count, largest, total = connection.execute(
                "SELECT COUNT(*), MAX(length(CAST(body AS BLOB))), "
                "SUM(length(CAST(body AS BLOB))) FROM events"
            ).fetchone()
            if (
                count > _MAX_HISTORY_EVENTS
                or (largest or 0) > _MAX_EVENT_BODY_BYTES
                or (total or 0) > _MAX_HISTORY_BODY_BYTES
            ):
                raise ResourceBudgetError("resource budget history exceeds bounded inventory read")
            state = self._snapshot(connection)
            prior_attempt = state["attempts"].get(task_id)
            if prior_attempt is not None and prior_attempt != attempt_id:
                raise ResourceBudgetError("resource budget attempt identity differs")
            reservations = []
            for (body_json,) in connection.execute(
                "SELECT body FROM events WHERE kind='reserve' ORDER BY ordinal"
            ):
                body = json.loads(body_json)
                if body["task_id"] != task_id:
                    continue
                reservations.append(
                    {
                        key: body[key]
                        for key in (
                            "request_id",
                            "allocation",
                            "run_ordinal",
                            "task_ordinal",
                            "allocation_ordinal",
                            "charge_units",
                        )
                    }
                )
            inventory = _json_bytes(
                {
                    "schema_version": 1,
                    "scope": "resource_reservation_inventory_only",
                    "run_id": state["run_id"],
                    "epoch": state["epoch"],
                    "budget_sha256": state["budget_sha256"],
                    "metering_policy_sha256": state["metering_policy_sha256"],
                    "task_id": task_id,
                    "attempt_id": attempt_id,
                    "accounting_sha256": state["accounting_sha256"],
                    "event_ordinal": state["event_ordinal"],
                    "provider_dispatch": "not_assessed",
                    "provider_usage": "not_assessed",
                    "reservations": reservations,
                }
            )
            if len(inventory) > _MAX_INVENTORY_BYTES:
                raise ResourceBudgetError("resource debit inventory exceeds bounded output")
            return inventory

    @staticmethod
    def _advance_clock(connection, state, now):
        observed = max(now, state["last_observed_ns"])
        if observed > state["last_observed_ns"]:
            connection.execute("UPDATE clock SET observed_ns=? WHERE id=1", (observed,))
        state["last_observed_ns"] = observed

    @staticmethod
    def _append(connection, state, kind, now, body):
        connection.execute(
            "INSERT INTO events VALUES(?,?,?,?)",
            (
                state["event_ordinal"] + 1,
                kind,
                max(now, state["last_observed_ns"]),
                _json_bytes(body).decode(),
            ),
        )
        state["event_ordinal"] += 1
        RunResourceBudget._advance_clock(connection, state, now)

    def _observed_clock(self, connection, state) -> tuple[int, str | None]:
        if self._schema_version == 1:
            return _clock(), None
        try:
            assert self._boot_clock_source is not None
            sample = _boot_sample(self._boot_clock_source)
            if (
                sample.boot_domain_sha256 != state["boot_domain_sha256"]
                or sample.uptime_ns < state["last_observed_ns"]
            ):
                raise ResourceBudgetError("boot clock changed or regressed")
        except (ResourceBudgetError, AssertionError):
            # The last trusted tick is the only honest time we can record.
            # Commit this stop before reporting it to the caller. If commit
            # fails, _transaction denies the operation without claiming that
            # the stop became durable.
            if state["stop"] is None:
                self._append(
                    connection,
                    state,
                    "stop",
                    state["last_observed_ns"],
                    {"reason": "clock_untrusted"},
                )
                return state["last_observed_ns"], "clock_untrusted"
            return state["last_observed_ns"], state["stop"]["reason"]
        return sample.uptime_ns, None

    def _check(self, connection, state, *, now: int, charge: int = 0) -> str | None:
        if state["stop"] is not None:
            return state["stop"]["reason"]
        reason = None
        if now < state["last_observed_ns"]:
            reason = "clock_regression"
        elif now >= state["deadline_ns"]:
            reason = "elapsed_limit"
        elif state["requests"] >= 15000:
            reason = "request_limit"
        elif (
            state["spend_units"] >= self._budget.max_spend_units
            or state["spend_units"] + charge > self._budget.max_spend_units
        ):
            reason = "spend_limit"
        if reason:
            self._append(connection, state, "stop", now, {"reason": reason})
        return reason

    def remaining_seconds(self) -> float:
        """Persist clock checks; downtime, preparation and cleanup consume elapsed time."""
        with self._transaction(write=True) as connection:
            # Full validation also catches same-ordinal content corruption.
            # History is bounded by 15,000 reservations, ten closures and one
            # stop. Clock polls update one row rather than extending history.
            state = self._snapshot(connection)
            now, untrusted = self._observed_clock(connection, state)
            reason = untrusted or self._check(connection, state, now=now)
            # Owned cleanup remains observable after a stop. Retain its elapsed
            # time without changing the original immutable stopping reason.
            self._advance_clock(connection, state, now)
        if reason:
            raise ResourceBudgetStopped(f"run stopped: {reason}")
        return (state["deadline_ns"] - now) / _NS

    def check_active(self) -> None:
        """Call before each stage/start/Send; never use to forbid owned cleanup."""
        self.remaining_seconds()

    def stop(self, *, reason: str) -> None:
        """Persist a controller stop without changing any task's terminal meaning."""
        if reason not in {"operator_stop", "controller_failure"}:
            raise ValueError("explicit controller stop reason required")
        untrusted = None
        with self._transaction(write=True) as connection:
            state = self._snapshot(connection)
            if state["stop"] is None:
                now, untrusted = self._observed_clock(connection, state)
                if untrusted is None:
                    self._append(connection, state, "stop", now, {"reason": reason})
            elif self._schema_version == 2 and state["stop"]["reason"] == "clock_untrusted":
                untrusted = "clock_untrusted"
        if untrusted:
            raise ResourceBudgetStopped(f"run stopped: {untrusted}")

    def reserve(
        self, *, task_id: str, attempt_id: str, request_id: str, allocation: Allocation
    ) -> RequestReservation:
        """Atomically reserve one request and its frozen conservative maximum charge."""
        for value, label in ((task_id, "task"), (attempt_id, "attempt"), (request_id, "request")):
            _identifier(value, label)
        if (
            task_id not in self._budget.task_ids
            or type(allocation) is not str
            or allocation not in _ALLOCATION_LIMITS
        ):
            raise ValueError("task or allocation outside this run")
        reservation = None
        with self._transaction(write=True) as connection:
            state = self._snapshot(connection)
            if task_id in state["closures"]:
                raise ResourceBudgetError("task accounting is closed")
            if state["attempts"].get(task_id, attempt_id) != attempt_id or any(
                task != task_id and attempt == attempt_id
                for task, attempt in state["attempts"].items()
            ):
                raise ResourceBudgetError("attempt identity changed or belongs to another task")
            for (body,) in connection.execute("SELECT body FROM events WHERE kind='reserve'"):
                if json.loads(body)["request_id"] == request_id:
                    raise DuplicateRequestReservation("request ID already reserved")
            counts = state["tasks"][task_id]
            now, untrusted = self._observed_clock(connection, state)
            charge = self._metering.charge(allocation)
            # A global stop takes precedence over a full task/allocation. Local
            # exhaustion alone must leave the other allocation and tasks usable.
            reason = untrusted or self._check(connection, state, now=now)
            if reason is None:
                if counts["requests"] >= 1500:
                    raise RequestBudgetExceeded("task request budget exhausted")
                if counts[allocation] >= _ALLOCATION_LIMITS[allocation]:
                    raise RequestBudgetExceeded("allocation request budget exhausted")
                reason = self._check(connection, state, now=now, charge=charge)
            if reason is None:
                reservation = RequestReservation(
                    self._budget.run_id,
                    task_id,
                    attempt_id,
                    request_id,
                    allocation,
                    state["requests"] + 1,
                    counts["requests"] + 1,
                    counts[allocation] + 1,
                )
                self._append(
                    connection,
                    state,
                    "reserve",
                    now,
                    asdict(reservation) | {"charge_units": charge},
                )
        if reason:
            raise ResourceBudgetStopped(f"run stopped: {reason}")
        assert reservation is not None
        return reservation

    def close_task(
        self,
        *,
        task_id: str,
        attempt_id: str,
        completion_sha256: str,
        expected_accounting_sha256: str,
    ) -> None:
        """Atomically close only after external verification of signed quiescence."""
        _identifier(attempt_id, "attempt")
        if (
            task_id not in self._budget.task_ids
            or not _digest(completion_sha256)
            or not _digest(expected_accounting_sha256)
        ):
            raise ValueError("exact task and verified completion/accounting digests required")
        untrusted = None
        with self._transaction(write=True) as connection:
            state = self._snapshot(connection)
            if task_id in state["closures"]:
                raise ResourceBudgetError("task accounting is already closed")
            if state["attempts"].get(task_id, attempt_id) != attempt_id or any(
                task != task_id and attempt == attempt_id
                for task, attempt in state["attempts"].items()
            ):
                raise ResourceBudgetError("closure attempt identity mismatch")
            if expected_accounting_sha256 != state["accounting_sha256"]:
                raise ResourceBudgetError("closure accounting changed after signed quiescence")
            now, untrusted = self._observed_clock(connection, state)
            if untrusted is None:
                self._check(connection, state, now=now)
                self._append(
                    connection,
                    state,
                    "close",
                    now,
                    {
                        "task_id": task_id,
                        "attempt_id": attempt_id,
                        "completion_sha256": completion_sha256,
                        "accounting_sha256": expected_accounting_sha256,
                        "run_ordinal": state["requests"],
                        "task_ordinal": state["tasks"][task_id]["requests"],
                        "spend_units": state["spend_units"],
                    },
                )
        if untrusted:
            raise ResourceBudgetStopped(f"run stopped: {untrusted}")
