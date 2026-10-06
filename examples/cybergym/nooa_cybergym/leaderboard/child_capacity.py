# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Durable shared capacity for native and controller-side advisory children.

Native capacity is fungible within an observed child type. The native start hook
does not expose its spawning provider tool ID, so this ledger deliberately does
not claim a tool-to-agent identity mapping. Unique provider tool IDs deduplicate
reservations; unique native child IDs track active capacity independently.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from .deepseek import DeepSeekRole

NATIVE_TYPES = frozenset({"cybergym-recon", "cybergym-debug", "cybergym-review"})


def _identifier(value):
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}", value):
        raise ValueError("child capacity identifier invalid")
    return value


class ChildCapacity:
    def __init__(
        self, database: Path, *, run_id: str, task_id: str, attempt_id: str, launch_id: str
    ):
        self.database = Path(database)
        self.identity = {
            key: _identifier(value)
            for key, value in {
                "run_id": run_id,
                "task_id": task_id,
                "attempt_id": attempt_id,
                "launch_id": launch_id,
            }.items()
        }
        identity = json.dumps(
            {**self.identity, "max_children": 3, "native_pairing": "unavailable_fungible_capacity"},
            sort_keys=True,
        )
        with self._connect() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS identity(id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS reservations(tool_id TEXT PRIMARY KEY, agent_type TEXT NOT NULL, consumed INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS workflows(tool_id TEXT PRIMARY KEY, script_sha256 TEXT NOT NULL, agent_types TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS workflow_slots(id INTEGER PRIMARY KEY, tool_id TEXT NOT NULL, agent_type TEXT NOT NULL, consumed INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS native_children(agent_id TEXT PRIMARY KEY, agent_type TEXT NOT NULL, closed INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS advisors(role TEXT PRIMARY KEY, closed INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS events(sequence INTEGER PRIMARY KEY, kind TEXT NOT NULL, payload TEXT NOT NULL);
            """)
            connection.execute("INSERT OR IGNORE INTO identity VALUES(1,?)", (identity,))
            if connection.execute("SELECT payload FROM identity").fetchone()[0] != identity:
                raise ValueError("child capacity database belongs to another task")

    def _verify_path(self):
        if (
            not self.database.is_absolute()
            or self.database.parent.resolve() != self.database.parent
            or not self.database.parent.is_dir()
            or (os.name == "posix" and self.database.parent.stat().st_mode & 0o022)
        ):
            raise ValueError("private absolute controller child capacity database required")
        for suffix in ("", "-journal", "-wal", "-shm"):
            path = self.database.with_name(self.database.name + suffix)
            if path.is_symlink() or (
                path.exists() and (not path.is_file() or path.stat().st_nlink != 1)
            ):
                raise ValueError("child capacity database cannot contain links")

    @contextmanager
    def _connect(self):
        self._verify_path()
        connection = sqlite3.connect(self.database, timeout=15)
        try:
            connection.execute("PRAGMA synchronous=FULL")
            with connection:
                yield connection
        finally:
            connection.close()

    @staticmethod
    def _snapshot(connection):
        counts = {
            "pending_native": connection.execute(
                "SELECT (SELECT count(*) FROM reservations WHERE consumed=0) + (SELECT count(*) FROM workflow_slots WHERE consumed=0)"
            ).fetchone()[0],
            "active_native": connection.execute(
                "SELECT count(*) FROM native_children WHERE closed=0"
            ).fetchone()[0],
            "active_advisory": connection.execute(
                "SELECT count(*) FROM advisors WHERE closed=0"
            ).fetchone()[0],
        }
        return {**counts, "occupied": sum(counts.values())}

    def snapshot(self):
        with self._connect() as connection:
            return self._snapshot(connection)

    def _require_capacity(self, connection):
        if self._snapshot(connection)["occupied"] >= 3:
            raise RuntimeError("shared child capacity exhausted")

    @staticmethod
    def _record(connection, kind, payload):
        connection.execute(
            "INSERT INTO events(kind,payload) VALUES(?,?)",
            (kind, json.dumps(payload, sort_keys=True)),
        )

    def reserve_native(self, tool_id: str, agent_type: str) -> None:
        _identifier(tool_id)
        if agent_type not in NATIVE_TYPES:
            raise ValueError("unfrozen native child type")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute("SELECT 1 FROM workflows WHERE tool_id=?", (tool_id,)).fetchone():
                raise ValueError("provider tool ID already reserved as Workflow")
            prior = connection.execute(
                "SELECT agent_type FROM reservations WHERE tool_id=?", (tool_id,)
            ).fetchone()
            if prior is not None:
                if prior[0] != agent_type:
                    raise ValueError("native reservation type changed")
                return
            self._require_capacity(connection)
            connection.execute(
                "INSERT INTO reservations(tool_id,agent_type) VALUES(?,?)", (tool_id, agent_type)
            )
            self._record(
                connection,
                "native_capacity_reserved",
                {"tool_id": tool_id, "agent_type": agent_type},
            )

    def reserve_workflow(
        self, tool_id: str, script_sha256: str, agent_types: tuple[str, ...]
    ) -> None:
        """Reserve the actual frozen script's child calls before allowing Workflow.

        The capability gate must have verified this exact immutable script digest.
        These are Workflow capacity tokens, never invented Agent provider calls.
        Ambiguous failures retain unconsumed capacity; the attempt must abort.
        """
        _identifier(tool_id)
        if (
            not re.fullmatch(r"[a-f0-9]{64}", script_sha256)
            or type(agent_types) is not tuple
            or not 1 <= len(agent_types) <= 3
            or any(kind not in NATIVE_TYPES for kind in agent_types)
        ):
            raise ValueError("invalid frozen Workflow child declaration")
        declaration = json.dumps(agent_types)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute(
                "SELECT 1 FROM reservations WHERE tool_id=?", (tool_id,)
            ).fetchone():
                raise ValueError("provider tool ID already reserved as Agent")
            prior = connection.execute(
                "SELECT script_sha256,agent_types FROM workflows WHERE tool_id=?", (tool_id,)
            ).fetchone()
            if prior is not None:
                if prior != (script_sha256, declaration):
                    raise ValueError("Workflow reservation declaration changed")
                return
            if self._snapshot(connection)["occupied"] + len(agent_types) > 3:
                raise RuntimeError("shared child capacity exhausted")
            connection.execute(
                "INSERT INTO workflows VALUES(?,?,?)", (tool_id, script_sha256, declaration)
            )
            connection.executemany(
                "INSERT INTO workflow_slots(tool_id,agent_type) VALUES(?,?)",
                ((tool_id, kind) for kind in agent_types),
            )
            self._record(
                connection,
                "workflow_capacity_reserved",
                {
                    "tool_id": tool_id,
                    "script_sha256": script_sha256,
                    "agent_types": agent_types,
                    "provider_tool_pairing": "unavailable_fungible_capacity",
                },
            )

    def bind_native(self, agent_id: str, agent_type: str) -> None:
        _identifier(agent_id)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            prior = connection.execute(
                "SELECT agent_type,closed FROM native_children WHERE agent_id=?", (agent_id,)
            ).fetchone()
            if prior is not None:
                if prior[1] or prior[0] != agent_type:
                    raise ValueError("native child terminal or type changed")
                return
            # Selecting one capacity token is bookkeeping, not evidence that the
            # selected provider call spawned this agent. No such link is stored.
            pending = connection.execute(
                "SELECT tool_id FROM reservations WHERE agent_type=? AND consumed=0 ORDER BY rowid LIMIT 1",
                (agent_type,),
            ).fetchone()
            if pending is None:
                workflow = connection.execute(
                    "SELECT id FROM workflow_slots WHERE agent_type=? AND consumed=0 ORDER BY id LIMIT 1",
                    (agent_type,),
                ).fetchone()
                if workflow is None:
                    raise ValueError("native child lacks reserved pending capacity")
                connection.execute("UPDATE workflow_slots SET consumed=1 WHERE id=?", workflow)
            else:
                connection.execute("UPDATE reservations SET consumed=1 WHERE tool_id=?", pending)
            connection.execute(
                "INSERT INTO native_children(agent_id,agent_type) VALUES(?,?)",
                (agent_id, agent_type),
            )
            self._record(
                connection,
                "native_capacity_bound",
                {
                    "agent_id": agent_id,
                    "agent_type": agent_type,
                    "provider_tool_pairing": "unavailable",
                },
            )

    def is_native_active(self, agent_id: str) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT closed FROM native_children WHERE agent_id=?", (agent_id,)
            ).fetchone()
            return row is not None and row[0] == 0

    def release_native(self, agent_id: str) -> None:
        _identifier(agent_id)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT closed FROM native_children WHERE agent_id=?", (agent_id,)
            ).fetchone()
            if row is None:
                raise ValueError("native child capacity absent")
            if row[0]:
                return
            connection.execute("UPDATE native_children SET closed=1 WHERE agent_id=?", (agent_id,))
            self._record(connection, "native_capacity_released", {"agent_id": agent_id})

    @contextmanager
    def advisory_slot(self, role: str):
        role = DeepSeekRole(role).value
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute("SELECT role FROM advisors WHERE role=?", (role,)).fetchone():
                raise ValueError("advisory child role already reserved")
            self._require_capacity(connection)
            connection.execute("INSERT INTO advisors(role) VALUES(?)", (role,))
            self._record(connection, "advisory_capacity_reserved", {"role": role})
        try:
            yield
        finally:
            # This synchronous controller lane has returned or raised. Process
            # death never executes finally, retaining the slot across restart.
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute("UPDATE advisors SET closed=1 WHERE role=?", (role,))
                self._record(connection, "advisory_capacity_released", {"role": role})
