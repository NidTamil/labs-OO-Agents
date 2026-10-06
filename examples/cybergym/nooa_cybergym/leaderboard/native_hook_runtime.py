# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Durable native hook observations, separate from trusted model admission.

The 2.1.289 binary exposes session_id, agent_id, tool_use_id and effort in
hooks and agent/parent headers in API calls. All originate in the agent
boundary: correlate them with captured provider tool streams/transcripts;
never promote these observations alone to TrustedAdmission.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import UUID

from .child_capacity import ChildCapacity
from .native_launcher import _canonical, _matches

HOOK_EVENTS = frozenset(
    {
        "SessionStart",
        "SessionEnd",
        "SubagentStart",
        "SubagentStop",
        "PreToolUse",
        "PostToolUse",
        "PostToolUseFailure",
        "Stop",
        "StopFailure",
    }
)
_MAX_NATIVE_SESSIONS = 8
_MAX_CONCURRENT_PREFLIGHT_SESSIONS = 3
_FIELDS = frozenset(
    {
        "hook_event_name",
        "session_id",
        "agent_id",
        "agent_type",
        "tool_name",
        "tool_use_id",
        "model",
        "source",
        "effort",
        "transcript_path",
        "agent_transcript_path",
        "cwd",
        "raw_input_sha256",
    }
)


def _text(value: object, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if not _matches(r"[A-Za-z0-9][A-Za-z0-9:_.\[\]/-]{0,255}", value):
        raise ValueError("native hook identifier is malformed")
    return value


def _transcript(value: object, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if (
        type(value) is not str
        or len(value) > 1024
        or not value.startswith("/home/agent/.claude/projects/")
        or not value.endswith(".jsonl")
        or str(PurePosixPath(value)) != value
        or ".." in PurePosixPath(value).parts
        or not re.fullmatch(r"[A-Za-z0-9/_.-]+", value)
    ):
        raise ValueError("native hook transcript path is outside task home")
    return value


def project_hook_input(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Keep lifecycle identifiers and hash the full input, excluding secret-bearing data."""
    if not isinstance(raw, Mapping) or raw.get("hook_event_name") not in HOOK_EVENTS:
        raise ValueError("unsupported native hook event")
    kind = raw["hook_event_name"]
    cwd = raw.get("cwd")
    if (
        type(cwd) is not str
        or not (cwd == "/workspace" or cwd.startswith("/workspace/"))
        or str(PurePosixPath(cwd)) != cwd
        or ".." in PurePosixPath(cwd).parts
    ):
        raise ValueError("native hook cwd is outside task workspace")
    result = {
        "hook_event_name": kind,
        "session_id": _text(raw.get("session_id")),
        "agent_id": _text(raw.get("agent_id"), optional=True),
        "agent_type": _text(raw.get("agent_type"), optional=True),
        "tool_name": _text(raw.get("tool_name"), optional=True),
        "tool_use_id": _text(raw.get("tool_use_id"), optional=True),
        "model": _text(raw.get("model"), optional=True),
        "source": _text(raw.get("source"), optional=True),
        "effort": _text((raw.get("effort") or {}).get("level"), optional=True),
        "transcript_path": _transcript(raw.get("transcript_path")),
        "agent_transcript_path": _transcript(raw.get("agent_transcript_path"), optional=True),
        "cwd": cwd,
        "raw_input_sha256": hashlib.sha256(_canonical(raw)).hexdigest(),
    }
    if kind.startswith("Subagent") and (not result["agent_id"] or not result["agent_type"]):
        raise ValueError("native child hook identity missing")
    if kind in {"PreToolUse", "PostToolUse", "PostToolUseFailure"} and (
        not result["tool_name"] or not result["tool_use_id"]
    ):
        raise ValueError("native tool hook identity missing")
    return result


def validate_projection(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _FIELDS:
        raise ValueError("invalid native hook projection")
    raw = dict(value)
    digest = raw.pop("raw_input_sha256")
    if not _matches(r"[a-f0-9]{64}", digest):
        raise ValueError("invalid native hook input digest")
    raw["effort"] = {"level": raw["effort"]} if raw["effort"] else None
    normalized = project_hook_input(raw)
    normalized["raw_input_sha256"] = digest
    return normalized


def native_request_identity(
    headers: Sequence[tuple[str, str]], body: Mapping[str, Any]
) -> dict[str, str | None]:
    """Extract only observed identity fields, never account/device identifiers or auth."""

    def header(name: str) -> str | None:
        values = [value for key, value in headers if key.lower() == name]
        if len(values) > 1:
            raise ValueError("ambiguous native identity header")
        return _text(values[0], optional=True) if values else None

    metadata = body.get("metadata") or {}
    user_id = metadata.get("user_id") if isinstance(metadata, Mapping) else None
    if type(user_id) is not str or len(user_id) > 8192:
        raise ValueError("native session metadata missing")
    try:
        parsed = json.loads(user_id)
    except ValueError:
        raise ValueError("native session metadata malformed") from None
    if type(parsed) is not dict:
        raise ValueError("native session metadata malformed")
    return {
        "session_id": _text(parsed.get("session_id")),
        "agent_id": header("x-claude-code-agent-id"),
        "parent_agent_id": header("x-claude-code-parent-agent-id"),
        "parent_session_id": _text(parsed.get("parent_session_id"), optional=True),
    }


class NativeHookCollector:
    """SQLite FULL-sync custody of lifecycle observations, surviving controller restart."""

    def __init__(
        self,
        database: Path,
        *,
        run_id: str,
        task_id: str,
        launch_id: str,
        capacity: ChildCapacity | None = None,
    ):
        self.database = Path(database)
        if (
            not self.database.is_absolute()
            or self.database.is_symlink()
            or self.database.parent.resolve() != self.database.parent
        ):
            raise ValueError("absolute controller hook database path required")
        self.identity = {"run_id": run_id, "task_id": task_id, "launch_id": launch_id}
        for value in self.identity.values():
            _text(value)
        if capacity is not None and (
            not isinstance(capacity, ChildCapacity)
            or any(capacity.identity[key] != value for key, value in self.identity.items())
        ):
            raise ValueError("same-task shared child capacity required")
        # None permits standalone observational collection only. Production
        # admission must supply the ledger shared with native grants/advisors.
        self.capacity = capacity
        database_identity = {
            **self.identity,
            "shared_child_capacity": str(capacity.database) if capacity else None,
        }
        with self._connect() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS identity (id INTEGER PRIMARY KEY CHECK(id=1), value BLOB NOT NULL);
                CREATE TABLE IF NOT EXISTS events (sequence INTEGER PRIMARY KEY, event_id TEXT UNIQUE NOT NULL, payload BLOB NOT NULL);
                CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, closed INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS model_session (id INTEGER PRIMARY KEY CHECK(id=1), session TEXT NOT NULL REFERENCES sessions(id));
                CREATE TABLE IF NOT EXISTS children (session TEXT NOT NULL, id TEXT NOT NULL, closed INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(session,id));
                CREATE TABLE IF NOT EXISTS tools (session TEXT NOT NULL, agent TEXT NOT NULL, id TEXT NOT NULL, name TEXT NOT NULL, closed INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(session,agent,id));
            """)
            connection.execute(
                "INSERT OR IGNORE INTO identity VALUES (1,?)", (_canonical(database_identity),)
            )
            if connection.execute("SELECT value FROM identity").fetchone()[0] != _canonical(
                database_identity
            ):
                raise ValueError("hook database belongs to another launch")

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(self.database, timeout=15)
        try:
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA foreign_keys=ON")
            with connection:
                yield connection
        finally:
            connection.close()

    def ingest(self, observation: Mapping[str, Any]) -> dict[str, Any]:
        required = {"schema_version", "event_id", "run_id", "task_id", "launch_id", "hook"}
        if (
            not isinstance(observation, Mapping)
            or set(observation) != required
            or type(observation["schema_version"]) is not int
            or observation["schema_version"] != 1
            or any(observation[key] != value for key, value in self.identity.items())
        ):
            raise ValueError("native hook launch identity mismatch")
        if str(UUID(observation["event_id"])) != observation["event_id"]:
            raise ValueError("native hook event UUID malformed")
        hook = validate_projection(observation["hook"])
        payload = _canonical({**observation, "hook": hook})
        kind = hook["hook_event_name"]
        session = hook["session_id"]
        agent = hook["agent_id"] or ""
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            prior = connection.execute(
                "SELECT payload FROM events WHERE event_id=?", (observation["event_id"],)
            ).fetchone()
            if prior:
                if prior[0] != payload:
                    raise ValueError("native hook event UUID changed payload")
                return {"status": "duplicate"}
            existing = connection.execute(
                "SELECT closed FROM sessions WHERE id=?", (session,)
            ).fetchone()
            if kind == "SessionStart":
                if agent:
                    raise ValueError("session start cannot claim child identity")
                if existing is None:
                    if connection.execute("SELECT session FROM model_session").fetchone():
                        raise ValueError("model session already selected")
                    if (
                        connection.execute("SELECT count(*) FROM sessions WHERE closed=0").fetchone()[0]
                        >= _MAX_CONCURRENT_PREFLIGHT_SESSIONS
                    ):
                        raise ValueError("concurrent preflight session bound exceeded")
                    if connection.execute("SELECT count(*) FROM sessions").fetchone()[0] >= _MAX_NATIVE_SESSIONS:
                        raise ValueError("preflight session bound exceeded")
                    if connection.execute("SELECT count(*) FROM children WHERE closed=0").fetchone()[0]:
                        raise ValueError("pending native child from preflight session")
                    if connection.execute("SELECT count(*) FROM tools WHERE closed=0").fetchone()[0]:
                        raise ValueError("pending native tool from preflight session")
                    connection.execute("INSERT INTO sessions(id) VALUES (?)", (session,))
                elif existing[0]:
                    raise ValueError("terminal native session cannot resume")
            else:
                if existing is None or existing[0]:
                    raise ValueError("native session absent or terminal")
                child = (
                    connection.execute(
                        "SELECT closed FROM children WHERE session=? AND id=?", (session, agent)
                    ).fetchone()
                    if agent
                    else None
                )
                if kind == "SubagentStart":
                    if child:
                        raise ValueError("native child already observed")
                    if (
                        connection.execute(
                            "SELECT count(*) FROM children WHERE session=? AND closed=0", (session,)
                        ).fetchone()[0]
                        >= 3
                    ):
                        raise ValueError("native child bound exceeded")
                    if self.capacity is not None:
                        self.capacity.bind_native(agent, hook["agent_type"])
                    connection.execute(
                        "INSERT INTO children(session,id) VALUES (?,?)", (session, agent)
                    )
                elif agent and (child is None or child[0]):
                    raise ValueError("native child absent or terminal")
                if kind == "SubagentStop":
                    if self.capacity is not None:
                        self.capacity.release_native(agent)
                    connection.execute(
                        "UPDATE children SET closed=1 WHERE session=? AND id=?", (session, agent)
                    )
                if kind == "PreToolUse":
                    try:
                        connection.execute(
                            "INSERT INTO tools(session,agent,id,name) VALUES (?,?,?,?)",
                            (session, agent, hook["tool_use_id"], hook["tool_name"]),
                        )
                    except sqlite3.IntegrityError:
                        raise ValueError("native tool already started") from None
                elif kind in {"PostToolUse", "PostToolUseFailure"}:
                    changed = connection.execute(
                        "UPDATE tools SET closed=1 WHERE session=? AND agent=? AND id=? AND name=? AND closed=0",
                        (session, agent, hook["tool_use_id"], hook["tool_name"]),
                    )
                    if changed.rowcount != 1:
                        raise ValueError("native tool completion lacks matching start")
                if kind == "SessionEnd":
                    connection.execute("UPDATE sessions SET closed=1 WHERE id=?", (session,))
            row = connection.execute(
                "INSERT INTO events(event_id,payload) VALUES (?,?)",
                (observation["event_id"], payload),
            )
            return {"status": "recorded", "sequence": row.lastrowid}

    def observed_role(self, session_id: str, agent_id: str | None) -> str | None:
        """Return live observed role only; caller must corroborate provider requests."""
        with self._connect() as connection:
            return self._observed_role(connection, session_id, agent_id)

    def model_role(self, session_id: str, agent_id: str | None) -> str | None:
        """Bind this launch to the first live session with an actual model request."""
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            role = self._observed_role(connection, session_id, agent_id)
            if role is None:
                return None
            selected = connection.execute("SELECT session FROM model_session").fetchone()
            if selected is None:
                connection.execute(
                    "INSERT INTO model_session(id,session) VALUES (1,?)", (session_id,)
                )
            elif selected[0] != session_id:
                return None
            return role

    def _observed_role(
        self, connection: sqlite3.Connection, session_id: str, agent_id: str | None
    ) -> str | None:
        session = connection.execute(
            "SELECT closed FROM sessions WHERE id=?", (session_id,)
        ).fetchone()
        if session is None or session[0]:
            return None
        if agent_id is None:
            return "parent"
        child = connection.execute(
            "SELECT closed FROM children WHERE session=? AND id=?", (session_id, agent_id)
        ).fetchone()
        if (
            child is None
            or child[0]
            or (self.capacity is not None and not self.capacity.is_native_active(agent_id))
        ):
            return None
        return "child"

    def summary(self) -> dict[str, int]:
        with self._connect() as connection:
            return {
                key: connection.execute(query).fetchone()[0]
                for key, query in {
                    "sessions": "SELECT count(*) FROM sessions",
                    "open_sessions": "SELECT count(*) FROM sessions WHERE closed=0",
                    "children": "SELECT count(*) FROM children",
                    "open_children": "SELECT count(*) FROM children WHERE closed=0",
                    "pending_tools": "SELECT count(*) FROM tools WHERE closed=0",
                    "events": "SELECT count(*) FROM events",
                }.items()
            }


def native_hook_handler(collector: NativeHookCollector, *, container_id: str, network_id: str):
    from .host_boundary_runtime import GatewayReply, GatewayRequest

    def handle(request: GatewayRequest) -> GatewayReply:
        if (
            request.endpoint != "registered-tool-gateway"
            or request.method != "POST"
            or request.path != "/native-launch/hooks"
            or request.peer.container_id != container_id
            or request.peer.network_id != network_id
            or not 0 < len(request.body) <= 256 * 1024
        ):
            return GatewayReply(403, b'{"error":"native hook denied"}')
        try:
            result = collector.ingest(json.loads(request.body))
        except (ValueError, TypeError, AttributeError):
            return GatewayReply(400, b'{"error":"invalid native hook observation"}')
        except (OSError, sqlite3.Error):
            return GatewayReply(503, b'{"error":"native hook custody unavailable"}')
        return GatewayReply(200, _canonical(result))

    return handle
