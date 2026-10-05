"""Correlate real provider tool calls with native hooks before authorization.

Container identity comes from the host gateway. Hook/session identifiers are
observations, corroborated by the provider stream and frozen native tool roster.
In-process children have no separate OS identity: their frozen native roster
must exclude execution/write tools, so they cannot manufacture HTTP requests.
This module does not substitute hook claims for a capability authorization.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
from collections.abc import Callable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from uuid import uuid4

from .host_boundary_runtime import AdmittedPeer, GatewayReply, GatewayRequest
from .model_gateway import TrustedAdmission
from .native_hook_runtime import native_request_identity


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _strict_json(value):
    def pairs(items):
        result = {}
        for key, item in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = item
        return result

    def constant(_value):
        raise ValueError("nonfinite JSON value")

    result = json.loads(value, object_pairs_hook=pairs, parse_constant=constant)
    _canonical(result)  # Also rejects overflow such as 1e999, at any nesting depth.
    return result


@dataclass(frozen=True)
class NativeToolCall:
    task_id: str
    attempt_id: str
    request_id: str
    session_id: str
    agent_id: str | None
    role: str
    tool_id: str
    name: str
    arguments: Mapping[str, object]


class NativeToolController:
    def __init__(
        self,
        database: Path,
        *,
        task_id: str,
        attempt_id: str,
        run_id: str,
        launch_id: str,
        peer: AdmittedPeer,
        policy_sha256: str,
        parent_tools: frozenset[str],
        child_tools: frozenset[str],
        captured_schemas: Mapping[str, str],
        observed_role: Callable[[str, str | None], str | None],
        authorize: Callable[[NativeToolCall], bool],
        redact: Callable[[object], object],
    ):
        self.database = Path(database)
        if (
            not self.database.is_absolute()
            or self.database.is_symlink()
            or self.database.parent.resolve() != self.database.parent
        ):
            raise ValueError("controller-owned absolute database required")
        if not parent_tools or not child_tools or not child_tools <= parent_tools:
            raise ValueError("explicit frozen parent and child tool rosters required")
        if any(
            name in child_tools
            for name in {"Bash", "Write", "Edit", "NotebookEdit", "Agent", "Task"}
        ):
            raise ValueError("native children must have read-only tools")
        if (
            not isinstance(captured_schemas, Mapping)
            or not captured_schemas
            or any(
                type(name) is not str
                or not name
                or type(digest) is not str
                or re.fullmatch(r"[a-f0-9]{64}", digest) is None
                for name, digest in captured_schemas.items()
            )
            or not parent_tools <= set(captured_schemas)
        ):
            raise ValueError("frozen captured native tool schemas required")
        self.task_id, self.attempt_id = task_id, attempt_id
        self.identity = {"run_id": run_id, "task_id": task_id, "launch_id": launch_id}
        self.peer, self.policy_sha256 = peer, policy_sha256
        self.parent_tools, self.child_tools = parent_tools, child_tools
        self.captured_schemas = dict(captured_schemas)
        self.observed_role, self.authorize, self.redact = observed_role, authorize, redact
        self._lock = threading.RLock()
        self._streams: dict[str, dict] = {}
        self._halted = False
        with self._connect() as c:
            c.executescript("""
                CREATE TABLE IF NOT EXISTS identity (id INTEGER PRIMARY KEY CHECK(id=1), value BLOB NOT NULL);
                CREATE TABLE IF NOT EXISTS requests (id TEXT PRIMARY KEY, session TEXT NOT NULL, agent TEXT NOT NULL, role TEXT NOT NULL, roster BLOB NOT NULL, native_roster BLOB NOT NULL, schema_drift BLOB NOT NULL, payload BLOB NOT NULL);
                CREATE TABLE IF NOT EXISTS tools (id TEXT PRIMARY KEY, request TEXT NOT NULL, name TEXT NOT NULL, input BLOB NOT NULL, input_hash TEXT NOT NULL, status TEXT NOT NULL, result BLOB);
                CREATE TABLE IF NOT EXISTS streams (sequence INTEGER PRIMARY KEY, request TEXT NOT NULL, data BLOB NOT NULL);
                CREATE TABLE IF NOT EXISTS request_lifecycle (request TEXT PRIMARY KEY, status TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS child_schema_discovery (id INTEGER PRIMARY KEY CHECK(id=1), request_sha256 TEXT NOT NULL, schemas BLOB NOT NULL);
            """)
            identity = _canonical(
                {
                    **self.identity,
                    "attempt_id": attempt_id,
                    "container_id": peer.container_id,
                    "network_id": peer.network_id,
                    "policy_sha256": policy_sha256,
                    "parent_tools": sorted(parent_tools),
                    "child_tools": sorted(child_tools),
                    "captured_schemas": dict(sorted(self.captured_schemas.items())),
                }
            )
            c.execute("INSERT OR IGNORE INTO identity VALUES(1,?)", (identity,))
            if c.execute("SELECT value FROM identity").fetchone()[0] != identity:
                raise ValueError("native tool database belongs to another configuration")
            # Reconnection keeps this controller alive. A restarted controller
            # cannot recreate partially consumed provider streams and grants.
            self._halted = bool(c.execute("SELECT count(*) FROM requests").fetchone()[0])

    @contextmanager
    def _connect(self):
        c = sqlite3.connect(self.database, timeout=15)
        try:
            c.execute("PRAGMA synchronous=FULL")
            with c:
                yield c
        finally:
            c.close()

    def begin_request(self, request: GatewayRequest) -> TrustedAdmission:
        with self._lock:
            if (
                self._halted
                or request.peer != self.peer
                or request.endpoint != "model-gateway"
                or request.method != "POST"
                or request.path not in {
                    "/v1/messages",
                    "/v1/messages?beta=true",
                    "/v1/messages/count_tokens",
                }
                or type(request.body) is not bytes
                or not 0 < len(request.body) <= 16 * 1024 * 1024
            ):
                raise PermissionError("native model peer denied")
            try:
                payload = _strict_json(request.body)
                if type(payload) is not dict or payload.get("model") != "glm-5.3":
                    raise ValueError
                identity = native_request_identity(request.headers, payload)
            except (ValueError, TypeError, AttributeError, RecursionError):
                raise PermissionError("native model request malformed") from None
            count_tokens = request.path == "/v1/messages/count_tokens"
            if not count_tokens and (
                payload.get("stream") is not True
                or type(payload.get("max_tokens")) is not int
                or not 1 <= payload["max_tokens"] <= 128000
                or type(payload.get("thinking")) is not dict
                or payload["thinking"].get("type") not in {"enabled", "adaptive"}
                or type(payload.get("output_config")) is not dict
                or payload["output_config"].get("effort") != "max"
            ):
                raise PermissionError("native generation settings differ from frozen policy")
            session, agent = identity["session_id"], identity["agent_id"]
            role = self.observed_role(session, agent)
            if role not in {"parent", "child"} or (role == "child") != bool(agent):
                raise PermissionError("native lifecycle identity not observed")
            tools = payload.get("tools", [])
            if not isinstance(tools, list) or any(
                not isinstance(t, dict) or type(t.get("name")) is not str for t in tools
            ):
                raise PermissionError("native tool roster malformed")
            names = [t["name"] for t in tools]
            allowed = self.child_tools if role == "child" else self.parent_tools
            if len(set(names)) != len(names):
                raise PermissionError("native advertised tool schema differs from frozen capture")
            schema_drift = []
            for tool in tools:
                name = tool["name"]
                frozen = self.captured_schemas.get(name)
                observed = hashlib.sha256(_canonical(tool)).hexdigest()
                if frozen is None:
                    if (
                        self.task_id.startswith("synthetic:")
                        and role == "child"
                        and set(names) == {"Read", "Grep", "Glob"}
                    ):
                        discovery = _canonical(
                            [item for item in tools if item["name"] in {"Grep", "Glob"}]
                        )
                        if len(discovery) <= 64 * 1024:
                            with self._connect() as c:
                                c.execute(
                                    "INSERT OR IGNORE INTO child_schema_discovery VALUES(1,?,?)",
                                    (hashlib.sha256(request.body).hexdigest(), discovery),
                                )
                    raise PermissionError("native advertised tool schema differs from frozen capture")
                if observed != frozen:
                    input_schema = tool.get("input_schema", tool.get("inputSchema"))
                    description = tool.get("description")
                    if (
                        name.startswith(("mcp__", "advisory__"))
                        or type(description) is not str
                        or not 0 < len(description) <= 65536
                        or type(input_schema) is not dict
                        or input_schema.get("type") != "object"
                        or len(_canonical(tool)) > 128 * 1024
                    ):
                        raise PermissionError("native advertised tool schema differs from frozen capture")
                    schema_drift.append(
                        {
                            "name": name,
                            "observed_sha256": observed,
                            "frozen_sha256": frozen,
                            "input_schema_sha256": hashlib.sha256(
                                _canonical(input_schema)
                            ).hexdigest(),
                        }
                    )
            approved = [name for name in names if name in allowed]
            forwarded = dict(payload)
            forwarded["tools"] = [tool for tool in tools if tool["name"] in allowed]
            request_id = str(uuid4())
            grant = TrustedAdmission(
                self.task_id, self.attempt_id, request_id, None, None, self.policy_sha256
            )
            try:
                with self._connect() as c:
                    c.execute(
                        "INSERT INTO requests VALUES(?,?,?,?,?,?,?,?)",
                        (
                            request_id,
                            session,
                            agent or "",
                            role,
                            _canonical(approved),
                            _canonical(names),
                            _canonical(schema_drift),
                            _canonical(self.redact(payload)),
                        ),
                    )
                    c.execute(
                        "INSERT INTO request_lifecycle VALUES(?,?)", (request_id, "streaming")
                    )
            except Exception:
                self._halted = True
                raise PermissionError("native request custody failed") from None
            self._streams[request_id] = {
                "buffer": bytearray(),
                "blocks": {},
                "used_indices": set(),
                "roster": frozenset(approved),
                "request_sha256": hashlib.sha256(request.body).hexdigest(),
                "forwarded_body": _canonical(forwarded),
                "grant": grant,
                "count_tokens": count_tokens,
                "started": False,
                "terminal": False,
                "trailer": False,
                "non_thinking": False,
            }
            return grant

    def forward_request(self, grant: TrustedAdmission, request: GatewayRequest) -> GatewayRequest:
        """Return only approved captured schemas after exact request custody."""
        with self._lock:
            state = self._streams.get(grant.request_id)
            if (
                state is None
                or state["grant"] != grant
                or type(request.body) is not bytes
                or hashlib.sha256(request.body).hexdigest() != state["request_sha256"]
            ):
                raise PermissionError("native forwarding lacks exact request custody")
            return replace(
                request,
                body=state["forwarded_body"],
                headers=tuple(
                    (name, value)
                    for name, value in request.headers
                    if name.lower() != "content-length"
                ),
            )

    def admission_diagnostic(self, request: GatewayRequest) -> dict:
        """Bounded policy metadata for rejected native requests; never prompt or schema text."""
        if type(request.body) is not bytes or len(request.body) > 16 * 1024 * 1024:
            return {}
        try:
            payload = _strict_json(request.body)
        except (ValueError, TypeError, RecursionError):
            return {}
        if type(payload) is not dict:
            return {}
        thinking = payload.get("thinking")
        output = payload.get("output_config")
        max_tokens = payload.get("max_tokens")
        tools = payload.get("tools")
        diagnostic = {
            "model_is_glm_5_3": payload.get("model") == "glm-5.3",
            "stream_is_true": payload.get("stream") is True,
            "max_tokens": max_tokens if type(max_tokens) is int and 0 <= max_tokens <= 128000 else None,
            "thinking_type": (
                thinking.get("type")
                if type(thinking) is dict
                and type(thinking.get("type")) is str
                and thinking.get("type") in {"enabled", "adaptive", "disabled"}
                else "other"
            ),
            "effort_is_max": type(output) is dict and output.get("effort") == "max",
            "tool_count": len(tools) if type(tools) is list and len(tools) <= 100 else None,
            "tool_schema_mismatches": [],
        }
        if type(tools) is list and len(tools) <= 100:
            for tool in tools:
                if type(tool) is not dict or type(tool.get("name")) is not str:
                    continue
                name = tool["name"]
                observed = hashlib.sha256(_canonical(tool)).hexdigest()
                expected = self.captured_schemas.get(name)
                if observed != expected:
                    diagnostic["tool_schema_mismatches"].append(
                        {
                            "name": name if expected is not None else "unknown",
                            "observed_sha256": observed,
                            "frozen_sha256": expected,
                            "input_schema_sha256": hashlib.sha256(
                                _canonical(tool.get("input_schema", tool.get("inputSchema")))
                            ).hexdigest(),
                        }
                    )
        return diagnostic

    def observe_stream(self, grant: TrustedAdmission, chunk: bytes):
        """Consume secret-checked bytes *before* releasing them to the native client."""
        with self._lock:
            if self._halted or grant.task_id != self.task_id or grant.attempt_id != self.attempt_id:
                raise PermissionError("native stream identity denied")
            state = self._streams.get(grant.request_id)
            if state is None or type(chunk) is not bytes or grant != state["grant"]:
                self._halted = True
                raise PermissionError("native stream has no request")
            try:
                with self._connect() as c:
                    c.execute(
                        "INSERT INTO streams(request,data) VALUES(?,?)", (grant.request_id, chunk)
                    )
                    state["buffer"].extend(chunk)
                    if state["count_tokens"]:
                        if len(state["buffer"]) > 16 * 1024 * 1024:
                            raise PermissionError("count response exceeds limit")
                        return
                    while match := re.search(rb"(?:\r?\n){2}", state["buffer"]):
                        if match.start() > 8 * 1024 * 1024:
                            raise PermissionError("native stream frame exceeds limit")
                        frame = bytes(state["buffer"][: match.start()])
                        del state["buffer"][: match.end()]
                        data = b"\n".join(
                            line[5:].lstrip(b" ")
                            for line in frame.splitlines()
                            if line.startswith(b"data:")
                        )
                        if not data:
                            if any(
                                line.startswith(b"event:") and line[6:].strip() != b"ping"
                                for line in frame.splitlines()
                            ):
                                raise PermissionError("native SSE event has no data")
                            continue
                        if data == b"[DONE]":
                            if not state["terminal"] or state["trailer"]:
                                raise PermissionError("native SSE terminal marker out of order")
                            state["trailer"] = True
                            continue
                        self._frame(c, grant.request_id, state, _strict_json(data))
                    if len(state["buffer"]) > 8 * 1024 * 1024:
                        raise PermissionError("native stream frame exceeds limit")
            except Exception:
                self._halted = True
                raise PermissionError("native provider stream rejected") from None

    def _frame(self, c, request_id, state, event):
        if type(event) is not dict or state["terminal"]:
            raise PermissionError("native stream event after terminal or malformed")
        kind, index = event.get("type"), event.get("index")
        if kind == "ping":
            return
        if kind == "message_start":
            message = event.get("message")
            if (
                state["started"]
                or type(message) is not dict
                or message.get("model") != "glm-5.3"
                or message.get("content", []) != []
            ):
                raise PermissionError("native message start malformed")
            state["started"] = True
            return
        if not state["started"]:
            raise PermissionError("native event precedes message start")
        if kind in {"message_delta", "message_stop"}:
            if state["blocks"]:
                raise PermissionError("native message terminated with open blocks")
            if kind == "message_stop":
                state["terminal"] = True
            return
        if kind not in {"content_block_start", "content_block_delta", "content_block_stop"}:
            raise PermissionError("unsupported native stream event")
        if type(index) is not int or not 0 <= index <= 4095:
            raise PermissionError("native block index malformed")
        if kind == "content_block_start":
            block = event.get("content_block") or {}
            if (
                type(block) is not dict
                or index in state["used_indices"]
                or block.get("type") not in {"tool_use", "text", "thinking", "redacted_thinking"}
            ):
                raise PermissionError("native block is duplicate or malformed")
            state["used_indices"].add(index)
            if block["type"] in {"text", "tool_use"}:
                state["non_thinking"] = True
            if block.get("type") == "tool_use" and (
                block.get("name") not in state["roster"]
                or type(block.get("id")) is not str
                or not 0 < len(block["id"]) <= 256
                or type(block.get("input")) is not dict
            ):
                raise PermissionError("provider returned an unrequested tool")
            state["blocks"][index] = {**block, "partial": ""}
        elif index not in state["blocks"]:
            raise PermissionError("native block delta or stop lacks start")
        elif kind == "content_block_delta":
            delta = event.get("delta") or {}
            block = state["blocks"][index]
            allowed_delta = {
                "tool_use": {"input_json_delta"},
                "text": {"text_delta"},
                "thinking": {"thinking_delta", "signature_delta"},
                "redacted_thinking": set(),
            }
            if type(delta) is not dict or delta.get("type") not in allowed_delta[block["type"]]:
                raise PermissionError("native block delta has wrong type")
            if block["type"] == "tool_use":
                if type(delta.get("partial_json")) is not str or block["input"]:
                    raise PermissionError("native tool input delta is ambiguous")
                block["partial"] += delta["partial_json"]
                if len(block["partial"].encode()) > 4 * 1024 * 1024:
                    raise PermissionError("native tool input exceeds limit")
        elif kind == "content_block_stop":
            block = state["blocks"].pop(index)
            if block["type"] != "tool_use":
                return
            args = _strict_json(block["partial"]) if block["partial"] else block["input"]
            if not isinstance(args, dict):
                raise PermissionError("native tool input malformed")
            c.execute(
                "INSERT INTO tools VALUES(?,?,?,?,?,?,NULL)",
                (
                    block["id"],
                    request_id,
                    block["name"],
                    _canonical(self.redact(args)),
                    hashlib.sha256(_canonical(args)).hexdigest(),
                    "observed",
                ),
            )

    def finish_stream(
        self, grant: TrustedAdmission, completed: bool, failure_code: str | None = None
    ) -> bool:
        with self._lock:
            state = self._streams.pop(grant.request_id, None)
            valid = (
                not self._halted
                and type(completed) is bool
                and state is not None
                and grant == state["grant"]
            )
            if valid and completed:
                if state["count_tokens"]:
                    # The model gateway validates the JSON count response; when
                    # it is observed here, also reject malformed custody bytes.
                    try:
                        if state["buffer"]:
                            _strict_json(state["buffer"])
                    except Exception:
                        valid = False
                else:
                    valid = bool(state["terminal"] and not state["blocks"] and not state["buffer"])
            retryable = False
            try:
                with self._connect() as c:
                    if valid and not completed and failure_code in {
                        "provider_stream_no_terminal",
                        "provider_sse_incomplete",
                        "provider_transport_failure",
                    }:
                        prior = c.execute(
                            "SELECT count(*) FROM request_lifecycle WHERE status='retryable_interrupted'"
                        ).fetchone()[0]
                        retryable = bool(
                            prior < 2
                            and state["started"]
                            and not state["count_tokens"]
                            and not state["terminal"]
                            and not state["trailer"]
                            and not state["buffer"]
                            and not state["non_thinking"]
                            and all(
                                block["type"] in {"thinking", "redacted_thinking"}
                                for block in state["blocks"].values()
                            )
                            and c.execute(
                                "SELECT count(*) FROM tools WHERE request=?", (grant.request_id,)
                            ).fetchone()[0] == 0
                        )
                    changed = c.execute(
                        "UPDATE request_lifecycle SET status=? WHERE request=? AND status='streaming'",
                        (
                            "completed"
                            if completed and valid
                            else "retryable_interrupted" if retryable else "interrupted",
                            grant.request_id,
                        ),
                    )
                    if changed.rowcount != 1:
                        valid = False
            except Exception:
                self._halted = True
                raise PermissionError("native terminal custody failed") from None
            if not completed and not retryable or not valid:
                self._halted = True
            if not valid:
                raise PermissionError("native provider stream incomplete or invalid")
            return retryable

    def abandon_request(self, grant: TrustedAdmission):
        """Finalize a rejected request once, without replaying a gateway terminal callback."""
        with self._lock:
            if grant.request_id in self._streams:
                self.finish_stream(grant, False)

    def _matching_hook(self, envelope, c, event):
        if (
            type(envelope) is not dict
            or set(envelope) != {"schema_version", "run_id", "task_id", "launch_id", "hook_input"}
            or envelope["schema_version"] != 1
            or any(envelope[k] != v for k, v in self.identity.items())
        ):
            raise PermissionError("native hook identity denied")
        h = envelope["hook_input"]
        if type(h) is not dict or h.get("hook_event_name") not in event:
            raise PermissionError("native tool event denied")
        row = c.execute(
            "SELECT t.id,t.name,t.input,t.input_hash,t.status,r.id,r.session,r.agent,r.role FROM tools t JOIN requests r ON r.id=t.request WHERE t.id=?",
            (h.get("tool_use_id"),),
        ).fetchone()
        if (
            row is None
            or h.get("tool_name") != row[1]
            or h.get("session_id") != row[6]
            or (h.get("agent_id") or "") != row[7]
            or hashlib.sha256(_canonical(h.get("tool_input"))).hexdigest() != row[3]
        ):
            raise PermissionError("native hook lacks exact provider tool evidence")
        if self.observed_role(row[6], row[7] or None) != row[8]:
            raise PermissionError("native lifecycle no longer active")
        return row, h

    def authorize_hook(self, envelope) -> bool:
        with self._lock:
            if self._halted:
                return False
            try:
                with self._connect() as c:
                    c.execute("BEGIN IMMEDIATE")
                    row, h = self._matching_hook(envelope, c, {"PreToolUse"})
                    if row[4] != "observed":
                        return False
                    call = NativeToolCall(
                        self.task_id,
                        self.attempt_id,
                        row[5],
                        row[6],
                        row[7] or None,
                        row[8],
                        row[0],
                        row[1],
                        h["tool_input"],
                    )
                    allowed = call.name != "Agent" or (
                        call.role == "parent"
                        and call.arguments.get("subagent_type")
                        in {"cybergym-recon", "cybergym-debug", "cybergym-review"}
                    )
                    if allowed:
                        try:
                            allowed = self.authorize(call) is True
                        except Exception:
                            self._halted = True
                            raise
                    c.execute(
                        "UPDATE tools SET status=? WHERE id=?",
                        ("allowed" if allowed else "denied", row[0]),
                    )
                return allowed
            except PermissionError:
                return False
            except Exception:
                self._halted = True
                return False

    def record_result(self, envelope):
        with self._lock:
            if self._halted:
                raise PermissionError("native tool controller is halted")
            try:
                with self._connect() as c:
                    c.execute("BEGIN IMMEDIATE")
                    row, hook = self._matching_hook(
                        envelope, c, {"PostToolUse", "PostToolUseFailure"}
                    )
                    if row[4] not in {"allowed", "dispatched"}:
                        raise PermissionError("native result has no authorized invocation")
                    status = (
                        "failed" if hook["hook_event_name"] == "PostToolUseFailure" else "completed"
                    )
                    c.execute(
                        "UPDATE tools SET status=?,result=? WHERE id=?",
                        (status, _canonical(self.redact(hook)), row[0]),
                    )
            except PermissionError:
                raise
            except Exception:
                self._halted = True
                raise PermissionError("native result custody failed") from None

    def resolve_mcp_call(self, tool_use_id: str, native_name: str, args: dict) -> NativeToolCall:
        """Consume one backend dispatch using provider evidence and prior admission.

        MCP `_meta` is an untrusted lookup key. Only an exact previously allowed
        provider invocation grants a dispatch; the name and full argument hash
        must match, and the request's observed lifecycle role must still be live.
        """
        with self._lock:
            if (
                self._halted
                or type(tool_use_id) is not str
                or type(native_name) is not str
                or not native_name.startswith("mcp__")
                or type(args) is not dict
            ):
                raise PermissionError("native MCP call denied")
            try:
                argument_hash = hashlib.sha256(_canonical(args)).hexdigest()
            except (ValueError, TypeError, RecursionError):
                raise PermissionError("native MCP arguments malformed") from None
            try:
                with self._connect() as c:
                    c.execute("BEGIN IMMEDIATE")
                    row = c.execute(
                        "SELECT t.id,t.name,t.input,t.input_hash,t.status,r.id,r.session,r.agent,r.role FROM tools t JOIN requests r ON r.id=t.request WHERE t.id=?",
                        (tool_use_id,),
                    ).fetchone()
                    if (
                        row is None
                        or row[1] != native_name
                        or row[3] != argument_hash
                        or row[4] != "allowed"
                        or self.observed_role(row[6], row[7] or None) != row[8]
                    ):
                        raise PermissionError(
                            "native MCP call lacks exact authorized provider evidence"
                        )
                    c.execute("UPDATE tools SET status='dispatched' WHERE id=?", (tool_use_id,))
                    call = NativeToolCall(
                        self.task_id,
                        self.attempt_id,
                        row[5],
                        row[6],
                        row[7] or None,
                        row[8],
                        row[0],
                        row[1],
                        args,
                    )
                return call
            except PermissionError:
                raise
            except Exception:
                self._halted = True
                raise PermissionError("native MCP dispatch custody failed") from None

    def summary(self):
        with self._connect() as c:
            return dict(c.execute("SELECT status,count(*) FROM tools GROUP BY status"))

    def handle(self, request: GatewayRequest) -> GatewayReply:
        if (
            request.peer != self.peer
            or request.endpoint != "registered-tool-gateway"
            or request.method != "POST"
            or len(request.body) > 16 * 1024 * 1024
        ):
            return GatewayReply(403, b'{"error":"native tool denied"}')
        try:
            envelope = _strict_json(request.body)
            if request.path == "/native-tools/authorize":
                return GatewayReply(
                    200,
                    _canonical(
                        {"permissionDecision": "allow" if self.authorize_hook(envelope) else "deny"}
                    ),
                )
            if request.path == "/native-tools/result":
                self.record_result(envelope)
                return GatewayReply(200, b'{"recorded":true}')
        except Exception:
            return GatewayReply(403, b'{"error":"native tool denied"}')
        return GatewayReply(404, b'{"error":"unknown native tool route"}')
