"""The sole GLM parent selection, joined to an actual authorized native MCP call."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sqlite3
import stat
import threading
from collections.abc import Callable
from contextlib import ExitStack, contextmanager
from datetime import UTC, datetime
from pathlib import Path

from .finalize import (
    FinalLock,
    ParentSelectionProof,
    _candidate_components,
    _candidate_file,
    _fsync_directory,
    _regular_file_fd,
    _rooted_directory_fd,
    _validate_declaration,
    lock_agent_final,
)
from .host_boundary_runtime import AdmittedPeer, GatewayReply, GatewayRequest
from .native_tool_runtime import NativeToolCall, _strict_json

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_NATIVE_NAME = "mcp__finalizer__select_final"

SELECT_FINAL_TOOL = {
    "name": "select_final",
    "description": "Select the single final candidate after the adversarial critic has completed for its exact hash. This selection is final.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "candidate_path": {"type": "string"},
            "sha256": {"type": "string"},
            "byte_length": {"type": "integer", "minimum": 0},
            "selection_reason": {"type": "string"},
        },
        "required": ["candidate_path", "sha256", "byte_length", "selection_reason"],
        "additionalProperties": False,
    },
}


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


class NativeFinalizer:
    """Controller-only consumer of calls resolved by NativeToolController.

    The resolver validates the actual provider's message_start model as
    glm-5.3 and the request's frozen configuration. The final-custody contract
    names that configured model glm-5.3[1m]; it is not a provider model echo.
    A NativeToolCall supplied by a solver, header, or JSON body is never proof.
    """

    def __init__(
        self,
        output: Path,
        evidence: Path,
        *,
        task_id: str,
        attempt_id: str,
        require_critic: Callable[[str], None],
    ):
        self.output, self.evidence = Path(output), Path(evidence)
        self.database = self.evidence / "native-final.sqlite"
        self._lock = threading.RLock()
        if any(
            type(value) is not str or not _IDENTIFIER.fullmatch(value)
            for value in (task_id, attempt_id)
        ) or not callable(require_critic):
            raise ValueError("task identity and trusted critic callback required")
        self._verify_paths()
        self.evidence.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._verify_paths()
        self.task_id, self.attempt_id, self.require_critic = task_id, attempt_id, require_critic
        identity = _canonical(
            {
                "task_id": task_id,
                "attempt_id": attempt_id,
                "output": str(self.output),
                "configured_model": "glm-5.3[1m]",
                "provider_model": "glm-5.3",
            }
        )
        with self._connect() as c:
            c.executescript("""
                CREATE TABLE IF NOT EXISTS selection(id INTEGER PRIMARY KEY CHECK(id=1), task TEXT, attempt TEXT, declaration BLOB, proof BLOB);
                CREATE TABLE IF NOT EXISTS identity(id INTEGER PRIMARY KEY CHECK(id=1), value BLOB NOT NULL);
                CREATE TABLE IF NOT EXISTS declaration_state(id INTEGER PRIMARY KEY CHECK(id=1), status TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS lock_attempt(id INTEGER PRIMARY KEY CHECK(id=1), status TEXT NOT NULL);
            """)
            c.execute("BEGIN IMMEDIATE")
            c.execute("INSERT OR IGNORE INTO identity VALUES(1,?)", (identity,))
            if c.execute("SELECT value FROM identity WHERE id=1").fetchone()[0] != identity:
                raise ValueError("finalization database belongs to another task/configuration")

    def _verify_paths(self):
        # All evidence ancestors are controller-owned. Recheck on every database
        # open, including SQLite's sidecars, rather than following stale links.
        if (
            not self.output.is_absolute()
            or not self.evidence.is_absolute()
            or self.output.resolve() != self.output
            or self.evidence.resolve() != self.evidence
            or self.output.is_symlink()
            or not self.output.is_dir()
            or self.evidence.is_symlink()
            or self.evidence.resolve().is_relative_to(self.output.parent.resolve())
        ):
            raise ValueError("separate absolute unlinked controller finalization evidence required")
        if self.evidence.exists() and (
            not self.evidence.is_dir()
            or (os.name == "posix" and self.evidence.stat().st_mode & 0o022)
        ):
            raise ValueError("private controller evidence directory required")
        for suffix in ("", "-journal", "-wal", "-shm"):
            path = self.database.with_name(self.database.name + suffix)
            if path.is_symlink() or (
                path.exists() and (not path.is_file() or path.stat().st_nlink != 1)
            ):
                raise ValueError("controller final database cannot contain links")

    @contextmanager
    def _connect(self):
        self._verify_paths()
        c = sqlite3.connect(self.database, timeout=15)
        try:
            c.execute("PRAGMA synchronous=FULL")
            with c:
                yield c
        finally:
            c.close()

    def select_final(self, call: NativeToolCall):
        with self._lock:
            return self._select_final(call)

    def _select_final(self, call: NativeToolCall):
        if (
            type(call) is not NativeToolCall
            or call.role != "parent"
            or call.agent_id is not None
            or call.task_id != self.task_id
            or call.attempt_id != self.attempt_id
            or call.name != _NATIVE_NAME
            or any(
                type(value) is not str or not _IDENTIFIER.fullmatch(value)
                for value in (call.request_id, call.session_id, call.tool_id)
            )
        ):
            raise PermissionError("authorized native GLM parent selection required")
        args = dict(call.arguments)
        if set(args) != {"candidate_path", "sha256", "byte_length", "selection_reason"}:
            raise ValueError("invalid final selection fields")
        declaration = {
            **args,
            "schema_version": 1,
            "task_id": self.task_id,
            "selected_at": datetime.now(UTC).isoformat(),
            "final_declaration": True,
            "selected_by": "glm_parent",
        }
        raw = _canonical(declaration)
        if len(raw) > 256 * 1024:
            raise ValueError("final declaration is too large")
        _validate_declaration(raw, self.task_id)
        self._verify_candidate(args)
        self.require_critic(args["sha256"])
        proof = {
            "task_id": self.task_id,
            "declaration_sha256": hashlib.sha256(raw).hexdigest(),
            "candidate_sha256": args["sha256"],
            "model": "glm-5.3[1m]",
            "role": "glm_parent",
            "event_digest": hashlib.sha256(
                _canonical(
                    {
                        "task_id": call.task_id,
                        "attempt_id": call.attempt_id,
                        "request_id": call.request_id,
                        "session_id": call.session_id,
                        "agent_id": call.agent_id,
                        "role": call.role,
                        "tool_id": call.tool_id,
                        "tool_name": call.name,
                        "configured_model": "glm-5.3[1m]",
                        "observed_provider_model": "glm-5.3",
                        "authority": "NativeToolController.resolve_mcp_call",
                        "arguments": args,
                    }
                )
            ).hexdigest(),
        }
        with self._connect() as c:
            c.execute("BEGIN IMMEDIATE")
            if c.execute("SELECT count(*) FROM selection").fetchone()[0]:
                raise RuntimeError("a native final was already selected")
            c.execute(
                "INSERT INTO selection VALUES(1,?,?,?,?)",
                (self.task_id, self.attempt_id, raw, _canonical(proof)),
            )
            c.execute("INSERT INTO declaration_state VALUES(1,'reserved')")
        # Reservation is durable first. An ambiguous file write cannot create a
        # second selection or permit automatic retry after controller restart.
        self._write_declaration(raw)
        with self._connect() as c:
            c.execute("UPDATE declaration_state SET status='declared' WHERE id=1")
        return {
            "selected": True,
            "sha256": args["sha256"],
            "native_event_digest": proof["event_digest"],
        }

    def _verify_candidate(self, args):
        self._read_candidate(
            args["candidate_path"], args["sha256"], expected_length=args["byte_length"]
        )

    def snapshot_candidate(self, candidate_path: str, sha256: str) -> dict:
        """Read bytes for the trusted critic, with a full hash and explicit prefix.

        A bounded prefix is not represented as a full candidate. Reading never
        chooses a final or creates a selection receipt.
        """
        with self._lock:
            length, prefix, _ = self._read_candidate(candidate_path, sha256, prefix_limit=64 * 1024)
        return {
            "candidate_path": candidate_path,
            "sha256": sha256,
            "byte_length": length,
            "content_base64": base64.b64encode(prefix).decode("ascii"),
            "captured_bytes": len(prefix),
            "truncated": len(prefix) < length,
        }

    def hash_candidate(self, candidate_path: str) -> dict:
        """Hash actual candidate bytes for a controller-observed vulnerable test."""
        with self._lock:
            length, _, digest = self._read_candidate(candidate_path, None)
        return {"candidate_path": candidate_path, "sha256": digest, "byte_length": length}

    def _read_candidate(self, declared, expected_hash, *, expected_length=None, prefix_limit=0):
        if type(declared) is not str or "\\" in declared or ":" in declared or "\x00" in declared:
            raise ValueError("candidate path must remain under /workspace/output")
        if expected_hash is not None and (type(expected_hash) is not str or not re.fullmatch(r"[a-f0-9]{64}", expected_hash)):
            raise ValueError("candidate hash required")
        components = _candidate_components(declared)
        if declared != "/workspace/output/" + "/".join(components) or (
            len(components) == 1
            and components[0].startswith("agent-final")
            and components[0].endswith(".json")
        ):
            raise ValueError("candidate path cannot name a declaration or noncanonical path")
        self._verify_paths()
        with ExitStack() as opened:
            if os.name == "posix":
                directory_fd = _rooted_directory_fd(self.output)
                opened.callback(os.close, directory_fd)
                descriptor = _regular_file_fd(directory_fd, components, "candidate")
            else:
                path = _candidate_file(self.output, declared)
                descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
            opened.callback(os.close, descriptor)
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or (
                expected_length is not None and info.st_size != expected_length
            ):
                raise RuntimeError("candidate changed or disagrees with hash/length")
            digest = hashlib.sha256()
            length = 0
            prefix = bytearray()
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                while block := stream.read(min(1024 * 1024, info.st_size - length + 1)):
                    digest.update(block)
                    length += len(block)
                    prefix.extend(block[: max(0, prefix_limit - len(prefix))])
                    if length > info.st_size:
                        break
            after = os.fstat(descriptor)
            changed = any(
                getattr(info, key) != getattr(after, key)
                for key in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
            )
            if changed or length != info.st_size or (expected_hash is not None and digest.hexdigest() != expected_hash):
                raise RuntimeError("candidate changed or disagrees with hash/length")
            return length, bytes(prefix), digest.hexdigest()

    def _write_declaration(self, raw):
        self._verify_paths()
        with ExitStack() as opened:
            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
            if os.name == "posix":
                directory_fd = _rooted_directory_fd(self.output)
                opened.callback(os.close, directory_fd)
                descriptor = os.open("agent-final.json", flags, 0o600, dir_fd=directory_fd)
            else:
                directory_fd = None
                descriptor = os.open(
                    self.output / "agent-final.json", flags | getattr(os, "O_BINARY", 0), 0o600
                )
            opened.callback(os.close, descriptor)
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            if directory_fd is not None:
                os.fsync(directory_fd)
            else:
                _fsync_directory(self.output)

    def lock_after_stop(self, container_is_stopped: Callable[[], bool]) -> FinalLock:
        with self._lock:
            return self._lock_after_stop(container_is_stopped)

    def _lock_after_stop(self, container_is_stopped):
        if container_is_stopped() is not True:
            raise RuntimeError("native solver container must be stopped before final lock")
        with self._connect() as c:
            c.execute("BEGIN IMMEDIATE")
            row = c.execute(
                "SELECT task,attempt,declaration,proof FROM selection WHERE id=1"
            ).fetchone()
            if row is None or row[:2] != (self.task_id, self.attempt_id):
                raise RuntimeError("no native parent selection for this task")
            state = c.execute("SELECT status FROM declaration_state WHERE id=1").fetchone()
            if state != ("declared",):
                raise RuntimeError("native final declaration write is incomplete")
            if c.execute("SELECT count(*) FROM lock_attempt").fetchone()[0]:
                raise RuntimeError("native final lock attempt already consumed")
            c.execute("INSERT INTO lock_attempt VALUES(1,'reserved')")

        def attest(raw):
            if raw != row[2]:
                raise PermissionError("final declaration changed after native selection")
            return ParentSelectionProof(**json.loads(row[3]))

        # Reserve before any copy. A failed hash/copy/audit cannot later become
        # successful by changing the candidate and retrying, even after restart.
        try:
            self._verify_paths()
            result = lock_agent_final(
                self.output, self.evidence, self.task_id, attest_parent_selection=attest
            )
            with self._connect() as c:
                c.execute("UPDATE lock_attempt SET status='locked' WHERE id=1")
            return result
        except BaseException:
            with self._connect() as c:
                c.execute("UPDATE lock_attempt SET status='failed' WHERE id=1")
            raise


def finalization_mcp_handler(
    finalizer: NativeFinalizer,
    *,
    peer: AdmittedPeer,
    resolve_parent_call: Callable[[str, str, dict], NativeToolCall],
):
    """Bind MCP to one peer and consume an exact native provider tool admission.

    Pass NativeToolController.resolve_mcp_call as the trusted resolver. Metadata
    is only a lookup key; its inert extra fields never grant role or authority.
    """
    if (
        type(finalizer) is not NativeFinalizer
        or type(peer) is not AdmittedPeer
        or not callable(resolve_parent_call)
    ):
        raise ValueError("trusted finalizer, admitted peer and resolver required")

    def handle(request: GatewayRequest) -> GatewayReply:
        if (
            request.peer != peer
            or request.endpoint != "registered-tool-gateway"
            or request.path != "/mcp/finalizer"
            or request.method != "POST"
            or type(request.body) is not bytes
            or not 0 < len(request.body) <= 256 * 1024
        ):
            return GatewayReply(403, b'{"error":"finalization route denied"}')
        try:
            body = _strict_json(request.body)
            if (
                type(body) is not dict
                or body.get("jsonrpc") != "2.0"
                or not set(body) <= {"jsonrpc", "id", "method", "params"}
            ):
                raise ValueError("invalid RPC envelope")
            method, params = body.get("method"), body.get("params", {})
            if type(params) is not dict:
                raise ValueError("invalid RPC params")
            if method == "notifications/initialized" and "id" not in body and not params:
                return GatewayReply(202, b"")
            if type(body.get("id")) not in (str, int):
                raise ValueError("RPC request id required")
            if method == "initialize":
                if (
                    set(params) != {"protocolVersion", "clientInfo", "capabilities"}
                    or params["protocolVersion"] not in {"2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"}
                    or type(params["clientInfo"]) is not dict
                    or type(params["capabilities"]) is not dict
                ):
                    raise ValueError("invalid MCP initialize")
                result = {
                    "protocolVersion": params["protocolVersion"],
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "cybergym-finalizer", "version": "1"},
                }
            elif method == "tools/list" and not params:
                result = {"tools": [SELECT_FINAL_TOOL]}
            elif method == "ping" and not params:
                result = {}
            elif method == "tools/call":
                if (
                    set(params) != {"name", "arguments", "_meta"}
                    or params["name"] != "select_final"
                    or type(params["arguments"]) is not dict
                    or type(params["_meta"]) is not dict
                    or len(_canonical(params["_meta"])) > 16 * 1024
                ):
                    raise PermissionError("invalid final tool call")
                tool_id = params["_meta"].get("claudecode/toolUseId")
                if type(tool_id) is not str or not _IDENTIFIER.fullmatch(tool_id):
                    raise PermissionError("native tool use id required")
                args = params["arguments"]
                call = resolve_parent_call(tool_id, _NATIVE_NAME, args)
                if (
                    type(call) is not NativeToolCall
                    or call.tool_id != tool_id
                    or call.name != _NATIVE_NAME
                    or _canonical(call.arguments) != _canonical(args)
                ):
                    raise PermissionError("native resolution mismatch")
                receipt = finalizer.select_final(call)
                result = {
                    "content": [{"type": "text", "text": _canonical(receipt).decode()}],
                    "isError": False,
                }
            else:
                raise PermissionError("undeclared finalization method")
            return GatewayReply(
                200, _canonical({"jsonrpc": "2.0", "id": body["id"], "result": result})
            )
        except PermissionError:
            return GatewayReply(403, b'{"error":"finalization route denied"}')
        except (ValueError, TypeError, AttributeError, RecursionError):
            return GatewayReply(400, b'{"error":"invalid finalization request"}')
        except Exception:
            return GatewayReply(
                503, b'{"error":"finalization failed; inspect controller evidence"}'
            )

    return handle
