# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Oracle-labelled episodic capture held exclusively by the trusted controller."""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from .memory import SOURCE_ID, AuditSink
from .memory_transport import ControllerMcpBridge, TransportDenied
from .synthetic_oracle import SyntheticOracleResult

_HASH = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,127}\Z")
_HASH_FIELDS = (
    "final_sha256",
    "final_declaration_sha256",
    "parent_event_digest",
    "oracle_request_sha256",
    "oracle_verdict_sha256",
)


class OracleMemoryWriter:
    """Publish deterministic episodes only after authoritative terminal verification.

    ``attest_receipt`` must verify the native Xeus signed terminal_receipt.
    The caller owns stopping the solver and oracle custody. The private bridge
    uses a distinct capture-only OAuth client. Episodes never enter the signed
    solver-readable manifest automatically; reviewed promotion is separate.
    """

    def __init__(
        self,
        *,
        bridge: ControllerMcpBridge,
        attest_receipt: Callable[[bytes], Mapping | None],
        audit: AuditSink,
        evidence_root: Path,
        run_id: str,
        epoch: str,
        expected_guard_binding_sha256: str,
    ) -> None:
        if not all(isinstance(value, str) and _ID.fullmatch(value) for value in (run_id, epoch)):
            raise ValueError("frozen campaign identity required")
        if not _HASH.fullmatch(expected_guard_binding_sha256):
            raise ValueError("frozen native guard binding required")
        self._bridge, self._attest, self._audit = bridge, attest_receipt, audit
        self._root, self._run, self._epoch = Path(evidence_root), run_id, epoch
        self._binding = expected_guard_binding_sha256
        if self._root.is_symlink() or not self._root.is_dir():
            raise ValueError("controller evidence directory required")
        self._lock = threading.Lock()

    def _record(self, event):
        if self._audit.record(event) is not True:
            raise TransportDenied("oracle memory audit unavailable")

    def publish(self, signed_receipt: bytes, *, task_id: str) -> dict:
        """Write at most one bounded factual episode for an actual oracle result."""
        with self._lock:
            return self._publish(signed_receipt, task_id)

    def publish_synthetic(
        self,
        result: SyntheticOracleResult,
        *,
        verifier,
        attempt_id: str,
        freeze_sha256: str,
        solver_stopped: Callable[[], bool],
    ) -> dict:
        """Capture a separately labelled toy episode from a signed stopped run."""
        with self._lock:
            if solver_stopped() is not True:
                raise TransportDenied("stopped solver required before synthetic capture")
            if (
                type(result) is not SyntheticOracleResult
                or result.signed_evidence.parent != self._root
                or result.signed_evidence.is_symlink()
                or not result.signed_evidence.is_file()
                or not _HASH.fullmatch(freeze_sha256)
                or not _ID.fullmatch(attempt_id)
            ):
                raise TransportDenied("signed synthetic oracle evidence required")
            raw = result.signed_evidence.read_bytes()
            if not 0 < len(raw) <= 65536:
                raise TransportDenied("bounded signed synthetic oracle evidence required")
            try:
                from xeus_cybergym.ledger import SignedEnvelope

                payload = verifier.verify(SignedEnvelope.model_validate_json(raw))
                verdict = json.loads(payload)
            except Exception as error:
                raise TransportDenied("synthetic oracle signature invalid") from error
            request = verdict.get("request") if isinstance(verdict, dict) else None
            if (
                type(request) is not dict
                or verdict.get("schema_version") != 1
                or verdict.get("artifact_kind") != "synthetic_oracle_evidence"
                or request.get("scope") != "synthetic_private_oracle"
                or request.get("run_id") != self._run
                or request.get("task_id") != result.task_id
                or request.get("attempt_id") != attempt_id
                or request.get("freeze_sha256") != freeze_sha256
                or request.get("candidate_sha256") != result.candidate_sha256
                or hashlib.sha256(payload).hexdigest() != result.evidence_sha256
                or type(verdict.get("oracle_true")) is not bool
                or verdict["oracle_true"] is not result.true
                or not _HASH.fullmatch(result.candidate_sha256)
                or not all(
                    isinstance(verdict.get(name), str) and _HASH.fullmatch(verdict[name])
                    for name in ("final_declaration_sha256", "parent_event_digest")
                )
            ):
                raise TransportDenied("synthetic oracle identity or verdict mismatch")
            self._check_writer_scope()
            receipt_hash = hashlib.sha256(raw).hexdigest()
            outcome = "synthetic_oracle_true" if result.true else "synthetic_oracle_false"
            event = self._event(
                task_id=result.task_id,
                receipt_hash=receipt_hash,
                outcome=outcome,
                verdict_id=result.evidence_sha256,
            )
            content = (
                "---\ntype: note\ntier: episodic\nreviewed: false\n"
                "title: Controller verified synthetic toy oracle outcome\nlicense: CC0-1.0\n"
                f"captured_at: {datetime.now(UTC).isoformat()}\n"
                f"source_document: synthetic-oracle:{receipt_hash}\nsource_sha256: {receipt_hash}\n"
                f"oracle_outcome: {outcome}\n---\n"
                "The trusted controller recorded a synthetic toy oracle verdict. "
                "This is not an official CyberGym result.\n"
                f"Final candidate SHA-256: {result.candidate_sha256}\n"
                f"Toy oracle evidence SHA-256: {result.evidence_sha256}\n"
                "This episode is an outcome record; it makes no general vulnerability claim.\n"
            )
            return self._capture(event, content)

    def _check_writer_scope(self):
        scope = {}
        try:
            scope_reply = self._bridge.exchange(
                {"jsonrpc": "2.0", "id": uuid4().hex, "method": "xeus/evidence"}, timeout_seconds=30
            )
            if isinstance(scope_reply.get("result"), dict):
                scope = scope_reply["result"]
        except Exception:
            pass
        if (
            scope.get("source_ids") != [SOURCE_ID]
            or scope.get("server_context_source_id") != SOURCE_ID
            or scope.get("scopes") != ["read", "write"]
            or scope.get("session_mode") != "writer"
            or scope.get("native_guard_bound") is not True
            or scope.get("native_guard_binding_sha256") != self._binding
        ):
            raise TransportDenied("separate authenticated writer scope or guard mismatch")

    def _event(self, *, task_id, receipt_hash, outcome, verdict_id):
        identity = hashlib.sha256(
            json.dumps([self._run, self._epoch, task_id]).encode()
        ).hexdigest()
        return {
            "task_id": task_id,
            "run_id": self._run,
            "epoch": self._epoch,
            "source_id": SOURCE_ID,
            "slug": f"cybergym/episodic/{identity}",
            "receipt_sha256": receipt_hash,
            "oracle_outcome": outcome,
            "verdict_id": verdict_id,
            "actor": "controller",
        }

    def _publish(self, signed_receipt, task_id):
        if (
            not isinstance(signed_receipt, bytes)
            or not 0 < len(signed_receipt) <= 65536
            or not isinstance(task_id, str)
            or not _ID.fullmatch(task_id)
        ):
            raise TransportDenied("signed oracle receipt required")
        try:
            verdict = self._attest(signed_receipt)
        except Exception:
            verdict = None
        if (
            not isinstance(verdict, Mapping)
            or verdict.get("artifact_kind") != "terminal_receipt"
            or verdict.get("schema_version") != 1
            or verdict.get("run_id") != self._run
            or verdict.get("epoch") != self._epoch
            or verdict.get("task_id") != task_id
            or verdict.get("status") not in {"oracle_true", "oracle_false"}
            or verdict.get("oracle_true") is not (verdict["status"] == "oracle_true")
            or any(
                not isinstance(verdict.get(name), str) or not _HASH.fullmatch(verdict[name])
                for name in _HASH_FIELDS
            )
        ):
            raise TransportDenied("actual signed oracle verdict is absent or mismatched")
        self._check_writer_scope()
        receipt_hash = hashlib.sha256(signed_receipt).hexdigest()
        event = self._event(
            task_id=task_id,
            receipt_hash=receipt_hash,
            outcome=verdict["status"],
            verdict_id=verdict["oracle_verdict_sha256"],
        )
        content = (
            "---\ntype: note\ntier: episodic\nreviewed: false\n"
            "title: Controller verified oracle outcome\nlicense: CC0-1.0\n"
            f"captured_at: {datetime.now(UTC).isoformat()}\n"
            f"source_document: oracle-receipt:{receipt_hash}\nsource_sha256: {receipt_hash}\n"
            f"oracle_outcome: {verdict['status']}\n---\n"
            "The trusted controller recorded an actual official oracle verdict.\n"
            f"Final candidate SHA-256: {verdict['final_sha256']}\n"
            f"Oracle verdict SHA-256: {verdict['oracle_verdict_sha256']}\n"
            "This episode is an outcome record; it makes no general vulnerability claim.\n"
        )
        return self._capture(event, content)

    def _capture(self, event, content):
        marker = self._root / f"memory-write-{event['slug'].rsplit('/', 1)[-1]}.json"
        try:
            descriptor = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raise TransportDenied("oracle memory capture already attempted") from None
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(event, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        if os.name == "posix":
            directory = os.open(self._root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        self._record({**event, "event": "memory_oracle_episode_attempted"})
        result = None
        try:
            reply = self._bridge.exchange(
                {
                    "jsonrpc": "2.0",
                    "id": uuid4().hex,
                    "method": "xeus/oracle-capture",
                    "params": {"arguments": {"slug": event["slug"], "content": content, "type": "note"}},
                },
                timeout_seconds=60,
            )
            raw = reply["result"]
            if raw.get("isError", False) is not False or len(raw["content"]) != 1:
                raise ValueError()
            candidate = json.loads(raw["content"][0]["text"])
            if (
                candidate.get("channel") != "capture"
                or candidate.get("slug") != event["slug"]
                or not _HASH.fullmatch(candidate.get("content_hash", ""))
            ):
                raise ValueError()
            result = candidate
        except Exception:
            pass
        if result is None:
            self._record({**event, "event": "memory_oracle_episode_unknown"})
            raise TransportDenied("native oracle memory capture acknowledgement unavailable")
        self._record(
            {
                **event,
                "event": "memory_oracle_episode_written",
                "native_content_hash": result["content_hash"],
            }
        )
        return {**event, "native_content_hash": result["content_hash"], "native_result": result}
