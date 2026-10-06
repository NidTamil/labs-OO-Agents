# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Controller-only duplex transport to GBrain's authenticated native sidecar.

The sidecar runs the installed native dispatcher in the dedicated profile. It
authenticates against GBrain's OAuth tables on every request and interrupts each
native AI invocation for controller admission and durable settlement. Neither
the subprocess nor this bridge is a solver-facing capability.
"""

from __future__ import annotations

import json
import math
import queue
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from uuid import uuid4

from .deepseek import SharedCampaignBudget
from .memory import SOURCE_ID, AuditSink
from .memory_transport import RuntimeReadEvidence, TransportDenied

_MAX_FRAME = 4 * 1024 * 1024


class GBrainControllerBridge:
    """A task-scoped native process with an irreversible shared request budget."""

    def __init__(
        self,
        command: Sequence[str],
        *,
        budget: SharedCampaignBudget,
        audit: AuditSink,
        allowed_models: Mapping[str, str],
    ) -> None:
        if not command or isinstance(command, str) or not allowed_models:
            raise ValueError("native command and exact model policy required")
        if any(
            kind not in {"chat", "embedding", "rerank", "multimodal"}
            for kind in allowed_models.values()
        ):
            raise ValueError("invalid native model kind")
        self._budget, self._audit = budget, audit
        self._models = dict(allowed_models)
        self._lock = threading.RLock()
        self._frames: queue.Queue = queue.Queue(maxsize=64)
        self._pending: dict[str, dict] = {}
        self._closed = False
        self._last_evidence: dict = {}
        self._process = subprocess.Popen(
            list(command),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )
        threading.Thread(target=self._read_frames, daemon=True).start()

    def __repr__(self) -> str:
        return "<GBrainControllerBridge controller-held authenticated native session>"

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _read_frames(self) -> None:
        try:
            for _ in iter(int, 1):
                line = self._process.stdout.readline(_MAX_FRAME + 1)
                if not line or len(line) > _MAX_FRAME:
                    break
                self._frames.put(json.loads(line), timeout=1)
        except Exception:
            pass
        try:
            self._frames.put(None, timeout=1)
        except queue.Full:
            pass

    def _write(self, value: Mapping) -> None:
        if self._closed:
            raise TransportDenied("native session closed")
        payload = json.dumps(value, separators=(",", ":"), allow_nan=False)
        if len(payload) > _MAX_FRAME:
            raise TransportDenied("native frame exceeds limit")
        self._process.stdin.write(payload + "\n")
        self._process.stdin.flush()

    def _record(self, event: Mapping) -> None:
        if self._audit.record(dict(event)) is not True:
            raise TransportDenied("native invocation audit unavailable")

    def _admit(self, frame: Mapping, request_id: str) -> None:
        permit_id, invocation = frame.get("id"), frame.get("invocation")
        if (
            not isinstance(permit_id, str)
            or permit_id in self._pending
            or frame.get("request_id") != request_id
            or not isinstance(invocation, dict)
        ):
            raise TransportDenied("native invocation correlation invalid")
        model, kind = invocation.get("model"), invocation.get("kind")
        if (
            not isinstance(model, str)
            or model not in self._models
            or self._models[model] != kind
            or not isinstance(invocation.get("operation"), str)
        ):
            self._write({"type": "guard_reply", "id": permit_id, "ok": False})
            return
        try:
            reservation = self._budget.reserve_request()
        except Exception:
            self._write({"type": "guard_reply", "id": permit_id, "ok": False})
            return
        event = {
            "request_id": request_id,
            "permit_id": permit_id,
            "reservation_id": reservation,
            "model_id": model,
            "kind": kind,
            "operation": invocation["operation"],
            "started_monotonic": time.monotonic(),
        }
        self._pending[permit_id] = event
        self._record({**event, "event": "memory_model_admitted"})
        self._write({"type": "guard_reply", "id": permit_id, "ok": True})

    def _settle(self, frame: Mapping, request_id: str) -> None:
        permit_id = frame.get("id")
        event = self._pending.get(permit_id)
        if event is None or frame.get("request_id") != request_id:
            raise TransportDenied("native settlement correlation invalid")
        usage = frame.get("usage")
        if usage is not None:
            if not isinstance(usage, dict) or not {"inputTokens", "outputTokens"} <= usage.keys():
                raise TransportDenied("native settlement usage invalid")
            usage = {
                name: usage.get(name, 0)
                for name in ("inputTokens", "outputTokens", "cacheReadTokens", "cacheWriteTokens")
            }
            if any(
                type(value) not in (int, float) or not math.isfinite(value) or value < 0
                for value in usage.values()
            ):
                raise TransportDenied("native settlement usage invalid")
        self._record(
            {
                **event,
                "event": "memory_model_settled",
                "usage": usage,
                "duration_seconds": time.monotonic() - event["started_monotonic"],
            }
        )
        del self._pending[permit_id]
        self._write({"type": "guard_reply", "id": permit_id, "ok": True})

    def exchange(self, message: Mapping[str, object], *, timeout_seconds: float) -> object:
        with self._lock:
            if (
                type(timeout_seconds) not in (int, float)
                or not 0 < timeout_seconds <= 60
                or not isinstance(message.get("id"), str)
            ):
                raise TransportDenied("native request correlation or timeout invalid")
            deadline = time.monotonic() + min(timeout_seconds, self._budget.remaining_seconds())
            try:
                self._write(message)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError()
                    frame = self._frames.get(timeout=remaining)
                    if not isinstance(frame, dict):
                        raise TransportDenied("native session ended")
                    if frame.get("type") == "guard_admit":
                        self._admit(frame, message["id"])
                    elif frame.get("type") == "guard_settle":
                        self._settle(frame, message["id"])
                    elif frame.get("jsonrpc") == "2.0" and frame.get("id") == message["id"]:
                        if self._pending:
                            raise TransportDenied("native response has unsettled invocations")
                        return frame
                    else:
                        raise TransportDenied("native response correlation invalid")
            except Exception:
                self.close()
            raise TransportDenied("native authenticated dispatch failed") from None

    def notify(self, message: Mapping[str, object]) -> None:
        with self._lock:
            if dict(message) != {"jsonrpc": "2.0", "method": "notifications/initialized"}:
                raise TransportDenied("unsupported native notification")
            self._write(message)

    def read_evidence(self) -> RuntimeReadEvidence:
        reply = self.exchange(
            {"jsonrpc": "2.0", "id": uuid4().hex, "method": "xeus/evidence"},
            timeout_seconds=30,
        )
        data = reply.get("result")
        if (
            not isinstance(data, dict)
            or data.get("source_ids") != [SOURCE_ID]
            or data.get("server_context_source_id") != SOURCE_ID
            or data.get("scopes") != ["read"]
            or data.get("transport") != "native-guarded-stdio"
        ):
            raise TransportDenied("authenticated native source scope invalid")
        binding = data.get("native_guard_binding_sha256")
        if (
            data.get("native_guard_bound") is not True
            or not isinstance(binding, str)
            or len(binding) != 64
            or any(char not in "0123456789abcdef" for char in binding)
        ):
            raise TransportDenied("authenticated native guard evidence invalid")
        self._last_evidence = data
        return RuntimeReadEvidence(
            frozenset(data["source_ids"]), data["server_context_source_id"], binding, True
        )

    def inspection(self) -> dict:
        """Refresh and return non-secret grant/package metadata for authority signing."""
        self.read_evidence()
        return json.loads(json.dumps(self._last_evidence))

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._process.terminate()
            try:
                self._process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=2)
            for event in self._pending.values():
                try:
                    self._record(
                        {
                            **event,
                            "event": "memory_model_settled",
                            "usage": None,
                            "reason": "native_session_ended",
                            "duration_seconds": time.monotonic() - event["started_monotonic"],
                        }
                    )
                except Exception:
                    pass  # The failed exchange remains denied; no result is released.
            self._pending.clear()
