# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Additive official DeepSeek controller adapter; never a solver-side client.

The trusted caller owns role assignment, failure observation, shared budgets and
audit persistence. Do not inject this object, its credentials or transport into
agent REPL globals. This Python boundary is not OS/process/network isolation;
the native harness and controller isolation require separate live certification.
There are no retries, fallback routes, redirects, final-selection methods or
solver-selected provider settings. Returned advice remains untrusted data.
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal, Protocol
from uuid import uuid4

import httpx
from pydantic import BaseModel, ConfigDict, model_validator

ENDPOINT = "https://api.deepseek.com/chat/completions"
MODEL = "deepseek-flash"
CONTEXT_TOKENS = 1048576
MAX_OUTPUT_TOKENS = 128000
ALIAS_DISCLOSURE = (
    "The deepseek-flash moving alias and recorded returned metadata do not "
    "guarantee immutable provider weights; weights may change under the same alias. "
    "Accepted settings and metadata require a separate live certification snapshot."
)


class PolicyViolation(ValueError):
    pass


class BudgetExceeded(RuntimeError):
    pass


class ProviderFailure(RuntimeError):
    pass


class AuditFailure(RuntimeError):
    pass


class ControllerHalted(RuntimeError):
    pass


class DeepSeekRole(StrEnum):
    INDEPENDENT_RECON = "independent_recon"
    CONDITIONAL_DEBUG_RECOVERY = "conditional_debug_recovery"
    FINAL_ADVERSARIAL_CRITIC = "final_adversarial_critic"


class FrozenPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ThinkingPolicy(FrozenPolicy):
    type: Literal["enabled"]


class ProviderPolicy(FrozenPolicy):
    model: Literal["deepseek-flash"]
    provider: Literal["deepseek-official-api"]
    base_url: Literal["https://api.deepseek.com"]
    api: Literal["chat_completions"]
    thinking: ThinkingPolicy
    reasoning_effort: Literal["max"]
    context_tokens: Literal[1048576]
    max_output_tokens: Literal[128000]
    credential_ref: Literal["controller:DEEPSEEK_API_KEY"]
    metadata_policy: Literal["record_returned_model_version_fingerprint_when_available"]
    provider_weights_frozen_guarantee: Literal[False]

    @model_validator(mode="before")
    @classmethod
    def strict_numbers(cls, data):
        _literal_types(
            data,
            {
                "context_tokens": int,
                "max_output_tokens": int,
                "provider_weights_frozen_guarantee": bool,
            },
        )
        return data


ROLE_LIMITS = {
    DeepSeekRole.INDEPENDENT_RECON: ("one_recon_lane", 12, 12582912, 3600),
    DeepSeekRole.CONDITIONAL_DEBUG_RECOVERY: (
        "observable_vulnerable_side_failure",
        16,
        16777216,
        3600,
    ),
    DeepSeekRole.FINAL_ADVERSARIAL_CRITIC: ("before_glm_parent_final_selection", 8, 8388608, 1800),
}


class RoleRoute(FrozenPolicy):
    role: DeepSeekRole
    model: Literal["deepseek-flash"]
    trigger: str
    max_calls: int
    max_tokens: int
    max_seconds: int

    @model_validator(mode="before")
    @classmethod
    def strict_numbers(cls, data):
        _literal_types(data, {"max_calls": int, "max_tokens": int, "max_seconds": int})
        return data

    @model_validator(mode="after")
    def exact_limits(self):
        if (self.trigger, self.max_calls, self.max_tokens, self.max_seconds) != ROLE_LIMITS[
            self.role
        ]:
            raise ValueError("role limits or trigger differ from approved policy")
        return self


def _literal_types(data, fields):
    if isinstance(data, dict):
        for name, expected in fields.items():
            if name in data and type(data[name]) is not expected:
                raise ValueError("policy scalar type mismatch")


class AlternateModelPolicy(FrozenPolicy):
    schema_version: Literal[1]
    status: Literal["active"]
    models: tuple[ProviderPolicy, ...]
    routes: tuple[RoleRoute, ...]
    child_capabilities: tuple[str, ...]
    may_propose_poc: Literal[True]
    official_final_selector: Literal["glm_parent"]
    shared_task_max_requests: Literal[600]
    deepseek_max_requests: Literal[36]
    glm_and_memory_auxiliary_max_requests: Literal[564]
    shared_task_wall_timeout_sec: Literal[43200]
    max_concurrent_children: Literal[3]
    counted_tokens: Literal["input_plus_output_including_thinking_and_cached_input_once"]

    @model_validator(mode="before")
    @classmethod
    def strict_numbers(cls, data):
        _literal_types(
            data,
            dict.fromkeys(
                (
                    "schema_version",
                    "shared_task_max_requests",
                    "deepseek_max_requests",
                    "glm_and_memory_auxiliary_max_requests",
                    "shared_task_wall_timeout_sec",
                    "max_concurrent_children",
                ),
                int,
            )
            | {"may_propose_poc": bool},
        )
        return data

    @model_validator(mode="after")
    def assert_ready(self):
        if len(self.models) != 1 or len(self.routes) != 3:
            raise ValueError("exactly one provider and three roles are required")
        if {r.role for r in self.routes} != set(DeepSeekRole):
            raise ValueError("roles must be unique and complete")
        if self.child_capabilities != (
            "local_read",
            "clangd_read",
            "gbrain_recall",
            "gbrain_search",
        ):
            raise ValueError("child capabilities differ from approved policy")
        return self

    @property
    def manifest_json(self) -> str:
        return json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.manifest_json.encode()).hexdigest()


class AuditSink(Protocol):
    def record(self, event: dict[str, Any]) -> bool: ...


@dataclass(frozen=True)
class ProviderResponse:
    status_code: int
    body: dict[str, Any]


class ProviderTransport(Protocol):
    def send(
        self, endpoint: str, headers: dict[str, str], payload: dict[str, Any], timeout: float
    ) -> ProviderResponse: ...


class HttpxTransport:
    """Fresh non-redirecting clients; custom transports are controller test seams."""

    def __init__(self, *, transport: httpx.BaseTransport | None = None):
        self._transport = transport

    def send(self, endpoint, headers, payload, timeout):
        if endpoint != ENDPOINT:
            raise PolicyViolation("undeclared endpoint")
        with httpx.Client(
            transport=self._transport, follow_redirects=False, trust_env=False, timeout=timeout
        ) as client:
            response = client.post(ENDPOINT, headers=headers, json=payload)
            # Error/redirect response bodies need not be JSON and are never exposed.
            body = response.json() if response.status_code == 200 else {}
            return ProviderResponse(response.status_code, body)


class SharedCampaignBudget:
    """One controller instance per task, shared with GLM and memory auxiliary calls.

    Reservations are irreversible: failed dispatches count. Elapsed time follows
    the single campaign clock, including work outside this adapter. Default
    reservations belong only to GLM/memory (564); the trusted DeepSeek controller
    uses its separate method (36). Neither allocation borrows the other's unused
    capacity. Do not expose the budget object to generated code. A native ledger
    adapter may subclass this interface and bind both reservation methods and the
    shared clock to the existing authoritative ledger; this in-memory base is not
    a replacement for its persistence or process isolation.
    """

    def __init__(self, *, clock: Callable[[], float] | None = None):
        self._clock = clock or time.monotonic
        self._started = self._clock()
        self._requests = 0
        self._allocation_requests = {"glm_and_memory_auxiliary": 0, "deepseek": 0}
        self._lock = threading.Lock()

    def remaining_seconds(self):
        elapsed = self._clock() - self._started
        if not math.isfinite(elapsed) or elapsed < 0:
            raise BudgetExceeded("invalid shared campaign clock")
        return max(0.0, 43200 - elapsed)

    def reserve_request(self):
        """Trusted GLM/memory reservation; no caller-selectable allocation knob."""
        return self._reserve_allocation("glm_and_memory_auxiliary", 564)

    def reserve_deepseek_request(self):
        """Trusted DeepSeek controller reservation, never selected by model data."""
        return self._reserve_allocation("deepseek", 36)

    def _reserve_allocation(self, allocation, allocation_limit):
        with self._lock:
            if self._requests >= 600 or self.remaining_seconds() <= 0:
                raise BudgetExceeded("shared campaign request/time budget exhausted")
            if self._allocation_requests[allocation] >= allocation_limit:
                raise BudgetExceeded("declared caller request allocation exhausted")
            self._requests += 1
            self._allocation_requests[allocation] += 1
            return self._requests

    def snapshot(self):
        with self._lock:
            return {
                "requests": self._requests,
                "remaining_seconds": self.remaining_seconds(),
                "glm_and_memory_auxiliary_requests": self._allocation_requests[
                    "glm_and_memory_auxiliary"
                ],
                "deepseek_requests": self._allocation_requests["deepseek"],
            }


@dataclass(frozen=True)
class FailureEvidence:
    task_id: str
    attempt_id: str
    source: str
    exit_code: int
    evidence_digest: str
    admission_id: int


def _digest(value):
    return (
        isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)
    )


def _identity(value):
    return isinstance(value, str) and bool(value.strip())


class DeepSeekController:
    """Trusted controller only; do not expose this object to generated code.

    Failure admission must be fed by actual vulnerable build/test observations,
    never parsed model claims. It binds evidence to this controller/task/attempt.
    SharedCampaignBudget is mandatory for production integration: the default is
    a fresh synthetic task budget, not discovery of any existing native ledger.
    """

    def __init__(
        self,
        policy: AlternateModelPolicy,
        api_key: str,
        *,
        audit: AuditSink,
        registry_digest: str,
        budget: SharedCampaignBudget,
        transport: ProviderTransport | None = None,
        clock: Callable[[], float] | None = None,
    ):
        if type(policy) is not AlternateModelPolicy:
            raise TypeError("validated AlternateModelPolicy required")
        policy.assert_ready()
        if not _identity(api_key) or not _digest(registry_digest):
            raise PolicyViolation("controller credential or registry identity invalid")
        if not isinstance(budget, SharedCampaignBudget):
            raise TypeError("shared campaign budget required")
        # All state is controller-owned. Repr deliberately displays no state.
        self._policy = policy
        self._key = api_key
        self._audit = audit
        self._registry_digest = registry_digest
        self._budget = budget
        self._transport = transport or HttpxTransport()
        self._clock = clock or time.monotonic
        self._lock = threading.Lock()
        self._halted = False
        self._usage = {r: {"requests": 0, "tokens": 0, "seconds": 0.0} for r in DeepSeekRole}
        self._failures: dict[int, FailureEvidence] = {}
        self._provider_identity = None

    def __repr__(self):
        return "<DeepSeekController controller-owned state>"

    @property
    def budget(self):
        return self._budget

    def role_usage(self):
        with self._lock:
            return {r.value: dict(v) for r, v in self._usage.items()}

    def _redact(self, value):
        if isinstance(value, str):
            return value.replace(self._key, "[REDACTED]")
        if isinstance(value, dict):
            return {self._redact(k): self._redact(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self._redact(v) for v in value]
        return value

    def _record(self, event):
        accepted = False
        try:
            accepted = self._audit.record(self._redact(event)) is True
        except Exception:
            pass
        if not accepted:
            self._halted = True
            raise AuditFailure("controller audit not acknowledged")

    def admit_failure(self, *, task_id, attempt_id, source, exit_code, evidence_digest):
        with self._lock:
            if self._halted:
                raise ControllerHalted("controller halted")
            if (
                not _identity(task_id)
                or not _identity(attempt_id)
                or source not in ("vulnerable_build", "vulnerable_test")
                or type(exit_code) is not int
                or exit_code == 0
                or not _digest(evidence_digest)
            ):
                raise PolicyViolation("requires observed nonzero vulnerable build/test result")
            evidence = FailureEvidence(
                task_id, attempt_id, source, exit_code, evidence_digest, len(self._failures) + 1
            )
            self._failures[evidence.admission_id] = evidence
            return evidence

    def _validate_messages(self, messages):
        if not isinstance(messages, list) or not messages:
            raise PolicyViolation("nonempty messages required")
        for message in messages:
            if (
                not isinstance(message, dict)
                or set(message) != {"role", "content"}
                or message["role"] not in ("user", "assistant")
                or not isinstance(message["content"], str)
            ):
                raise PolicyViolation("only user/assistant content messages are admitted")
        return self._redact(messages)

    def _parse_response(self, response):
        if not isinstance(response, ProviderResponse) or response.status_code != 200:
            raise ProviderFailure("provider returned non-success status; no retry")
        body = self._redact(response.body)
        if (
            not isinstance(body, dict)
            or body.get("model") != MODEL
            or not _identity(body.get("id"))
        ):
            raise ProviderFailure("provider model/request identity missing or mismatched")
        identity = tuple(body.get(k) for k in ("model", "model_version", "system_fingerprint"))
        if any(v is not None and not _identity(v) for v in identity):
            raise ProviderFailure("invalid provider metadata")
        if self._provider_identity is not None and identity != self._provider_identity:
            raise ProviderFailure("visible provider metadata drift; recertification required")
        raw = body.get("usage")
        names = (
            "prompt_tokens",
            "completion_tokens",
            "total_tokens",
            "prompt_cache_hit_tokens",
            "prompt_cache_miss_tokens",
        )
        if not isinstance(raw, dict) or any(
            type(raw.get(n)) is not int or raw[n] < 0 for n in names
        ):
            raise ProviderFailure("complete nonnegative provider usage required")
        prompt, completion, total, hit, miss = (raw[n] for n in names)
        details = raw.get("completion_tokens_details", {})
        if not isinstance(details, dict):
            raise ProviderFailure("invalid completion token classes")
        thinking = details.get("reasoning_tokens")
        if thinking is not None and (type(thinking) is not int or not 0 <= thinking <= completion):
            raise ProviderFailure("invalid reasoning usage")
        if (
            total != prompt + completion
            or hit + miss != prompt
            or completion > MAX_OUTPUT_TOKENS
            or total > CONTEXT_TOKENS
        ):
            raise ProviderFailure("provider token accounting or context/output limit mismatch")
        choices = body.get("choices")
        if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict):
            raise ProviderFailure("single provider choice required")
        message = choices[0].get("message")
        if not isinstance(message, dict) or not isinstance(message.get("content"), str):
            raise ProviderFailure("provider advice content missing")
        self._provider_identity = identity
        usage = {
            "input_tokens": prompt,
            "output_tokens": completion,
            "counted_tokens": total,
            "cache_hit_input_tokens": hit,
            "cache_miss_input_tokens": miss,
            "reasoning_tokens": thinking,
            "provider_usage": raw,
        }
        return body, message, usage

    def request(
        self,
        *,
        role: DeepSeekRole,
        messages: list[dict[str, str]],
        task_id: str,
        attempt_id: str,
        failure: FailureEvidence | None = None,
    ):
        with self._lock:
            if self._halted:
                raise ControllerHalted("controller halted; review audit/provider evidence")
            if (
                type(role) is not DeepSeekRole
                or not _identity(task_id)
                or not _identity(attempt_id)
            ):
                raise PolicyViolation("trusted declared role and task/attempt identity required")
            if role is DeepSeekRole.CONDITIONAL_DEBUG_RECOVERY:
                if (
                    type(failure) is not FailureEvidence
                    or self._failures.get(failure.admission_id) is not failure
                    or failure.task_id != task_id
                    or failure.attempt_id != attempt_id
                ):
                    raise PolicyViolation("debug requires controller-admitted vulnerable failure")
            elif failure is not None:
                raise PolicyViolation("failure trigger only belongs to debug role")
            clean_messages = self._validate_messages(messages)
            _, max_calls, max_tokens, max_seconds = ROLE_LIMITS[role]
            state = self._usage[role]
            remaining = min(max_seconds - state["seconds"], self._budget.remaining_seconds())
            allowed_duration = remaining
            # Reserve an entire possible context before forwarding, then settle to
            # actual usage. Unknown usage retains the reservation and halts calls.
            if (
                state["requests"] >= max_calls
                or state["tokens"] + CONTEXT_TOKENS > max_tokens
                or remaining <= 0
            ):
                raise BudgetExceeded("role request/token/time budget exhausted")
            shared_request = self._budget.reserve_deepseek_request()
            state["requests"] += 1
            state["tokens"] += CONTEXT_TOKENS
            started = self._clock()
            payload = {
                "model": MODEL,
                "thinking": {"type": "enabled"},
                "reasoning_effort": "max",
                "max_tokens": MAX_OUTPUT_TOKENS,
                "messages": clean_messages,
            }
            event = {
                "event": "request",
                "role": role.value,
                "task_id": task_id,
                "request_id": uuid4().hex,
                "attempt_id": attempt_id,
                "request_number": state["requests"],
                "shared_request_number": shared_request,
                "registry_digest": self._registry_digest,
                "policy_digest": self._policy.digest,
                "endpoint": ENDPOINT,
                "requested_model": MODEL,
                "request_sha256": hashlib.sha256(
                    json.dumps(payload, sort_keys=True).encode()
                ).hexdigest(),
                "request_settings": {k: v for k, v in payload.items() if k != "messages"},
                "requested_at_utc": datetime.now(UTC).isoformat(),
                "started_monotonic_seconds": started,
                "failure_evidence_digest": failure.evidence_digest if failure else None,
            }
            self._record(event)
            # Audit persistence can block. Recheck both clocks after it acknowledges
            # the reservation, before placing any provider credential on the wire.
            audit_duration = self._clock() - started
            if not math.isfinite(audit_duration) or audit_duration < 0:
                forward_remaining = 0.0
                audit_duration = allowed_duration
            else:
                forward_remaining = min(
                    allowed_duration - audit_duration, self._budget.remaining_seconds()
                )
            if forward_remaining <= 0:
                self._halted = True
                state["seconds"] += audit_duration
                self._record(
                    event
                    | {
                        "event": "failure",
                        "duration_seconds": audit_duration,
                        "completed_at_utc": datetime.now(UTC).isoformat(),
                        "error": "budget exhausted during pre-forward audit",
                        "http_status": None,
                    }
                )
                raise BudgetExceeded("budget exhausted during pre-forward audit")
            # Do not propagate provider/transport exceptions (or their traceback
            # chains), which may embed controller credentials in HTTP headers.
            error_message = None
            response = None
            try:
                response = self._transport.send(
                    ENDPOINT,
                    {"Authorization": "Bearer " + self._key, "Content-Type": "application/json"},
                    payload,
                    forward_remaining,
                )
                body, message, usage = self._parse_response(response)
            except Exception as error:
                error_message = (
                    str(error)
                    if isinstance(error, ProviderFailure)
                    else "provider transport failed; no retry"
                )
            duration = self._clock() - started
            if not math.isfinite(duration) or duration < 0:
                error_message = "invalid controller clock"
                duration = allowed_duration
            state["seconds"] += duration
            if duration > allowed_duration:
                error_message = "provider exceeded declared time budget"
            if error_message is not None:
                self._halted = True
                observed = (
                    response.body
                    if isinstance(response, ProviderResponse) and isinstance(response.body, dict)
                    else {}
                )
                self._record(
                    event
                    | {
                        "event": "failure",
                        "duration_seconds": duration,
                        "completed_at_utc": datetime.now(UTC).isoformat(),
                        "http_status": response.status_code
                        if isinstance(response, ProviderResponse)
                        else None,
                        "returned_model": observed.get("model"),
                        "provider_request_id": observed.get("id"),
                        "model_version": observed.get("model_version"),
                        "system_fingerprint": observed.get("system_fingerprint"),
                        "provider_usage": observed.get("usage"),
                        "error": self._redact(error_message),
                    }
                )
                raise ProviderFailure(self._redact(error_message))
            state["tokens"] += usage["counted_tokens"] - CONTEXT_TOKENS
            metadata = {
                "returned_model": body["model"],
                "provider_request_id": body["id"],
                "model_version": body.get("model_version"),
                "system_fingerprint": body.get("system_fingerprint"),
                "usage": usage,
                "duration_seconds": duration,
                "http_status": response.status_code,
                "completed_at_utc": datetime.now(UTC).isoformat(),
                "provider_weights_frozen_guarantee": False,
                "metadata_disclosure": ALIAS_DISCLOSURE,
            }
            self._record(event | metadata | {"event": "response"})
            return self._redact(metadata | {"content": message["content"], "message": message})
