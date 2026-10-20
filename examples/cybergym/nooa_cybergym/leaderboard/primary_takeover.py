# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Versioned controller-only policy for one pre-response primary takeover.

This module neither admits requests nor owns budgets, clocks or native sessions.
The trusted controller classifies availability failures and keeps every admitted
provider attempt bound to its original immutable route. It must not expose this
state or its writer to solver code.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import threading
from collections.abc import Callable
from dataclasses import asdict, dataclass, fields


@dataclass(frozen=True, slots=True)
class PrimaryRoute:
    provider: str
    model: str
    wire_model: str
    base_url: str
    api: str = "anthropic_messages"
    allocation: str = "primary_and_memory"
    metadata_policy: str = "record_returned_model_version_fingerprint_when_available"
    provider_weights_frozen_guarantee: bool = False


_INITIAL_ROUTE = PrimaryRoute(
    provider="zai-coding-plan",
    model="glm-5.3[1m]",
    wire_model="glm-5.3",
    base_url="https://api.z.ai/api/anthropic",
)
_FALLBACK_ROUTE = PrimaryRoute(
    provider="deepseek-official-api",
    model="deepseek-flash",
    wire_model="deepseek-flash",
    base_url="https://api.deepseek.com/anthropic",
)
_ELIGIBLE_FAILURE_KINDS = (
    "connection_failure",
    "connect_timeout",
    "read_timeout",
    "rate_limited",
    "provider_unavailable",
)


@dataclass(frozen=True, slots=True)
class PrimaryTakeoverPolicy:
    """Exact version-one policy; the DeepSeek selector remains a moving alias."""

    schema_version: int = 1
    initial: PrimaryRoute = _INITIAL_ROUTE
    fallback: PrimaryRoute = _FALLBACK_ROUTE
    eligible_failure_kinds: tuple[str, ...] = _ELIGIBLE_FAILURE_KINDS
    max_transitions: int = 1
    require_no_response_started: bool = True

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != 1
            or type(self.max_transitions) is not int
            or self.max_transitions != 1
            or self.require_no_response_started is not True
            or type(self.eligible_failure_kinds) is not tuple
            or any(type(value) is not str for value in self.eligible_failure_kinds)
            or self.eligible_failure_kinds != _ELIGIBLE_FAILURE_KINDS
        ):
            raise ValueError("fixed primary takeover policy required")
        for actual, expected in (
            (self.initial, _INITIAL_ROUTE),
            (self.fallback, _FALLBACK_ROUTE),
        ):
            if type(actual) is not PrimaryRoute or any(
                type(getattr(actual, field.name)) is not type(getattr(expected, field.name))
                or getattr(actual, field.name) != getattr(expected, field.name)
                for field in fields(PrimaryRoute)
            ):
                raise ValueError("fixed primary takeover route required")

    @property
    def manifest_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"), allow_nan=False)

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.manifest_json.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class PrimaryTakeoverEvent:
    """Transition evidence, not evidence that the fallback dispatch occurred."""

    task_id: str
    attempt_id: str
    policy_sha256: str
    request_id: str
    failed_provider_attempt_id: str
    fallback_provider_attempt_id: str
    failure_kind: str
    from_route: PrimaryRoute
    to_route: PrimaryRoute
    response_started: bool = False
    schema_version: int = 1
    event: str = "primary_route_switched"


class PrimaryTakeoverPersistenceError(RuntimeError):
    """An ambiguous or failed durable write makes this attempt unroutable."""


def _validate_identity(value: str) -> None:
    if (
        type(value) is not str
        or not value
        or len(value) > 128
        or value != value.strip()
        or not value.isprintable()
    ):
        raise ValueError("nonempty bounded controller identity required")


class PrimaryTakeoverState:
    """Own a single live attempt's route; never reconstruct or resume an attempt.

    ``event_writer`` must synchronously persist the event and acknowledge with
    exactly ``True``. It can be ``RuntimeAudit.record``. Any exception or other
    return value poisons the state, including when the record may already exist.

    Failure categories are trusted controller observations, never solver inputs.
    ``connect_timeout`` and ``read_timeout`` mean provider transport timeouts;
    a task deadline, role deadline, audit failure or cancellation is ineligible.
    ``response_started`` includes downstream headers and any SSE bytes, even if
    no model text or tool output has appeared.

    The fallback attempt ID identifies the intended continuation only. Request
    reservation, actual dispatch and settlement remain the caller's duties.
    Already admitted calls keep their captured ``PrimaryRoute`` unchanged.
    """

    def __init__(
        self,
        *,
        task_id: str,
        attempt_id: str,
        policy: PrimaryTakeoverPolicy,
        policy_sha256: str,
        event_writer: Callable[[PrimaryTakeoverEvent], bool],
    ) -> None:
        _validate_identity(task_id)
        _validate_identity(attempt_id)
        if (
            type(policy) is not PrimaryTakeoverPolicy
            or type(policy_sha256) is not str
            or policy_sha256 != policy.digest
        ):
            raise ValueError("matching primary takeover policy identity required")
        if (
            not callable(event_writer)
            or inspect.iscoroutinefunction(event_writer)
            or inspect.iscoroutinefunction(event_writer.__call__)
        ):
            raise TypeError("synchronous durable event writer required")
        self._task_id = task_id
        self._attempt_id = attempt_id
        self._policy = policy
        self._policy_sha256 = policy_sha256
        self._event_writer = event_writer
        self._route = policy.initial
        self._lock = threading.RLock()
        self._poisoned = False
        self._transition_in_progress = False
        self._switched = False

    def _require_available(self) -> None:
        if self._poisoned:
            raise PrimaryTakeoverPersistenceError("primary takeover persistence unavailable")

    @property
    def route(self) -> PrimaryRoute:
        with self._lock:
            self._require_available()
            return self._route

    def switch(
        self,
        *,
        request_id: str,
        failure_kind: str,
        response_started: bool,
        failed_provider_attempt_id: str,
        fallback_provider_attempt_id: str,
    ) -> PrimaryRoute:
        """Persist one eligible GLM-to-DeepSeek transition before publishing it."""
        with self._lock:
            self._require_available()
            if self._switched:
                raise RuntimeError("primary route already switched")
            if self._transition_in_progress:
                raise RuntimeError("primary route transition in progress")
            for value in (request_id, failed_provider_attempt_id, fallback_provider_attempt_id):
                _validate_identity(value)
            if len({request_id, failed_provider_attempt_id, fallback_provider_attempt_id}) != 3:
                raise ValueError("request and provider attempt identity must be distinct")
            if (
                type(failure_kind) is not str
                or failure_kind not in self._policy.eligible_failure_kinds
            ):
                raise ValueError("failure is not eligible for primary takeover")
            if response_started is not False:
                raise ValueError("primary takeover requires no downstream response started")
            event = PrimaryTakeoverEvent(
                task_id=self._task_id,
                attempt_id=self._attempt_id,
                policy_sha256=self._policy_sha256,
                request_id=request_id,
                failed_provider_attempt_id=failed_provider_attempt_id,
                fallback_provider_attempt_id=fallback_provider_attempt_id,
                failure_kind=failure_kind,
                from_route=self._route,
                to_route=self._policy.fallback,
            )
            self._transition_in_progress = True
            try:
                acknowledged = self._event_writer(event)
                if inspect.iscoroutine(acknowledged):
                    acknowledged.close()
                if acknowledged is not True:
                    raise PrimaryTakeoverPersistenceError(
                        "primary takeover durable write was not acknowledged"
                    )
                self._route = self._policy.fallback
                self._switched = True
                return self._route
            except BaseException as error:
                self._poisoned = True
                if not isinstance(error, Exception):
                    raise
                raise PrimaryTakeoverPersistenceError(
                    "primary takeover durable write failed"
                ) from error
            finally:
                self._transition_in_progress = False
