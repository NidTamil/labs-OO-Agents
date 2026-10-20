# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Verify independently pinned conservative dispatch bounds without inventing prices.

The trusted controller supplies the complete allowed route/lane/model inventory
and its enforced token caps from frozen runtime inputs. A separately reviewed
metering document must cover that exact inventory. Each charge is an attested
conservative upper bound, including unknown or failed attempts, not a measured
provider bill. This verifier checks the binding and structure; operational price
evidence and enforcement of the declared input/output caps remain admission gates.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from dataclasses import asdict, dataclass

from .campaign import _json_bytes
from .run_request_budget import Allocation

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_MAX_INTEGER = 2**53 - 1
_LANES = frozenset(
    {
        "primary",
        "count_tokens",
        "advisory_recon",
        "advisory_debug",
        "advisory_critic",
        "memory",
        "post_oracle_memory",
    }
)


def _digest(value: object) -> bool:
    return type(value) is str and _DIGEST.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class DispatchBound:
    lane: str
    provider: str
    model: str
    input_token_limit: int
    output_token_limit: int

    @property
    def allocation(self) -> Allocation:
        return "deepseek_advisory" if self.lane.startswith("advisory_") else "primary_and_memory"

    def validate(self) -> None:
        if (
            self.lane not in _LANES
            or any(
                type(value) is not str
                or not value
                or len(value) > 512
                or value != value.strip()
                or not value.isprintable()
                for value in (self.provider, self.model)
            )
            or type(self.input_token_limit) is not int
            or not 0 < self.input_token_limit <= _MAX_INTEGER
            or type(self.output_token_limit) is not int
            or not 0 <= self.output_token_limit <= _MAX_INTEGER
        ):
            raise ValueError("invalid frozen dispatch bound")


@dataclass(frozen=True, slots=True)
class VerifiedMeteringPolicy:
    policy_json: bytes
    sha256: str
    model_policy_sha256: str
    required_dispatch_bounds: tuple[DispatchBound, ...]
    primary_and_memory_charge: int
    deepseek_advisory_charge: int

    def reverify(self) -> None:
        verified = verify_metering_policy(
            policy_json=self.policy_json,
            expected_sha256=self.sha256,
            model_policy_sha256=self.model_policy_sha256,
            required_dispatch_bounds=self.required_dispatch_bounds,
        )
        if verified != self:
            raise ValueError("metering policy binding changed")

    def charge(self, allocation: Allocation) -> int:
        if allocation == "primary_and_memory":
            return self.primary_and_memory_charge
        if allocation == "deepseek_advisory":
            return self.deepseek_advisory_charge
        raise ValueError("unknown controller allocation")


def verify_metering_policy(
    *,
    policy_json: bytes,
    expected_sha256: str,
    model_policy_sha256: str,
    required_dispatch_bounds: Sequence[DispatchBound],
) -> VerifiedMeteringPolicy:
    """Bind exact canonical bytes to independently supplied runtime caps and digest."""
    if (
        type(policy_json) is not bytes
        or not 0 < len(policy_json) <= 262144
        or not _digest(expected_sha256)
        or not _digest(model_policy_sha256)
        or hashlib.sha256(policy_json).hexdigest() != expected_sha256
        or not isinstance(required_dispatch_bounds, (tuple, list))
        or not required_dispatch_bounds
    ):
        raise ValueError("independently pinned canonical metering policy required")
    bounds = tuple(required_dispatch_bounds)
    for bound in bounds:
        if type(bound) is not DispatchBound:
            raise ValueError("explicit frozen dispatch bounds required")
        bound.validate()
    identities = {(bound.lane, bound.provider, bound.model) for bound in bounds}
    if len(identities) != len(bounds) or {bound.lane for bound in bounds} != _LANES:
        raise ValueError("complete unique dispatch coverage required")
    try:
        document = json.loads(policy_json)
        if _json_bytes(document) != policy_json:
            raise ValueError("metering policy must be canonical")
    except (UnicodeError, TypeError, json.JSONDecodeError) as error:
        raise ValueError("invalid canonical metering policy") from error
    fixed = {
        "schema_version": 1,
        "artifact_kind": "conservative_dispatch_metering",
        "model_policy_sha256": model_policy_sha256,
        "spend_unit": "usd_micros",
        "accounting": "reserve_all_attempts_no_refunds",
    }
    if (
        type(document) is not dict
        or set(document) != set(fixed) | {"dispatch_bounds"}
        or any(
            type(document[key]) is not type(value) or document[key] != value
            for key, value in fixed.items()
        )
        or type(document["dispatch_bounds"]) is not list
        or len(document["dispatch_bounds"]) != len(bounds)
    ):
        raise ValueError("metering policy scope or dispatch coverage invalid")
    charges = {"primary_and_memory": 0, "deepseek_advisory": 0}
    for entry, bound in zip(document["dispatch_bounds"], bounds, strict=True):
        expected = asdict(bound)
        if (
            type(entry) is not dict
            or set(entry) != set(expected) | {"max_charge_units", "bound_evidence_sha256"}
            or any(
                type(entry[key]) is not type(value) or entry[key] != value
                for key, value in expected.items()
            )
            or type(entry["max_charge_units"]) is not int
            or not 0 < entry["max_charge_units"] <= _MAX_INTEGER
            or not _digest(entry["bound_evidence_sha256"])
        ):
            raise ValueError("metering bound does not cover frozen runtime caps")
        charges[bound.allocation] = max(charges[bound.allocation], entry["max_charge_units"])
    return VerifiedMeteringPolicy(
        policy_json,
        expected_sha256,
        model_policy_sha256,
        bounds,
        charges["primary_and_memory"],
        charges["deepseek_advisory"],
    )
