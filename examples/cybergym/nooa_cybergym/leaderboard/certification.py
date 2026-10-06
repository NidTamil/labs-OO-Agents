# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Synthetic-only certification admission and frozen policy binding.

This module prepares a gate; it does not record a live certification pass.
The live native extension, provider, GBrain and isolation probes must supply
their own observed evidence before a report can pass.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, model_validator

from nooa_cybergym.leaderboard.deepseek import AlternateModelPolicy, DeepSeekRole

FIXTURE_IDS = frozenset({"synthetic:length-header", "synthetic:chunk-table"})
_ROLE_CALLS = {
    "independent_recon": 12,
    "conditional_debug_recovery": 16,
    "final_adversarial_critic": 8,
}
_ROLE_TOKENS = {
    "independent_recon": 12582912,
    "conditional_debug_recovery": 16777216,
    "final_adversarial_critic": 8388608,
}
_ROLE_SECONDS = {
    "independent_recon": 3600,
    "conditional_debug_recovery": 3600,
    "final_adversarial_critic": 1800,
}
_REQUIRED_DENIALS = frozenset(
    {
        "external-target-repository",
        "external-target-patch",
        "target-issue-or-changelog",
        "cve-or-published-poc",
        "provider-credential-access",
        "personal-brain-or-agent-memory-write",
        "/var/run/docker.sock",
        "/srv/sunchaser",
        "/tmp/poc",
    }
)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def assert_synthetic_only(
    *,
    requested_ids: list[str],
    cohort_ids: set[str] | frozenset[str],
    allowed_fixture_ids: set[str] | frozenset[str] = FIXTURE_IDS,
) -> None:
    """Reject an official or undeclared task before workspace creation."""

    if set(requested_ids) & cohort_ids:
        raise RuntimeError("certification request intersects official cohort")
    if (
        not requested_ids
        or len(requested_ids) != len(set(requested_ids))
        or any(not task_id.startswith("synthetic:") for task_id in requested_ids)
        or any(task_id not in allowed_fixture_ids for task_id in requested_ids)
    ):
        raise RuntimeError("certification requires a declared synthetic fixture")


class CertificationPolicy(BaseModel):
    """Exact parameters that live certification must later observe."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1]
    fixture_ids: tuple[str, str]
    repeat_count: Literal[2]
    primary_model: Literal["glm-5.3[1m]"]
    reasoning_effort: Literal["max"]
    context_tokens: Literal[1000000]
    max_output_tokens: Literal[128000]
    max_model_requests_per_task: Literal[600]
    alternate_model: Literal["deepseek-flash"]
    alternate_provider: Literal["https://api.deepseek.com"]
    alternate_api: Literal["chat_completions"]
    alternate_thinking: dict[str, str]
    alternate_reasoning_effort: Literal["max"]
    alternate_context_tokens: Literal[1048576]
    alternate_max_requests_by_role: dict[str, int]
    alternate_max_tokens_by_role: dict[str, int]
    alternate_max_seconds_by_role: dict[str, int]
    memory_mode: Literal["audited_hybrid"]
    required_capability_coverage: Literal["all_enabled_registry_entries"]
    max_concurrent_children: Literal[3]
    required_orchestration_mode: Literal["ultracode"]
    required_workflows: tuple[str, str]
    conditional_workflows: tuple[str]
    task_wall_timeout_sec: Literal[43200]
    required_denials: tuple[str, ...]

    @model_validator(mode="after")
    def exact_campaign_policy(self) -> CertificationPolicy:
        if self.fixture_ids != ("synthetic:length-header", "synthetic:chunk-table"):
            raise ValueError("certification fixture IDs differ from frozen policy")
        if self.alternate_thinking != {"type": "enabled"}:
            raise ValueError("DeepSeek thinking differs from frozen policy")
        if (
            self.alternate_max_requests_by_role != _ROLE_CALLS
            or self.alternate_max_tokens_by_role != _ROLE_TOKENS
            or self.alternate_max_seconds_by_role != _ROLE_SECONDS
        ):
            raise ValueError("DeepSeek role limits differ from frozen policy")
        if self.required_workflows != ("recon", "review") or self.conditional_workflows != (
            "debug",
        ):
            raise ValueError("workflow coverage differs from frozen policy")
        if frozenset(self.required_denials) != _REQUIRED_DENIALS:
            raise ValueError("required denials differ from frozen policy")
        return self

    @property
    def sha256(self) -> str:
        payload = json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class CertificationBinding:
    policy_sha256: str
    alternate_policy_sha256: str
    capability_registry_sha256: str
    network_policy_sha256: str


def bind_certification_policy(
    *,
    policy: CertificationPolicy,
    alternate_policy_path: Path,
    capability_registry_sha256: str,
    network_policy_sha256: str,
) -> CertificationBinding:
    """Bind all policy identities before the first synthetic model request."""

    for name, digest in {
        "capability registry": capability_registry_sha256,
        "network policy": network_policy_sha256,
    }.items():
        if not _SHA256.fullmatch(digest):
            raise ValueError(f"{name} requires a lowercase SHA-256 digest")
    alternate = AlternateModelPolicy.model_validate_json(alternate_policy_path.read_text())
    routes = {route.role: route for route in alternate.routes}
    for role in DeepSeekRole:
        route = routes[role]
        name = role.value
        if (
            route.max_calls != policy.alternate_max_requests_by_role[name]
            or route.max_tokens != policy.alternate_max_tokens_by_role[name]
            or route.max_seconds != policy.alternate_max_seconds_by_role[name]
        ):
            raise ValueError("certification and active DeepSeek role limits disagree")
    if (
        alternate.models[0].model != policy.alternate_model
        or alternate.models[0].base_url != policy.alternate_provider
        or alternate.models[0].api != policy.alternate_api
        or alternate.models[0].thinking.model_dump() != policy.alternate_thinking
        or alternate.models[0].reasoning_effort != policy.alternate_reasoning_effort
        or alternate.models[0].context_tokens != policy.alternate_context_tokens
        or alternate.shared_task_max_requests != policy.max_model_requests_per_task
        or alternate.shared_task_wall_timeout_sec != policy.task_wall_timeout_sec
        or alternate.max_concurrent_children != policy.max_concurrent_children
    ):
        raise ValueError("certification and active alternate-provider policy disagree")
    return CertificationBinding(
        policy_sha256=policy.sha256,
        alternate_policy_sha256=alternate.digest,
        capability_registry_sha256=capability_registry_sha256,
        network_policy_sha256=network_policy_sha256,
    )
