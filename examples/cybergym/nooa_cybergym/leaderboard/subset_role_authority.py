# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Role-separated public verification for the explicit budgeted subset path.

Approval, runtime-controller and evaluator trust are independently pinned public
registries. Correct signatures from another role never confer approval. This
module does not load private keys, sign artifacts, or replace full admission and
raw-evidence verification. Historical Xeus authority behavior is unchanged.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .scored_campaign_inputs import load_scored_public_keys
from .xeus_authority import XeusCampaignAuthority

_APPROVAL_KINDS = frozenset(
    {
        "harness_lock",
        "cohort",
        "subset_run_budget",
        "budgeted_subset_admission",
        "certification",
    }
)
_RUNTIME_KINDS = frozenset(
    {"terminal_receipt", "subset_driver_quiescence", "subset_preparation_quiescence"}
)


@dataclass(frozen=True, slots=True)
class _PinnedRoleVerifier:
    """Public-key signature verification for separately typed receipt consumers."""

    _owner: SubsetRoleAuthority = field(repr=False)
    _role: str

    def verify(self, envelope: Any) -> bytes:
        """Return signed bytes; the typed consumer must verify receipt semantics."""
        from xeus_cybergym.ledger import Ed25519Verifier

        if self._role not in {"runtime", "evaluator"}:
            raise RuntimeError("separate runtime or evaluator verification role required")
        keys = self._owner._role_keys()
        return Ed25519Verifier(keys[self._role]).verify(envelope)


@dataclass(frozen=True, slots=True, init=False)
class SubsetRoleAuthority:
    """CampaignAuthority with disjoint, rechecked public trust for each role.

    Every operation reloads all three pinned registries before delegating. The
    native ledger remains the Xeus hash-chain/atomic-revision implementation;
    it is neither signed here nor treated as an approval authority. Native
    ledger access uses the runtime role only. No trusted key mapping is exposed.
    """

    _pins: tuple[tuple[str, Path, str], ...] = field(repr=False)

    def __init__(
        self,
        *,
        approval_registry: Path,
        approval_sha256: str,
        runtime_registry: Path,
        runtime_sha256: str,
        evaluator_registry: Path,
        evaluator_sha256: str,
    ) -> None:
        object.__setattr__(
            self,
            "_pins",
            (
                ("approval", Path(approval_registry), approval_sha256),
                ("runtime", Path(runtime_registry), runtime_sha256),
                ("evaluator", Path(evaluator_registry), evaluator_sha256),
            ),
        )
        self._role_keys()

    def _role_keys(self) -> dict[str, dict[str, Ed25519PublicKey]]:
        roles: dict[str, dict[str, Ed25519PublicKey]] = {}
        ids_seen: set[str] = set()
        public_bytes_seen: set[bytes] = set()
        for role, path, digest in self._pins:
            keys = load_scored_public_keys(path, expected_sha256=digest)
            raw_keys = {
                key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                for key in keys.values()
            }
            if ids_seen.intersection(keys) or public_bytes_seen.intersection(raw_keys):
                raise RuntimeError("public key IDs or raw public keys overlap across trust roles")
            ids_seen.update(keys)
            public_bytes_seen.update(raw_keys)
            roles[role] = keys
        return roles

    @property
    def runtime_verifier(self) -> _PinnedRoleVerifier:
        """For typed runtime launch/start/oracle receipt consumers, never approval."""
        return _PinnedRoleVerifier(self, "runtime")

    @property
    def evaluator_verifier(self) -> _PinnedRoleVerifier:
        """For independently typed evaluator results, never runtime or approval."""
        return _PinnedRoleVerifier(self, "evaluator")

    def attest_signed(self, kind: str, envelope: bytes) -> Mapping[str, Any] | None:
        roles = self._role_keys()
        if type(kind) is not str:
            return None
        if kind in _APPROVAL_KINDS:
            role = "approval"
        elif kind in _RUNTIME_KINDS:
            role = "runtime"
        else:
            return None
        return XeusCampaignAuthority(roles[role]).attest_signed(kind, envelope)

    def attest_takeover_certification(self, envelope: bytes) -> Mapping[str, Any] | None:
        roles = self._role_keys()
        return XeusCampaignAuthority(roles["approval"]).attest_takeover_certification(envelope)

    def create_campaign_once(
        self, evidence_root: Path, run_id: str, event: Mapping[str, Any]
    ) -> bool:
        roles = self._role_keys()
        return XeusCampaignAuthority(roles["runtime"]).create_campaign_once(
            evidence_root, run_id, event
        )

    def read_verified_events(self, evidence_root: Path, run_id: str) -> Sequence[Mapping[str, Any]]:
        roles = self._role_keys()
        return XeusCampaignAuthority(roles["runtime"]).read_verified_events(evidence_root, run_id)

    def append_event(
        self,
        evidence_root: Path,
        run_id: str,
        event: Mapping[str, Any],
        expected_revision: int,
    ) -> bool:
        roles = self._role_keys()
        return XeusCampaignAuthority(roles["runtime"]).append_event(
            evidence_root, run_id, event, expected_revision=expected_revision
        )
