"""Read-only inventory of the scored GBrain integration boundary.

Local source hashes are observations, not backend identity or live memory
certification. This audit intentionally remains blocked until a frozen policy
and a trusted verifier can bind the isolated native service, OAuth grant, and
AI invocation guard to raw runtime evidence. It reads no GBrain configuration,
credentials, database, provider state, or source content.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .memory import SOURCE_ID

_ADAPTER_FILES = ("memory.py", "memory_transport.py")
_CONTRACTS = {
    "frozen_memory_policy_and_backend_identity": (
        "Freeze a signed memory-policy.json against the isolated GBrain package/version and "
        "source SHA-256, service TLS identity, exact backend profile/database, adapter source "
        "hashes, and snapshot. Observed version 0.50.0.0 and endpoint alone are not pins."
    ),
    "concrete_controller_mcp_bridge": (
        "Implement ControllerMcpBridge.read_evidence/exchange/notify for the scored "
        "authenticated MCP session. Keep OAuth and database credentials controller-only; "
        "do not expose capture or other write tools to a solver or child."
    ),
    "exact_source_oauth_grant": (
        f"Introspect the actual authenticated scored OAuth credential and prove its read "
        f"grant is exactly "
        f"{{{SOURCE_ID}}}, excluding default. Omitted-source recall must remain scoped, "
        "explicit-default requests must fail, and controller capture needs separate authority."
    ),
    "trusted_server_source_context": (
        f"Attest that the native server dispatch derives source context from the trusted "
        f"OAuth session and fixes it to {SOURCE_ID} for recall, search, and get_page; "
        "request arguments alone do not establish the scope."
    ),
    "native_ai_invocation_guard_budget_binding": (
        "Bind the installed withAIInvocationGuard(guard, run) to each real chat, embed, "
        "rerank, and guarded-generation dispatch. Reserve shared controller requests/time "
        "before calls; permit.settle(usage | null) on success and failure, including null usage. "
        "Native get_usage is not sufficient accounting."
    ),
    "authenticated_native_catalog": (
        "Pin signed initialize/serverInfo and authenticated tools/list schema hashes for the "
        "scored grant, then compare each live session before any read. Permit model-facing "
        "recall/search and controller-only canonical get_page hydration."
    ),
    "signed_canonical_provenance": (
        "Verify an Xeus-signed exact-source allowlist with canonical numeric page IDs, native "
        "content_hash and separately observed get_page content SHA-256. Exclude raw episodes "
        "and task-answer material before injection."
    ),
    "audited_read_and_oracle_write_paths": (
        "Certify automatic plus parent/child model-initiated read-only recall/search under a "
        "single 12-result and 2000-token post-filter cap, with durable retrieval/usage records. "
        "Only controller capture after a true signed oracle verdict may write memory."
    ),
    "local_memory_adapter_sources": (
        "Keep regular, non-symlinked memory.py and memory_transport.py files in the "
        "controller package; inspect their hashes before binding a frozen backend policy."
    ),
}


@dataclass(frozen=True, slots=True)
class MemoryReadinessReport:
    schema_version: int
    scope: str
    gate: str
    observed: dict[str, Any]
    missing_interfaces: tuple[str, ...]
    missing_contracts: dict[str, str]

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"), allow_nan=False)


def _local_sha256(path: Path) -> str | None:
    try:
        if path.is_symlink() or not path.is_file():
            return None
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def audit_memory_readiness(*, repo_root: Path) -> MemoryReadinessReport:
    """Inventory local adapter files without treating them as a live backend proof."""
    cybergym = Path(repo_root) / "examples" / "cybergym"
    controller = cybergym / "nooa_cybergym" / "leaderboard"
    adapter_hashes = {name: _local_sha256(controller / name) for name in _ADAPTER_FILES}
    policy_path = cybergym / "leaderboard" / "config" / "memory-policy.json"
    observed: dict[str, Any] = {
        "adapter_sha256": adapter_hashes,
        "memory_policy_present": policy_path.is_file() and not policy_path.is_symlink(),
        "backend_identity_attested": False,
        "native_guard_attested": False,
        "oauth_scope_attested": False,
    }
    missing = [name for name in _CONTRACTS if name != "local_memory_adapter_sources"]
    if any(digest is None for digest in adapter_hashes.values()):
        missing.append("local_memory_adapter_sources")
    return MemoryReadinessReport(
        schema_version=1,
        scope="read_only_memory_readiness",
        gate="blocked",
        observed=observed,
        missing_interfaces=tuple(missing),
        missing_contracts={name: _CONTRACTS[name] for name in missing},
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only scored GBrain readiness audit")
    parser.add_argument("--repo-root", type=Path, required=True)
    args = parser.parse_args(argv)
    print(audit_memory_readiness(repo_root=args.repo_root).to_json())
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
