# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Controller-owned, read-only facade for the dedicated CyberGym GBrain.

The caller supplies an authenticated native transport, an attestor backed by
the existing Xeus signing authority, and a task-specific answer filter. This
module never reads GBrain configuration, credentials, databases, or personal
memory. The transport must bind GBrain's native AI invocation guard to the
controller budget before dispatch; a digest of that certified binding is
required in its read-scope attestation. A live binding still needs separate
service certification.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol

SOURCE_ID = "xeus-cybergym-workspace"
READ_TOOLS = frozenset({"recall", "search", "get_page"})
MAX_RESULTS = 12
MAX_TOKENS = 2000
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class UnsafeMemory(RuntimeError):
    """An untrusted read, provenance, scope, or audit condition blocked output."""


class MemoryUnavailable(RuntimeError):
    """A native read outage; the controller may continue without memory."""


class Caller(StrEnum):
    AUTOMATIC = "automatic"
    PARENT = "parent"
    CHILD = "child"


def _sha256(value: bytes | str) -> str:
    return hashlib.sha256(value.encode("utf-8") if isinstance(value, str) else value).hexdigest()


def _json_bytes(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _identity(value: object) -> bool:
    return isinstance(value, str) and _ID.fullmatch(value) is not None


def _digest(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class AllowedPage:
    """One page identity and both hashes approved by a signed authority manifest.

    ``content_hash`` is GBrain's native value. ``content_sha256`` hashes the
    controller-observed get_page content. The two may differ because GBrain
    hashes an ingested representation and returns reserialized markdown.
    """

    page_id: int
    slug: str
    source_id: str
    content_hash: str
    content_sha256: str
    frontmatter: Mapping[str, object]
    structural_terms: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.page_id) is not int or self.page_id <= 0 or not _identity(self.slug):
            raise ValueError("invalid canonical page identity")
        if (
            self.source_id != SOURCE_ID
            or not _digest(self.content_hash)
            or not _digest(self.content_sha256)
        ):
            raise ValueError("invalid canonical page source or hashes")
        if not isinstance(self.frontmatter, Mapping):
            raise ValueError("canonical frontmatter required")
        try:
            frontmatter = deepcopy(dict(self.frontmatter))
            _json_bytes(frontmatter)
        except (TypeError, ValueError):
            raise ValueError("invalid canonical frontmatter") from None
        tier = frontmatter.get("tier")
        if (
            tier not in {"semantic", "procedural", "principle", "episodic"}
            or frontmatter.get("type") != "note"
            or frontmatter.get("reviewed") is not True
            or not self.slug.startswith(f"cybergym/{tier}/")
            or not all(
                isinstance(frontmatter.get(name), str) and frontmatter[name].strip()
                for name in ("title", "license", "captured_at")
            )
            or not _digest(frontmatter.get("source_sha256"))
            or not any(frontmatter.get(name) for name in ("source_url", "source_document"))
        ):
            raise ValueError("canonical frontmatter or tier is incomplete")
        if not isinstance(self.structural_terms, tuple) or any(
            not isinstance(term, str) or not term.strip() for term in self.structural_terms
        ):
            raise ValueError("invalid signed structural terms")
        object.__setattr__(self, "frontmatter", MappingProxyType(frontmatter))
        object.__setattr__(
            self, "structural_terms", tuple(term.casefold() for term in self.structural_terms)
        )


@dataclass(frozen=True, slots=True)
class ManifestAttestation:
    """Result of trusted Xeus signature verification, never model-provided."""

    source_id: str
    envelope_sha256: str
    signature_key_id: str
    pages: tuple[AllowedPage, ...]

    def __post_init__(self) -> None:
        if self.source_id != SOURCE_ID or not _digest(self.envelope_sha256):
            raise ValueError("signed manifest has wrong source or digest")
        if not _identity(self.signature_key_id) or not isinstance(self.pages, tuple):
            raise ValueError("signed manifest lacks authority identity or pages")
        if any(type(page) is not AllowedPage for page in self.pages):
            raise ValueError("signed manifest contains invalid pages")
        if len({page.slug for page in self.pages}) != len(self.pages) or len(
            {page.page_id for page in self.pages}
        ) != len(self.pages):
            raise ValueError("signed manifest contains duplicate page identities")


@dataclass(frozen=True, slots=True)
class ReadScopeAttestation:
    """Current authenticated grant/catalog and native guard binding evidence."""

    source_ids: frozenset[str]
    server_context_source_id: str
    tool_names: frozenset[str]
    catalog_sha256: str
    native_guard_binding_sha256: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.source_ids, frozenset)
            or not isinstance(self.tool_names, frozenset)
            or not _digest(self.catalog_sha256)
            or not _digest(self.native_guard_binding_sha256)
        ):
            raise ValueError("invalid authenticated read-scope attestation")


@dataclass(frozen=True, slots=True)
class MemorySelection:
    page_id: int
    slug: str
    source_id: str
    tier: str
    content_hash: str
    excerpt: str
    excerpt_sha256: str
    token_count: int
    manifest_sha256: str


class NativeMemoryTransport(Protocol):
    """Trusted adapter returning decoded native MCP results, never raw credentials.

    The adapter must authenticate, inspect current tools/list and source grant,
    apply the native GBrain AI invocation guard around each dispatch, and debit
    every actual provider call through the controller budget. It must not make
    the transport or its credential available to solver generated code.
    """

    def read_scope(self) -> ReadScopeAttestation: ...

    def call(
        self, tool: str, arguments: Mapping[str, object], *, request_id: str, timeout_seconds: float
    ) -> Mapping[str, object] | list[object]: ...


class AuditSink(Protocol):
    def record(self, event: Mapping[str, object]) -> bool: ...


class MemoryFacade:
    """One attempt's automatic and parent/child read-only memory boundary."""

    def __init__(
        self,
        *,
        transport: NativeMemoryTransport,
        signed_manifest: bytes,
        attest_manifest: Callable[[bytes], ManifestAttestation],
        audit: AuditSink,
        answer_filter: Callable[[str], bool],
        token_counter: Callable[[str], int],
        timeout_seconds: float = 20.0,
    ) -> None:
        if not isinstance(signed_manifest, bytes) or not signed_manifest:
            raise UnsafeMemory("signed manifest required")
        if not all(
            callable(item)
            for item in (
                getattr(transport, "read_scope", None),
                getattr(transport, "call", None),
                attest_manifest,
                getattr(audit, "record", None),
                answer_filter,
                token_counter,
            )
        ):
            raise TypeError("trusted transport, authority, audit, and filters required")
        if type(timeout_seconds) not in (float, int) or not 0 < timeout_seconds <= 60:
            raise ValueError("bounded native read timeout required")
        try:
            manifest = attest_manifest(signed_manifest)
            if type(manifest) is not ManifestAttestation or manifest.envelope_sha256 != _sha256(
                signed_manifest
            ):
                raise ValueError("authority attestation mismatch")
        except Exception:
            raise UnsafeMemory("signed manifest verification failed") from None
        self._transport = transport
        self._audit = audit
        self._answer_filter = answer_filter
        self._token_counter = token_counter
        self._timeout_seconds = float(timeout_seconds)
        self._manifest_sha256 = manifest.envelope_sha256
        self._pages = {page.slug: page for page in manifest.pages}

    def __repr__(self) -> str:
        return "<MemoryFacade controller-owned read-only state>"

    def automatic_recall(
        self,
        *,
        level1_facts: Sequence[str],
        structural_terms: Sequence[str],
        task_id: str,
        attempt_id: str,
        request_id: str,
    ) -> tuple[MemorySelection, ...]:
        """Use only supplied current-task facts and source-derived terms."""
        if not isinstance(level1_facts, (tuple, list)):
            raise UnsafeMemory("current Level 1 facts required")
        parts = list(level1_facts) + list(structural_terms)
        if any(not isinstance(part, str) or not part.strip() for part in parts):
            raise UnsafeMemory("invalid source-derived recall terms")
        query = " ".join(dict.fromkeys(part.strip() for part in parts))
        return self._retrieve(
            "recall",
            query,
            Caller.AUTOMATIC,
            structural_terms,
            task_id,
            attempt_id,
            request_id,
            "harness",
        )

    def model_tool(
        self,
        tool: str,
        query: str,
        *,
        caller: Caller,
        structural_terms: Sequence[str],
        task_id: str,
        attempt_id: str,
        request_id: str,
        model_id: str,
    ) -> tuple[MemorySelection, ...]:
        """Controller wrapper binds caller; agents can request only read tools."""
        if tool not in {"recall", "search"}:
            raise UnsafeMemory("model memory tools are read-only")
        if type(caller) is not Caller or caller not in {Caller.PARENT, Caller.CHILD}:
            raise UnsafeMemory("model memory caller must be parent or child")
        return self._retrieve(
            tool, query, caller, structural_terms, task_id, attempt_id, request_id, model_id
        )

    def _record(self, event: Mapping[str, object]) -> None:
        try:
            if self._audit.record(event) is not True:
                raise RuntimeError("unacknowledged")
        except Exception:
            raise UnsafeMemory("memory audit unavailable") from None

    def _scope(self) -> ReadScopeAttestation:
        try:
            scope = self._transport.read_scope()
        except Exception:
            raise UnsafeMemory("read source scope attestation unavailable") from None
        if type(scope) is not ReadScopeAttestation:
            raise UnsafeMemory("read source scope attestation invalid")
        if (
            scope.source_ids != frozenset({SOURCE_ID})
            or scope.server_context_source_id != SOURCE_ID
        ):
            raise UnsafeMemory("read source scope is not exact")
        if not READ_TOOLS <= scope.tool_names or scope.tool_names - READ_TOOLS - {"capture"}:
            raise UnsafeMemory("read-only native catalog required")
        return scope

    def _call(self, tool: str, arguments: Mapping[str, object], request_id: str):
        return self._transport.call(
            tool, arguments, request_id=request_id, timeout_seconds=self._timeout_seconds
        )

    def _hydrate(self, slug: str, excerpt: str, request_id: str):
        allowed = self._pages.get(slug)
        if allowed is None:
            raise UnsafeMemory("canonical provenance is absent from signed manifest")
        try:
            canonical = self._call(
                "get_page",
                {
                    "slug": slug,
                    "source_id": SOURCE_ID,
                    "include_content": True,
                    "fuzzy": False,
                },
                request_id,
            )
        except KeyError:
            raise UnsafeMemory("canonical provenance could not be resolved") from None
        if not isinstance(canonical, Mapping):
            raise UnsafeMemory("canonical provenance record is malformed")
        content = canonical.get("content")
        frontmatter = canonical.get("frontmatter")
        if (
            type(canonical.get("id")) is not int
            or canonical.get("id") != allowed.page_id
            or canonical.get("slug") != allowed.slug
            or canonical.get("source_id") != allowed.source_id
            or canonical.get("content_hash") != allowed.content_hash
            or not isinstance(content, str)
            or _sha256(content) != allowed.content_sha256
            or not isinstance(frontmatter, Mapping)
            or _json_bytes(dict(frontmatter)) != _json_bytes(dict(allowed.frontmatter))
            or excerpt not in content
        ):
            raise UnsafeMemory("canonical provenance differs from signed manifest")
        return allowed, canonical

    def _retrieve(
        self,
        tool: str,
        query: str,
        caller: Caller,
        structural_terms: Sequence[str],
        task_id: str,
        attempt_id: str,
        request_id: str,
        model_id: str,
    ) -> tuple[MemorySelection, ...]:
        if (
            not isinstance(query, str)
            or not query.strip()
            or len(query) > 1000
            or not all(_identity(value) for value in (task_id, attempt_id, request_id, model_id))
            or not isinstance(structural_terms, (tuple, list, set, frozenset))
            or any(not isinstance(term, str) or not term.strip() for term in structural_terms)
        ):
            raise UnsafeMemory("invalid memory read context")
        try:
            if self._answer_filter(query) is not True:
                raise UnsafeMemory("query rejected by task answer filter")
        except UnsafeMemory:
            raise
        except Exception:
            raise UnsafeMemory("task answer filter unavailable") from None
        scope = self._scope()
        terms = {term.casefold() for term in structural_terms}
        arguments: dict[str, object] = {"query": query, "limit": MAX_RESULTS}
        if tool == "recall":
            arguments["budget_tokens"] = MAX_TOKENS
        else:
            arguments.update({"source_id": SOURCE_ID, "types": ["note"], "snippet_chars": 1000})
        path = "automatic" if caller is Caller.AUTOMATIC else "model_initiated"
        event = {
            "path": path,
            "caller": caller.value,
            "model_id": model_id,
            "tool": tool,
            "task_id": task_id,
            "attempt_id": attempt_id,
            "request_id": request_id,
            "source_id": SOURCE_ID,
            "query_sha256": _sha256(query),
            "manifest_sha256": self._manifest_sha256,
            "catalog_sha256": scope.catalog_sha256,
            "native_guard_binding_sha256": scope.native_guard_binding_sha256,
        }
        self._record(event | {"event": "request"})
        started = time.monotonic()
        try:
            raw = self._call(tool, arguments, f"{request_id}:{tool}")
            if tool == "recall":
                if not isinstance(raw, Mapping):
                    raise UnsafeMemory("native recall result is malformed")
                facts, results = raw.get("facts"), raw.get("results")
                if not isinstance(facts, list) or not isinstance(results, list):
                    raise UnsafeMemory("native recall result is malformed")
                rows = [(row, "fact") for row in facts] + [
                    (row, "recall_result") for row in results
                ]
            else:
                if not isinstance(raw, list):
                    raise UnsafeMemory("native search result is malformed")
                rows = [(row, "search_result") for row in raw]
            selected: list[MemorySelection] = []
            hydration_hashes: list[str] = []
            seen_pages: set[str] = set()
            used_tokens = 0
            for index, (row, kind) in enumerate(rows):
                if not isinstance(row, Mapping):
                    raise UnsafeMemory("native memory row is malformed")
                if kind == "fact":
                    # GBrain's fact source names the producer (for example
                    # mcp:extract_facts), not a canonical page. Only context
                    # may identify a signed page; unlinked facts stay private.
                    slug, excerpt = row.get("context"), row.get("fact")
                    if slug is not None and not isinstance(slug, str):
                        raise UnsafeMemory("native fact context is malformed")
                    if slug not in self._pages:
                        continue
                    if type(row.get("id")) is not int or row["id"] <= 0:
                        raise UnsafeMemory("native fact identity is malformed")
                elif kind == "recall_result":
                    slug, excerpt = row.get("slug"), row.get("chunk")
                else:
                    slug, excerpt = row.get("slug"), row.get("chunk_text")
                    if type(row.get("page_id")) is not int:
                        raise UnsafeMemory("canonical provenance is missing from search row")
                if not isinstance(slug, str) or not isinstance(excerpt, str) or not excerpt.strip():
                    raise UnsafeMemory("canonical provenance is missing from native row")
                if slug.startswith("cybergym/episodic/"):
                    continue
                allowed, canonical = self._hydrate(slug, excerpt, f"{request_id}:hydrate:{index}")
                if kind == "search_result" and row["page_id"] != allowed.page_id:
                    raise UnsafeMemory("canonical provenance page ID differs from search row")
                hydration_hashes.append(_sha256(_json_bytes(dict(canonical))))
                tier = allowed.frontmatter["tier"]
                if tier == "episodic":
                    continue
                if tier in {"procedural", "semantic"} and not terms.intersection(
                    allowed.structural_terms
                ):
                    continue
                try:
                    safe = (
                        self._answer_filter(canonical["content"]) is True
                        and self._answer_filter(excerpt) is True
                        and self._answer_filter(str(allowed.page_id)) is True
                        and self._answer_filter(allowed.slug) is True
                    )
                except Exception:
                    raise UnsafeMemory("task answer filter unavailable") from None
                if not safe or allowed.page_id in seen_pages:
                    continue
                try:
                    count = self._token_counter(f"{allowed.page_id} {allowed.slug} {excerpt}")
                except Exception:
                    raise UnsafeMemory("memory token accounting unavailable") from None
                if type(count) is not int or count <= 0:
                    raise UnsafeMemory("memory token accounting unavailable")
                if len(selected) >= MAX_RESULTS or used_tokens + count > MAX_TOKENS:
                    continue
                seen_pages.add(allowed.page_id)
                used_tokens += count
                selected.append(
                    MemorySelection(
                        page_id=allowed.page_id,
                        slug=allowed.slug,
                        source_id=SOURCE_ID,
                        tier=tier,
                        content_hash=allowed.content_hash,
                        excerpt=excerpt,
                        excerpt_sha256=_sha256(excerpt),
                        token_count=count,
                        manifest_sha256=self._manifest_sha256,
                    )
                )
            self._record(
                event
                | {
                    "event": "result",
                    "raw_result_sha256": _sha256(_json_bytes(raw)),
                    "hydration_sha256": _sha256(_json_bytes(hydration_hashes)),
                    "selected": [
                        {
                            "page_id": item.page_id,
                            "content_hash": item.content_hash,
                            "excerpt_sha256": item.excerpt_sha256,
                        }
                        for item in selected
                    ],
                    "selected_count": len(selected),
                    "injected_tokens": used_tokens,
                    "duration_seconds": max(0.0, time.monotonic() - started),
                }
            )
            return tuple(selected)
        except UnsafeMemory as error:
            if str(error) != "memory audit unavailable":
                self._record(event | {"event": "denied", "reason": str(error)})
            raise
        except Exception:
            self._record(event | {"event": "failure", "reason": "native read unavailable"})
            raise MemoryUnavailable("native GBrain read unavailable") from None
