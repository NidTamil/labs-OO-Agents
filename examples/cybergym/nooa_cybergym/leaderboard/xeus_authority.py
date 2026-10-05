"""Xeus-backed campaign signatures, payload custody, and serial event ledger.

This adapter runs only in the trusted POSIX controller. A campaign-wide
exclusive marker is written before the native ledger's first event. An
ambiguous write leaves that marker in place so a second run cannot launch.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import UUID, uuid4, uuid5

_CAMPAIGN_NAMESPACE = UUID("67be1942-d811-44f5-8ad9-c3f70b7bfa49")
_MARKER = "campaign-created.json"
_LEDGER = "campaign.sqlite3"
_ARTIFACTS = "campaign-artifacts"
_REQUIRED_SIGNED_KEYS = {
    "decision": frozenset(
        {"schema_version", "official_launch_authorised", "run_id", "certification_sha256"}
    ),
    "certification": frozenset(
        {
            "schema_version",
            "status",
            "scope",
            "harness_sha256",
            "cohort_sha256",
            "campaign_policy_sha256",
        }
    ),
    "harness_lock": frozenset({"schema_version", "epoch", "campaign_policy_sha256"}),
    "cohort": frozenset({"schema_version", "task_ids", "tasks_json_sha256"}),
    "terminal_receipt": frozenset(
        {"schema_version", "artifact_kind", "run_id", "epoch", "task_id", "status"}
    ),
}
_LIFECYCLE_TYPES = frozenset({"campaign_created", "prepared", "started", "terminal"})


def _load_native() -> SimpleNamespace:
    try:
        from xeus_cybergym.canonical import canonical_json
        from xeus_cybergym.contracts.events import EventEnvelope
        from xeus_cybergym.ledger import ArtifactStore, Ed25519Verifier, SignedEnvelope
        from xeus_cybergym.ledger.events import SqliteEventLedger
    except ImportError:
        raise RuntimeError("native Xeus authority package is unavailable") from None
    return SimpleNamespace(
        SignedEnvelope=SignedEnvelope,
        Ed25519Verifier=Ed25519Verifier,
        EventEnvelope=EventEnvelope,
        ArtifactStore=ArtifactStore,
        SqliteEventLedger=SqliteEventLedger,
        canonical_json=canonical_json,
    )


def _fsync_directory(path: Path) -> None:
    if os.name != "posix":
        raise RuntimeError("campaign creation requires POSIX directory fsync")
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _stream_id(run_id: str) -> UUID:
    return uuid5(_CAMPAIGN_NAMESPACE, run_id)


def _root(path: Path) -> Path:
    if type(path) is not Path and not isinstance(path, Path):
        raise RuntimeError("absolute controller evidence directory required")
    if not path.is_absolute() or path.is_symlink() or not path.is_dir():
        raise RuntimeError("absolute controller evidence directory required")
    if path.resolve(strict=True) != path:
        raise RuntimeError("controller evidence directory has an alias")
    return path


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class XeusCampaignAuthority:
    """Concrete campaign adapter using native Xeus signing and ledger classes.

    `native` is a test seam. Production callers omit it and supply only the
    trusted public-key registry; private signing keys never enter this class.
    """

    def __init__(self, public_keys: Mapping[str, Any], *, native: Any | None = None) -> None:
        if not isinstance(public_keys, Mapping) or not public_keys:
            raise RuntimeError("trusted Xeus public-key registry required")
        self._native = native if native is not None else _load_native()
        self._verifier = self._native.Ed25519Verifier(public_keys)
        self._ledger_type = self._durable_ledger_type(self._native.SqliteEventLedger)

    @staticmethod
    def _durable_ledger_type(base: type) -> type:
        class DurableCampaignLedger(base):
            def _connect(self, database_path=None):
                connection = super()._connect(database_path)
                if str(database_path) == ":memory:":
                    return connection
                try:
                    connection.execute("PRAGMA synchronous=FULL")
                    level = connection.execute("PRAGMA synchronous").fetchone()[0]
                    if type(level) is not int or level < 2:
                        raise RuntimeError("native Xeus ledger durability is below FULL")
                except Exception:
                    connection.close()
                    raise
                return connection

        return DurableCampaignLedger

    def attest_signed(self, kind: str, envelope: bytes) -> Mapping[str, Any] | None:
        required = _REQUIRED_SIGNED_KEYS.get(kind)
        if required is None or type(envelope) is not bytes or not envelope:
            return None
        try:
            parsed = self._native.SignedEnvelope.model_validate_json(envelope)
            payload_bytes = self._verifier.verify(parsed)
            payload = json.loads(payload_bytes)
            if (
                not isinstance(payload, dict)
                or not required.issubset(payload)
                or type(payload.get("schema_version")) is not int
                or payload["schema_version"] != 1
                or payload.get("artifact_kind", kind) != kind
                or self._native.canonical_json(payload) != payload_bytes
            ):
                return None
            return payload
        except Exception:
            return None

    def _marker(self, root: Path, run_id: str) -> Mapping[str, Any]:
        try:
            data = (root / _MARKER).read_bytes()
            marker = json.loads(data)
            if (
                not isinstance(marker, dict)
                or self._native.canonical_json(marker) != data
                or marker.get("schema_version") != 1
                or marker.get("run_id") != run_id
                or marker.get("stream_id") != str(_stream_id(run_id))
                or type(marker.get("created_event_digest")) is not str
            ):
                raise ValueError("invalid campaign marker")
            return marker
        except Exception:
            raise RuntimeError("durable campaign creation marker is unavailable") from None

    def _ledger(self, root: Path, *, initialize: bool):
        path = root / _LEDGER
        if initialize:
            if path.exists() or path.is_symlink():
                raise RuntimeError("campaign ledger already exists")
        elif path.is_symlink() or not path.is_file():
            raise RuntimeError("native campaign ledger is unavailable")
        ledger = self._ledger_type(path)
        if initialize:
            ledger.initialize()
        else:
            ledger.verify_compatible()
        return ledger

    def _artifact_store(self, root: Path):
        return self._native.ArtifactStore(root / _ARTIFACTS)

    def _event_envelope(
        self,
        *,
        run_id: str,
        event: Mapping[str, Any],
        sequence: int,
        previous_digest: str | None,
        artifact_digest: str,
    ):
        timestamp = datetime.now(UTC)
        return self._native.EventEnvelope(
            event_id=uuid4(),
            task_run_id=_stream_id(run_id),
            attempt_id=None,
            sequence=sequence,
            source_timestamp=timestamp,
            ingested_at=timestamp,
            actor="sunchaser-controller",
            category=event["type"],
            provider_event_id=None,
            trace_id=None,
            span_id=None,
            payload_digest=artifact_digest,
            payload_ref=f"artifact:{artifact_digest}",
            redaction_class="controller_only",
            previous_event_digest=previous_digest,
        )

    def _append_native(
        self,
        *,
        root: Path,
        run_id: str,
        event: Mapping[str, Any],
        sequence: int,
        previous_digest: str | None,
        ledger,
    ) -> None:
        if not isinstance(event, Mapping) or event.get("type") not in _LIFECYCLE_TYPES:
            raise RuntimeError("unsupported campaign event type")
        payload_bytes = self._native.canonical_json(dict(event))
        artifact = self._artifact_store(root).put_bytes(payload_bytes, "application/json")
        if artifact.digest != _digest(payload_bytes):
            raise RuntimeError("native Xeus artifact digest mismatch")
        envelope = self._event_envelope(
            run_id=run_id,
            event=event,
            sequence=sequence,
            previous_digest=previous_digest,
            artifact_digest=artifact.digest,
        )
        key = f"campaign:{run_id}:{sequence}"
        stored = ledger.append(_stream_id(run_id), sequence, key, envelope)
        if stored.event.event_id != envelope.event_id or stored.sequence != sequence:
            raise RuntimeError("native Xeus append acknowledgement differs from event")

    def create_campaign_once(
        self, evidence_root: Path, run_id: str, event: Mapping[str, Any]
    ) -> bool:
        root = _root(evidence_root)
        if type(run_id) is not str or not run_id or event.get("type") != "campaign_created":
            raise RuntimeError("campaign creation identity is invalid")
        if event.get("run_id") != run_id:
            raise RuntimeError("campaign creation run identity differs")
        marker_path = root / _MARKER
        if marker_path.exists() or marker_path.is_symlink():
            return False
        if (root / _LEDGER).exists() or (root / _LEDGER).is_symlink():
            raise RuntimeError("campaign ledger exists without creation marker")
        marker = {
            "schema_version": 1,
            "run_id": run_id,
            "stream_id": str(_stream_id(run_id)),
            "created_event_digest": _digest(self._native.canonical_json(dict(event))),
        }
        try:
            descriptor = os.open(marker_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            return False
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(self._native.canonical_json(marker))
            stream.flush()
            os.fsync(stream.fileno())
        _fsync_directory(root)
        ledger = self._ledger(root, initialize=True)
        _fsync_directory(root)
        try:
            self._append_native(
                root=root,
                run_id=run_id,
                event=event,
                sequence=1,
                previous_digest=None,
                ledger=ledger,
            )
        except Exception:
            raise RuntimeError("campaign creation acknowledgement unavailable") from None
        return True

    def _read_verified(self, root: Path, run_id: str):
        marker = self._marker(root, run_id)
        ledger = self._ledger(root, initialize=False)
        stream_id = _stream_id(run_id)
        try:
            ledger.verify_chain(stream_id)
            rows = ledger.read(stream_id, 0)
            if not rows:
                raise ValueError("campaign creation event is absent")
            store = self._artifact_store(root)
            events = []
            for sequence, row in enumerate(rows, 1):
                envelope = row.event
                if (
                    row.sequence != sequence
                    or envelope.sequence != sequence
                    or envelope.task_run_id != stream_id
                    or envelope.category not in _LIFECYCLE_TYPES
                    or envelope.payload_ref != f"artifact:{envelope.payload_digest}"
                    or envelope.redaction_class != "controller_only"
                ):
                    raise ValueError("campaign ledger row is invalid")
                payload = store.get_bytes(envelope.payload_digest)
                if _digest(payload) != envelope.payload_digest:
                    raise ValueError("campaign artifact digest differs")
                event = json.loads(payload)
                if (
                    not isinstance(event, dict)
                    or self._native.canonical_json(event) != payload
                    or event.get("type") != envelope.category
                ):
                    raise ValueError("campaign artifact does not match ledger row")
                events.append(event)
            if _digest(self._native.canonical_json(events[0])) != marker["created_event_digest"]:
                raise ValueError("campaign creation differs from marker")
            if events[0].get("run_id") != run_id:
                raise ValueError("campaign creation run identity differs")
            return tuple(events), tuple(rows), ledger
        except Exception:
            raise RuntimeError("verified native campaign chain or artifact unavailable") from None

    def read_verified_events(
        self, evidence_root: Path, run_id: str
    ) -> tuple[Mapping[str, Any], ...]:
        root = _root(evidence_root)
        events, _, _ = self._read_verified(root, run_id)
        return events

    def append_event(
        self,
        evidence_root: Path,
        run_id: str,
        event: Mapping[str, Any],
        expected_revision: int,
    ) -> bool:
        if type(expected_revision) is not int or expected_revision < 1:
            raise RuntimeError("verified campaign revision required")
        if not isinstance(event, Mapping) or event.get("type") not in {
            "prepared",
            "started",
            "terminal",
        }:
            raise RuntimeError("unsupported campaign transition")
        root = _root(evidence_root)
        events, rows, ledger = self._read_verified(root, run_id)
        if len(events) != expected_revision:
            return False
        self._append_native(
            root=root,
            run_id=run_id,
            event=event,
            sequence=expected_revision + 1,
            previous_digest=rows[-1].digest,
            ledger=ledger,
        )
        return True
