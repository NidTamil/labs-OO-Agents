"""Contract tests for the Xeus campaign adapter; no official campaign runs."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest
from nooa_cybergym.leaderboard.xeus_authority import XeusCampaignAuthority


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


class FakeEnvelope:
    @classmethod
    def model_validate_json(cls, data):
        return json.loads(data)


class FakeVerifier:
    def __init__(self, public_keys):
        assert public_keys == {"test-key": object_key}

    def verify(self, envelope):
        if envelope.get("signature") != "valid":
            raise ValueError("invalid native signature")
        return base64.b64decode(envelope["payload"], validate=True)


object_key = object()


class FakeArtifactStore:
    objects = {}

    def __init__(self, root):
        self.root = str(root)

    def put_bytes(self, data, media_type):
        assert media_type == "application/json"
        identity = digest(data)
        self.objects[(self.root, identity)] = data
        return SimpleNamespace(digest=identity, byte_size=len(data), media_type=media_type)

    def get_bytes(self, identity):
        data = self.objects[(self.root, identity)]
        if digest(data) != identity:
            raise ValueError("artifact digest mismatch")
        return data


class FakeConnection:
    def __init__(self, *, memory=False):
        self.memory = memory
        self.synchronous = 0 if memory else 1
        self.closed = False

    def execute(self, statement):
        if statement == "PRAGMA synchronous=FULL" and not self.memory:
            self.synchronous = 2
        elif statement != "PRAGMA synchronous":
            raise AssertionError(statement)
        return self

    def fetchone(self):
        return (self.synchronous,)

    def close(self):
        self.closed = True


class FakeEvent:
    def __init__(self, **fields):
        assert isinstance(fields["task_run_id"], UUID)
        assert isinstance(fields["event_id"], UUID)
        assert fields["attempt_id"] is None
        assert fields["source_timestamp"].tzinfo is not None
        assert fields["ingested_at"].tzinfo is not None
        assert fields["provider_event_id"] is None
        assert fields["trace_id"] is None
        assert fields["span_id"] is None
        assert fields["payload_ref"] == f"artifact:{fields['payload_digest']}"
        assert fields["redaction_class"] == "controller_only"
        self.__dict__.update(fields)


class FakeLedger:
    records = {}
    connections = []
    chain_failure = False
    commit_then_lose_ack = False
    verify_calls = 0

    def __init__(self, database_path):
        self.path = str(database_path)

    def _connect(self, database_path=None):
        connection = FakeConnection(memory=database_path == ":memory:")
        self.connections.append(connection)
        return connection

    def initialize(self):
        memory_probe = self._connect(":memory:")
        memory_probe.close()
        connection = self._connect()
        connection.close()
        Path(self.path).touch()
        self.records.setdefault(self.path, [])

    def verify_compatible(self):
        connection = self._connect()
        connection.close()
        assert Path(self.path).is_file()

    def verify_chain(self, task_run_id):
        FakeLedger.verify_calls += 1
        if self.chain_failure:
            raise ValueError("broken native ledger chain")
        rows = self.records[self.path]
        for index, row in enumerate(rows, 1):
            assert row.event.task_run_id == task_run_id
            assert row.sequence == index
            assert row.event.previous_event_digest == (
                rows[index - 2].digest if index > 1 else None
            )

    def read(self, task_run_id, after_sequence):
        assert after_sequence == 0
        return tuple(self.records[self.path])

    def append(self, task_run_id, expected_sequence, idempotency_key, event):
        connection = self._connect()
        connection.close()
        rows = self.records[self.path]
        if expected_sequence != len(rows) + 1 or event.sequence != expected_sequence:
            raise ValueError("native sequence conflict")
        previous = rows[-1].digest if rows else None
        if event.previous_event_digest != previous:
            raise ValueError("native digest conflict")
        row = SimpleNamespace(
            task_run_id=task_run_id,
            sequence=event.sequence,
            event_id=event.event_id,
            idempotency_key=idempotency_key,
            previous_digest=previous,
            payload_digest=event.payload_digest,
            digest=digest(canonical({"sequence": event.sequence, "event_id": str(event.event_id)})),
            ingested_at=event.ingested_at,
            event=event,
        )
        rows.append(row)
        if self.commit_then_lose_ack:
            raise TimeoutError("native ledger committed but ack lost")
        return row


def signed(payload, signature="valid"):
    return canonical(
        {
            "algorithm": "Ed25519",
            "key_id": "test-key",
            "payload": base64.b64encode(canonical(payload)).decode(),
            "signature": signature,
        }
    )


@pytest.fixture
def adapter(tmp_path, monkeypatch):
    FakeArtifactStore.objects = {}
    FakeLedger.records = {}
    FakeLedger.connections = []
    FakeLedger.chain_failure = False
    FakeLedger.commit_then_lose_ack = False
    FakeLedger.verify_calls = 0
    sync_calls = []
    monkeypatch.setattr(
        "nooa_cybergym.leaderboard.xeus_authority._fsync_directory",
        lambda path: sync_calls.append(path),
    )
    native = SimpleNamespace(
        SignedEnvelope=FakeEnvelope,
        Ed25519Verifier=FakeVerifier,
        EventEnvelope=FakeEvent,
        ArtifactStore=FakeArtifactStore,
        SqliteEventLedger=FakeLedger,
        canonical_json=canonical,
    )
    authority = XeusCampaignAuthority({"test-key": object_key}, native=native)
    root = tmp_path / "evidence"
    root.mkdir()
    return authority, root, sync_calls


def created_event(run_id="run-1"):
    return {
        "type": "campaign_created",
        "run_id": run_id,
        "epoch": "epoch-1",
        "policy_sha256": "a" * 64,
        "cohort_sha256": "b" * 64,
        "task_count": 1507,
    }


def test_native_verifier_must_accept_canonical_signed_payload(adapter):
    authority, _, _ = adapter
    payload = {"schema_version": 1, "task_ids": [], "tasks_json_sha256": "a" * 64}
    assert authority.attest_signed("cohort", signed(payload)) == payload
    assert authority.attest_signed("cohort", signed(payload, "invalid")) is None
    assert authority.attest_signed("decision", signed(payload)) is None
    noncanonical_payload = json.dumps(payload, indent=2).encode()
    noncanonical_envelope = canonical(
        {
            "payload": base64.b64encode(noncanonical_payload).decode(),
            "signature": "valid",
        }
    )
    assert authority.attest_signed("cohort", noncanonical_envelope) is None


def test_certification_attestation_requires_campaign_hash_bindings(adapter):
    authority, _, _ = adapter
    payload = {
        "schema_version": 1,
        "status": "accepted",
        "scope": "live_native",
        "harness_sha256": "a" * 64,
    }
    assert authority.attest_signed("certification", signed(payload)) is None
    payload["cohort_sha256"] = "b" * 64
    payload["campaign_policy_sha256"] = "c" * 64
    assert authority.attest_signed("certification", signed(payload)) == payload


def test_native_attestation_requires_domain_bound_terminal_receipt(adapter):
    authority, _, _ = adapter
    payload = {
        "schema_version": 1,
        "run_id": "run-1",
        "epoch": "epoch-1",
        "task_id": "arvo:1",
        "status": "oracle_false",
    }
    assert authority.attest_signed("terminal_receipt", signed(payload)) is None
    payload["artifact_kind"] = "terminal_receipt"
    assert authority.attest_signed("terminal_receipt", signed(payload)) == payload
    payload["artifact_kind"] = "cohort"
    assert authority.attest_signed("terminal_receipt", signed(payload)) is None


def test_created_once_across_run_ids_and_verified_artifact_replay(adapter):
    authority, root, sync_calls = adapter
    event = created_event()
    assert authority.create_campaign_once(root, "run-1", event) is True
    assert authority.create_campaign_once(root, "run-2", created_event("run-2")) is False
    assert authority.read_verified_events(root, "run-1") == (event,)
    assert sync_calls == [root, root]
    assert FakeLedger.verify_calls >= 1
    assert all(
        connection.synchronous == (0 if connection.memory else 2)
        for connection in FakeLedger.connections
    )


def test_native_cas_append_and_restart_read_without_retry(adapter):
    authority, root, _ = adapter
    authority.create_campaign_once(root, "run-1", created_event())
    prepared = {"type": "prepared", "task_id": "arvo:1"}
    assert authority.append_event(root, "run-1", prepared, expected_revision=1) is True
    assert authority.append_event(root, "run-1", prepared, expected_revision=1) is False
    restarted = XeusCampaignAuthority({"test-key": object_key}, native=authority._native)
    assert restarted.read_verified_events(root, "run-1") == (created_event(), prepared)
    started = {"type": "started", "task_id": "arvo:1", "request_id": "req-1"}
    assert restarted.append_event(root, "run-1", started, expected_revision=2) is True
    assert restarted.read_verified_events(root, "run-1")[-1] == started


def test_corrupt_artifact_or_native_chain_never_replays(adapter):
    authority, root, _ = adapter
    authority.create_campaign_once(root, "run-1", created_event())
    path = str(root / "campaign.sqlite3")
    identity = FakeLedger.records[path][0].event.payload_digest
    FakeArtifactStore.objects[(str(root / "campaign-artifacts"), identity)] = b"tampered"
    with pytest.raises(RuntimeError, match="artifact|verified"):
        authority.read_verified_events(root, "run-1")
    FakeLedger.chain_failure = True
    with pytest.raises(RuntimeError, match="chain|verified"):
        authority.read_verified_events(root, "run-1")


def test_ambiguous_creation_keeps_exclusive_marker_and_never_retries(adapter):
    authority, root, _ = adapter
    FakeLedger.commit_then_lose_ack = True
    with pytest.raises(RuntimeError, match="acknowledgement"):
        authority.create_campaign_once(root, "run-1", created_event())
    FakeLedger.commit_then_lose_ack = False
    assert authority.create_campaign_once(root, "run-2", created_event("run-2")) is False
    assert authority.read_verified_events(root, "run-1") == (created_event(),)


def test_ambiguous_transition_is_only_observed_after_restart(adapter):
    authority, root, _ = adapter
    authority.create_campaign_once(root, "run-1", created_event())
    prepared = {"type": "prepared", "task_id": "arvo:1"}
    FakeLedger.commit_then_lose_ack = True
    with pytest.raises(TimeoutError, match="ack lost"):
        authority.append_event(root, "run-1", prepared, expected_revision=1)
    FakeLedger.commit_then_lose_ack = False
    restarted = XeusCampaignAuthority({"test-key": object_key}, native=authority._native)
    assert restarted.read_verified_events(root, "run-1") == (created_event(), prepared)
    assert restarted.append_event(root, "run-1", prepared, expected_revision=1) is False
