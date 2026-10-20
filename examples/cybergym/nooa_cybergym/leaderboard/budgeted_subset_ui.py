# SPDX-License-Identifier: Apache-2.0
"""Inert schema-2 subset UI custody contracts; schema-1 UI code is unchanged.

This module does NOT supply a Windows producer, authenticated RPC endpoint, or
production factory. A production adapter must pin both custody directories and
the runtime public-key registry, route claim/ack RPCs over authenticated outbound
transport, and independently collect the observations described below. Passing
these validators with synthetic observations is not evidence of a live cleanup.

The trusted producer must durably write the preparation ownership intent before
creating any process; enumerate exact PID/creation/executable/profile identities;
terminate only matching identities through held process handles; wait and freshly
enumerate; preserve incomplete ownership on any failure; and return only after
its effect has stopped. It must preserve other preparations' manifest entries.
Cleanup observations are data from that trusted boundary, not self-authenticating
JSON. Only an acknowledgement attached to this mailbox's signed command and claim
can yield VerifiedOwnedUiCleanup. A later adapter must re-read that custody when
signing quiescence. No approval key or production private key is loaded here.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import sqlite3
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path, PureWindowsPath
from uuid import uuid4

from xeus_cybergym.canonical import canonical_json
from xeus_cybergym.ledger import SignedEnvelope

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9:_.-]{0,127}\Z")
_HASH = re.compile(r"[a-f0-9]{64}\Z")
_MAX_COMMAND = 32768
_MAX_OBSERVATION = 65536
_MAX_ACK = 98304
_SCOPE = "budgeted_subset_native_level1"


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _json(raw: bytes, maximum: int) -> dict:
    if type(raw) is not bytes or not 0 < len(raw) <= maximum:
        raise ValueError("bounded canonical evidence required")
    value = json.loads(raw)
    if type(value) is not dict or canonical_json(value) != raw:
        raise ValueError("canonical evidence object required")
    return value


def _shape(value: dict, keys: set[str]) -> None:
    if type(value) is not dict or set(value) != keys:
        raise ValueError("exact versioned evidence fields required")


def _identifier(value: str) -> None:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise ValueError("bounded identity required")


def _digest(value: str) -> None:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise ValueError("SHA-256 digest required")


def _windows_path(value: str) -> None:
    if (
        type(value) is not str
        or not 0 < len(value) <= 512
        or any(ord(c) < 32 for c in value)
        or not PureWindowsPath(value).is_absolute()
        or ".." in PureWindowsPath(value).parts
    ):
        raise ValueError("bounded absolute Windows identity path required")


def _decode(value: str, maximum: int) -> bytes:
    if type(value) is not str or len(value) > 4 * ((maximum + 2) // 3):
        raise ValueError("bounded canonical Base64 required")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("canonical Base64 required") from None
    if len(raw) > maximum or base64.b64encode(raw).decode("ascii") != value:
        raise ValueError("bounded canonical Base64 required")
    return raw


def _encode(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


@dataclass(frozen=True, slots=True)
class SubsetUiBinding:
    """Pinned preparation identity, supplied by the verified subset adapter.

    This value is not admission authority: the future adapter must derive it from
    current BudgetedSubsetState and independently pinned workstation inputs.
    """

    run_id: str
    task_id: str
    preparation_id: str
    preparation_started_event_sha256: str
    budget_sha256: str
    remote_host: str
    port: int
    profile_directory: str
    tunnel_config_path: str
    tunnel_config_sha256: str
    producer_sha256: str
    code_executable: str
    code_sha256: str
    ssh_executable: str
    ssh_sha256: str

    def __post_init__(self):
        for name in ("run_id", "task_id", "preparation_id"):
            _identifier(getattr(self, name))
        for name in (
            "preparation_started_event_sha256",
            "budget_sha256",
            "tunnel_config_sha256",
            "producer_sha256",
            "code_sha256",
            "ssh_sha256",
        ):
            _digest(getattr(self, name))
        for name in (
            "profile_directory",
            "tunnel_config_path",
            "code_executable",
            "ssh_executable",
        ):
            _windows_path(getattr(self, name))
        if (
            type(self.remote_host) is not str
            or re.fullmatch(r"[a-z][a-z0-9-]{1,63}", self.remote_host) is None
            or type(self.port) is not int
            or not 1024 <= self.port <= 65535
        ):
            raise ValueError("isolated SSH alias and port required")

    @property
    def payload(self) -> dict:
        return asdict(self)

    @property
    def sha256(self) -> str:
        return _sha(canonical_json(self.payload))


@dataclass(frozen=True, slots=True)
class SubsetUiLaunch:
    request_id: str
    attempt_id: str
    launch_sha256: str
    started_event_sha256: str
    receipt: bytes = field(repr=False)

    def __post_init__(self):
        _identifier(self.request_id)
        _identifier(self.attempt_id)
        _digest(self.launch_sha256)
        _digest(self.started_event_sha256)
        receipt = _json(self.receipt, 4096)
        if (
            receipt.get("event") != "launch_reserved"
            or receipt.get("launch_id") != self.request_id
            or receipt.get("session_id", "missing") is not None
        ):
            raise ValueError("exact pre-model launch receipt required")
        _digest(receipt.get("prompt_sha256"))

    @property
    def payload(self) -> dict:
        return {
            "request_id": self.request_id,
            "attempt_id": self.attempt_id,
            "launch_sha256": self.launch_sha256,
            "started_event_sha256": self.started_event_sha256,
            "receipt_base64": _encode(self.receipt),
            "receipt_sha256": _sha(self.receipt),
        }


def _launch(value: dict | None) -> None:
    if value is None:
        return
    _shape(
        value,
        {
            "request_id",
            "attempt_id",
            "launch_sha256",
            "started_event_sha256",
            "receipt_base64",
            "receipt_sha256",
        },
    )
    checked = SubsetUiLaunch(
        value["request_id"],
        value["attempt_id"],
        value["launch_sha256"],
        value["started_event_sha256"],
        _decode(value["receipt_base64"], 4096),
    )
    if checked.payload != value:
        raise ValueError("launch receipt digest differs")


def _signed(raw: bytes, verifier) -> tuple[bytes, dict]:
    envelope = _json(raw, _MAX_COMMAND)
    payload = verifier.verify(SignedEnvelope.model_validate(envelope))
    return payload, _json(payload, _MAX_COMMAND // 2)


def _command(raw: bytes, binding: SubsetUiBinding, verifier) -> tuple[bytes, dict]:
    payload, value = _signed(raw, verifier)
    _shape(
        value,
        {
            "schema_version",
            "artifact_kind",
            "scope",
            "command_id",
            "operation_key",
            "action",
            "binding",
            "launch",
        },
    )
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 2
        or value["artifact_kind"] != "subset_ui_command"
        or value["scope"] != _SCOPE
        or value["binding"] != binding.payload
        or type(value["command_id"]) is not str
        or re.fullmatch(r"[a-f0-9]{32}", value["command_id"]) is None
        or value["action"] not in ("open", "submit", "cleanup")
    ):
        raise ValueError("signed subset command identity differs")
    _identifier(value["operation_key"])
    _launch(value["launch"])
    if value["action"] == "open" and value["launch"] is not None:
        raise ValueError("open binds preparation before a launch exists")
    if value["action"] == "submit" and value["launch"] is None:
        raise ValueError("Submit requires committed started identity")
    return payload, value


def _claim(
    raw: bytes,
    envelope: bytes,
    binding: SubsetUiBinding,
    verifier,
    *,
    reservation_id: str | None = None,
) -> dict:
    payload, command = _command(envelope, binding, verifier)
    _, claim = _signed(raw, verifier)
    _shape(
        claim,
        {
            "schema_version",
            "artifact_kind",
            "scope",
            "binding_sha256",
            "command_id",
            "command_sha256",
            "command_envelope_sha256",
            "action",
            "permission",
            "ownership_claim_sha256",
            "open_command_sha256",
            "fence_command_sha256",
            "reservation_id",
        },
    )
    expected = {
        "schema_version": 2,
        "artifact_kind": "subset_ui_execution_claim",
        "scope": _SCOPE,
        "binding_sha256": binding.sha256,
        "command_id": command["command_id"],
        "command_sha256": _sha(payload),
        "command_envelope_sha256": _sha(envelope),
        "action": command["action"],
    }
    if any(claim[k] != v or type(claim[k]) is not type(v) for k, v in expected.items()):
        raise ValueError("execution claim differs from signed command")
    if (
        type(claim["reservation_id"]) is not str
        or re.fullmatch(r"[a-f0-9]{32}", claim["reservation_id"]) is None
        or (reservation_id is not None and claim["reservation_id"] != reservation_id)
    ):
        raise ValueError("execution claim differs from durable workstation reservation")
    if claim["permission"] not in ("allowed", "revoked"):
        raise ValueError("execution claim permission differs")
    for key in ("ownership_claim_sha256", "open_command_sha256", "fence_command_sha256"):
        if claim[key] is not None:
            _digest(claim[key])
    if command["action"] == "cleanup":
        if claim["permission"] != "allowed" or claim["fence_command_sha256"] != _sha(payload):
            raise ValueError("cleanup requires its durable fence")
    elif claim["permission"] == "allowed" and claim["fence_command_sha256"] is not None:
        raise ValueError("fenced preparation cannot execute open or Submit")
    elif claim["permission"] == "revoked" and claim["fence_command_sha256"] is None:
        raise ValueError("revocation lacks a cleanup fence")
    if command["action"] == "submit" and claim["permission"] == "allowed":
        if claim["ownership_claim_sha256"] is None or claim["open_command_sha256"] is None:
            raise ValueError("Submit lacks prior owned open")
    return {**claim, "claim_sha256": _sha(raw)}


def _process(value: dict, binding: SubsetUiBinding) -> str:
    _shape(
        value,
        {
            "kind",
            "pid",
            "creation_time_ns",
            "executable_path",
            "executable_sha256",
            "command_line",
            "profile_directory",
            "tunnel_config_sha256",
            "run_id",
            "task_id",
            "preparation_id",
        },
    )
    if value["kind"] not in ("window", "tunnel"):
        raise ValueError("owned process kind required")
    for key in ("pid", "creation_time_ns"):
        if type(value[key]) is not int or not 0 < value[key] < 2**63:
            raise ValueError("exact PID and creation time required")
    for key in ("run_id", "task_id", "preparation_id", "profile_directory", "tunnel_config_sha256"):
        if value[key] != getattr(binding, key):
            raise ValueError("process belongs to a different preparation")
    window = value["kind"] == "window"
    if (
        value["executable_path"] != (binding.code_executable if window else binding.ssh_executable)
        or value["executable_sha256"] != (binding.code_sha256 if window else binding.ssh_sha256)
        or type(value["command_line"]) is not str
        or not 0 < len(value["command_line"]) <= 4096
    ):
        raise ValueError("pinned executable identity required")
    markers = (
        (binding.profile_directory,)
        if window
        else (
            binding.tunnel_config_path,
            f"CYBERGYM_RUN_ID={binding.run_id}",
            f"CYBERGYM_TASK_ID={binding.task_id}",
            f"CYBERGYM_PREPARATION_ID={binding.preparation_id}",
        )
    )
    if any(marker not in value["command_line"] for marker in markers):
        raise ValueError("auditable process ownership markers required")
    return _sha(canonical_json(value))


def _processes(values: list, binding: SubsetUiBinding) -> set[str]:
    if type(values) is not list or len(values) > 128:
        raise ValueError("bounded owned process enumeration required")
    keys = [_process(value, binding) for value in values]
    identities = [(value["pid"], value["creation_time_ns"]) for value in values]
    if len(set(keys)) != len(keys) or len(set(identities)) != len(keys):
        raise ValueError("duplicate owned process identity")
    return set(keys)


def _manifest(encoded: str) -> dict:
    manifest = _json(_decode(encoded, _MAX_OBSERVATION), _MAX_OBSERVATION)
    _shape(manifest, {"schema_version", "owners"})
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 2:
        raise ValueError("versioned ownership manifest required")
    owners = manifest["owners"]
    if type(owners) is not list or len(owners) > 128:
        raise ValueError("bounded ownership manifest required")
    result = {}
    for owner in owners:
        _shape(
            owner, {"binding_sha256", "open_command_sha256", "ownership_claim_sha256", "processes"}
        )
        for key in ("binding_sha256", "open_command_sha256", "ownership_claim_sha256"):
            _digest(owner[key])
        if owner["binding_sha256"] in result:
            raise ValueError("duplicate preparation owner")
        result[owner["binding_sha256"]] = owner
    return result


def _cleanup(raw: bytes, command: dict, claim: dict, binding: SubsetUiBinding) -> None:
    value = _json(raw, _MAX_OBSERVATION)
    _shape(
        value,
        {
            "schema_version",
            "artifact_kind",
            "binding_sha256",
            "command_sha256",
            "claim_sha256",
            "ownership_claim_sha256",
            "producer_sha256",
            "observed_start_ns",
            "observed_end_ns",
            "enumeration_complete",
            "manifest_before_base64",
            "manifest_after_base64",
            "processes_before",
            "processes_after",
            "dispositions",
            "errors",
        },
    )
    expected = {
        "schema_version": 1,
        "artifact_kind": "subset_owned_ui_cleanup",
        "binding_sha256": binding.sha256,
        "command_sha256": _sha(canonical_json(command)),
        "claim_sha256": claim["claim_sha256"],
        "ownership_claim_sha256": claim["ownership_claim_sha256"],
        "producer_sha256": binding.producer_sha256,
        "enumeration_complete": True,
        "processes_after": [],
        "errors": [],
    }
    if any(value[k] != v or type(value[k]) is not type(v) for k, v in expected.items()):
        raise ValueError("cleanup identity, enumeration or result is incomplete")
    start, end = value["observed_start_ns"], value["observed_end_ns"]
    if type(start) is not int or type(end) is not int or not 0 < start <= end < 2**63:
        raise ValueError("ordered cleanup observation times required")
    before = _manifest(value["manifest_before_base64"])
    after = _manifest(value["manifest_after_base64"])
    target = before.pop(binding.sha256, None)
    if binding.sha256 in after or before != after:
        raise ValueError("cleanup must remove only its own manifest entry")
    recorded = set()
    if claim["ownership_claim_sha256"] is None:
        if target is not None:
            raise ValueError("unclaimed open cannot own a manifest entry")
    else:
        if (
            target is None
            or target["ownership_claim_sha256"] != claim["ownership_claim_sha256"]
            or target["open_command_sha256"] != claim["open_command_sha256"]
        ):
            raise ValueError("durable pre-open ownership intent is missing or changed")
        recorded = _processes(target["processes"], binding)
    observed = _processes(value["processes_before"], binding)
    if not recorded <= observed or (claim["ownership_claim_sha256"] is None and observed):
        raise ValueError("manifest process identity missing from cleanup observation")
    dispositions = value["dispositions"]
    if type(dispositions) is not list or len(dispositions) != len(observed):
        raise ValueError("every owned process requires a final disposition")
    settled = set()
    for disposition in dispositions:
        _shape(disposition, {"process_sha256", "outcome"})
        if disposition["outcome"] not in ("terminated", "already_exited"):
            raise ValueError("owned process has not settled")
        _digest(disposition["process_sha256"])
        settled.add(disposition["process_sha256"])
    if settled != observed:
        raise ValueError("process disposition identity differs")


def _send(raw: bytes, command: dict) -> None:
    audit = _json(raw, 8192)
    receipt = _json(_decode(command["launch"]["receipt_base64"], 4096), 4096)
    expected = {
        "schema_version": 1,
        "event": "ui_send_attempted",
        "launch_id": command["launch"]["request_id"],
        "prompt_sha256": receipt["prompt_sha256"],
        "observed_prompt_sha256": receipt["prompt_sha256"],
        "remote_alias": command["binding"]["remote_host"],
        "provider_request_observed": False,
    }
    if any(audit.get(k) != v or type(audit.get(k)) is not type(v) for k, v in expected.items()):
        raise ValueError("native Send evidence differs from committed launch")


def _ack(
    envelope: bytes,
    claim_raw: bytes,
    binding: SubsetUiBinding,
    verifier,
    status: str,
    evidence: bytes | None,
) -> bytes:
    payload, command = _command(envelope, binding, verifier)
    return canonical_json(
        {
            "schema_version": 2,
            "artifact_kind": "subset_ui_ack",
            "binding_sha256": binding.sha256,
            "command_id": command["command_id"],
            "command_sha256": _sha(payload),
            "command_envelope_sha256": _sha(envelope),
            "action": command["action"],
            "claim_sha256": _sha(claim_raw),
            "status": status,
            "evidence_base64": _encode(evidence) if evidence is not None else None,
            "evidence_sha256": _sha(evidence) if evidence is not None else None,
        }
    )


def _checked_ack(
    raw: bytes, envelope: bytes, claim_raw: bytes, binding: SubsetUiBinding, verifier
) -> dict:
    value = _json(raw, _MAX_ACK)
    _shape(
        value,
        {
            "schema_version",
            "artifact_kind",
            "binding_sha256",
            "command_id",
            "command_sha256",
            "command_envelope_sha256",
            "action",
            "claim_sha256",
            "status",
            "evidence_base64",
            "evidence_sha256",
        },
    )
    claim = _claim(claim_raw, envelope, binding, verifier)
    _, command = _command(envelope, binding, verifier)
    evidence = (
        None
        if value["evidence_base64"] is None
        else _decode(value["evidence_base64"], _MAX_OBSERVATION)
    )
    if value["status"] not in ("completed", "ambiguous", "failed", "revoked"):
        raise ValueError("explicit UI acknowledgement status required")
    if raw != _ack(envelope, claim_raw, binding, verifier, value["status"], evidence):
        raise ValueError("acknowledgement differs from command, claim or evidence")
    if (value["status"] == "revoked") != (claim["permission"] == "revoked"):
        raise ValueError("revoked commands cannot acknowledge an effect")
    if value["status"] == "completed":
        if command["action"] == "cleanup":
            _cleanup(evidence, command, claim, binding)
        elif command["action"] == "submit":
            _send(evidence, command)
        elif evidence is not None:
            raise ValueError("open acknowledgement is not cleanup evidence")
    elif value["status"] == "revoked" and evidence is not None:
        raise ValueError("revoked command carries no effect evidence")
    return value


class _Store:
    def __init__(self, root: Path, binding: SubsetUiBinding, name: str):
        self.root = Path(root)
        if type(binding) is not SubsetUiBinding:
            raise ValueError("typed pinned preparation binding required")
        self.binding = binding
        self.database = self.root / f"{name}.sqlite"
        self.marker = self.root / f"{name}.identity.json"
        self.identity = canonical_json({"store": name, "binding": binding.payload})
        self._paths()
        existed = self.database.exists()
        if self.marker.exists() != existed:
            raise RuntimeError("UI custody database or initialization marker is missing")
        if not existed:
            # A crash during initialization leaves an explicit incomplete store;
            # it must never silently reset the same preparation to unused.
            with self.marker.open("xb") as stream:
                stream.write(self.identity)
                stream.flush()
                os.fsync(stream.fileno())
        with self._connect(check=False) as connection:
            connection.execute("BEGIN IMMEDIATE")
            if not existed:
                connection.executescript(
                    "CREATE TABLE identity (id INTEGER PRIMARY KEY CHECK(id=1), value BLOB NOT NULL);"
                    "CREATE TABLE commands (command_id TEXT PRIMARY KEY, operation_key TEXT UNIQUE NOT NULL,"
                    "action TEXT UNIQUE NOT NULL, envelope BLOB NOT NULL, claim BLOB, revocation BLOB, ack BLOB, reservation_id TEXT);"
                    "CREATE TRIGGER identity_no_update BEFORE UPDATE ON identity BEGIN SELECT RAISE(ABORT,'immutable identity'); END;"
                    "CREATE TRIGGER identity_no_delete BEFORE DELETE ON identity BEGIN SELECT RAISE(ABORT,'immutable identity'); END;"
                    "CREATE TRIGGER identity_no_replace BEFORE INSERT ON identity WHEN EXISTS(SELECT 1 FROM identity) "
                    "BEGIN SELECT RAISE(ABORT,'immutable identity'); END;"
                    "CREATE TRIGGER commands_no_delete BEFORE DELETE ON commands BEGIN SELECT RAISE(ABORT,'immutable command'); END;"
                    "CREATE TRIGGER commands_no_replace BEFORE INSERT ON commands WHEN EXISTS(SELECT 1 FROM commands WHERE "
                    "command_id=NEW.command_id OR operation_key=NEW.operation_key OR action=NEW.action) "
                    "BEGIN SELECT RAISE(ABORT,'immutable command'); END;"
                    "CREATE TRIGGER commands_update BEFORE UPDATE ON commands WHEN "
                    "NEW.command_id IS NOT OLD.command_id OR NEW.operation_key IS NOT OLD.operation_key OR "
                    "NEW.action IS NOT OLD.action OR NEW.envelope IS NOT OLD.envelope OR "
                    "(OLD.claim IS NOT NULL AND NEW.claim IS NOT OLD.claim) OR "
                    "(OLD.revocation IS NOT NULL AND NEW.revocation IS NOT OLD.revocation) OR "
                    "(OLD.ack IS NOT NULL AND NEW.ack IS NOT OLD.ack) "
                    "OR (OLD.reservation_id IS NOT NULL AND NEW.reservation_id IS NOT OLD.reservation_id) "
                    "BEGIN SELECT RAISE(ABORT,'immutable custody'); END;"
                )
                connection.execute("INSERT INTO identity VALUES(1,?)", (self.identity,))
            self._identity(connection)
        if os.name == "posix":
            descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

    def _paths(self):
        if (
            not self.root.is_absolute()
            or self.root.resolve() != self.root
            or not self.root.is_dir()
            or self.root.is_symlink()
            or self.database.is_symlink()
            or self.marker.is_symlink()
        ):
            raise ValueError("absolute unlinked custody directory required")

    def _identity(self, connection):
        if (
            not self.marker.is_file()
            or self.marker.stat().st_size != len(self.identity)
            or self.marker.read_bytes() != self.identity
        ):
            raise RuntimeError("UI custody initialization marker differs")
        if connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise RuntimeError("UI custody database integrity differs")
        if connection.execute("SELECT id,value FROM identity").fetchall() != [(1, self.identity)]:
            raise RuntimeError("UI custody preparation identity differs")

    @contextmanager
    def _connect(self, *, check=True):
        self._paths()
        if check and not self.database.is_file():
            raise RuntimeError("UI custody database disappeared")
        connection = sqlite3.connect(self.database, timeout=15)
        try:
            connection.execute("PRAGMA synchronous=FULL")
            with connection:
                if check:
                    self._identity(connection)
                yield connection
        finally:
            connection.close()


@dataclass(frozen=True, slots=True)
class VerifiedOwnedUiCleanup:
    command_payload: bytes = field(repr=False)
    observation: bytes = field(repr=False)
    acknowledgement: bytes = field(repr=False)

    @property
    def observation_sha256(self) -> str:
        return _sha(self.observation)


class SubsetUiMailbox(_Store):
    """One preparation's signed commands; claim/ack require authenticated RPC.

    Publishing cleanup atomically fences all subsequent open/Submit claims. A
    previously issued claim must settle before cleanup can acquire permission.
    A claim is permission for at most one locally reserved effect, not replay.
    """

    def __init__(self, root: Path, *, binding: SubsetUiBinding, signer, verifier):
        if not callable(getattr(signer, "sign", None)) or not callable(
            getattr(verifier, "verify", None)
        ):
            raise ValueError("runtime command signer and pinned verifier required")
        self.signer, self.verifier = signer, verifier
        super().__init__(root, binding, "subset-ui-mailbox")

    def _rows(self, connection):
        rows = {}
        for (
            command_id,
            operation_key,
            action,
            envelope,
            claim,
            revoked,
            ack,
            reservation_id,
        ) in connection.execute("SELECT * FROM commands"):
            _, value = _command(envelope, self.binding, self.verifier)
            if (command_id, operation_key, action) != (
                value["command_id"],
                value["operation_key"],
                value["action"],
            ):
                raise RuntimeError("durable UI command indices differ")
            for proof in (claim, revoked):
                if proof is not None:
                    if reservation_id is None:
                        raise RuntimeError("controller claim lacks a workstation reservation")
                    _claim(
                        proof, envelope, self.binding, self.verifier, reservation_id=reservation_id
                    )
            if ack is not None:
                matching = self._ack_claim(ack, claim, revoked)
                _checked_ack(ack, envelope, matching, self.binding, self.verifier)
            rows[action] = {
                "command": value,
                "envelope": envelope,
                "claim": claim,
                "revocation": revoked,
                "ack": ack,
                "reservation_id": reservation_id,
            }
        return rows

    @staticmethod
    def _ack_claim(ack, claim, revoked):
        digest = _json(ack, _MAX_ACK)["claim_sha256"]
        for candidate in (claim, revoked):
            if candidate is not None and _sha(candidate) == digest:
                return candidate
        raise RuntimeError("acknowledgement has no durable execution claim")

    def publish(
        self, *, action: str, operation_key: str, launch: SubsetUiLaunch | None = None
    ) -> bytes:
        _identifier(operation_key)
        if action not in ("open", "submit", "cleanup"):
            raise ValueError("explicit subset UI action required")
        if launch is not None and type(launch) is not SubsetUiLaunch:
            raise ValueError("typed committed launch required")
        spec = {
            "schema_version": 2,
            "artifact_kind": "subset_ui_command",
            "scope": _SCOPE,
            "operation_key": operation_key,
            "action": action,
            "binding": self.binding.payload,
            "launch": None if launch is None else launch.payload,
        }
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = self._rows(connection)
            for row in rows.values():
                if row["command"]["operation_key"] == operation_key:
                    if {k: v for k, v in row["command"].items() if k != "command_id"} != spec:
                        raise RuntimeError("operation key reused with different inputs")
                    return row["envelope"]
            if action in rows or ("cleanup" in rows and action != "cleanup"):
                raise RuntimeError("one-shot preparation action is already reserved or fenced")
            if action == "submit" and "open" not in rows:
                raise RuntimeError("Submit requires prior owned open")
            if (
                action == "cleanup"
                and "submit" in rows
                and spec["launch"] != rows["submit"]["command"]["launch"]
            ):
                raise RuntimeError("cleanup must retain exact started launch identity")
            payload = canonical_json({**spec, "command_id": uuid4().hex})
            raw = canonical_json(self.signer.sign(payload).model_dump())
            _, command = _command(raw, self.binding, self.verifier)
            changed = connection.execute(
                "INSERT INTO commands(command_id,operation_key,action,envelope) VALUES(?,?,?,?)",
                (command["command_id"], operation_key, action, raw),
            )
            if (
                changed.rowcount != 1
                or self._rows(connection).get(action, {}).get("envelope") != raw
            ):
                raise RuntimeError("controller command custody was not durably inserted")
        return raw

    def claim(self, envelope: bytes, *, reservation_id: str) -> bytes:
        if type(reservation_id) is not str or re.fullmatch(r"[a-f0-9]{32}", reservation_id) is None:
            raise ValueError("durable workstation reservation ID required")
        payload, command = _command(envelope, self.binding, self.verifier)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = self._rows(connection)
            row = rows.get(command["action"])
            if row is None or row["envelope"] != envelope:
                raise RuntimeError("execution claim requires exact published command")
            if row["ack"] is not None:
                raise RuntimeError("settled command permits acknowledgement replay only")
            if row["reservation_id"] is not None and row["reservation_id"] != reservation_id:
                raise RuntimeError("execution claim belongs to a different workstation reservation")
            cleanup = rows.get("cleanup")
            revoked = cleanup is not None and command["action"] != "cleanup"
            column = "revocation" if revoked else "claim"
            if row[column] is not None:
                return row[column]
            if command["action"] == "cleanup":
                if any(
                    r["claim"] is not None and r["ack"] is None
                    for a, r in rows.items()
                    if a != "cleanup"
                ):
                    raise RuntimeError("cleanup cannot pass an unsettled prior execution claim")
            opening = rows.get("open")
            ownership_claim = opening["claim"] if opening else None
            if (
                opening
                and opening["ack"] is not None
                and _json(opening["ack"], _MAX_ACK)["status"] == "revoked"
            ):
                # An authenticated revocation acknowledges no effect. This also
                # covers a granted claim whose reply was lost before the local
                # effect boundary, then revoked before the same nonce retried.
                ownership_claim = None
            if command["action"] == "submit" and not revoked:
                if (
                    opening is None
                    or opening["ack"] is None
                    or _json(opening["ack"], _MAX_ACK)["status"] != "completed"
                ):
                    raise RuntimeError("Submit requires completed owned open")
            claim = {
                "schema_version": 2,
                "artifact_kind": "subset_ui_execution_claim",
                "scope": _SCOPE,
                "binding_sha256": self.binding.sha256,
                "command_id": command["command_id"],
                "command_sha256": _sha(payload),
                "command_envelope_sha256": _sha(envelope),
                "action": command["action"],
                "reservation_id": reservation_id,
                "permission": "revoked" if revoked else "allowed",
                "ownership_claim_sha256": _sha(ownership_claim)
                if ownership_claim is not None
                else None,
                "open_command_sha256": _sha(canonical_json(opening["command"]))
                if opening
                else None,
                "fence_command_sha256": _sha(canonical_json(cleanup["command"]))
                if cleanup
                else None,
            }
            raw = canonical_json(self.signer.sign(canonical_json(claim)).model_dump())
            _claim(raw, envelope, self.binding, self.verifier)
            changed = connection.execute(
                f"UPDATE commands SET {column}=?,reservation_id=? WHERE command_id=? AND {column} IS NULL",
                (raw, reservation_id, command["command_id"]),
            )
            persisted = self._rows(connection).get(command["action"], {})
            if (
                changed.rowcount != 1
                or persisted.get(column) != raw
                or persisted.get("reservation_id") != reservation_id
            ):
                raise RuntimeError("controller execution claim custody was not durably updated")
        return raw

    def pending(self) -> bytes | None:
        """Read the first unsettled command; polling grants no effect permission."""
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = self._rows(connection)
            for action in ("open", "submit", "cleanup"):
                if action in rows and rows[action]["ack"] is None:
                    return rows[action]["envelope"]
        return None

    def acknowledge(self, raw: bytes) -> bytes:
        value = _json(raw, _MAX_ACK)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = self._rows(connection)
            row = rows.get(value.get("action"))
            if row is None:
                raise RuntimeError("unknown subset acknowledgement")
            claim = self._ack_claim(raw, row["claim"], row["revocation"])
            _checked_ack(raw, row["envelope"], claim, self.binding, self.verifier)
            if row["ack"] is not None:
                if row["ack"] != raw:
                    raise RuntimeError("immutable acknowledgement differs on replay")
                return row["ack"]
            changed = connection.execute(
                "UPDATE commands SET ack=? WHERE command_id=? AND ack IS NULL",
                (raw, value["command_id"]),
            )
            if (
                changed.rowcount != 1
                or self._rows(connection).get(value["action"], {}).get("ack") != raw
            ):
                raise RuntimeError("controller acknowledgement custody was not durably updated")
        return raw

    def verified_cleanup(self, envelope: bytes) -> VerifiedOwnedUiCleanup:
        payload, command = _command(envelope, self.binding, self.verifier)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = self._rows(connection)
            row = rows.get("cleanup")
            if (
                command["action"] != "cleanup"
                or row is None
                or row["envelope"] != envelope
                or row["ack"] is None
            ):
                raise RuntimeError("durable completed cleanup acknowledgement required")
            ack = _checked_ack(row["ack"], envelope, row["claim"], self.binding, self.verifier)
            if ack["status"] != "completed" or any(
                r["claim"] is not None and r["ack"] is None for r in rows.values()
            ):
                raise RuntimeError("cleanup has not established owned quiescence")
            return VerifiedOwnedUiCleanup(
                payload, _decode(ack["evidence_base64"], _MAX_OBSERVATION), row["ack"]
            )


class SubsetUiCustody(_Store):
    """Workstation-side one-shot custody; contains no real process implementation.

    ``transport`` must implement authenticated claim(envelope, reservation_id=...)
    and acknowledge(ack). Claims cannot migrate to a different local reservation.
    ``producer.execute(command, claim)`` is a trusted pinned producer, not a task
    callback. Its command/claim arguments are defensive copies. An independent
    SQLite lock spans the effect to serialize clients, while the reservation is
    committed separately before the effect. A crash never permits re-execution.
    """

    def __init__(self, root: Path, *, binding: SubsetUiBinding, verifier):
        if not callable(getattr(verifier, "verify", None)):
            raise ValueError("pinned runtime command verifier required")
        self.verifier = verifier
        super().__init__(root, binding, "subset-ui-custody")
        self.lock_path = self.root / "subset-ui-effect-lock.sqlite"

    @contextmanager
    def _effect_lock(self):
        self._paths()
        if self.lock_path.is_symlink():
            raise RuntimeError("effect lock may not be linked")
        lock = sqlite3.connect(self.lock_path, timeout=15)
        try:
            lock.execute("BEGIN IMMEDIATE")
            yield
        finally:
            lock.rollback()
            lock.close()

    def execute(self, envelope: bytes, *, transport, producer) -> bytes:
        _, command = _command(envelope, self.binding, self.verifier)
        with self._effect_lock():
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                rows = connection.execute(
                    "SELECT command_id,operation_key,action,envelope,claim,revocation,ack,reservation_id FROM commands"
                ).fetchall()
                existing = None
                fenced = False
                for (
                    command_id,
                    operation_key,
                    action,
                    prior,
                    claim_raw,
                    revocation,
                    ack_raw,
                    reservation_id,
                ) in rows:
                    _, parsed = _command(prior, self.binding, self.verifier)
                    if (command_id, operation_key, action) != (
                        parsed["command_id"],
                        parsed["operation_key"],
                        parsed["action"],
                    ):
                        raise RuntimeError("local command indices differ")
                    if revocation is not None:
                        raise RuntimeError("unexpected local custody revocation")
                    if (
                        type(reservation_id) is not str
                        or re.fullmatch(r"[a-f0-9]{32}", reservation_id) is None
                    ):
                        raise RuntimeError("local workstation reservation is missing")
                    if claim_raw is not None:
                        _claim(
                            claim_raw,
                            prior,
                            self.binding,
                            self.verifier,
                            reservation_id=reservation_id,
                        )
                    elif ack_raw is not None:
                        raise RuntimeError("local acknowledgement lacks its execution claim")
                    if ack_raw is not None:
                        _checked_ack(ack_raw, prior, claim_raw, self.binding, self.verifier)
                    if action == "cleanup":
                        fenced = True
                    if action == command["action"]:
                        if prior != envelope:
                            raise RuntimeError("one-shot local action was replaced")
                        existing = (claim_raw, ack_raw, reservation_id)
                if existing is None:
                    reservation_id = uuid4().hex
                    changed = connection.execute(
                        "INSERT INTO commands(command_id,operation_key,action,envelope,reservation_id) VALUES(?,?,?,?,?)",
                        (
                            command["command_id"],
                            command["operation_key"],
                            command["action"],
                            envelope,
                            reservation_id,
                        ),
                    )
                    if changed.rowcount != 1 or connection.execute(
                        "SELECT envelope,reservation_id FROM commands WHERE command_id=?",
                        (command["command_id"],),
                    ).fetchall() != [(envelope, reservation_id)]:
                        raise RuntimeError("local reservation custody was not durably inserted")
                else:
                    claim_raw, ack_raw, reservation_id = existing
            if existing is not None and claim_raw is not None:
                if ack_raw is None:
                    claim = _claim(claim_raw, envelope, self.binding, self.verifier)
                    ack_raw = _ack(
                        envelope,
                        claim_raw,
                        self.binding,
                        self.verifier,
                        "revoked" if claim["permission"] == "revoked" else "ambiguous",
                        None,
                    )
                    self._save_ack(command, envelope, claim_raw, ack_raw)
                _checked_ack(ack_raw, envelope, claim_raw, self.binding, self.verifier)
                return self._deliver(transport, ack_raw)
            # The nonce is durable before this current permission check. A lost
            # RPC reply can retry only that reservation. A durable claim marks
            # the point after which recovery must assume the effect ran.
            claim_raw = transport.claim(envelope, reservation_id=reservation_id)
            claim = _claim(
                claim_raw, envelope, self.binding, self.verifier, reservation_id=reservation_id
            )
            if fenced and command["action"] != "cleanup" and claim["permission"] != "revoked":
                raise RuntimeError("local cleanup fence rejects later effect")
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                changed = connection.execute(
                    "UPDATE commands SET claim=? WHERE command_id=? AND operation_key=? "
                    "AND action=? AND envelope=? AND reservation_id=? AND claim IS NULL AND ack IS NULL",
                    (
                        claim_raw,
                        command["command_id"],
                        command["operation_key"],
                        command["action"],
                        envelope,
                        reservation_id,
                    ),
                )
                if changed.rowcount != 1 or connection.execute(
                    "SELECT claim FROM commands WHERE command_id=?", (command["command_id"],)
                ).fetchall() != [(claim_raw,)]:
                    raise RuntimeError("local claim custody was not durably updated")
            evidence = None
            status = "revoked" if claim["permission"] == "revoked" else "ambiguous"
            if claim["permission"] == "allowed":
                try:
                    evidence = producer.execute(
                        json.loads(canonical_json(command)), json.loads(canonical_json(claim))
                    )
                    if evidence is not None and (
                        type(evidence) is not bytes or not 0 < len(evidence) <= _MAX_OBSERVATION
                    ):
                        evidence = None
                        raise ValueError("bounded producer observation required")
                    candidate = _ack(
                        envelope, claim_raw, self.binding, self.verifier, "completed", evidence
                    )
                    _checked_ack(candidate, envelope, claim_raw, self.binding, self.verifier)
                    status = "completed"
                except Exception:
                    # Retain bounded evidence, including incomplete cleanup, but
                    # never turn an exception into a completed acknowledgement.
                    status = "ambiguous"
            ack_raw = _ack(envelope, claim_raw, self.binding, self.verifier, status, evidence)
            _checked_ack(ack_raw, envelope, claim_raw, self.binding, self.verifier)
            self._save_ack(command, envelope, claim_raw, ack_raw)
            return self._deliver(transport, ack_raw)

    def _save_ack(self, command: dict, envelope: bytes, claim: bytes, raw: bytes):
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            changed = connection.execute(
                "UPDATE commands SET ack=? WHERE command_id=? AND operation_key=? "
                "AND action=? AND envelope=? AND claim=? AND ack IS NULL",
                (
                    raw,
                    command["command_id"],
                    command["operation_key"],
                    command["action"],
                    envelope,
                    claim,
                ),
            )
            if changed.rowcount != 1 or connection.execute(
                "SELECT ack FROM commands WHERE command_id=?", (command["command_id"],)
            ).fetchall() != [(raw,)]:
                raise RuntimeError("local acknowledgement custody was not durably updated")

    @staticmethod
    def _deliver(transport, raw: bytes) -> bytes:
        confirmed = transport.acknowledge(raw)
        if type(confirmed) is not bytes or confirmed != raw:
            raise RuntimeError("authenticated controller acknowledgement differs")
        return confirmed
