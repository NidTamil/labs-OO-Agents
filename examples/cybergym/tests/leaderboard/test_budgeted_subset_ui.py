# SPDX-License-Identifier: Apache-2.0
"""Synthetic Windows observations exercise real signatures and durable custody."""

import base64
import hashlib
import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nooa_cybergym.leaderboard.budgeted_subset_ui import (
    SubsetUiBinding,
    SubsetUiCustody,
    SubsetUiLaunch,
    SubsetUiMailbox,
)
from xeus_cybergym.canonical import canonical_json
from xeus_cybergym.ledger import Ed25519Signer, Ed25519Verifier, SignedEnvelope


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return base64.b64encode(canonical_json(value)).decode("ascii")


@pytest.fixture
def setup(tmp_path):
    key = Ed25519PrivateKey.generate()
    signer = Ed25519Signer(private_key=key, key_id="synthetic-runtime")
    verifier = Ed25519Verifier({"synthetic-runtime": key.public_key()})
    binding = SubsetUiBinding(
        run_id="run-1",
        task_id="arvo:10400",
        preparation_id="prep-1",
        preparation_started_event_sha256="a" * 64,
        budget_sha256="b" * 64,
        remote_host="cybergym-task-1",
        port=32100,
        profile_directory=r"C:\Synthetic\prep-1\user-data",
        tunnel_config_path=r"C:\Synthetic\prep-1\ssh.config",
        tunnel_config_sha256="c" * 64,
        producer_sha256="d" * 64,
        code_executable=r"C:\Synthetic\Code.exe",
        code_sha256="e" * 64,
        ssh_executable=r"C:\Synthetic\ssh.exe",
        ssh_sha256="f" * 64,
    )
    controller = tmp_path / "controller"
    client = tmp_path / "client"
    controller.mkdir()
    client.mkdir()
    box = SubsetUiMailbox(controller, binding=binding, signer=signer, verifier=verifier)
    custody = SubsetUiCustody(client, binding=binding, verifier=verifier)
    return box, custody, binding, signer, verifier


def launch():
    return SubsetUiLaunch(
        request_id="launch-1",
        attempt_id="attempt-1",
        launch_sha256="1" * 64,
        started_event_sha256="2" * 64,
        receipt=canonical_json(
            {
                "event": "launch_reserved",
                "launch_id": "launch-1",
                "session_id": None,
                "prompt_sha256": "3" * 64,
            }
        ),
    )


class Observations:
    """An inert producer double; it never opens a window or kills a process."""

    def __init__(self, binding):
        self.binding = binding
        self.actions = []
        self.owner = None
        self.mutate = lambda value: None

    def execute(self, command, claim):
        self.actions.append(command["action"])
        if command["action"] == "open":
            self.owner = {
                "binding_sha256": self.binding.sha256,
                "open_command_sha256": sha(canonical_json(command)),
                "ownership_claim_sha256": claim["claim_sha256"],
                "processes": [],
            }
            return None
        if command["action"] == "submit":
            return canonical_json(
                {
                    "schema_version": 1,
                    "event": "ui_send_attempted",
                    "launch_id": "launch-1",
                    "prompt_sha256": "3" * 64,
                    "observed_prompt_sha256": "3" * 64,
                    "remote_alias": self.binding.remote_host,
                    "provider_request_observed": False,
                }
            )
        processes = [] if self.owner is None else self.owner["processes"]
        value = {
            "schema_version": 1,
            "artifact_kind": "subset_owned_ui_cleanup",
            "binding_sha256": self.binding.sha256,
            "command_sha256": sha(canonical_json(command)),
            "claim_sha256": claim["claim_sha256"],
            "ownership_claim_sha256": claim["ownership_claim_sha256"],
            "producer_sha256": self.binding.producer_sha256,
            "observed_start_ns": 10,
            "observed_end_ns": 20,
            "enumeration_complete": True,
            "manifest_before_base64": encoded(
                {"schema_version": 2, "owners": [] if self.owner is None else [self.owner]}
            ),
            "manifest_after_base64": encoded({"schema_version": 2, "owners": []}),
            "processes_before": processes,
            "processes_after": [],
            "dispositions": [
                {"process_sha256": sha(canonical_json(p)), "outcome": "terminated"}
                for p in processes
            ],
            "errors": [],
        }
        self.mutate(value)
        return canonical_json(value)


def opened(setup):
    box, custody, binding, *_ = setup
    producer = Observations(binding)
    command = box.publish(action="open", operation_key="open")
    ack = custody.execute(command, transport=box, producer=producer)
    assert json.loads(ack)["status"] == "completed"
    return producer, command


def test_signed_open_binding_is_durable_and_replay_never_reopens(setup):
    box, custody, binding, signer, verifier = setup
    producer, command = opened(setup)
    assert box.publish(action="open", operation_key="open") == command
    fresh = SubsetUiCustody(custody.root, binding=binding, verifier=verifier)
    fresh.execute(command, transport=box, producer=producer)
    assert producer.actions == ["open"]
    reopened = SubsetUiMailbox(box.root, binding=binding, signer=signer, verifier=verifier)
    assert reopened.publish(action="open", operation_key="open") == command
    with pytest.raises((ValueError, RuntimeError)):
        SubsetUiCustody(
            custody.root, binding=replace(binding, preparation_id="other"), verifier=verifier
        )


def test_fence_revokes_already_queued_submit_and_survives_restart(setup):
    box, custody, binding, signer, verifier = setup
    producer, _ = opened(setup)
    submit = box.publish(action="submit", operation_key="submit", launch=launch())
    cleanup = box.publish(action="cleanup", operation_key="cleanup", launch=launch())
    reopened = SubsetUiMailbox(box.root, binding=binding, signer=signer, verifier=verifier)
    ack = custody.execute(submit, transport=reopened, producer=producer)
    assert json.loads(ack)["status"] == "revoked"
    assert producer.actions == ["open"]
    custody.execute(cleanup, transport=reopened, producer=producer)
    proof = reopened.verified_cleanup(cleanup)
    assert proof.observation_sha256 == sha(proof.observation)
    assert json.loads(proof.observation)["ownership_claim_sha256"] is not None
    with pytest.raises(RuntimeError):
        reopened.publish(action="submit", operation_key="second", launch=launch())


def test_cleanup_waits_for_previously_claimed_effect_and_does_not_invent_ack(setup):
    box, custody, binding, *_ = setup
    opened_command = box.publish(action="open", operation_key="open")
    box.claim(opened_command, reservation_id="0" * 32)
    cleanup = box.publish(action="cleanup", operation_key="cleanup")
    with pytest.raises(RuntimeError, match="unsettled"):
        custody.execute(cleanup, transport=box, producer=Observations(binding))
    with pytest.raises(RuntimeError):
        box.verified_cleanup(cleanup)


def test_cleanup_can_fence_open_before_any_process_is_created(setup):
    box, custody, binding, *_ = setup
    open_command = box.publish(action="open", operation_key="open")
    cleanup = box.publish(action="cleanup", operation_key="cleanup")
    producer = Observations(binding)
    assert (
        json.loads(custody.execute(open_command, transport=box, producer=producer))["status"]
        == "revoked"
    )
    custody.execute(cleanup, transport=box, producer=producer)
    assert box.verified_cleanup(cleanup).observation
    assert producer.actions == ["cleanup"]


def test_crash_after_local_reservation_never_reexecutes(setup):
    box, custody, binding, *_ = setup
    command = box.publish(action="open", operation_key="open")

    class Crash:
        def execute(self, command, claim):
            raise KeyboardInterrupt("synthetic process death")

    with pytest.raises(KeyboardInterrupt):
        custody.execute(command, transport=box, producer=Crash())
    producer = Observations(binding)
    ack = custody.execute(command, transport=box, producer=producer)
    assert json.loads(ack)["status"] == "ambiguous"
    assert producer.actions == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("binding_sha256", "0" * 64),
        ("claim_sha256", "0" * 64),
        ("command_sha256", "0" * 64),
        ("producer_sha256", "0" * 64),
        ("ownership_claim_sha256", None),
        ("enumeration_complete", False),
        ("errors", ["enumeration failed"]),
        ("observed_end_ns", 9),
        ("manifest_before_base64", encoded({"schema_version": 2, "owners": []})),
    ],
)
def test_incomplete_or_substituted_cleanup_never_becomes_quiescence(setup, field, value):
    box, custody, *_ = setup
    producer, _ = opened(setup)
    producer.mutate = lambda observation: observation.__setitem__(field, value)
    command = box.publish(action="cleanup", operation_key="cleanup")
    ack = custody.execute(command, transport=box, producer=producer)
    assert json.loads(ack)["status"] == "ambiguous"
    with pytest.raises(RuntimeError):
        box.verified_cleanup(command)


def process(binding):
    return {
        "kind": "window",
        "pid": 777,
        "creation_time_ns": 123,
        "executable_path": binding.code_executable,
        "executable_sha256": binding.code_sha256,
        "command_line": f'Code.exe --user-data-dir "{binding.profile_directory}"',
        "profile_directory": binding.profile_directory,
        "tunnel_config_sha256": binding.tunnel_config_sha256,
        "run_id": binding.run_id,
        "task_id": binding.task_id,
        "preparation_id": binding.preparation_id,
    }


@pytest.mark.parametrize(
    "failure", [None, "alive", "pid_reused", "missing_disposition", "unrelated"]
)
def test_cleanup_requires_complete_exact_owned_process_accounting(setup, failure):
    box, custody, binding, *_ = setup
    producer, _ = opened(setup)
    producer.owner["processes"] = [process(binding)]

    def mutate(value):
        if failure == "alive":
            value["processes_after"] = [process(binding)]
        elif failure == "pid_reused":
            value["processes_before"][0]["creation_time_ns"] = 999
        elif failure == "missing_disposition":
            value["dispositions"] = []
        elif failure == "unrelated":
            value["processes_before"][0]["preparation_id"] = "other"

    producer.mutate = mutate
    command = box.publish(action="cleanup", operation_key="cleanup")
    ack = json.loads(custody.execute(command, transport=box, producer=producer))
    assert ack["status"] == ("completed" if failure is None else "ambiguous")
    if failure is None:
        assert box.verified_cleanup(command).observation
    else:
        with pytest.raises(RuntimeError):
            box.verified_cleanup(command)


def test_unsigned_command_and_foreign_claim_cannot_execute(setup):
    box, custody, binding, signer, verifier = setup
    producer = Observations(binding)
    command = box.publish(action="open", operation_key="open")
    payload = json.loads(verifier.verify(SignedEnvelope.model_validate_json(command)))
    payload["binding"]["preparation_id"] = "other"
    changed = canonical_json(signer.sign(canonical_json(payload)).model_dump())
    with pytest.raises((ValueError, RuntimeError)):
        custody.execute(changed, transport=box, producer=producer)
    assert producer.actions == []


def test_submit_is_one_shot_and_cleanup_keeps_full_started_identity(setup):
    box, custody, *_ = setup
    producer, _ = opened(setup)
    submit = box.publish(action="submit", operation_key="submit", launch=launch())
    assert (
        json.loads(custody.execute(submit, transport=box, producer=producer))["status"]
        == "completed"
    )
    custody.execute(submit, transport=box, producer=producer)
    cleanup = box.publish(action="cleanup", operation_key="cleanup", launch=launch())
    custody.execute(cleanup, transport=box, producer=producer)
    proof = box.verified_cleanup(cleanup)
    assert json.loads(proof.command_payload)["launch"]["attempt_id"] == "attempt-1"
    assert producer.actions == ["open", "submit", "cleanup"]


def test_settled_controller_claim_cannot_reexecute_with_missing_client_history(setup, tmp_path):
    box, _, binding, _, verifier = setup
    producer, command = opened(setup)
    empty = tmp_path / "lost-client-history"
    empty.mkdir()
    fresh = SubsetUiCustody(empty, binding=binding, verifier=verifier)
    with pytest.raises(RuntimeError, match="settled"):
        fresh.execute(command, transport=box, producer=producer)
    assert producer.actions == ["open"]


def test_ambiguous_controller_claim_cannot_move_to_a_new_local_reservation(setup, tmp_path):
    box, custody, binding, _, verifier = setup
    command = box.publish(action="open", operation_key="open")

    class Crash:
        def execute(self, command, claim):
            raise KeyboardInterrupt("possibly opened a window")

    with pytest.raises(KeyboardInterrupt):
        custody.execute(command, transport=box, producer=Crash())
    empty = tmp_path / "different-client-history"
    empty.mkdir()
    fresh = SubsetUiCustody(empty, binding=binding, verifier=verifier)
    producer = Observations(binding)
    with pytest.raises(RuntimeError, match="reservation"):
        fresh.execute(command, transport=box, producer=producer)
    assert producer.actions == []


def test_missing_database_is_not_reinitialized_as_a_new_preparation(setup):
    _, custody, binding, _, verifier = setup
    custody.database.unlink()
    with pytest.raises(RuntimeError, match="missing"):
        SubsetUiCustody(custody.root, binding=binding, verifier=verifier)


def test_lost_transport_ack_replays_only_the_durable_ack(setup):
    box, custody, _, _, _ = setup
    producer, _ = opened(setup)
    command = box.publish(action="submit", operation_key="submit", launch=launch())

    class DropAcknowledgement:
        def claim(self, envelope, *, reservation_id):
            return box.claim(envelope, reservation_id=reservation_id)

        def acknowledge(self, raw):
            box.acknowledge(raw)
            raise ConnectionError("synthetic lost reply")

    with pytest.raises(ConnectionError):
        custody.execute(command, transport=DropAcknowledgement(), producer=producer)
    ack = custody.execute(command, transport=box, producer=producer)
    assert json.loads(ack)["status"] == "completed"
    assert producer.actions == ["open", "submit"]


@pytest.mark.parametrize("fence_before_retry", [False, True])
def test_lost_claim_reply_reuses_only_the_original_reservation(setup, fence_before_retry):
    box, custody, binding, *_ = setup
    command = box.publish(action="open", operation_key="open")
    producer = Observations(binding)

    class DropClaim:
        def claim(self, envelope, *, reservation_id):
            box.claim(envelope, reservation_id=reservation_id)
            raise ConnectionError("synthetic lost claim reply")

    with pytest.raises(ConnectionError):
        custody.execute(command, transport=DropClaim(), producer=producer)
    assert producer.actions == []
    if fence_before_retry:
        cleanup = box.publish(action="cleanup", operation_key="cleanup")
    ack = json.loads(custody.execute(command, transport=box, producer=producer))
    assert ack["status"] == ("revoked" if fence_before_retry else "completed")
    if fence_before_retry:
        custody.execute(cleanup, transport=box, producer=producer)
        assert box.verified_cleanup(cleanup).observation
        assert producer.actions == ["cleanup"]
    else:
        assert producer.actions == ["open"]


def test_signed_claim_for_a_different_command_is_rejected_before_effect(setup):
    box, custody, binding, signer, verifier = setup
    command = box.publish(action="open", operation_key="open")
    original = box.claim(command, reservation_id="0" * 32)
    value = json.loads(verifier.verify(SignedEnvelope.model_validate_json(original)))
    value["command_envelope_sha256"] = "0" * 64
    foreign = canonical_json(signer.sign(canonical_json(value)).model_dump())

    class ForeignClaim:
        def claim(self, envelope, *, reservation_id):
            return foreign

    producer = Observations(binding)
    with pytest.raises(ValueError, match="claim"):
        custody.execute(command, transport=ForeignClaim(), producer=producer)
    assert producer.actions == []


@pytest.mark.parametrize("remove_unrelated", [False, True])
def test_cleanup_preserves_unrelated_manifest_ownership(setup, remove_unrelated):
    box, custody, *_ = setup
    producer, _ = opened(setup)
    unrelated = {
        "binding_sha256": "4" * 64,
        "open_command_sha256": "5" * 64,
        "ownership_claim_sha256": "6" * 64,
        "processes": [],
    }

    def mutate(value):
        before = json.loads(base64.b64decode(value["manifest_before_base64"]))
        before["owners"].append(unrelated)
        value["manifest_before_base64"] = encoded(before)
        value["manifest_after_base64"] = encoded(
            {"schema_version": 2, "owners": [] if remove_unrelated else [unrelated]}
        )

    producer.mutate = mutate
    command = box.publish(action="cleanup", operation_key="cleanup")
    ack = json.loads(custody.execute(command, transport=box, producer=producer))
    assert ack["status"] == ("ambiguous" if remove_unrelated else "completed")


def test_arbitrary_cleanup_json_without_durable_ack_is_not_proof(setup):
    box, _, _, *_ = setup
    command = box.publish(action="cleanup", operation_key="cleanup")
    with pytest.raises(RuntimeError, match="acknowledgement"):
        box.verified_cleanup(command)
    with pytest.raises((ValueError, RuntimeError)):
        box.acknowledge(
            canonical_json({"action": "cleanup", "status": "completed", "claim_sha256": "0" * 64})
        )


def test_untrusted_signature_cannot_execute(setup):
    box, custody, binding, _, verifier = setup
    command = box.publish(action="open", operation_key="open")
    payload = verifier.verify(SignedEnvelope.model_validate_json(command))
    attacker = Ed25519Signer(private_key=Ed25519PrivateKey.generate(), key_id="unknown")
    signed = canonical_json(attacker.sign(payload).model_dump())
    producer = Observations(binding)
    with pytest.raises(ValueError, match="signature verification"):
        custody.execute(signed, transport=box, producer=producer)
    assert producer.actions == []


def test_concurrent_clients_cannot_execute_the_same_reservation_twice(setup):
    box, custody, binding, _, verifier = setup
    command = box.publish(action="open", operation_key="open")
    entered = threading.Event()
    release = threading.Event()
    second_started = threading.Event()

    class BlockingProducer(Observations):
        def execute(self, command, claim):
            entered.set()
            assert release.wait(5)
            return super().execute(command, claim)

    producer = BlockingProducer(binding)
    other = SubsetUiCustody(custody.root, binding=binding, verifier=verifier)

    def second():
        second_started.set()
        return other.execute(command, transport=box, producer=producer)

    with ThreadPoolExecutor(max_workers=2) as workers:
        first = workers.submit(custody.execute, command, transport=box, producer=producer)
        assert entered.wait(5)
        duplicate = workers.submit(second)
        assert second_started.wait(5)
        release.set()
        assert first.result(5) == duplicate.result(5)
    assert producer.actions == ["open"]


def test_polling_is_read_only_and_fenced_queue_drains_without_send(setup):
    box, custody, binding, *_ = setup
    opening = box.publish(action="open", operation_key="open")
    cleanup = box.publish(action="cleanup", operation_key="cleanup")
    assert box.pending() == opening
    assert box.pending() == opening
    producer = Observations(binding)
    custody.execute(box.pending(), transport=box, producer=producer)
    assert box.pending() == cleanup
    custody.execute(box.pending(), transport=box, producer=producer)
    assert box.pending() is None
    assert producer.actions == ["cleanup"]


@pytest.mark.parametrize("field", ["command_id", "operation_key"])
def test_local_command_index_corruption_blocks_effect_before_claim(setup, field):
    box, custody, *_ = setup
    producer, _ = opened(setup)
    command = box.publish(action="submit", operation_key="submit", launch=launch())

    class Offline:
        def claim(self, envelope, *, reservation_id):
            raise ConnectionError("synthetic unavailable transport")

    with pytest.raises(ConnectionError):
        custody.execute(command, transport=Offline(), producer=producer)
    with sqlite3.connect(custody.database) as connection:
        trigger = connection.execute(
            "SELECT sql FROM sqlite_master WHERE name='commands_update'"
        ).fetchone()[0]
        connection.execute("DROP TRIGGER commands_update")
        connection.execute(f"UPDATE commands SET {field}='corrupted' WHERE action='submit'")
        connection.execute(trigger)
        assert connection.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
    with pytest.raises(RuntimeError, match="indices"):
        custody.execute(command, transport=box, producer=producer)
    assert producer.actions == ["open"]


@pytest.mark.parametrize("field", ["claim", "ack"])
def test_unpersisted_claim_or_ack_never_reports_success_or_repeats_effect(setup, field):
    box, custody, *_ = setup
    producer, _ = opened(setup)
    command = box.publish(action="submit", operation_key="submit", launch=launch())
    with sqlite3.connect(custody.database) as connection:
        connection.execute(
            f"CREATE TRIGGER suppress_update BEFORE UPDATE OF {field} ON commands "
            "WHEN OLD.action='submit' BEGIN SELECT RAISE(IGNORE); END"
        )
    for _ in range(2):
        with pytest.raises(RuntimeError, match="custody"):
            custody.execute(command, transport=box, producer=producer)
    assert producer.actions == (["open"] if field == "claim" else ["open", "submit"])


@pytest.mark.parametrize("field", ["claim", "revocation", "ack"])
def test_controller_does_not_release_unpersisted_permission_or_acknowledgement(setup, field):
    box, custody, binding, *_ = setup
    command = box.publish(action="open", operation_key="open")
    if field == "revocation":
        box.publish(action="cleanup", operation_key="cleanup")
    with sqlite3.connect(box.database) as connection:
        connection.execute(
            f"CREATE TRIGGER suppress_update BEFORE UPDATE OF {field} ON commands "
            "WHEN OLD.action='open' BEGIN SELECT RAISE(IGNORE); END"
        )
    producer = Observations(binding)
    for _ in range(2):
        with pytest.raises(RuntimeError, match="custody"):
            custody.execute(command, transport=box, producer=producer)
    assert producer.actions == (["open"] if field == "ack" else [])


def test_controller_does_not_return_an_unpersisted_command(setup):
    box, *_ = setup
    with sqlite3.connect(box.database) as connection:
        connection.execute(
            "CREATE TRIGGER suppress_insert BEFORE INSERT ON commands "
            "BEGIN SELECT RAISE(IGNORE); END"
        )
    with pytest.raises(RuntimeError, match="custody"):
        box.publish(action="open", operation_key="open")
