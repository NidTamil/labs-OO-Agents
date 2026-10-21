# SPDX-License-Identifier: Apache-2.0
"""Inert route-custody contract tests; no process or network is started."""

from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest
from nooa_cybergym.leaderboard import subset_route_custody as custody_module
from nooa_cybergym.leaderboard.subset_route_custody import (
    NodeObservation,
    OwnedJobObservation,
    PinnedRouteFile,
    ProcessCreationObservation,
    RouteLeaseObservation,
    VerifiedRouteCustody,
)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


@pytest.fixture(autouse=True)
def _synthetic_approved_pin(monkeypatch):
    monkeypatch.setattr(
        custody_module, "_APPROVED_KNOWN_HOSTS_PATH", r"D:\fixture\known_hosts", raising=False
    )
    monkeypatch.setattr(
        custody_module, "_APPROVED_KNOWN_HOSTS_SHA256", _sha(b"host key"), raising=False
    )


class FakeRouteBackend:
    def __init__(self):
        self.leases = {}
        self.nodes = {}
        self.released = set()
        self.resumed = []
        self.resume_error = None
        self.release_error = None
        self.job_observation = None
        self.lease_ids = {}
        self.lease_observations = {}
        self.creation_observation = None
        self.arm_error = None
        self.armed = {}

    def acquire(self, preparation_id: str, paths: tuple[str, ...]):
        assert preparation_id not in self.leases
        self.leases[preparation_id] = paths
        return preparation_id

    def observe(self, lease):
        return dict(self.nodes[lease])

    def observe_lease(self, lease):
        if lease in self.lease_observations:
            return self.lease_observations[lease]
        return RouteLeaseObservation(
            preparation_id=lease,
            lease_id=self.lease_ids.get(lease, f"{id(self)}:{lease}"),
            lease_open=True,
            exclusive_owner=True,
        )

    def arm_creation(self, lease):
        if self.arm_error is not None:
            raise self.arm_error
        guard = f"armed-after-hold:{id(self)}:{lease}"
        self.armed[lease] = guard
        return guard

    def observe_creation(self, lease, job):
        if self.creation_observation is not None:
            return self.creation_observation
        return ProcessCreationObservation(
            preparation_id=lease,
            lease_id=self.observe_lease(lease).lease_id,
            creation_guard_id=self.armed[lease],
            job_id=job.job_id,
            process_identity=job.process_identity,
            image_file_id=self.nodes[lease][r"D:\fixture\ssh.exe"].held_id,
            created_after_verified_hold=True,
        )

    def release(self, lease):
        self.released.add(lease)
        if self.release_error is not None:
            raise self.release_error

    def resume_assigned(self, lease, job):
        self.resumed.append((lease, job.job_id))
        if self.resume_error is not None:
            raise self.resume_error

    def observe_job(self, job):
        return self.job_observation if self.job_observation is not None else job


def _prepared(preparation_id="prep-a", backend=None):
    backend = backend or FakeRouteBackend()
    materials = {
        "transport_config": (r"D:\fixture\config.json", b"transport"),
        "ssh_executable": (r"D:\fixture\ssh.exe", b"ssh"),
        "ssh_config": (r"D:\fixture\ssh-config", b"config"),
        "tailscale_executable": (r"D:\fixture\tailscale.exe", b"tailscale"),
        "known_hosts": (r"D:\fixture\known_hosts", b"host key"),
    }
    pins = tuple(PinnedRouteFile(role, path, _sha(raw)) for role, (path, raw) in materials.items())
    root = "D:\\"
    parent = r"D:\fixture"
    observations = {
        root: NodeObservation(
            root, "directory", "volume:root", "volume:root", True, True, True, False, None
        ),
        parent: NodeObservation(
            parent, "directory", "volume:fixture", "volume:fixture", True, True, True, False, None
        ),
    }
    for index, (path, raw) in enumerate(materials.values()):
        observations[path] = NodeObservation(
            path,
            "file",
            f"volume:file-{index}",
            f"volume:file-{index}",
            True,
            True,
            True,
            False,
            raw,
        )
    backend.nodes[preparation_id] = observations
    custody = VerifiedRouteCustody(preparation_id, pins, backend)
    return custody, backend, materials


def _job(preparation_id="prep-a"):
    return OwnedJobObservation(
        preparation_id=preparation_id,
        job_id="job-1",
        process_identity="pid:created:image",
        created_suspended=True,
        assigned_before_resume=True,
        breakaway_disabled=True,
        kill_on_job_close=True,
        job_handle_open=True,
        process_terminated=False,
        enumeration_complete=False,
        members_empty=False,
        member_ids=(),
    )


def test_verified_route_stays_held_until_exact_owned_job_is_empty():
    custody, backend, _ = _prepared()
    custody.hold()
    custody.resume_assigned(_job())
    assert backend.resumed == [("prep-a", "job-1")]

    with pytest.raises(RuntimeError, match="empty owned job"):
        custody.finish(replace(_job(), process_terminated=True, enumeration_complete=True))
    assert "prep-a" not in backend.released

    custody.finish(
        replace(
            _job(),
            process_terminated=True,
            enumeration_complete=True,
            members_empty=True,
        )
    )
    assert "prep-a" in backend.released
    with pytest.raises(RuntimeError):
        custody.resume_assigned(_job())


def test_ambiguous_resume_retains_handles_and_cannot_resume_again():
    custody, backend, _ = _prepared()
    custody.hold()
    backend.resume_error = OSError("lost release acknowledgement")

    with pytest.raises(OSError):
        custody.resume_assigned(_job())
    assert "prep-a" not in backend.released
    with pytest.raises(RuntimeError):
        custody.resume_assigned(_job())
    assert backend.resumed == [("prep-a", "job-1")]


def test_modified_held_bytes_block_resume_without_unlocking():
    custody, backend, materials = _prepared()
    custody.hold()
    path = materials["known_hosts"][0]
    backend.nodes["prep-a"][path] = replace(backend.nodes["prep-a"][path], raw=b"other host key")

    with pytest.raises(RuntimeError, match="bytes changed"):
        custody.resume_assigned(_job())
    assert backend.resumed == []
    assert backend.released == set()


def test_path_swap_with_identical_bytes_blocks_resume():
    custody, backend, materials = _prepared()
    custody.hold()
    path = materials["ssh_config"][0]
    backend.nodes["prep-a"][path] = replace(
        backend.nodes["prep-a"][path], path_id="volume:replacement"
    )

    with pytest.raises(RuntimeError, match="identity changed"):
        custody.resume_assigned(_job())
    assert backend.resumed == []
    assert backend.released == set()


def test_replaced_file_cannot_replace_both_held_and_path_identity():
    custody, backend, materials = _prepared()
    custody.hold()
    path = materials["ssh_config"][0]
    backend.nodes["prep-a"][path] = replace(
        backend.nodes["prep-a"][path],
        held_id="volume:replacement",
        path_id="volume:replacement",
    )

    with pytest.raises(RuntimeError, match="identity changed"):
        custody.resume_assigned(_job())
    assert backend.resumed == []
    assert backend.released == set()


@pytest.mark.parametrize(
    "path,field,value",
    [(r"D:\fixture", "lock_open", False), (r"D:\fixture\known_hosts", "blocks_delete", False)],
)
def test_lost_ancestor_or_file_lock_blocks_resume(path, field, value):
    custody, backend, _ = _prepared()
    custody.hold()
    backend.nodes["prep-a"][path] = replace(backend.nodes["prep-a"][path], **{field: value})

    with pytest.raises(RuntimeError, match="identity changed"):
        custody.resume_assigned(_job())
    assert backend.resumed == []
    assert backend.released == set()


@pytest.mark.parametrize(
    "change",
    [
        {"assigned_before_resume": False},
        {"created_suspended": False},
        {"job_handle_open": False},
        {"preparation_id": "other-prep"},
    ],
)
def test_assignment_or_preparation_failure_never_resumes(change):
    custody, backend, _ = _prepared()
    custody.hold()

    with pytest.raises(RuntimeError, match="suspended and assigned"):
        custody.resume_assigned(replace(_job(), **change))
    assert backend.resumed == []
    assert backend.released == set()


@pytest.mark.parametrize("change", [{"breakaway_disabled": False}, {"kill_on_job_close": False}])
def test_permissive_job_policy_cannot_release_child(change):
    custody, backend, _ = _prepared()
    custody.hold()

    with pytest.raises(RuntimeError, match="suspended and assigned"):
        custody.resume_assigned(replace(_job(), **change))
    assert backend.resumed == []
    assert backend.released == set()


def test_caller_supplied_assignment_cannot_override_backend_observation():
    custody, backend, _ = _prepared()
    custody.hold()
    backend.job_observation = replace(_job(), assigned_before_resume=False)

    with pytest.raises(RuntimeError, match="suspended and assigned"):
        custody.resume_assigned(_job())
    assert backend.resumed == []
    assert backend.released == set()


def test_terminal_cannot_change_original_assignment_proof():
    custody, backend, _ = _prepared()
    custody.hold()
    custody.resume_assigned(_job())
    terminal = replace(
        _job(),
        assigned_before_resume=False,
        process_terminated=True,
        enumeration_complete=True,
        members_empty=True,
    )

    with pytest.raises(RuntimeError, match="exact empty owned job"):
        custody.finish(terminal)
    assert backend.released == set()


def test_terminal_cannot_disclaim_no_breakaway_policy():
    custody, backend, _ = _prepared()
    custody.hold()
    custody.resume_assigned(_job())

    with pytest.raises(RuntimeError, match="exact empty owned job"):
        custody.finish(
            replace(
                _job(),
                breakaway_disabled=False,
                process_terminated=True,
                enumeration_complete=True,
                members_empty=True,
            )
        )
    assert backend.released == set()


def test_claimed_empty_job_with_surviving_member_cannot_unlock_route():
    custody, backend, _ = _prepared()
    custody.hold()
    custody.resume_assigned(_job())

    with pytest.raises(RuntimeError, match="exact empty owned job"):
        custody.finish(
            replace(
                _job(),
                process_terminated=True,
                enumeration_complete=True,
                members_empty=True,
                member_ids=("tailscale-proxy:created:image",),
            )
        )
    assert backend.released == set()


def test_other_preparation_route_handles_remain_owned():
    backend = FakeRouteBackend()
    first, _, _ = _prepared("prep-a", backend)
    second, _, _ = _prepared("prep-b", backend)
    first.hold()
    second.hold()
    first.resume_assigned(_job())
    first.finish(
        replace(_job(), process_terminated=True, enumeration_complete=True, members_empty=True)
    )

    assert backend.released == {"prep-a"}
    second.resume_assigned(_job("prep-b"))
    assert backend.resumed[-1] == ("prep-b", "job-1")


def test_two_preparations_cannot_share_a_backend_lease_identity():
    backend = FakeRouteBackend()
    backend.lease_ids = {"prep-a": "same-held-route", "prep-b": "same-held-route"}
    first, _, _ = _prepared("prep-a", backend)
    second, _, _ = _prepared("prep-b", backend)
    first.hold()

    with pytest.raises(RuntimeError, match="already owned"):
        second.hold()
    with pytest.raises(RuntimeError, match="held route custody"):
        second.resume_assigned(_job("prep-b"))
    assert backend.released == set()
    first.resume_assigned(_job())
    assert backend.resumed == [("prep-a", "job-1")]


def test_lease_observation_must_prove_exclusive_ownership():
    custody, backend, _ = _prepared()
    backend.lease_observations["prep-a"] = RouteLeaseObservation(
        preparation_id="prep-a",
        lease_id="unowned",
        lease_open=True,
        exclusive_owner=False,
    )

    with pytest.raises(RuntimeError, match="exclusive preparation"):
        custody.hold()
    with pytest.raises(RuntimeError, match="held route custody"):
        custody.resume_assigned(_job())
    assert backend.resumed == []


def test_pre_hold_created_process_cannot_resume_under_later_route_hold():
    custody, backend, _ = _prepared()
    custody.hold()
    backend.creation_observation = replace(
        backend.observe_creation("prep-a", _job()), created_after_verified_hold=False
    )

    with pytest.raises(RuntimeError, match="verified held route"):
        custody.resume_assigned(_job())
    assert backend.resumed == []


@pytest.mark.parametrize(
    "change",
    [
        {"lease_id": "another-lease"},
        {"creation_guard_id": "pre-hold-create"},
        {"image_file_id": "volume:another-image"},
    ],
)
def test_creation_must_join_original_hold_guard_and_ssh_image(change):
    custody, backend, _ = _prepared()
    custody.hold()
    backend.creation_observation = replace(backend.observe_creation("prep-a", _job()), **change)

    with pytest.raises(RuntimeError, match="verified held route"):
        custody.resume_assigned(_job())
    assert backend.resumed == []


def test_ambiguous_creation_arm_cannot_resume_or_arm_again():
    custody, backend, _ = _prepared()
    backend.arm_error = OSError("lost creation-arm acknowledgement")

    with pytest.raises(OSError, match="creation-arm"):
        custody.hold()
    with pytest.raises(RuntimeError, match="held route custody"):
        custody.resume_assigned(_job())
    with pytest.raises(RuntimeError, match="cannot be acquired again"):
        custody.hold()
    assert backend.resumed == []


def test_ambiguous_release_cannot_be_repeated():
    custody, backend, _ = _prepared()
    custody.hold()
    custody.resume_assigned(_job())
    backend.release_error = OSError("lost release acknowledgement")
    terminal = replace(
        _job(), process_terminated=True, enumeration_complete=True, members_empty=True
    )

    with pytest.raises(OSError, match="lost release"):
        custody.finish(terminal)
    with pytest.raises(RuntimeError, match="not running"):
        custody.finish(terminal)
    assert backend.released == {"prep-a"}


def test_windows_alias_or_ads_route_path_is_not_accepted_as_a_pin():
    _, backend, materials = _prepared()
    pins = tuple(PinnedRouteFile(role, path, _sha(raw)) for role, (path, raw) in materials.items())
    for bad_path in (r"D:\fixture\ssh-config:alternate", r"D:\fixture\ssh-config."):
        altered = tuple(
            replace(pin, path=bad_path) if pin.role == "ssh_config" else pin for pin in pins
        )
        with pytest.raises(ValueError, match="canonical absolute path"):
            VerifiedRouteCustody("prep-a", altered, backend)


def test_identical_known_hosts_copy_or_new_digest_does_not_replace_approved_pin():
    _, backend, materials = _prepared()
    pins = tuple(PinnedRouteFile(role, path, _sha(raw)) for role, (path, raw) in materials.items())
    for copied_pin in (
        PinnedRouteFile("known_hosts", r"D:\fixture\copy", _sha(b"host key")),
        PinnedRouteFile("known_hosts", r"D:\fixture\known_hosts", _sha(b"other host key")),
    ):
        altered = tuple(copied_pin if pin.role == "known_hosts" else pin for pin in pins)
        with pytest.raises(ValueError, match="approved known-hosts"):
            VerifiedRouteCustody("prep-a", altered, backend)
