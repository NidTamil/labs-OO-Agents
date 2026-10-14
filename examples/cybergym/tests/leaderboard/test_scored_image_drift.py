"""A fresh bounded registry pass must agree with the scored image candidate."""

from __future__ import annotations

import hashlib
import json

import pytest
from nooa_cybergym.leaderboard.scored_image_drift import check_drift_batch
from nooa_cybergym.leaderboard.scored_image_registry import assemble_scored_image_manifest

from .test_scored_image_registry import IDS, _docker_observation

LOCK = hashlib.sha256(b"locked cohort").hexdigest()


def _candidate(tmp_path):
    observations = {}
    for task_id in IDS:
        repository = "n132/arvo" if task_id.startswith("arvo:") else "cybergym/oss-fuzz"
        number = task_id.split(":", 1)[1]
        for mode in ("vul", "fix"):
            ref = f"{repository}:{number}-{mode}"
            observations[ref] = _docker_observation(ref)
    raw = assemble_scored_image_manifest(task_ids=IDS, observations=observations)
    path = tmp_path / "candidate.json"
    path.write_bytes(raw)
    return path, hashlib.sha256(raw).hexdigest()


def test_drift_pass_fetches_only_new_refs_and_rechecks_existing_evidence(tmp_path):
    candidate, digest = _candidate(tmp_path)
    output = tmp_path / "drift"
    fetched = []

    def fetch(ref):
        fetched.append(ref)
        return _docker_observation(ref)

    args = (IDS, LOCK, candidate, digest, output)
    assert check_drift_batch(*args, limit=2, fetch=fetch) == 2
    assert fetched == ["n132/arvo:0-vul", "n132/arvo:0-fix"]
    assert check_drift_batch(*args, limit=1, fetch=fetch) == 1
    assert fetched[-1] == "n132/arvo:1-vul"
    assert check_drift_batch(*args, limit=0, fetch=fetch) == 0
    assert len(fetched) == 3
    assert json.loads((output / "drift.identity.json").read_bytes()) == {
        "candidate_sha256": digest,
        "cohort_sha256": LOCK,
    }
    (output / "n132-arvo-0-vul.json").write_bytes(b"{}")
    with pytest.raises(ValueError, match="observation|manifest"):
        check_drift_batch(*args, limit=1, fetch=fetch)
    assert len(fetched) == 3


def test_drift_pass_stops_before_checkpointing_changed_tag(tmp_path):
    candidate, _ = _candidate(tmp_path)
    value = json.loads(candidate.read_bytes())
    value["images"][0]["vulnerable"] = "sha256:" + "0" * 64
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    candidate.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    output = tmp_path / "drift"

    with pytest.raises(ValueError, match="drift"):
        check_drift_batch(IDS, LOCK, candidate, digest, output, limit=15, fetch=_docker_observation)
    assert not (output / "n132-arvo-0-vul.json").exists()
