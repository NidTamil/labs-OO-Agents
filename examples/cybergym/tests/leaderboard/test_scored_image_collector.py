"""The scored image metadata collector must resume without replacing evidence."""

from __future__ import annotations

import hashlib
import json
import subprocess

import pytest
from nooa_cybergym.leaderboard.scored_image_collector import collect_batch, fetch_docker_manifest

from .test_scored_image_registry import _docker_observation

IDS = tuple(f"arvo:{i}" for i in range(1506)) + ("oss-fuzz:999999",)
LOCK = hashlib.sha256(b"locked cohort").hexdigest()


def test_collector_resumes_exact_observations_without_refetch(tmp_path):
    fetched = []

    def fetch(ref):
        fetched.append(ref)
        return _docker_observation(ref)

    assert collect_batch(IDS, LOCK, tmp_path, limit=2, fetch=fetch) == 2
    assert fetched == ["n132/arvo:0-vul", "n132/arvo:0-fix"]
    assert collect_batch(IDS, LOCK, tmp_path, limit=1, fetch=fetch) == 1
    assert fetched[-1] == "n132/arvo:1-vul"
    assert collect_batch(IDS, LOCK, tmp_path, limit=0, fetch=fetch) == 0
    assert len(fetched) == 3
    assert json.loads((tmp_path / "cohort.sha256.json").read_bytes()) == {"cohort_sha256": LOCK}


def test_collector_rejects_changed_lock_and_tampered_checkpoint(tmp_path):
    fetch = _docker_observation
    collect_batch(IDS, LOCK, tmp_path, limit=1, fetch=fetch)
    with pytest.raises(ValueError, match="cohort"):
        collect_batch(IDS, hashlib.sha256(b"other").hexdigest(), tmp_path, limit=1, fetch=fetch)
    (tmp_path / "n132-arvo-0-vul.json").write_bytes(b"{}")
    with pytest.raises(ValueError, match="observation|manifest"):
        collect_batch(IDS, LOCK, tmp_path, limit=1, fetch=fetch)


@pytest.mark.parametrize(
    ("stderr", "category"),
    [
        (b"429 Too Many Requests token=private", "rate_limit"),
        (b"unauthorized token=private", "auth"),
        (b"manifest unknown token=private", "not_found"),
        (b"unexpected n132/arvo:429-vul token=private", "unknown"),
        (b"unexpected token=private", "unknown"),
    ],
)
def test_fetch_failure_reports_safe_category_without_captured_bytes(monkeypatch, stderr, category):
    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args[0], 1, b'manifest 429 token=private', stderr)

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match=f"category={category}") as error:
        fetch_docker_manifest("n132/arvo:1-vul")
    assert "token=private" not in str(error.value)
    assert "stdout_bytes=26" in str(error.value)
    assert f"stderr_bytes={len(stderr)}" in str(error.value)


def test_fetch_success_does_not_classify_manifest_text_as_rate_limit(monkeypatch):
    manifest = b'manifest 429 token=private'

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(args[0], 0, manifest, b"")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert fetch_docker_manifest("n132/arvo:1-vul") == manifest
