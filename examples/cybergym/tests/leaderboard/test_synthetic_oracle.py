import hashlib
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nooa_cybergym.leaderboard.finalize import FinalLock
from nooa_cybergym.leaderboard.runtime_custody import AttemptStart, RuntimeAudit
from nooa_cybergym.leaderboard.synthetic_oracle import SyntheticOracle
from xeus_cybergym.ledger import Ed25519Signer, Ed25519Verifier, SignedEnvelope


def test_actual_oracle_launch_is_private_stopped_only_and_signed(tmp_path):
    output, evidence = tmp_path / "solver-output", tmp_path / "controller-evidence"
    output.mkdir(mode=0o700)
    evidence.mkdir(mode=0o700)
    candidate = evidence / "locked.bin"
    candidate.write_bytes(b"synthetic-reproducer")
    declaration = evidence / "declaration.json"
    declaration.write_text('{"task_id":"synthetic:length-header"}')
    fixed, vulnerable = tmp_path / "fixed.c", tmp_path / "vulnerable.c"
    fixed.write_text("int main(void){return 0;}")
    vulnerable.write_text("int main(void){return 1;}")
    digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
    lock = FinalLock("synthetic:length-header", digest, candidate.stat().st_size,
                     candidate, declaration, {}, "c" * 64)
    observations = {
        "vulnerable": {"build_exit": 0, "test_exit": 1, "sanitizer": True},
        "fixed": {"build_exit": 0, "test_exit": 0, "sanitizer": False},
    }

    class Container:
        def __init__(self):
            self.started = False
            self.removed = False

        def start(self):
            self.started = True

        def wait(self, timeout):
            assert timeout <= 240
            return {"StatusCode": 0}

        def logs(self, **_):
            return json.dumps(observations).encode()

        def remove(self, **_):
            self.removed = True

    class Docker:
        def __init__(self):
            self.containers = self
            self.created = None
            self.args = None

        def create(self, *args, **kwargs):
            self.args = args, kwargs
            self.created = Container()
            return self.created

    key = Ed25519PrivateKey.generate()
    signer = Ed25519Signer(private_key=key, key_id="synthetic-signing")
    verifier = Ed25519Verifier({"synthetic-signing": key.public_key()})
    docker = Docker()
    start = AttemptStart(evidence / "start.sqlite", task_id=lock.task_id, attempt_id="attempt-a")
    with RuntimeAudit(evidence / "audit.jsonl", secrets=("synthetic-secret",), start=start) as audit:
        oracle = SyntheticOracle(docker_client=docker, image_id="sha256:" + "a" * 64,
            evidence=evidence, audit=audit, signer=signer, verifier=verifier,
            fixed_source=fixed, vulnerable_source=vulnerable, run_id="synthetic-run-a",
            task_id=lock.task_id, attempt_id="attempt-a", freeze_sha256="b" * 64)
        with pytest.raises(RuntimeError, match="stopped solver"):
            oracle.evaluate(lock, solver_stopped=lambda: False)
        assert docker.created is None
        result = oracle.evaluate(lock, solver_stopped=lambda: True)
        assert result.true is True and docker.created.removed is True
        args, kwargs = docker.args
        assert args == ("sha256:" + "a" * 64,)
        assert kwargs["network_disabled"] is True and kwargs["read_only"] is True
        assert kwargs["volumes"][str(fixed)]["mode"] == "ro"
        assert "environment" not in kwargs and "ports" not in kwargs
        raw = SignedEnvelope.model_validate_json(result.signed_evidence.read_bytes())
        payload = json.loads(verifier.verify(raw))
        assert payload["artifact_kind"] == "synthetic_oracle_evidence"
        assert payload["oracle_true"] is True
        assert payload["request"]["candidate_sha256"] == digest
        assert payload["request"]["fixed_source_sha256"] == hashlib.sha256(fixed.read_bytes()).hexdigest()
