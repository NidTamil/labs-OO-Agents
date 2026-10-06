# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Only the GLM agent's declared PoC may become the immutable final."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest
from nooa_cybergym.leaderboard.finalize import ParentSelectionProof, lock_agent_final


def _attest(raw: bytes) -> ParentSelectionProof:
    declaration = json.loads(raw)
    return ParentSelectionProof(
        task_id=declaration["task_id"],
        declaration_sha256=hashlib.sha256(raw).hexdigest(),
        candidate_sha256=declaration["sha256"],
        model="glm-5.3[1m]",
        role="glm_parent",
        event_digest="a" * 64,
    )


def _declare(output: Path, *, content: bytes = b"one-final", **overrides: object) -> None:
    output.mkdir(parents=True)
    (output / "final-poc").write_bytes(content)
    record = {
        "schema_version": 1,
        "task_id": "synthetic:length-header",
        "candidate_path": "/workspace/output/final-poc",
        "sha256": hashlib.sha256(content).hexdigest(),
        "byte_length": len(content),
        "selected_at": "2026-10-05T00:00:00Z",
        "selection_reason": "stable vulnerable crash",
        "final_declaration": True,
        "selected_by": "glm_parent",
    }
    record.update(overrides)
    (output / "agent-final.json").write_text(json.dumps(record))


def test_lock_accepts_one_agent_declaration_and_refuses_second_lock(tmp_path: Path) -> None:
    output, evidence = tmp_path / "workspace" / "output", tmp_path / "evidence"
    _declare(output)
    locked = lock_agent_final(
        output, evidence, "synthetic:length-header", attest_parent_selection=_attest
    )
    assert locked.sha256 == hashlib.sha256(b"one-final").hexdigest()
    assert locked.byte_length == len(b"one-final")
    assert (evidence / "final" / "poc").read_bytes() == b"one-final"
    assert locked.declaration["selected_by"] == "glm_parent"
    assert not (evidence / "final" / "poc").stat().st_mode & 0o222
    with pytest.raises(FileExistsError):
        lock_agent_final(
            output, evidence, "synthetic:length-header", attest_parent_selection=_attest
        )


def test_timeout_without_agent_final_is_not_recovered(tmp_path: Path) -> None:
    output = tmp_path / "workspace" / "output"
    output.mkdir(parents=True)
    (output / "candidate.poc").write_bytes(b"crash")
    with pytest.raises(RuntimeError, match="missing agent final"):
        lock_agent_final(
            output,
            tmp_path / "evidence",
            "synthetic:length-header",
            attest_parent_selection=_attest,
        )
    assert not (tmp_path / "evidence" / "final").exists()


@pytest.mark.parametrize(
    "overrides",
    [
        {"task_id": "other:1"},
        {"sha256": "0" * 64},
        {"byte_length": 99},
        {"final_declaration": False},
        {"selected_by": "deepseek"},
        {"candidate_path": "/workspace/output/../controller-secret"},
        {"selected_at": "yesterday"},
    ],
)
def test_lock_rejects_invalid_or_non_glm_declaration(
    tmp_path: Path, overrides: dict[str, object]
) -> None:
    output, evidence = tmp_path / "workspace" / "output", tmp_path / "evidence"
    _declare(output, **overrides)
    with pytest.raises((RuntimeError, ValueError)):
        lock_agent_final(
            output, evidence, "synthetic:length-header", attest_parent_selection=_attest
        )
    assert not (evidence / "final").exists()


def test_lock_rejects_symlink_candidate_and_duplicate_declaration(tmp_path: Path) -> None:
    output, evidence = tmp_path / "workspace" / "output", tmp_path / "evidence"
    _declare(output)
    (output / "final-poc").unlink()
    (output / "final-poc").symlink_to(output / "agent-final.json")
    with pytest.raises(RuntimeError, match="symlink"):
        lock_agent_final(
            output, evidence, "synthetic:length-header", attest_parent_selection=_attest
        )
    (output / "final-poc").unlink()
    (output / "final-poc").write_bytes(b"one-final")
    (output / "agent-final-2.json").write_text("{}")
    with pytest.raises(RuntimeError, match="multiple agent final"):
        lock_agent_final(
            output, evidence, "synthetic:length-header", attest_parent_selection=_attest
        )


def test_lock_requires_trusted_matching_parent_event_and_private_evidence(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    output = workspace / "output"
    _declare(output)

    def wrong_event(raw: bytes) -> ParentSelectionProof:
        proof = _attest(raw)
        return ParentSelectionProof(
            task_id=proof.task_id,
            declaration_sha256="0" * 64,
            candidate_sha256=proof.candidate_sha256,
            model=proof.model,
            role=proof.role,
            event_digest=proof.event_digest,
        )

    with pytest.raises(RuntimeError, match="attestation disagrees"):
        lock_agent_final(
            output,
            tmp_path / "evidence",
            "synthetic:length-header",
            attest_parent_selection=wrong_event,
        )
    with pytest.raises(ValueError, match="outside the agent workspace"):
        lock_agent_final(
            output,
            workspace / "evidence",
            "synthetic:length-header",
            attest_parent_selection=_attest,
        )


@pytest.mark.skipif(os.name != "posix", reason="rooted dir_fd traversal is POSIX-specific")
def test_output_ancestor_symlink_is_rejected_even_if_output_itself_is_regular(
    tmp_path: Path,
) -> None:
    external = tmp_path / "external"
    _declare(external / "output")
    workspace = tmp_path / "workspace"
    workspace.symlink_to(external, target_is_directory=True)
    evidence = tmp_path / "evidence"

    with pytest.raises(RuntimeError, match="output directory is missing or linked"):
        lock_agent_final(
            workspace / "output",
            evidence,
            "synthetic:length-header",
            attest_parent_selection=_attest,
        )
    assert not (evidence / "final").exists()


@pytest.mark.skipif(os.name != "posix", reason="rooted dir_fd traversal is POSIX-specific")
def test_ancestor_symlink_swap_during_attestation_cannot_import_external_file(
    tmp_path: Path,
) -> None:
    output, evidence = tmp_path / "workspace" / "output", tmp_path / "evidence"
    private = tmp_path / "controller-private"
    private.mkdir()
    secret = b"synthetic-controller-private-content"
    (private / "poc").write_bytes(secret)
    _declare(
        output,
        content=b"safe",
        candidate_path="/workspace/output/nested/poc",
        sha256=hashlib.sha256(secret).hexdigest(),
        byte_length=len(secret),
    )
    nested = output / "nested"
    nested.mkdir()
    (nested / "poc").write_bytes(b"safe")

    def swap_ancestor(raw: bytes) -> ParentSelectionProof:
        nested.rename(output / "nested-original")
        nested.symlink_to(private, target_is_directory=True)
        return _attest(raw)

    with pytest.raises(RuntimeError):
        lock_agent_final(
            output,
            evidence,
            "synthetic:length-header",
            attest_parent_selection=swap_ancestor,
        )
    assert not (evidence / "final").exists()
