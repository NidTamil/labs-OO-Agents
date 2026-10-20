# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Independent debit and provider-attribution checks on synthetic raw files."""

import copy
import hashlib
import json
import sqlite3
from dataclasses import asdict

import pytest
from nooa_cybergym.leaderboard.primary_takeover import PrimaryTakeoverPolicy
from nooa_cybergym.leaderboard.raw_fixture_attestor import RawEvidenceError
from xeus_cybergym.canonical import canonical_json

TASK, ATTEMPT = "synthetic:chunk-table", "attempt-one"
POLICY = PrimaryTakeoverPolicy()
BINDINGS = {"embedding-model": {"provider": "frozen-memory-provider", "kind": "embedding"}}
ROLES = ("independent_recon", "conditional_debug_recovery", "final_adversarial_critic")


def _write(root, runtime, requests, usage):
    prior = "0" * 64
    rows = []
    for sequence, event in enumerate(runtime, 1):
        row = {
            "sequence": sequence,
            "previous_sha256": prior,
            "task_id": TASK,
            "attempt_id": ATTEMPT,
            "timestamp": "2026-10-21T00:00:00+00:00",
            "event": event,
        }
        prior = hashlib.sha256(canonical_json(row)).hexdigest()
        rows.append(row | {"sha256": prior})
    for name, values in (
        ("runtime-events.jsonl", rows),
        ("model-requests.jsonl", requests),
        ("model-usage.jsonl", usage),
    ):
        (root / name).write_bytes(b"".join(canonical_json(value) + b"\n" for value in values))


def _fixture():
    runtime, requests, usage = [], [], []
    allocation_counts = {"primary_and_memory": 0, "deepseek_advisory": 0}

    def reserve(allocation, *, post=False):
        ordinal = sum(allocation_counts.values()) + 1
        allocation_counts[allocation] += 1
        row = {
            "event": "task_request_reserved",
            "task_id": TASK,
            "attempt_id": ATTEMPT,
            "request_id": f"debit-{ordinal}",
            "task_ordinal": ordinal,
            "allocation": allocation,
            "allocation_ordinal": allocation_counts[allocation],
        }
        if post:
            row.update(
                event="post_oracle_memory_model_reserved",
                request_number=ordinal,
                allocation="glm_and_memory_auxiliary",
                run_allocation=allocation,
            )
        runtime.append(row)
        return ordinal

    def primary(route, native_id, provider_attempt_id, *, failed=False, count=False):
        ordinal = reserve("primary_and_memory")
        base = {
            "task_id": TASK,
            "attempt_id": ATTEMPT,
            "request_id": native_id,
            "provider_attempt_id": provider_attempt_id,
            "provider": route.provider,
            "configured_model": route.model,
            "requested_model": route.wire_model,
            "takeover_policy_sha256": POLICY.digest,
            "allocation": "primary_and_memory",
            "role": "primary",
            "shared_request_number": ordinal,
            "upstream_endpoint": route.base_url
            + ("/v1/messages/count_tokens" if count else "/v1/messages"),
            "request_sha256": "e" * 64,
            "policy_sha256": "f" * 64,
            "capability_policy_sha256": "b" * 64,
            "official_final_selector": "primary_parent",
        }
        requests.append(base | {"event": "request_reserved"})
        row = {
            "event": "usage",
            "task_id": TASK,
            "attempt_id": ATTEMPT,
            "request_id": native_id,
            "provider_attempt_id": provider_attempt_id,
            "provider": route.provider,
            "configured_model": route.model,
            "model": route.wire_model,
            "takeover_policy_sha256": POLICY.digest,
            "allocation": "primary_and_memory",
            "shared_request_number": ordinal,
            "usage_status": "interrupted" if failed else "observed",
            "input_tokens": None if failed else 10,
            "output_tokens": None if failed or count else 3,
            "cache_read_tokens": None if failed or count else 2,
            "cache_creation_tokens": None if failed or count else 1,
            "counted_tokens": 1_000_000 if failed else 10 if count else 16,
            "reserved_tokens": 1_000_000,
            "returned_model": None if failed or count else route.wire_model,
            "provider_request_id": None if failed or count else f"provider-{ordinal}",
            "model_version": None,
            "system_fingerprint": None,
        }
        usage.append(row)
        requests.append(
            base
            | {
                "event": "request_terminal",
                "outcome": "provider_error" if failed else "completed",
                "failure_code": "provider_unavailable" if failed else None,
                "http_status": 503 if failed else 200,
                "takeover_eligible": failed,
                "response_started": not failed,
                "duration_seconds": 1.0,
                **{
                    key: row[key]
                    for key in (
                        "usage_status",
                        "counted_tokens",
                        "returned_model",
                        "provider_request_id",
                        "model_version",
                        "system_fingerprint",
                    )
                },
            }
        )

    primary(POLICY.initial, "count", "count-attempt", count=True)
    requests.append(
        {
            "event": "native_request_terminal",
            "task_id": TASK,
            "attempt_id": ATTEMPT,
            "request_id": "count",
            "takeover_policy_sha256": POLICY.digest,
            "outcome": "completed",
            "failure_code": None,
        }
    )
    primary(POLICY.initial, "native", "glm-attempt", failed=True)
    requests.append(
        {
            "schema_version": 1,
            "event": "primary_route_switched",
            "task_id": TASK,
            "attempt_id": ATTEMPT,
            "policy_sha256": POLICY.digest,
            "request_id": "native",
            "failed_provider_attempt_id": "glm-attempt",
            "fallback_provider_attempt_id": "ds-attempt",
            "failure_kind": "provider_unavailable",
            "response_started": False,
            "from_route": asdict(POLICY.initial),
            "to_route": asdict(POLICY.fallback),
        }
    )
    primary(POLICY.fallback, "native", "ds-attempt")
    requests.append(
        {
            "event": "native_request_terminal",
            "task_id": TASK,
            "attempt_id": ATTEMPT,
            "request_id": "native",
            "takeover_policy_sha256": POLICY.digest,
            "outcome": "completed",
            "failure_code": None,
        }
    )
    for role in ROLES:
        ordinal = reserve("deepseek_advisory")
        base = {
            "event": "request",
            "role": role,
            "task_id": TASK,
            "attempt_id": ATTEMPT,
            "request_id": f"advice-{ordinal}",
            "request_number": 1,
            "shared_request_number": ordinal,
            "request_sha256": "e" * 64,
            "registry_digest": "b" * 64,
            "policy_digest": "c" * 64,
            "endpoint": "https://api.deepseek.com/chat/completions",
            "requested_model": "deepseek-flash",
            "request_settings": {
                "model": "deepseek-flash",
                "thinking": {"type": "enabled"},
                "reasoning_effort": "max",
                "max_tokens": 128000,
            },
            "failure_evidence_digest": "d" * 64 if role == ROLES[1] else None,
        }
        runtime.extend(
            [
                base,
                base
                | {
                    "event": "response",
                    "returned_model": "deepseek-flash",
                    "http_status": 200,
                    "provider_request_id": f"provider-{ordinal}",
                    "model_version": None,
                    "system_fingerprint": None,
                    "duration_seconds": 2.0,
                    "usage": {
                        "input_tokens": 10,
                        "output_tokens": 3,
                        "counted_tokens": 13,
                        "cache_hit_input_tokens": 4,
                        "cache_miss_input_tokens": 6,
                        "provider_usage": {
                            "prompt_tokens": 10,
                            "completion_tokens": 3,
                            "total_tokens": 13,
                            "prompt_cache_hit_tokens": 4,
                            "prompt_cache_miss_tokens": 6,
                        },
                    },
                },
            ]
        )

    def memory(post=False):
        ordinal = reserve("primary_and_memory", post=post)
        base = {
            "request_id": f"memory-rpc-{ordinal}",
            "permit_id": f"permit-{ordinal}",
            "reservation_id": ordinal,
            "model_id": "embedding-model",
            "kind": "embedding",
            "operation": "embed",
            "started_monotonic": 1.0,
        }
        runtime.extend(
            [
                base | {"event": "memory_model_admitted"},
                base
                | {
                    "event": "memory_model_settled",
                    "duration_seconds": 0.1,
                    "usage": {
                        "inputTokens": 4,
                        "outputTokens": 0,
                        "cacheReadTokens": 0,
                        "cacheWriteTokens": 0,
                    },
                },
            ]
        )

    memory()
    runtime.append(
        {"event": "synthetic_oracle_observed", "oracle_true": True, "evidence_sha256": "a" * 64}
    )
    memory(post=True)
    runtime.append({"event": "memory_oracle_episode_written", "actor": "controller"})
    return runtime, requests, usage


def _verify(root):
    from nooa_cybergym.leaderboard.raw_request_accounting import verify_request_accounting

    return verify_request_accounting(
        root,
        task_id=TASK,
        attempt_id=ATTEMPT,
        takeover_policy=POLICY,
        registry_sha256="b" * 64,
        alternate_policy_sha256="c" * 64,
        memory_model_bindings=BINDINGS,
    )


def test_raw_accounting_counts_failed_takeover_memory_count_tokens_and_post_oracle(tmp_path):
    _write(tmp_path, *_fixture())
    observed = _verify(tmp_path)
    manifest = observed.manifest
    assert manifest["schema_version"] == 2 and manifest["reconciled"] is True
    assert manifest["allocations"] == {"primary_and_memory": 5, "deepseek_advisory": 3}
    assert manifest["totals"]["model_requests"] == 8
    assert manifest["totals"]["unknown_usage_requests"] == 1
    assert manifest["totals"]["conservative_tokens"] == 1_000_000
    assert [row["lane"] for row in manifest["requests"]] == [
        "count_tokens",
        "primary",
        "primary",
        "advisory",
        "advisory",
        "advisory",
        "memory",
        "post_oracle_memory",
    ]
    assert manifest["requests"][1]["input_tokens"] is None
    assert manifest["requests"][2]["provider"] == "deepseek-official-api"
    assert manifest["requests"][6]["provider_request_id"] is None
    assert observed.digest == hashlib.sha256(canonical_json(manifest)).hexdigest()


@pytest.mark.parametrize(
    "change",
    [
        "duplicate_debit",
        "wrong_allocation",
        "ordinal_gap",
        "duplicate_usage",
        "unmatched_usage",
        "missing_transition",
        "after_exposure",
        "wrong_provider",
        "duplicate_provider_id",
        "missing_memory_admission",
        "changed_memory_model",
        "post_before_oracle",
        "native_terminal_missing",
        "usage_conservative_erased",
        "primary_terminal_before_reserve",
    ],
)
def test_raw_accounting_rejects_unexplained_or_relabelled_dispatches(tmp_path, change):
    runtime, requests, usage = _fixture()
    if change == "duplicate_debit":
        runtime.insert(1, copy.deepcopy(runtime[0]))
    elif change == "wrong_allocation":
        runtime[0]["allocation"] = "deepseek_advisory"
    elif change == "ordinal_gap":
        runtime[0]["task_ordinal"] = 9
    elif change == "duplicate_usage":
        usage.append(copy.deepcopy(usage[0]))
    elif change == "unmatched_usage":
        usage.append(usage[0] | {"provider_attempt_id": "unmatched"})
    elif change == "missing_transition":
        requests = [row for row in requests if row["event"] != "primary_route_switched"]
    elif change == "after_exposure":
        next(
            row
            for row in requests
            if row.get("provider_attempt_id") == "glm-attempt"
            and row["event"] == "request_terminal"
        )["response_started"] = True
    elif change == "wrong_provider":
        next(row for row in requests if row.get("provider_attempt_id") == "ds-attempt")[
            "provider"
        ] = "zai-coding-plan"
    elif change == "duplicate_provider_id":
        for row in requests + usage:
            if row.get("provider_attempt_id") == "ds-attempt" and "provider_request_id" in row:
                row["provider_request_id"] = "provider-4"
    elif change == "missing_memory_admission":
        runtime = [
            row
            for row in runtime
            if not (row["event"] == "memory_model_admitted" and row["reservation_id"] == 7)
        ]
    elif change == "changed_memory_model":
        next(row for row in runtime if row["event"] == "memory_model_settled")["model_id"] = (
            "other-model"
        )
    elif change == "post_before_oracle":
        oracle = next(row for row in runtime if row["event"] == "synthetic_oracle_observed")
        runtime.remove(oracle)
        runtime.insert(len(runtime) - 1, oracle)
    elif change == "native_terminal_missing":
        requests = [
            row
            for row in requests
            if not (row["event"] == "native_request_terminal" and row["request_id"] == "native")
        ]
    elif change == "usage_conservative_erased":
        usage[1]["counted_tokens"] = 0
    elif change == "primary_terminal_before_reserve":
        requests[0], requests[1] = requests[1], requests[0]
    _write(tmp_path, runtime, requests, usage)
    with pytest.raises(RawEvidenceError):
        _verify(tmp_path)


def test_orphan_debit_is_counted_and_cannot_claim_reconciled_accounting(tmp_path):
    runtime, requests, usage = _fixture()
    runtime.append(
        {
            "event": "task_request_reserved",
            "task_id": TASK,
            "attempt_id": ATTEMPT,
            "request_id": "orphan",
            "task_ordinal": 9,
            "allocation": "primary_and_memory",
            "allocation_ordinal": 6,
        }
    )
    _write(tmp_path, runtime, requests, usage)
    manifest = _verify(tmp_path).manifest
    assert manifest["totals"]["model_requests"] == 9
    assert manifest["totals"]["unmatched_reservations"] == 1
    assert manifest["totals"]["unbounded_unknown_usage_requests"] == 1
    assert manifest["reconciled"] is False
    assert manifest["requests"][-1]["lane"] == "unmatched_reservation"


def _final_custody(root):
    from nooa_cybergym.leaderboard.finalize import _PRIMARY_IDENTITY_FIELDS, _primary_event_digest

    declaration = {
        "schema_version": 2,
        "task_id": TASK,
        "attempt_id": ATTEMPT,
        "request_id": "native",
        "session_id": "session",
        "tool_id": "select-final",
        "provider_attempt_id": "ds-attempt",
        "provider": POLICY.fallback.provider,
        "configured_model": POLICY.fallback.model,
        "provider_model": POLICY.fallback.wire_model,
        "takeover_policy_sha256": POLICY.digest,
        "selected_by": "primary_parent",
        "final_declaration": True,
        "selection_reason": "Select tested bytes.",
        "selected_at": "2026-10-21T00:00:00+00:00",
        "sha256": hashlib.sha256(b"candidate").hexdigest(),
        "byte_length": 9,
        "candidate_path": "/workspace/output/poc",
    }
    raw = json.dumps(declaration, sort_keys=True, separators=(",", ":")).encode()
    proof = {
        "schema_version": 2,
        "task_id": TASK,
        "declaration_sha256": hashlib.sha256(raw).hexdigest(),
        "candidate_sha256": declaration["sha256"],
        "model": declaration["configured_model"],
        "role": "primary_parent",
        "event_digest": _primary_event_digest(declaration),
        **{key: declaration[key] for key in _PRIMARY_IDENTITY_FIELDS - {"configured_model"}},
    }
    (root / "final").mkdir()
    (root / "final" / "agent-final.json").write_bytes(raw)
    (root / "final" / "poc").write_bytes(b"candidate")
    with sqlite3.connect(root / "native-final.sqlite") as db:
        db.executescript("""
        CREATE TABLE selection(id INTEGER PRIMARY KEY, task TEXT, attempt TEXT, declaration BLOB, proof BLOB);
        CREATE TABLE identity(id INTEGER PRIMARY KEY, value BLOB);
        CREATE TABLE declaration_state(id INTEGER PRIMARY KEY, status TEXT);
        CREATE TABLE lock_attempt(id INTEGER PRIMARY KEY, status TEXT);
        """)
        db.execute(
            "INSERT INTO selection VALUES(1,?,?,?,?)", (TASK, ATTEMPT, raw, canonical_json(proof))
        )
        db.execute("INSERT INTO declaration_state VALUES(1,'declared')")
        db.execute("INSERT INTO lock_attempt VALUES(1,'locked')")
        db.execute(
            "INSERT INTO identity VALUES(1,?)",
            (
                canonical_json(
                    {
                        "task_id": TASK,
                        "attempt_id": ATTEMPT,
                        "schema_version": 2,
                        "takeover_policy_sha256": POLICY.digest,
                        "output": "/offline/output",
                    }
                ),
            ),
        )
    args = {
        key: declaration[key]
        for key in ("candidate_path", "sha256", "byte_length", "selection_reason")
    }
    args_raw = json.dumps(args, sort_keys=True, separators=(",", ":")).encode()
    with sqlite3.connect(root / "native-tools.sqlite") as db:
        db.executescript("""
        CREATE TABLE requests(id TEXT, session TEXT, agent TEXT, role TEXT);
        CREATE TABLE identity(id INTEGER PRIMARY KEY, value BLOB);
        CREATE TABLE tools(id TEXT, request TEXT, name TEXT, input_hash TEXT, status TEXT);
        CREATE TABLE provider_bindings(sequence INTEGER PRIMARY KEY, request TEXT, provider_attempt_id TEXT, provider TEXT, configured_model TEXT, provider_model TEXT, takeover_policy_sha256 TEXT);
        CREATE TABLE streams(sequence INTEGER PRIMARY KEY, request TEXT, data BLOB);
        """)
        db.execute("INSERT INTO requests VALUES('native','session','','parent')")
        db.execute(
            "INSERT INTO identity VALUES(1,?)",
            (
                canonical_json(
                    {
                        "task_id": TASK,
                        "attempt_id": ATTEMPT,
                        "primary_takeover_sha256": POLICY.digest,
                    }
                ),
            ),
        )
        db.execute(
            "INSERT INTO tools VALUES('select-final','native','mcp__finalizer__select_final',?,'dispatched')",
            (hashlib.sha256(args_raw).hexdigest(),),
        )
        for i, route, attempt in (
            (1, POLICY.initial, "glm-attempt"),
            (2, POLICY.fallback, "ds-attempt"),
        ):
            db.execute(
                "INSERT INTO provider_bindings VALUES(?,'native',?,?,?,?,?)",
                (i, attempt, route.provider, route.model, route.wire_model, POLICY.digest),
            )
        frames = [
            {"type": "message_start", "message": {"model": "deepseek-flash", "id": "provider-3"}},
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {
                    "type": "tool_use",
                    "id": "select-final",
                    "name": "mcp__finalizer__select_final",
                    "input": args,
                },
            },
            {"type": "content_block_stop", "index": 0},
            {"type": "message_stop"},
        ]
        wire = b"".join(b"data: " + canonical_json(frame) + b"\n\n" for frame in frames)
        db.execute("INSERT INTO streams VALUES(1,'native',?)", (wire,))
    return declaration


@pytest.mark.parametrize(
    "change",
    [
        None,
        "child",
        "wrong_binding",
        "wrong_stream",
        "changed_proof",
        "unadmitted_tool",
        "wrong_task_identity",
    ],
)
def test_takeover_final_attribution_requires_actual_parent_stream_and_bound_attempt(
    tmp_path, change
):
    from nooa_cybergym.leaderboard.raw_fixture_attestor import verify_primary_final_selection

    _write(tmp_path, *_fixture())
    declaration = _final_custody(tmp_path)
    if change == "changed_proof":
        with sqlite3.connect(tmp_path / "native-final.sqlite") as db:
            proof = json.loads(db.execute("SELECT proof FROM selection").fetchone()[0])
            proof["provider_attempt_id"] = "glm-attempt"
            db.execute("UPDATE selection SET proof=?", (canonical_json(proof),))
    else:
        with sqlite3.connect(tmp_path / "native-tools.sqlite") as db:
            if change == "child":
                db.execute("UPDATE requests SET role='child',agent='child-one'")
            elif change == "wrong_binding":
                db.execute(
                    "UPDATE provider_bindings SET provider='zai-coding-plan' WHERE sequence=2"
                )
            elif change == "wrong_stream":
                wire = db.execute("SELECT data FROM streams").fetchone()[0]
                db.execute(
                    "UPDATE streams SET data=?", (wire.replace(b"deepseek-flash", b"glm-5.3"),)
                )
            elif change == "unadmitted_tool":
                db.execute("UPDATE tools SET status='observed'")
            elif change == "wrong_task_identity":
                db.execute(
                    "UPDATE identity SET value=?",
                    (
                        canonical_json(
                            {
                                "task_id": "other-task",
                                "attempt_id": ATTEMPT,
                                "primary_takeover_sha256": POLICY.digest,
                            }
                        ),
                    ),
                )

    def verify():
        return verify_primary_final_selection(
            tmp_path,
            task_id=TASK,
            attempt_id=ATTEMPT,
            takeover_policy=POLICY,
            accounting=_verify(tmp_path),
        )

    if change is None:
        assert verify() == declaration
    else:
        with pytest.raises(RawEvidenceError):
            verify()


@pytest.mark.parametrize(
    "change", ["unknown_advisory_role", "debit_after_dispatch", "response_before_dispatch"]
)
def test_runtime_model_dispatches_must_have_known_lane_and_preceding_debit(tmp_path, change):
    runtime, requests, usage = _fixture()
    advice = next(row for row in runtime if row["event"] == "request")
    if change == "unknown_advisory_role":
        runtime.append(advice | {"request_id": "hidden", "role": "unrecognized_model"})
    elif change == "debit_after_dispatch":
        debit = next(row for row in runtime if row.get("task_ordinal") == 4)
        runtime.remove(debit)
        runtime.insert(runtime.index(advice) + 1, debit)
    else:
        response = next(row for row in runtime if row["event"] == "response")
        runtime.remove(response)
        runtime.insert(runtime.index(advice), response)
    _write(tmp_path, runtime, requests, usage)
    with pytest.raises(RawEvidenceError):
        _verify(tmp_path)


@pytest.mark.parametrize("change", ["missing_settlement", "unknown_tokens"])
def test_memory_unknown_usage_remains_separate_and_unbounded(tmp_path, change):
    runtime, requests, usage = _fixture()
    row = next(row for row in runtime if row["event"] == "memory_model_settled")
    if change == "missing_settlement":
        runtime.remove(row)
    else:
        row["usage"] = None
    _write(tmp_path, runtime, requests, usage)
    facts = _verify(tmp_path).manifest
    assert facts["totals"]["model_requests"] == 8
    assert facts["totals"]["unknown_usage_requests"] == 2
    assert facts["totals"]["unbounded_unknown_usage_requests"] == 1
    assert facts["requests"][6]["input_tokens"] is None
    if change == "missing_settlement":
        assert facts["reconciled"] is False


@pytest.mark.parametrize(
    "allocation,limit", [("primary_and_memory", 1410), ("deepseek_advisory", 90)]
)
def test_raw_reservations_enforce_separate_allocation_limits(tmp_path, allocation, limit):
    runtime, requests, usage = _fixture()
    current = 5 if allocation == "primary_and_memory" else 3
    for number in range(current + 1, limit + 2):
        ordinal = 8 + number - current
        runtime.append(
            {
                "event": "task_request_reserved",
                "task_id": TASK,
                "attempt_id": ATTEMPT,
                "request_id": f"excess-{ordinal}",
                "task_ordinal": ordinal,
                "allocation": allocation,
                "allocation_ordinal": number,
            }
        )
    _write(tmp_path, runtime, requests, usage)
    with pytest.raises(RawEvidenceError, match="allocation"):
        _verify(tmp_path)


@pytest.mark.parametrize(
    "change", [None, "wrong_run", "duplicate_ordinal", "over_run_cap", "missing_run"]
)
def test_aggregate_reservations_require_frozen_run_and_unique_bounded_ordinals(tmp_path, change):
    from nooa_cybergym.leaderboard.raw_request_accounting import verify_request_accounting

    runtime, requests, usage = _fixture()
    debits = [row for row in runtime if "task_ordinal" in row]
    for row in debits:
        if row["event"] == "task_request_reserved":
            row["event"] = "run_request_reserved"
        row.update(run_id="aggregate-one", run_ordinal=100 + row["task_ordinal"])
    if change == "wrong_run":
        debits[-1]["run_id"] = "other-run"
    elif change == "duplicate_ordinal":
        debits[-1]["run_ordinal"] = debits[-2]["run_ordinal"]
    elif change == "over_run_cap":
        debits[-1]["run_ordinal"] = 15001
    elif change == "missing_run":
        del debits[-1]["run_id"]
    _write(tmp_path, runtime, requests, usage)

    def verify():
        return verify_request_accounting(
            tmp_path,
            task_id=TASK,
            attempt_id=ATTEMPT,
            takeover_policy=POLICY,
            registry_sha256="b" * 64,
            alternate_policy_sha256="c" * 64,
            memory_model_bindings=BINDINGS,
            budget_run_id="aggregate-one",
        )

    if change is None:
        facts = verify().manifest
        assert facts["reconciled"] is True
        assert [row["run_ordinal"] for row in facts["requests"]] == list(range(101, 109))
    else:
        with pytest.raises(RawEvidenceError):
            verify()


def _complete_fixture(root):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from nooa_cybergym.leaderboard.raw_fixture_attestor import _NEGATIVE_PREFLIGHT_NAMES
    from xeus_cybergym.ledger import Ed25519Signer, Ed25519Verifier

    final = _final_custody(root)
    private = Ed25519PrivateKey.generate()
    signer = Ed25519Signer(private_key=private, key_id="offline-unit-test")
    verifier = Ed25519Verifier({"offline-unit-test": private.public_key()})
    oracle = {
        "request": {
            "run_id": "run-one",
            "task_id": TASK,
            "attempt_id": ATTEMPT,
            "freeze_sha256": "f" * 64,
            "image_id": "image-one",
            "candidate_sha256": final["sha256"],
        },
        "observations": {
            "vulnerable": {"build_exit": 0, "test_exit": 1, "sanitizer": True},
            "fixed": {"build_exit": 0, "test_exit": 0, "sanitizer": False},
        },
        "oracle_true": True,
    }
    payload = canonical_json(oracle)
    (root / "synthetic-oracle.signed.json").write_text(signer.sign(payload).model_dump_json())
    oracle_digest = hashlib.sha256(payload).hexdigest()
    runtime, requests, usage = _fixture()
    next(row for row in runtime if row["event"] == "synthetic_oracle_observed")[
        "evidence_sha256"
    ] = oracle_digest
    _write(root, runtime, requests, usage)
    shared = {"run_id": "run-one", "task_id": TASK, "configuration_sha256": "f" * 64}
    files = {
        "result.json": shared
        | {
            "scope": "synthetic_native_live",
            "oracle_true": True,
            "provider_dispatched": True,
            "memory_episode_written": True,
            "boundary_failed": False,
            "candidate_sha256": final["sha256"],
            "oracle_evidence_sha256": oracle_digest,
        },
        "connection.json": shared
        | {
            "image_id": "image-one",
            "capability_registry_sha256": "b" * 64,
            "capability_bindings_sha256": "d" * 64,
            "attempt_id": ATTEMPT,
            "launch_id": "launch-one",
            "launch_receipt": str(root / "launch.json"),
        },
        "task-manifest.json": shared,
        "launch.json": {
            "event": "launch_reserved",
            "run_id": "run-one",
            "task_id": TASK,
            "launch_id": "launch-one",
        },
    }
    for name, value in files.items():
        (root / name).write_bytes(canonical_json(value))
    names = sorted(_NEGATIVE_PREFLIGHT_NAMES)
    names += [f"other-{index}" for index in range(62 - len(names))]
    for index, context in enumerate(("parent", "child", "child")):
        folder = root / "preflight" / str(index)
        folder.mkdir(parents=True)
        (folder / "report.json").write_bytes(
            canonical_json(
                {
                    "passed": True,
                    "execution_mode": "native",
                    "failures": [],
                    "contexts": [context],
                    "container_id": f"container-{index}",
                    "probes": [
                        {
                            "name": name,
                            "passed": True,
                            "exit_code": 0,
                            "observed_context": context,
                            "observed_container_id": f"container-{index}",
                        }
                        for name in names
                    ],
                }
            )
        )
    with sqlite3.connect(root / "advisory.sqlite") as db:
        db.execute("CREATE TABLE roles(role TEXT,status TEXT)")
        db.executemany("INSERT INTO roles VALUES(?,'complete')", [(role,) for role in ROLES])
    with sqlite3.connect(root / "native-tools.sqlite") as db:
        for index, name in enumerate(
            ("Bash", "mcp__vulnerable__run_test", "mcp__gbrain__recall", "mcp__gbrain__search")
        ):
            db.execute(
                "INSERT INTO tools VALUES(?,'native',?,?,'completed')",
                (f"other-{index}", name, "a" * 64),
            )
    return verifier


@pytest.mark.parametrize("mode", ["takeover", "legacy", "tampered_stream", "tampered_oracle"])
def test_complete_fixture_attestation_requires_explicit_policy_and_raw_primary_custody(
    tmp_path, mode
):
    from nooa_cybergym.leaderboard.raw_fixture_attestor import verify_live_synthetic_fixture

    verifier = _complete_fixture(tmp_path)
    kwargs = {}
    if mode != "legacy":
        kwargs = {
            "takeover_policy": POLICY,
            "alternate_policy_sha256": "c" * 64,
            "memory_model_bindings": BINDINGS,
        }
    if mode == "tampered_stream":
        with sqlite3.connect(tmp_path / "native-tools.sqlite") as db:
            db.execute("UPDATE streams SET data=?", (b'data: {"type":"message_stop"}\n\n',))
    elif mode == "tampered_oracle":
        envelope = json.loads((tmp_path / "synthetic-oracle.signed.json").read_bytes())
        envelope["signature"] = "tampered"
        (tmp_path / "synthetic-oracle.signed.json").write_bytes(canonical_json(envelope))

    def verify():
        return verify_live_synthetic_fixture(
            tmp_path,
            verifier=verifier,
            run_id="run-one",
            task_id=TASK,
            freeze_sha256="f" * 64,
            image_id="image-one",
            registry_sha256="b" * 64,
            bindings_sha256="d" * 64,
            **kwargs,
        )

    if mode == "takeover":
        facts = verify()
        assert facts.primary_completed_requests == 1
        assert facts.request_accounting.manifest["totals"]["model_requests"] == 8
        assert (
            facts.request_accounting.manifest["requests"][2]["provider"] == POLICY.fallback.provider
        )
        assert facts.oracle_key_id == "offline-unit-test"
        selection = json.loads(facts.primary_final_selection)
        assert selection["provider_attempt_id"] == "ds-attempt"
        assert selection["tool_id"] == "select-final"
        assert selection["sha256"] == facts.candidate_sha256
    else:
        with pytest.raises(RawEvidenceError):
            verify()
