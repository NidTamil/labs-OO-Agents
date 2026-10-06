# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Exercise the controller's real duplex subprocess transport with synthetic wire peers."""

import sys

import pytest
from nooa_cybergym.leaderboard.deepseek import SharedCampaignBudget
from nooa_cybergym.leaderboard.gbrain_bridge import GBrainControllerBridge
from nooa_cybergym.leaderboard.memory_transport import TransportDenied


class Audit:
    def __init__(self):
        self.events = []

    def record(self, event):
        self.events.append(dict(event))
        return True


def peer(tmp_path, *, source="xeus-cybergym-workspace", extra="", usage=None):
    path = tmp_path / "peer.py"
    path.write_text(
        "import json,sys\n"
        "for line in sys.stdin:\n"
        " m=json.loads(line)\n"
        " if m.get('method') == 'xeus/evidence':\n"
        f"  r={{'source_ids':[{source!r}], 'server_context_source_id':{source!r}, "
        "'native_guard_binding_sha256':'a'*64, 'native_guard_bound':True, "
        "'scopes':['read'], 'client_id':'synthetic-oauth', 'transport':'native-guarded-stdio'}\n"
        " else:\n"
        "  print(json.dumps({'type':'guard_admit','id':'permit1','request_id':m['id'],"
        "'invocation':{'model':'openai:test-embedding','kind':'embedding','operation':'embed'}}),flush=True)\n"
        "  admission=json.loads(sys.stdin.readline())\n"
        "  if admission.get('ok') is not True:\n"
        "   print(json.dumps({'jsonrpc':'2.0','id':m['id'],'error':{'code':-32000,'message':'denied'}}),flush=True)\n"
        "   continue\n"
        + ("  sys.exit(0)\n" if extra == "crash" else "")
        + f"  print(json.dumps({{'type':'guard_settle','id':'permit1','request_id':m['id'],'usage':{usage!r}}}),flush=True)\n"
        "  receipt=json.loads(sys.stdin.readline())\n"
        "  r={'accepted':receipt.get('ok')}\n"
        " print(json.dumps({'jsonrpc':'2.0','id':m['id'],'result':r}),flush=True)\n",
        encoding="utf-8",
    )
    return [sys.executable, "-u", str(path)]


def test_actual_subprocess_requires_exact_authenticated_scope(tmp_path):
    with GBrainControllerBridge(
        peer(tmp_path, source="default"),
        budget=SharedCampaignBudget(),
        audit=Audit(),
        allowed_models={"openai:test-embedding": "embedding"},
    ) as bridge:
        with pytest.raises(TransportDenied, match="scope"):
            bridge.read_evidence()


def test_native_invocation_reserves_shared_budget_and_records_token_classes(tmp_path):
    budget, audit = SharedCampaignBudget(), Audit()
    with GBrainControllerBridge(
        peer(tmp_path, usage={"inputTokens": 10, "outputTokens": 0, "cacheReadTokens": 2}),
        budget=budget,
        audit=audit,
        allowed_models={"openai:test-embedding": "embedding"},
    ) as bridge:
        assert bridge.read_evidence().native_guard_bound
        result = bridge.exchange(
            {"jsonrpc": "2.0", "id": "read-1", "method": "tools/list"}, timeout_seconds=2
        )
        assert result["result"] == {"accepted": True}
    assert budget.snapshot()["requests"] == 1
    assert audit.events[0]["event"] == "memory_model_admitted"
    assert audit.events[1]["usage"] == {
        "inputTokens": 10,
        "outputTokens": 0,
        "cacheReadTokens": 2,
        "cacheWriteTokens": 0,
    }


def test_unknown_model_denied_without_provider_admission(tmp_path):
    budget, audit = SharedCampaignBudget(), Audit()
    with GBrainControllerBridge(
        peer(tmp_path), budget=budget, audit=audit, allowed_models={"other": "chat"}
    ) as bridge:
        bridge.read_evidence()
        result = bridge.exchange(
            {"jsonrpc": "2.0", "id": "read-2", "method": "tools/list"}, timeout_seconds=2
        )
        assert "error" in result
    assert budget.snapshot()["requests"] == 0


def test_missing_model_identity_cannot_match_missing_policy_key(tmp_path):
    command = peer(tmp_path)
    path = tmp_path / "peer.py"
    path.write_text(
        path.read_text().replace("'model':'openai:test-embedding','kind':'embedding',", "")
    )
    budget, audit = SharedCampaignBudget(), Audit()
    with GBrainControllerBridge(
        command, budget=budget, audit=audit, allowed_models={"openai:test-embedding": "embedding"}
    ) as bridge:
        bridge.read_evidence()
        result = bridge.exchange(
            {"jsonrpc": "2.0", "id": "missing-model", "method": "tools/list"}, timeout_seconds=2
        )
        assert "error" in result
    assert budget.snapshot()["requests"] == 0


def test_peer_crash_settles_admitted_request_as_unknown(tmp_path):
    budget, audit = SharedCampaignBudget(), Audit()
    with GBrainControllerBridge(
        peer(tmp_path, extra="crash"),
        budget=budget,
        audit=audit,
        allowed_models={"openai:test-embedding": "embedding"},
    ) as bridge:
        bridge.read_evidence()
        with pytest.raises(TransportDenied):
            bridge.exchange(
                {"jsonrpc": "2.0", "id": "read-3", "method": "tools/list"}, timeout_seconds=2
            )
    assert budget.snapshot()["requests"] == 1
    assert audit.events[-1]["event"] == "memory_model_settled"
    assert audit.events[-1]["usage"] is None


def test_audit_failure_never_approves_provider_call(tmp_path):
    class FailedAudit(Audit):
        def record(self, event):
            return False

    budget = SharedCampaignBudget()
    with GBrainControllerBridge(
        peer(tmp_path),
        budget=budget,
        audit=FailedAudit(),
        allowed_models={"openai:test-embedding": "embedding"},
    ) as bridge:
        bridge.read_evidence()
        with pytest.raises(TransportDenied):
            bridge.exchange(
                {"jsonrpc": "2.0", "id": "read-4", "method": "tools/list"}, timeout_seconds=2
            )
    assert budget.snapshot()["requests"] == 1
