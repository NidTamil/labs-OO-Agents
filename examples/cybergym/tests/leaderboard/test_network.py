"""Boundary behavior for the controller's terminating documentation gateway."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

import pytest
from nooa_cybergym.leaderboard.network import (
    DocumentationGateway,
    GatewayResponse,
    NetworkDenied,
    NetworkPolicy,
)

POLICY_PATH = Path(__file__).parents[2] / "leaderboard/config/network-policy.json"


@dataclass
class _Audit:
    events: list

    def record(self, event):
        self.events.append(event)
        return True


def _request(route: str = "documentation/compiler/reference-v1"):
    from nooa_cybergym.leaderboard.capabilities import (
        Capability,
        CapabilityAuthorizer,
        CapabilityRegistry,
        CapabilityRequest,
        ControlLabel,
        Effect,
        Role,
        Status,
        ToolIdentity,
    )

    identity = ToolIdentity(
        "documentation-gateway",
        "1",
        "1" * 64,
        "documentation.fetch",
        "1",
        "2" * 64,
        "terminating-docs-adapter",
        "1",
        "3" * 64,
    )
    entry = Capability(
        capability_id="docs.compiler",
        identity=identity,
        operation="fetch",
        status=Status.APPROVED,
        control_label=ControlLabel.LEAKAGE_BOUNDARY,
        purpose="Read audited generic compiler documentation",
        roles=(Role.PARENT, Role.CHILD),
        effects=(Effect.READ, Effect.NETWORK),
        data_scopes=("generic-compiler-documentation",),
        path_scopes=(),
        routes=("documentation/compiler/reference-v1",),
        provider_ids=(),
        model_ids=(),
        credential_refs=(),
        accounting="one tool call",
        log_schema="network-v1",
        evidence_refs=("synthetic-route-cert",),
        certification_digest="4" * 64,
    )
    authorizer = CapabilityAuthorizer(CapabilityRegistry((entry,)), Role.CHILD, _Audit([]))
    request = CapabilityRequest(
        capability_id="docs.compiler",
        tool_id=identity.tool_id,
        identity=identity,
        operation="fetch",
        adapter_digest=identity.adapter_digest,
        effects=(Effect.READ, Effect.NETWORK),
        data_scopes=("generic-compiler-documentation",),
        paths=(),
        routes=(route,),
        provider_ids=(),
        model_ids=(),
        task_id="synthetic-task",
        attempt_id="synthetic-attempt",
        request_id="synthetic-request",
    )
    return authorizer, request


class _Transport:
    def __init__(self, responses: dict[str, GatewayResponse]):
        self.responses = responses
        self.calls = []

    def get_no_redirect(self, url: str, *, max_bytes: int) -> GatewayResponse:
        self.calls.append((url, max_bytes))
        return self.responses[url]


def _gateway(responses):
    authorizer, request = _request()
    transport = _Transport(responses)
    return (
        DocumentationGateway(NetworkPolicy.load(POLICY_PATH), authorizer, transport),
        request,
        transport,
    )


def test_audited_generic_docs_pass_and_supplied_archive_is_not_classified_external():
    url = "https://clang.llvm.org/docs/UsersManual.html"
    gateway, request, transport = _gateway(
        {
            url: GatewayResponse(200, "text/html", b"<h1>Clang command-line options</h1>"),
        }
    )
    result = gateway.fetch(request, url)
    assert result.body == b"<h1>Clang command-line options</h1>"
    assert result.final_url == url
    assert transport.calls == [(url, 2_097_152)]
    assert NetworkPolicy.load(POLICY_PATH).is_supplied_archive("/workspace/repo-vul.tar.gz")


@pytest.mark.parametrize(
    "url",
    [
        "https://clang.llvm.org/docs/../../repo-fix.tar.gz",
        "https://clang.llvm.org/docs/%252e%252e/patch.diff",
        "https://clang.llvm.org/docs/UsersManual.html?next=https%3A%2F%2Fgithub.com%2Ftarget%2Frepo%2Fcommit%2Fabc",
        "https://clang.llvm.org/docs/UsersManual.html?issue=CVE-2025-12345",
        "https://clang.llvm.org/docs/UsersManual.html?api_key=controller-secret",
        "https://clang.llvm.org/docs/UsersManual.html?next=access%255Ftoken%3Dcontroller-secret",
        "https://clang.llvm.org.evil.test/docs/UsersManual.html",
        "https://user:pass@clang.llvm.org/docs/UsersManual.html",
        "https://127.0.0.1/docs/UsersManual.html",
        "http://clang.llvm.org/docs/UsersManual.html",
        "https://clang.llvm.org/private/patch.diff",
        "https://github.com/llvm/llvm-project/issues/123",
    ],
)
def test_answer_or_host_route_denied_before_transport(url):
    gateway, request, transport = _gateway({})
    with pytest.raises(NetworkDenied):
        gateway.fetch(request, url)
    assert transport.calls == []


def test_redirect_is_checked_before_second_request():
    url = "https://clang.llvm.org/docs/UsersManual.html"
    target = "https://github.com/target/repository/commit/fix"
    gateway, request, transport = _gateway(
        {
            url: GatewayResponse(302, "text/html", b"", location=target),
        }
    )
    with pytest.raises(NetworkDenied):
        gateway.fetch(request, url)
    assert [item[0] for item in transport.calls] == [url]


def test_mirror_response_with_fixed_or_prior_answer_is_rejected():
    url = "https://clang.llvm.org/docs/UsersManual.html"
    gateway, request, _ = _gateway(
        {
            url: GatewayResponse(200, "text/html", b"Download repo-fix.tar.gz for the answer"),
        }
    )
    with pytest.raises(NetworkDenied, match="answer"):
        gateway.fetch(request, url)


def test_unknown_capability_or_route_cannot_use_allowlisted_hostname():
    url = "https://clang.llvm.org/docs/UsersManual.html"
    gateway, _, transport = _gateway({})
    _, wrong_route = _request("documentation/unknown")
    with pytest.raises(NetworkDenied, match="capability"):
        gateway.fetch(wrong_route, url)
    assert transport.calls == []


def test_direct_provider_and_cloud_metadata_are_controller_only():
    policy = NetworkPolicy.load(POLICY_PATH)
    assert not policy.check_endpoint("parent", "https://api.deepseek.com/chat/completions")
    assert policy.check_endpoint("controller", "https://api.deepseek.com/chat/completions")
    assert not policy.check_endpoint("child", "http://169.254.169.254/latest/meta-data/")


@pytest.mark.parametrize("role", ("parent", "child"))
def test_zai_provider_endpoint_is_controller_only(role):
    policy = NetworkPolicy.load(POLICY_PATH)
    endpoint = "https://api.z.ai/api/anthropic/v1/messages"
    assert not policy.check_endpoint(role, endpoint)
    assert policy.check_endpoint("controller", endpoint)


def test_policy_documentation_routes_cannot_change_after_digest_is_frozen():
    policy = NetworkPolicy.load(POLICY_PATH)
    assert isinstance(policy.documentation_routes, MappingProxyType)
    with pytest.raises(TypeError):
        policy.documentation_routes["documentation/compiler/reference-v1"] = (
            policy.documentation_routes["documentation/python/reference-v1"]
        )


def test_external_repository_mirror_query_is_denied_before_transport():
    url = "https://clang.llvm.org/docs/UsersManual.html?repo=github.com%2Ftarget%2Frepository"
    gateway, request, transport = _gateway({})
    with pytest.raises(NetworkDenied):
        gateway.fetch(request, url)
    assert transport.calls == []
