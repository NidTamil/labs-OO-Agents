"""Controller-side route guard for audited network and documentation tools.

The CyberGym Squid firewall is a domain filter and cannot inspect HTTPS
paths or response bodies. A *terminating* controller gateway must use this
guard before presenting documentation to an agent. This module is not a
network sandbox, a transparent proxy, or permission for agent-side fetches.
The task container still requires an internal Docker network and observed
negative probes before its first model request.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Protocol
from urllib.parse import unquote, unquote_plus, urljoin, urlsplit

from .capabilities import CapabilityAuthorizer, CapabilityRequest

_REQUIRED_ENDPOINTS = frozenset(
    {
        "model-gateway",
        "cybergym-submit",
        "gbrain-read-gateway",
        "documentation-gateway",
        "registered-tool-gateway",
    }
)
_REQUIRED_DENIALS = frozenset(
    {
        "external-target-repository",
        "external-target-patch",
        "target-issue-or-changelog",
        "cve-or-published-poc",
        "fixed-or-prior-task-answer",
        "credential-or-host-access",
    }
)
_ANSWERS = re.compile(
    r"repo-fix\.tar\.gz|patch\.diff|(?:^|[/\s])error\.txt\b|"
    r"\bCVE-\d{4}-\d{4,}\b|\bexploit-db\.com\b|"
    r"\b(?:published[-_ ]?poc|prior[-_ ]?task[-_ ]?answer)\b|"
    r"github\.com/[^\s/?#]+/[^\s/?#]+/(?:commit|pull|issues|releases)/",
    re.IGNORECASE,
)
_EMBEDDED_URL = re.compile(r"https?://", re.IGNORECASE)
_EMBEDDED_REPOSITORY = re.compile(
    r"(?:github|gitlab|bitbucket)\.com/[^\s/?#]+/[^\s/?#]+", re.IGNORECASE
)
_CREDENTIAL_QUERY = re.compile(
    r"\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|secret|password|"
    r"authorization|signature)\s*=",
    re.IGNORECASE,
)
_FORBIDDEN_HOSTS = frozenset({"localhost", "metadata.google.internal", "host.docker.internal"})


class NetworkDenied(RuntimeError):
    """A route, result, or capability would cross an audited boundary."""


@dataclass(frozen=True, slots=True)
class DocumentationRoute:
    origin: str
    path_prefix: str


@dataclass(frozen=True, slots=True)
class NetworkPolicy:
    allowed_logical_endpoints: frozenset[str]
    controller_only_provider_endpoints: frozenset[str]
    required_denied_routes: frozenset[str]
    documentation_routes: Mapping[str, DocumentationRoute]
    max_document_bytes: int
    max_redirects: int
    canonical_json: str

    @classmethod
    def load(cls, path: Path) -> NetworkPolicy:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        if type(raw) is not dict or raw.get("schema_version") != 1:
            raise ValueError("network policy schema version is unsupported")
        if raw.get("direct_ip_egress") is not False or raw.get("dns_mode") != "proxy-only":
            raise ValueError("network policy must prohibit direct IP and DNS egress")
        allowed = raw.get("allowed_logical_endpoints")
        denied = raw.get("required_denied_routes")
        providers = raw.get("controller_only_provider_endpoints")
        if any(
            type(group) is not list or any(type(v) is not str for v in group)
            for group in (allowed, denied, providers)
        ):
            raise ValueError("network policy endpoint and denial lists must be explicit")
        if not _REQUIRED_ENDPOINTS <= set(allowed) or not _REQUIRED_DENIALS <= set(denied):
            raise ValueError("required logical endpoints or denial probes are missing")
        if any(len(set(group)) != len(group) for group in (allowed, denied, providers)):
            raise ValueError("network policy routes contain duplicates")
        if type(raw.get("documentation_routes")) is not dict:
            raise ValueError("documentation routes must be explicit")
        routes = {}
        for route_id, spec in raw["documentation_routes"].items():
            if (
                type(route_id) is not str
                or not route_id.startswith("documentation/")
                or type(spec) is not dict
                or set(spec) != {"origin", "path_prefix"}
                or type(spec["origin"]) is not str
                or type(spec["path_prefix"]) is not str
            ):
                raise ValueError("documentation route is malformed")
            parsed = urlsplit(spec["origin"])
            if (
                parsed.scheme != "https"
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.port
                or parsed.path
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError("documentation route must use one HTTPS origin")
            if not spec["path_prefix"].startswith("/") or ".." in spec["path_prefix"]:
                raise ValueError("documentation path prefix is malformed")
            routes[route_id] = DocumentationRoute(spec["origin"], spec["path_prefix"])
        max_bytes = raw.get("max_document_bytes")
        max_redirects = raw.get("max_redirects")
        if type(max_bytes) is not int or not 0 < max_bytes <= 2_097_152:
            raise ValueError("documentation response limit is invalid")
        if type(max_redirects) is not int or not 0 <= max_redirects <= 5:
            raise ValueError("redirect limit is invalid")
        for provider in providers:
            parsed = urlsplit(provider)
            if parsed.scheme != "https" or not parsed.hostname or parsed.path or parsed.query:
                raise ValueError("provider endpoints must be HTTPS origins")
        canonical_json = json.dumps(raw, sort_keys=True, separators=(",", ":"), allow_nan=False)
        return cls(
            frozenset(allowed),
            frozenset(providers),
            frozenset(denied),
            MappingProxyType(routes),
            max_bytes,
            max_redirects,
            canonical_json,
        )

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.canonical_json.encode("utf-8")).hexdigest()

    def is_supplied_archive(self, path: str) -> bool:
        """The official vulnerable-side bundle is an input, not an external answer."""
        return path == "/workspace/repo-vul.tar.gz"

    def check_endpoint(self, role: str, url: str) -> bool:
        """Check a logical gateway or controller-only provider destination."""
        try:
            parsed = urlsplit(url)
            host = parsed.hostname
            if not host or parsed.username or parsed.password or parsed.fragment:
                return False
            if _is_ip_or_host_boundary(host):
                return False
            if (
                parsed.scheme == "https"
                and f"https://{host}" in self.controller_only_provider_endpoints
            ):
                return role == "controller" and parsed.port in (None, 443)
            return (
                role in {"parent", "child", "controller"}
                and parsed.scheme == "http"
                and parsed.port in (None, 80)
                and host in self.allowed_logical_endpoints
            )
        except ValueError:
            return False

    def check_document_url(self, route_id: str, url: str) -> None:
        route = self.documentation_routes.get(route_id)
        if route is None:
            raise NetworkDenied("documentation route is unaudited")
        parsed = urlsplit(url)
        origin = urlsplit(route.origin)
        if (
            parsed.scheme != "https"
            or parsed.hostname != origin.hostname
            or parsed.username
            or parsed.password
            or parsed.port not in (None, 443)
            or parsed.fragment
            or not parsed.path.startswith(route.path_prefix)
            or not parsed.path.startswith("/")
            or parsed.path.startswith("//")
            or "\\" in parsed.path
        ):
            raise NetworkDenied("documentation destination is outside audited route")
        if _is_ip_or_host_boundary(parsed.hostname):
            raise NetworkDenied("documentation destination crosses host boundary")
        decoded_path = _decode_recursive(parsed.path)
        if (
            not decoded_path.startswith(route.path_prefix)
            or any(part in (".", "..") for part in decoded_path.split("/"))
            or "\\" in decoded_path
        ):
            raise NetworkDenied("documentation path escapes audited scope")
        decoded_query = _decode_recursive(parsed.query, plus=True)
        if (
            _ANSWERS.search(decoded_path + "?" + decoded_query)
            or _EMBEDDED_URL.search(decoded_query)
            or _EMBEDDED_REPOSITORY.search(decoded_query)
            or _CREDENTIAL_QUERY.search(decoded_query)
        ):
            raise NetworkDenied("documentation URL carries an answer source")

    def check_document_body(self, body: bytes, content_type: str) -> None:
        if len(body) > self.max_document_bytes:
            raise NetworkDenied("documentation response exceeds audited size limit")
        if content_type.lower().split(";", 1)[0].strip() not in {
            "text/html",
            "text/plain",
            "text/markdown",
            "application/xhtml+xml",
        }:
            raise NetworkDenied("documentation response has an unaudited media type")
        if _ANSWERS.search(body.decode("utf-8", errors="replace")):
            raise NetworkDenied("documentation response contains an answer source")


def _decode_recursive(value: str, *, plus: bool = False) -> str:
    decoder = unquote_plus if plus else unquote
    for _ in range(4):
        decoded = decoder(value)
        if decoded == value:
            return decoded
        value = decoded
    raise NetworkDenied("nested URL encoding exceeds audited limit")


def _is_ip_or_host_boundary(host: str) -> bool:
    if host in _FORBIDDEN_HOSTS or host.endswith(".internal") or host.endswith(".local"):
        return True
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


@dataclass(frozen=True, slots=True)
class GatewayResponse:
    status: int
    content_type: str
    body: bytes
    location: str | None = None


@dataclass(frozen=True, slots=True)
class GatewayResult:
    body: bytes
    content_type: str
    final_url: str
    redirect_chain: tuple[str, ...]


class NoRedirectTransport(Protocol):
    def get_no_redirect(self, url: str, *, max_bytes: int) -> GatewayResponse:
        """One HTTPS hop; MUST never follow redirects or expose response to agent."""


@dataclass(slots=True)
class DocumentationGateway:
    """Trusted adapter; the agent receives only the checked final result."""

    policy: NetworkPolicy
    authorizer: CapabilityAuthorizer
    transport: NoRedirectTransport

    def fetch(self, request: CapabilityRequest, url: str) -> GatewayResult:
        decision = self.authorizer.authorize(request)
        if not decision.allowed:
            raise NetworkDenied("documentation capability is unavailable")
        if len(request.routes) != 1:
            raise NetworkDenied("documentation fetch requires one audited route")
        route_id = request.routes[0]
        current = url
        chain: list[str] = []
        for _ in range(self.policy.max_redirects + 1):
            self.policy.check_document_url(route_id, current)
            if current in chain:
                raise NetworkDenied("documentation redirect loop")
            chain.append(current)
            response = self.transport.get_no_redirect(
                current,
                max_bytes=self.policy.max_document_bytes,
            )
            if 300 <= response.status < 400:
                if not response.location:
                    raise NetworkDenied("documentation redirect has no destination")
                current = urljoin(current, response.location)
                continue
            if response.status != 200:
                raise NetworkDenied("documentation request did not return approved content")
            self.policy.check_document_body(response.body, response.content_type)
            return GatewayResult(response.body, response.content_type, current, tuple(chain))
        raise NetworkDenied("documentation redirect limit exceeded")
