"""Synthetic boundary checks; no service, model, or benchmark data is contacted."""

import hashlib
import importlib.util
import json
from dataclasses import FrozenInstanceError, replace

import pytest


def test_registry_module_exists():
    assert importlib.util.find_spec("nooa_cybergym.leaderboard.capabilities") is not None


def api():
    from nooa_cybergym.leaderboard import capabilities

    return capabilities


def capability(capability_id="local.read", **changes):
    c = api()
    values = {
        "capability_id": capability_id,
        "identity": c.ToolIdentity(
            service_id="synthetic-local",
            service_version="1",
            service_digest="1" * 64,
            tool_id=capability_id,
            tool_version="1",
            tool_digest="2" * 64,
            adapter_id="audited.synthetic",
            adapter_version="1",
            adapter_digest="3" * 64,
        ),
        "operation": "read",
        "status": c.Status.APPROVED,
        "control_label": c.ControlLabel.PERFORMANCE_OPTIMISATION,
        "purpose": "Read provided vulnerable task source",
        "roles": (c.Role.PARENT, c.Role.CHILD),
        "effects": (c.Effect.READ,),
        "data_scopes": ("provided-vulnerable-source",),
        "path_scopes": ("/workspace/source",),
        "routes": (),
        "provider_ids": (),
        "model_ids": (),
        "credential_refs": (),
        "accounting": "tool_calls,latency",
        "log_schema": "audit.v1",
        "evidence_refs": ("synthetic-audit:local-read",),
        "certification_digest": "4" * 64,
    }
    values.update(changes)
    return c.Capability(**values)


def request(entry, **changes):
    c = api()
    values = {
        "capability_id": entry.capability_id,
        "tool_id": entry.identity.tool_id,
        "identity": entry.identity,
        "operation": entry.operation,
        "adapter_digest": entry.identity.adapter_digest,
        "effects": entry.effects,
        "data_scopes": entry.data_scopes,
        "paths": ("/workspace/source/input.c",) if entry.path_scopes else (),
        "routes": entry.routes,
        "provider_ids": entry.provider_ids,
        "model_ids": entry.model_ids,
        "task_id": "synthetic-task",
        "attempt_id": "attempt-1",
        "request_id": "request-1",
    }
    values.update(changes)
    return c.CapabilityRequest(**values)


class AuditLog:
    def __init__(self):
        self.events = []

    def record(self, event):
        self.events.append(event)
        return True


def authorize(entry, role=None, req=None, sink=None):
    c = api()
    registry = c.CapabilityRegistry((entry,))
    log = sink or AuditLog()
    authorizer = c.CapabilityAuthorizer(registry, role or c.Role.CHILD, log)
    return authorizer.authorize(req or request(entry)), log, registry


@pytest.mark.parametrize(
    "route,operation",
    [
        ("local.read", "read"),
        ("local.search", "search"),
        ("clangd.references", "references"),
        ("gbrain.recall", "recall"),
        ("gbrain.search", "search"),
    ],
)
def test_audited_read_only_operations_work_for_parent_and_child(route, operation):
    c = api()
    entry = capability(route, operation=operation)
    for role in (c.Role.PARENT, c.Role.CHILD):
        decision, log, registry = authorize(entry, role)
        assert decision.allowed
        assert len(log.events) == 1
        event = log.events[0]
        assert event.registry_digest == registry.digest
        assert (event.role, event.tool_id, event.capability_id) == (role, route, route)
        assert (event.task_id, event.attempt_id, event.request_id) == (
            "synthetic-task",
            "attempt-1",
            "request-1",
        )
        assert event.disposition == "allowed" and event.reason


def test_controller_owns_writes_and_solver_cannot_supply_role():
    c = api()
    entry = capability(
        "gbrain.capture",
        operation="capture",
        effects=(c.Effect.WRITE,),
        roles=(c.Role.CONTROLLER,),
        path_scopes=(),
        write_domain=c.WriteDomain.CONTROLLER_AUTHORITY,
    )
    assert authorize(entry, c.Role.CONTROLLER)[0].allowed
    assert not authorize(entry, c.Role.PARENT)[0].allowed
    assert not authorize(entry, c.Role.CHILD)[0].allowed
    with pytest.raises(TypeError):
        request(entry, role=c.Role.CONTROLLER)
    with pytest.raises(ValueError):
        replace(entry, roles=(c.Role.CHILD,))


def test_parent_can_write_audited_task_output_while_child_cannot():
    c = api()
    entry = capability(
        "task.write_poc",
        operation="write",
        effects=(c.Effect.WRITE,),
        roles=(c.Role.PARENT,),
        path_scopes=("/workspace/output",),
        data_scopes=("task-poc",),
        write_domain=c.WriteDomain.TASK_WORKSPACE,
    )
    scoped_request = request(entry, paths=("/workspace/output/poc.bin",))
    assert authorize(entry, c.Role.PARENT, req=scoped_request)[0].allowed
    assert not authorize(entry, c.Role.CHILD, req=scoped_request)[0].allowed
    assert not authorize(
        entry, c.Role.PARENT, req=request(entry, paths=("/workspace/source/other.c",))
    )[0].allowed
    with pytest.raises(ValueError):
        replace(entry, roles=(c.Role.PARENT, c.Role.CHILD))


def test_approved_writes_require_explicit_domain_and_task_writes_require_path_scope():
    c = api()
    with pytest.raises(ValueError):
        capability(effects=(c.Effect.WRITE,), roles=(c.Role.CONTROLLER,))
    with pytest.raises(ValueError):
        capability(
            effects=(c.Effect.WRITE,),
            roles=(c.Role.PARENT,),
            path_scopes=(),
            write_domain=c.WriteDomain.TASK_WORKSPACE,
        )
    with pytest.raises(ValueError):
        capability(write_domain=c.WriteDomain.TASK_WORKSPACE)


@pytest.mark.parametrize(
    "route,reason",
    [
        ("external.target.repository", "answer_leakage"),
        ("external.target.patch", "answer_leakage"),
        ("external.target.issues", "answer_leakage"),
        ("external.cve", "answer_leakage"),
        ("external.published-poc", "answer_leakage"),
        ("host.secret", "credential_exposure"),
        ("host.files", "host_boundary"),
    ],
)
def test_evidenced_denied_operations_remain_denied(route, reason):
    c = api()
    entry = capability(
        route,
        status=c.Status.DENIED,
        denial_reason=c.DenialReason(reason),
        evidence_refs=("synthetic-probe:" + route,),
    )
    decision, log, _ = authorize(entry)
    assert not decision.allowed
    assert reason in decision.reason
    assert log.events[0].disposition == "denied"


def test_pending_and_unknown_are_logged_and_fail_closed():
    c = api()
    entry = capability(status=c.Status.PENDING, evidence_refs=(), certification_digest="")
    decision, log, _ = authorize(entry)
    assert not decision.allowed and "pending" in decision.reason
    decision, unknown_log, _ = authorize(entry, req=request(entry, capability_id="not-audited"))
    assert not decision.allowed and "unknown" in decision.reason
    assert len(log.events) == len(unknown_log.events) == 1


@pytest.mark.parametrize(
    "changes",
    [
        {"paths": ("/workspace/source-escape/secret",)},
        {"paths": ("/root/secret",)},
        {"routes": ("raw-host-mcp",)},
        {"model_ids": ("undeclared-model",)},
        {"provider_ids": ("undeclared-provider",)},
        {"data_scopes": ("fixed-side-source",)},
        {"tool_id": "another-tool"},
        {"operation": "write"},
        {"adapter_digest": "9" * 64},
    ],
)
def test_approval_does_not_extend_to_other_scope_or_identity(changes):
    entry = capability()
    decision, log, _ = authorize(entry, req=request(entry, **changes))
    assert not decision.allowed
    assert log.events[0].disposition == "denied"


def test_read_approval_cannot_authorize_write_effect():
    c = api()
    entry = capability()
    assert not authorize(entry, req=request(entry, effects=(c.Effect.WRITE,)))[0].allowed


def test_documentation_uses_exact_audited_routes_and_paths():
    c = api()
    entry = capability(
        "docs.compiler",
        routes=("documentation/compiler/reference-v1",),
        effects=(c.Effect.READ, c.Effect.NETWORK),
        data_scopes=("generic-compiler-documentation",),
        path_scopes=("/audited-docs/compiler",),
    )
    assert authorize(entry, req=request(entry, paths=("/audited-docs/compiler/options",)))[
        0
    ].allowed
    assert not authorize(entry, req=request(entry, paths=("/audited-docs/target/patch",)))[
        0
    ].allowed
    assert not authorize(
        entry, req=request(entry, routes=("documentation/compiler/reference-v1/redirect",))
    )[0].allowed


def test_approved_provider_and_model_identity_do_not_enable_other_models():
    c = api()
    entry = capability(
        "synthetic.advisory",
        effects=(c.Effect.MODEL, c.Effect.NETWORK),
        path_scopes=(),
        routes=("model-gateway/advisory",),
        provider_ids=("synthetic-provider",),
        model_ids=("synthetic-model@1",),
    )
    assert authorize(entry)[0].allowed
    assert not authorize(entry, req=request(entry, model_ids=("synthetic-model@2",)))[0].allowed
    assert not authorize(entry, req=request(entry, provider_ids=("other-provider",)))[0].allowed


def test_manifest_is_stable_frozen_and_tamper_evident():
    c = api()
    first, second = capability(), capability("gbrain.recall")
    registry = c.CapabilityRegistry((first, second))
    reordered = c.CapabilityRegistry((second, first))
    assert registry.manifest_json == reordered.manifest_json
    assert registry.digest == hashlib.sha256(registry.manifest_json.encode()).hexdigest()
    manifest = json.loads(registry.manifest_json)
    assert manifest["schema_version"] == 1
    assert manifest["capabilities"][0]["identity"]["adapter_digest"] == "3" * 64
    assert (
        c.CapabilityRegistry((replace(first, purpose="Changed audited purpose"), second)).digest
        != registry.digest
    )
    with pytest.raises(FrozenInstanceError):
        first.status = c.Status.DENIED
    with pytest.raises(FrozenInstanceError):
        first.identity.adapter_digest = "9" * 64
    with pytest.raises(FrozenInstanceError):
        registry.entries = ()
    with pytest.raises(TypeError):
        first.roles[0] = c.Role.CONTROLLER
    manifest["capabilities"][0]["purpose"] = "tampered copy"
    assert registry.manifest_json == reordered.manifest_json


def test_duplicate_entries_fail_closed_even_if_equal():
    c = api()
    entry = capability()
    for other in (entry, replace(entry, purpose="conflicting")):
        with pytest.raises(ValueError):
            c.CapabilityRegistry((entry, other))


@pytest.mark.parametrize(
    "changes",
    [
        {"roles": ["child"]},
        {"status": "approved"},
        {"control_label": "optional"},
        {"effects": ("read",)},
        {"evidence_refs": ()},
        {"certification_digest": "not-sha256"},
        {"path_scopes": ("/workspace/../root",)},
        {"path_scopes": ("/",)},
        {"path_scopes": ("relative/path",)},
        {"path_scopes": ("/workspace\\source",)},
        {"capability_id": ""},
        {"path_scopes": ("//workspace/source",)},
        {"accounting": ""},
        {"log_schema": ""},
    ],
)
def test_invalid_approval_schema_rejected(changes):
    with pytest.raises((TypeError, ValueError)):
        capability(**changes)


def test_denial_requires_boundary_reason_and_evidence():
    c = api()
    with pytest.raises(ValueError):
        capability(status=c.Status.DENIED)
    with pytest.raises(ValueError):
        capability(
            status=c.Status.DENIED, denial_reason=c.DenialReason.ANSWER_LEAKAGE, evidence_refs=()
        )


@pytest.mark.parametrize("effect", ["write", "host", "credential"])
def test_child_cannot_be_granted_dangerous_effects(effect):
    c = api()
    with pytest.raises(ValueError):
        capability(effects=(c.Effect(effect),))


@pytest.mark.parametrize(
    "field,value",
    [
        ("task_id", ""),
        ("attempt_id", ""),
        ("request_id", ""),
        ("paths", ("/workspace/source/../secret",)),
        ("paths", ["/workspace/source"]),
        ("data_scopes", ()),
    ],
)
def test_malformed_request_rejected(field, value):
    with pytest.raises((TypeError, ValueError)):
        request(capability(), **{field: value})


def test_audit_must_acknowledge_before_permission_is_returned():
    c = api()
    entry = capability()

    class FailedSink:
        def record(self, event):
            raise OSError("controller audit unavailable")

    class UnacknowledgedSink:
        def record(self, event):
            return None

    for sink in (FailedSink(), UnacknowledgedSink()):
        with pytest.raises(c.AuditFailure):
            authorize(entry, sink=sink)


def test_untrusted_role_string_cannot_bind_authorizer():
    c = api()
    with pytest.raises(TypeError):
        c.CapabilityAuthorizer(c.CapabilityRegistry((capability(),)), "controller", AuditLog())


@pytest.mark.parametrize(
    "changes",
    [
        {"service_id": "another-service"},
        {"service_version": "2"},
        {"service_digest": "8" * 64},
        {"tool_version": "2"},
        {"tool_digest": "8" * 64},
        {"adapter_id": "unaudited.adapter"},
        {"adapter_version": "2"},
    ],
)
def test_live_service_tool_and_adapter_identity_must_match_audit(changes):
    entry = capability()
    changed_identity = replace(entry.identity, **changes)
    assert not authorize(entry, req=request(entry, identity=changed_identity))[0].allowed


@pytest.mark.parametrize("write", [False, True])
def test_scoped_filesystem_operations_require_observed_paths(write):
    c = api()
    changes = {}
    if write:
        changes = {
            "roles": (c.Role.PARENT,),
            "effects": (c.Effect.WRITE,),
            "write_domain": c.WriteDomain.TASK_WORKSPACE,
        }
    entry = capability(**changes)
    decision, audit, _ = authorize(entry, role=c.Role.PARENT, req=request(entry, paths=()))
    assert not decision.allowed
    assert "paths required" in decision.reason
    assert audit.events[-1].disposition == "denied"


def test_audit_exception_does_not_expose_backend_credentials():
    import traceback

    c = api()

    class SecretFailure:
        def record(self, event):
            raise OSError("postgres://audit-secret@example.invalid/db")

    with pytest.raises(c.AuditFailure) as raised:
        authorize(capability(), sink=SecretFailure())
    assert "audit-secret" not in "".join(traceback.format_exception(raised.value))


def test_frozen_capability_registry_loads_exact_canonical_manifest(tmp_path):
    c = api()
    registry = c.CapabilityRegistry((capability(),))
    path = tmp_path / "capability-policy.json"
    path.write_text(registry.manifest_json, encoding="utf-8")
    assert c.CapabilityRegistry.load(path, expected_sha256=registry.digest) == registry


@pytest.mark.parametrize("mutation", ["extra", "changed", "duplicate_key", "format"])
def test_capability_registry_loader_rejects_unfrozen_or_ambiguous_manifest(tmp_path, mutation):
    c = api()
    registry = c.CapabilityRegistry((capability(),))
    path = tmp_path / "capability-policy.json"
    manifest = registry.manifest_json
    if mutation == "extra":
        data = json.loads(manifest)
        data["capabilities"][0]["unknown"] = "unreviewed"
        manifest = json.dumps(data, sort_keys=True, separators=(",", ":"))
    elif mutation == "changed":
        manifest = manifest.replace("provided-vulnerable-source", "host-secret")
    elif mutation == "duplicate_key":
        manifest = manifest.replace('"schema_version":1', '"schema_version":1,"schema_version":1')
    else:
        manifest += "\n"
    path.write_text(manifest, encoding="utf-8")
    with pytest.raises((ValueError, RuntimeError)):
        c.CapabilityRegistry.load(path, expected_sha256=registry.digest)
