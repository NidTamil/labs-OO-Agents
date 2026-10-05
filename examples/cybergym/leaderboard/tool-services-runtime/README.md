# Registered read-only tools

`nooa_cybergym.leaderboard.tool_services_runtime` provides the synchronous
`GatewayRequest -> GatewayReply` handler used by the task's existing host gateway.
The gateway's admitted peer and the controller's consumed native provider tool
record both have to match before a backend call. Metadata other than
`params._meta["claudecode/toolUseId"]` is inert; it cannot select a role.

Freeze these MCP entries in the native launch configuration:

| Server | URL | Tools |
| --- | --- | --- |
| `clangd` | `http://registered-tool-gateway/mcp/clangd` | `document_symbols`, `hover`, `definition`, `references` |
| `documentation` | `http://registered-tool-gateway/mcp/documentation` | `fetch` |

The native provider names are `mcp__clangd__document_symbols`,
`mcp__clangd__hover`, `mcp__clangd__definition`, `mcp__clangd__references`, and
`mcp__documentation__fetch`. List/init require an admitted task peer; tool calls
additionally require an exact controller-authorized native tool ID, name and
argument match. A child uses the same endpoints and is attributed to its verified
child lifecycle. Tools have no role, source, executable, credential or scope override.

## Controller construction

```python
clangd = ClangdClient.for_docker(
    docker_client.api,
    container_id=task_container.container_id,
    source_roots=("/workspace/src",),
    compile_commands=observed_compile_commands,
)
documents = DocumentationReader(
    policy=frozen_network_policy,
    transport=VerifiedHTTPSNoRedirectTransport(),
    resolve_admission=resolve_documentation_capability,
    audit=documentation_audit,
)
handler = RegisteredToolGateway(
    clangd=clangd,
    documentation=documents,
    authorize_peer=authorize_task_peer,
    resolve_caller=resolve_native_tool_call,
    audit=tool_audit,
    task_id=task_id,
    attempt_id=attempt_id,
)
```

`resolve_native_tool_call(peer, tool_use_id, native_name, arguments)` returns the
actual `NativeToolCall` consumed by `NativeToolController.resolve_mcp_call` after
checking the peer. The `native_name` is already fully qualified. The returned
task, attempt, tool ID, role, tool name and arguments are verified again.

`resolve_documentation_capability(native_call, route_id)` returns a
`DocumentationAdmission` built from the frozen certified capability registry.
Its request identity and trusted role must match `native_call`; the controller
supplies it directly to `DocumentationHTTPService`, never through HTTP headers.
The only routes are `documentation/compiler/reference-v1` and
`documentation/python/reference-v1`. The existing network policy restricts them
to `https://clang.llvm.org/docs/` and `https://docs.python.org/3/`, applies answer
source filtering, and rechecks redirect destinations and resolved public IPs.

## Container LSP boundary

The concrete Docker SDK transport starts `/usr/bin/clangd` as `agent` inside the
specific task container. A fixed isolated Python helper (`-I -S`) creates a
private temporary compilation database and replaces itself with clangd using a
minimal environment. It disables project `.clangd` loading, query-driver
execution, clang-tidy, and background indexing. Read operations update only the
LSP document buffers; the adapter exposes no edits, code actions, formatting,
shell, arbitrary LSP methods, or host filesystem access.

Supply the controller-observed compilation database as `compile_commands` to
retain real project language, include, macro, optimization and warning flags.
`sanitize_compile_commands` fails closed on unknown flags, response files,
plugins, external include paths and unapproved compiler names. It does not run
the listed compiler. An absent database uses clangd's normal fallback command;
cross-translation-unit references are limited without background indexing.
The sanitized database digest is available as
`clangd.compile_database_sha256` for the frozen manifest.

Source reads run a fixed helper as `agent`, use `openat` with `O_NOFOLLOW` on every
path component, accept regular UTF-8 files up to 1 MiB, and are restricted to the
explicit source roots. LSP result locations must also remain in those roots.
The concrete exec socket decodes Docker stream framing before bounded LSP
Content-Length framing. Model-facing results are released only after a durable
result audit acknowledgement. Call `clangd.close()` during controller cleanup;
task-container shutdown remains the final process-lifetime boundary.

## Verification

Local tests use real byte sockets for Docker and LSP framing, the actual
documentation ASGI service, its real capability authorizer, and synthetic HTTP
upstreams. They cover exact native grants, additional inert native metadata,
duplicate metadata, request/result audit failures, source path restrictions,
external LSP locations, useful compilation flags, unsafe compiler flags, and
private/target/answer documentation denials.

`probe_clangd.py` exercises the installed clangd in an existing **synthetic** task
container labelled `org.xeus.cybergym.fixture=synthetic`. It reads an existing
fixture source only, dispatches all four operations, and saves results plus
container image and version evidence. It does not authorize an official task or
certify native provider correlation; the full native certification must exercise
these same endpoints with real provider-generated tool IDs.
