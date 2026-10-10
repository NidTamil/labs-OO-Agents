# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""One controller-owned Level-1 practice task through the native Claude runtime.

The signed practice ledger gates the first model request. Fixed-side ARVO
images remain private until the stopped parent's one final is locked.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import asdict, dataclass
from pathlib import Path
from uuid import uuid4

import docker
from cryptography.hazmat.primitives import serialization
from xeus_cybergym.canonical import canonical_json
from xeus_cybergym.ledger import Ed25519Signer, Ed25519Verifier, SignedEnvelope

from .capability_inventory import load_captured_native_schemas, load_frozen_bindings
from .capability_runtime import CapabilityRuntime, DockerPathObserver
from .container import start_task_container
from .gbrain_bridge import GBrainControllerBridge
from .gbrain_writer import OracleMemoryWriter
from .host_boundary_runtime import HostBoundaryRuntime
from .native_first_request import NativeFirstRequestWitness
from .native_launcher import NativeLaunchAuthority, build_launch_manifest
from .native_process import frozen_hook_verifier, frozen_parent_verifier
from .native_start_intent import wait_start_intent
from .practice_arvo_evaluator import PracticeArvoEvaluator
from .practice_campaign import (
    PRACTICE_TASK_IDS,
    PracticeState,
    selected_assets_sha256,
    verify_practice_assets,
)
from .practice_capability_permit import PracticeCapabilityPermit
from .practice_native_workspace import overlay_native_template
from .practice_vulnerable_runtime import OfficialArvoRecipe
from .runtime_config import NativeRuntimeConfig, load_runtime_config
from .runtime_custody import TaskRuntimeContext
from .services_runtime import NativeServices, SealedRoutes
from .synthetic_native_driver import (
    _memory_guard_binding,
    _observe,
    _PostOracleMemoryBudget,
    _quiesce_and_stop,
    _selected,
    _staged_assets,
    _stopped_tool_dispositions,
    _verified_primary_provider,
)
from .synthetic_workspace import write_new
from .workspace import ControllerPaths, prepare_workspace


@dataclass(frozen=True, slots=True)
class PreparedPracticeLaunch:
    task_id: str
    launch_id: str
    attempt_id: str
    remote_alias: str
    ssh_port: int
    evidence: Path
    launch_authority: NativeLaunchAuthority
    witness: NativeFirstRequestWitness


def validate_request(config: NativeRuntimeConfig, *, state: PracticeState, task_id: str):
    if type(config) is not NativeRuntimeConfig or type(state) is not PracticeState:
        raise ValueError("verified native donor and signed practice state required")
    if task_id not in PRACTICE_TASK_IDS or state.next_action().task_id != task_id:
        raise ValueError("only the current signed practice task is admitted")
    config.verify_unchanged()
    return task_id


def practice_task_root(controller_paths: ControllerPaths, slug: str) -> Path:
    """Keep the agent-visible workspace beside, never inside, trusted staging."""
    if (
        type(controller_paths) is not ControllerPaths
        or type(slug) is not str
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", slug) is None
        or controller_paths.staging_root.parent != controller_paths.evidence_root.parent
    ):
        raise ValueError("one separated practice controller run root required")
    return controller_paths.staging_root.parent / slug


def run(
    *,
    config_path: Path,
    bindings_path: Path,
    public_ssh_key: Path,
    state: PracticeState,
    task_id: str,
    ssh_port: int,
    timeout: int,
    controller_paths: ControllerPaths,
    practice_freeze_sha256: str,
    signed_report_path: Path,
    report_path: Path,
    signed_report_sha256: str,
    vulnerable_image_id: str,
    fixed_image_id: str,
    official_verifier_source: Path,
    official_verifier_sha256: str,
    evaluator_signer,
    evaluator_verifier,
    remote_alias: str,
    on_prepared: Callable[[PreparedPracticeLaunch], None],
    stop: threading.Event,
) -> bytes:
    config = load_runtime_config(config_path)
    validate_request(config, state=state, task_id=task_id)
    if (
        type(ssh_port) is not int
        or not 1024 <= ssh_port <= 65535
        or not 60 <= timeout <= config.budgets.task_wall_timeout_sec
        or type(controller_paths) is not ControllerPaths
        or type(stop) is not threading.Event
        or not callable(on_prepared)
        or not re.fullmatch(r"[a-z][a-z0-9-]{1,63}", remote_alias)
        or practice_freeze_sha256 != state._root_event()["freeze_sha256"]
    ):
        raise ValueError("frozen signed practice worker inputs required")
    observed_assets = verify_practice_assets(
        registry=controller_paths.official_registry, data_dir=controller_paths.data_dir
    )
    if selected_assets_sha256(observed_assets) != state._root_event()["selected_assets_sha256"]:
        raise RuntimeError("selected practice assets differ from signed admission")
    bindings = load_frozen_bindings(bindings_path, config.registry)
    captured_schemas = load_captured_native_schemas(bindings_path, config.registry)
    binding_hash = hashlib.sha256(Path(bindings_path).read_bytes()).hexdigest()
    key = public_ssh_key.read_text(encoding="ascii").strip()
    if not re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/]+={0,2}(?: [^\s\x00-\x1f]+)?", key):
        raise ValueError("one dedicated SSH public key required")
    client = docker.from_env()
    if client.images.get(config.image_id).id != config.image_id:
        raise RuntimeError("native image pin changed")
    for image_id in (vulnerable_image_id, fixed_image_id):
        if type(image_id) is not str or not re.fullmatch(r"sha256:[a-f0-9]{64}", image_id):
            raise ValueError("pinned ARVO image IDs required")
        if client.images.get(image_id).id != image_id:
            raise RuntimeError("practice ARVO image pin changed")
    if vulnerable_image_id == fixed_image_id:
        raise ValueError("distinct private vulnerable and fixed images required")
    observed_runtime = client.containers.run(
        config.image_id,
        command="/opt/sunchaser/native-runtime.json",
        entrypoint="/usr/bin/cat",
        network_disabled=True,
        read_only=True,
        remove=True,
    )
    if observed_runtime != config.artifacts["native_runtime"].read_bytes():
        raise RuntimeError("native image/runtime bytes differ from frozen config")
    run_id = state.run_id
    slug = run_id + "-" + task_id.replace(":", "-")
    root = practice_task_root(controller_paths, slug)
    evidence = controller_paths.evidence_root / slug
    prepared = prepare_workspace(
        task_id=task_id,
        agent_id=run_id + "-" + task_id.replace(":", "-"),
        controller_paths=controller_paths,
        task_root=root,
    )
    template = config.repo_root / "examples/cybergym/leaderboard/agent-template"
    template_files = {
        item.path.relative_to(template).as_posix(): (item.path, item.sha256)
        for item in config.harness_files
        if item.path.is_relative_to(template)
    }
    stage = overlay_native_template(
        prepared,
        template_files=template_files,
        evidence=evidence,
        run_id=run_id,
        practice_freeze_sha256=practice_freeze_sha256,
    )
    if os.name == "posix" and os.geteuid() == 0:
        os.chown(stage.root / "output", 1001, 1001)
        (stage.root / "output").chmod(0o700)
    workflow_hashes, skills = _staged_assets(stage)
    private_key = config.signing.load_private_key()
    public_keys = {config.signing.key_id: private_key.public_key()}
    signer = Ed25519Signer(private_key=private_key, key_id=config.signing.key_id)
    verifier = Ed25519Verifier(public_keys)
    evaluator = PracticeArvoEvaluator(
        run_id=run_id,
        epoch=state.epoch,
        task_id=task_id,
        evidence_dir=stage.evidence,
        vulnerable_image_id=vulnerable_image_id,
        fixed_image_id=fixed_image_id,
        official_verifier_source=official_verifier_source,
        official_verifier_sha256=official_verifier_sha256,
        docker_client=client,
        controller_signer=signer,
        controller_verifier=verifier,
        evaluator_signer=evaluator_signer,
        evaluator_verifier=evaluator_verifier,
    )
    pem = (
        private_key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode("ascii")
    )
    trust = stage.evidence / "native-launch-trust.json"
    write_new(trust, canonical_json({config.signing.key_id: pem}), 0o444)
    network = client.networks.create(
        "cg-practice-" + uuid4().hex[:12],
        driver="bridge",
        internal=True,
        labels={"org.xeus.cybergym.boundary": "task-v1"},
    )
    sealed = SealedRoutes(config.network_policy)
    with ExitStack() as stack:
        stack.callback(network.remove)
        boundary = stack.enter_context(
            HostBoundaryRuntime(
                docker_client=client,
                network=network,
                policy=config.network_policy,
                handlers=sealed.handlers,
                audit_path=stage.evidence / "gateway.jsonl",
            )
        )
        stack.callback(sealed.close)
        task = start_task_container(
            stage.root,
            stage.evidence,
            network.name,
            key,
            expected_network_id=network.id,
            image=config.image_id,
            docker_client=client,
            host_gateway_sentinel=boundary,
            native_trust_file=trust,
            ssh_port=ssh_port,
            startup_timeout_seconds=120,
        )
        container = client.containers.get(task.container_id)
        stack.callback(container.remove, force=True)
        stack.callback(task.close_relay)
        uid = int(_observe(container, "id", "-u"))
        if uid != 1001:
            raise RuntimeError("native agent UID differs from pinned output owner")
        launch_id = "practice-" + uuid4().hex
        attempt_id = "attempt-" + uuid4().hex
        manifest = build_launch_manifest(
            scope="official",
            run_id=run_id,
            task_id=task_id,
            launch_id=launch_id,
            ordinal=PRACTICE_TASK_IDS.index(task_id) + 1,
            harness_sha256=hashlib.sha256(stage.manifest_bytes).hexdigest(),
            task_manifest_bytes=stage.manifest_bytes,
            file_hashes=stage.file_hashes,
            container_id=container.id,
            hostname=_observe(container, "hostname"),
            uid=uid,
            pid_namespace=_observe(container, "readlink", "/proc/self/ns/pid"),
            mount_namespace=_observe(container, "readlink", "/proc/self/ns/mnt"),
            vscode_version=config.versions.vscode,
            claude_extension_version=config.versions.claude_extension,
            claude_extension_sha256=config.native_identity["claude_extension_sha256"],
            native_launch_url="http://registered-tool-gateway/native-launch",
        )
        envelope = canonical_json(signer.sign(canonical_json(manifest)).model_dump())
        write_new(stage.root / ".sunchaser/launch.json", envelope, 0o444)
        launch = NativeLaunchAuthority.from_signed_envelope(envelope, public_keys, stage.evidence)
        peer = boundary.peers[task.container_ip]
        zai = config.credentials.zai.read_text()
        deepseek = config.credentials.deepseek.read_text()
        context = stack.enter_context(
            TaskRuntimeContext(
                stage.evidence,
                task_id=task_id,
                attempt_id=attempt_id,
                secrets=(zai, deepseek),
            )
        )
        observer = DockerPathObserver(client.api, container_id=container.id)
        terms = ("arvo", "input", "crash")
        permit = PracticeCapabilityPermit.from_signed_report(
            state=state,
            task_id=task_id,
            registry=config.registry,
            image_id=config.image_id,
            report_path=report_path,
            signed_report_path=signed_report_path,
            expected_signed_report_sha256=signed_report_sha256,
            verifier=verifier,
        )
        capabilities = CapabilityRuntime(
            registry=config.registry,
            expected_registry_sha256=config.registry.digest,
            bindings=bindings,
            peer=peer,
            task_id=task_id,
            attempt_id=attempt_id,
            audit=context.audit,
            path_observer=observer,
            boundary_check=lambda p: boundary._peer(p.source_ip) == p,
            working_directory="/workspace",
            execution_paths=("/workspace/src", "/workspace/output", "/home/agent", "/tmp", "/run"),
            execution_routes=tuple(sorted(config.network_policy.allowed_logical_endpoints)),
            model_id="glm-5.3",
            structural_terms=terms,
            practice_permit=permit,
            observed_image_id=container.image.id,
            network_policy=config.network_policy,
            forbidden_memory_identifiers=("arvo:", "cve-", "github.com"),
            frozen_workflows=workflow_hashes,
            frozen_skills=skills,
            content_digest=observer.digest,
        )
        services = stack.enter_context(
            NativeServices(
                run_id=run_id,
                task_id=task_id,
                attempt_id=attempt_id,
                launch_id=launch_id,
                evidence=stage.evidence,
                output=stage.root / "output",
                peer=peer,
                docker_client=client,
                container=container,
                capabilities=capabilities,
                context=context,
                model_policy=config.model_policy,
                network_policy=config.network_policy,
                launch_authority=launch,
                zai_token=zai,
                deepseek_key=deepseek,
                gbrain_command=config.gbrain.command(config.credentials.gbrain_read),
                gbrain_models=dict(config.gbrain.allowed_models),
                signer=signer,
                verifier=verifier,
                public_keys=public_keys,
                task_brief=(stage.root / "description.txt").read_bytes().decode("utf-8"),
                structural_terms=terms,
                vulnerable_recipe=OfficialArvoRecipe(task_id, vulnerable_image_id),
                captured_schemas=captured_schemas,
                workspace_manifest=stage.evidence / "task-manifest.json",
                workspace_root=stage.root,
                hook_process_verifier=frozen_hook_verifier(
                    inspect=client.api.inspect_container(container.id),
                    peer=peer,
                    audit=context.audit,
                ),
                parent_process_verifier=frozen_parent_verifier(
                    inspect=client.api.inspect_container(container.id),
                    peer=peer,
                    launch_authority=launch,
                    audit=context.audit,
                ),
            )
        )
        sealed.seal(services.handlers)

        def start_automatic_lanes():
            selected = services.start_automatic_lanes(
                level1_facts=("Official ARVO Level-1 vulnerable input task",),
                structural_terms=terms,
            )
            write_new(
                stage.root / "automatic-memory.json",
                canonical_json(
                    {"schema_version": 1, "selected": [asdict(item) for item in selected]}
                ),
                0o444,
            )
            return selected

        # No automatic model or memory request occurs until the signed ledger
        # has a durable started event and its exact start intent is observed.
        connection = {
            "scope": "native_practice_level1",
            "run_id": run_id,
            "task_id": task_id,
            "attempt_id": attempt_id,
            "launch_id": launch_id,
            "practice_freeze_sha256": practice_freeze_sha256,
            "donor_configuration_sha256": config.freeze_sha256,
            "capability_registry_sha256": config.registry.digest,
            "capability_bindings_sha256": binding_hash,
            "image_id": config.image_id,
            "container_id": container.id,
            "ssh_host_port": task.host_ssh_port,
            "known_hosts": str(stage.evidence / "known_hosts"),
            "launch_receipt": str(launch.launch_dir / "launcher-receipt.json"),
            "workspace": str(stage.root),
            "evidence": str(stage.evidence),
            "status": "awaiting_signed_practice_start_intent",
        }
        write_new(stage.evidence / "connection.json", canonical_json(connection))
        witness = NativeFirstRequestWitness(
            launch_authority=launch,
            attempt_id=attempt_id,
            model_audit=stage.evidence / "model-requests.jsonl",
            policy_sha256=config.model_policy.digest,
            expected_model="glm-5.3",
        )
        on_prepared(
            PreparedPracticeLaunch(
                task_id,
                launch_id,
                attempt_id,
                remote_alias,
                task.host_ssh_port,
                stage.evidence,
                launch,
                witness,
            )
        )
        deadline = time.monotonic() + timeout
        wait_start_intent(
            stage.evidence,
            verifier=verifier,
            run_id=run_id,
            task_id=task_id,
            attempt_id=attempt_id,
            launch_id=launch_id,
            timeout_seconds=max(0, deadline - time.monotonic()),
            stopped=stop.is_set,
        )
        start_automatic_lanes()
        while not stop.wait(1):
            if boundary.failed.is_set() or not context.active:
                raise RuntimeError("task boundary or shared budget failed")
            if _selected(services.finalizer):
                break
            if time.monotonic() >= deadline:
                raise TimeoutError("native practice final was not selected before deadline")
        else:
            raise RuntimeError("native practice run interrupted before final")
        stop_started = time.monotonic()
        remaining_at_stop = context.budget.remaining_seconds()
        _quiesce_and_stop(services, container)
        stopped_dispositions = _stopped_tool_dispositions(
            stage.evidence, final_declared=_selected(services.finalizer)
        )
        native_hooks = services.hooks.summary()
        if native_hooks["pending_tools"] != sum(
            count
            for name, count in stopped_dispositions.items()
            if name != "sessions_closed_by_controller_stop"
        ):
            raise RuntimeError("native hook terminal reconciliation differs from raw observations")
        context.audit.record({"event": "controller_stop_hook_dispositions", **stopped_dispositions})
        lock = services.finalizer.lock_after_stop(lambda: container.status == "exited")
        terminal = evaluator.evaluate(lock, solver_stopped=lambda: container.status == "exited")
        terminal_payload = json.loads(verifier.verify(SignedEnvelope.model_validate_json(terminal)))
        episode = None
        try:
            binding = _memory_guard_binding(stage.evidence / "memory-catalog.signed.json", verifier)
            prior_budget = context.budget.snapshot()
            with GBrainControllerBridge(
                config.gbrain.command(config.credentials.gbrain_write, writer=True),
                budget=_PostOracleMemoryBudget(
                    context.audit,
                    prior_requests=prior_budget["requests"],
                    prior_auxiliary_requests=prior_budget["glm_and_memory_auxiliary_requests"],
                    remaining_seconds=max(0, remaining_at_stop - (time.monotonic() - stop_started)),
                ),
                audit=context.audit,
                allowed_models=dict(config.gbrain.allowed_models),
            ) as bridge:
                episode = OracleMemoryWriter(
                    bridge=bridge,
                    attest_receipt=lambda raw: state.authority.attest_signed(
                        "terminal_receipt", raw
                    ),
                    audit=context.audit,
                    evidence_root=stage.evidence,
                    run_id=run_id,
                    epoch=state.epoch,
                    expected_guard_binding_sha256=binding,
                ).publish_practice(
                    terminal,
                    task_id=task_id,
                    solver_stopped=lambda: container.status == "exited",
                )
        except Exception as error:
            context.audit.record(
                {"event": "practice_memory_episode_failed", "error_type": type(error).__name__}
            )
        result = {
            "scope": "native_practice_level1",
            "run_id": run_id,
            "task_id": task_id,
            "practice_freeze_sha256": practice_freeze_sha256,
            "candidate_sha256": lock.sha256,
            "oracle_true": terminal_payload["oracle_true"],
            "terminal_receipt_sha256": hashlib.sha256(terminal).hexdigest(),
            "provider_dispatched": _verified_primary_provider(
                stage.evidence / "model-requests.jsonl"
            ),
            "memory_episode_written": episode is not None,
            "memory_episode_content_hash": (
                episode["native_content_hash"] if episode is not None else None
            ),
            "native_hooks": native_hooks,
            "stopped_tool_dispositions": stopped_dispositions,
            "boundary_failed": boundary.failed.is_set(),
        }
        write_new(stage.evidence / "result.json", canonical_json(result))
        return terminal
