# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Controller-only serial entrypoint for the two frozen native practice tasks."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from xeus_cybergym.canonical import canonical_json
from xeus_cybergym.ledger import Ed25519Signer, Ed25519Verifier

from .campaign_runner import MailboxNativeUi, run_campaign
from .native_ui_mailbox import NativeUiMailbox
from .practice_campaign import (
    PRACTICE_TASK_IDS,
    admit_practice,
    selected_assets_sha256,
    verify_practice_assets,
)
from .practice_native_driver import run as run_native_practice
from .practice_runtime_freeze import load_practice_freeze
from .practice_task_executor import NativePracticeTaskExecutor
from .practice_worker import PracticeNativeWorker
from .runtime_config import load_runtime_config
from .selected_practice_registry import SelectedPracticeRegistry
from .workspace import ControllerPaths
from .xeus_authority import XeusCampaignAuthority


def _path(ref: dict) -> Path:
    return Path(ref["path"])


def _evaluator_signer(freeze: dict) -> tuple[Ed25519Signer, Ed25519Verifier]:
    path = Path(freeze["evaluator_private_key_path"])
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 8192:
        raise RuntimeError("controller-only practice evaluator key is unavailable")
    private = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(private, Ed25519PrivateKey):
        raise RuntimeError("separate Ed25519 practice evaluator key required")
    public = private.public_key()
    pem = public.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if hashlib.sha256(pem).hexdigest() != freeze["evaluator_public_key_sha256"]:
        raise RuntimeError("practice evaluator public key differs from freeze")
    key_id = freeze["evaluator_key_id"]
    return Ed25519Signer(private_key=private, key_id=key_id), Ed25519Verifier({key_id: public})


def _paths(freeze: dict, selected: SelectedPracticeRegistry) -> ControllerPaths:
    root = Path(freeze["input_root"])
    return ControllerPaths(
        data_dir=root / "data",
        mask_map_path=_path(freeze["mask_map"]),
        server="http://registered-tool-gateway",
        staging_root=Path(freeze["staging_root"]),
        evidence_root=Path(freeze["evidence_root"]),
        harness_dir=root / "harness/agent-template",
        harness_manifest_path=_path(freeze["harness_manifest"]),
        harness_manifest_sha256=freeze["harness_manifest"]["sha256"],
        mask_map_sha256=freeze["mask_map"]["sha256"],
        generator_source=_path(freeze["generator_source"]),
        generator_sha256=freeze["generator_source"]["sha256"],
        official_registry=selected,
    )


def run_segment(*, freeze_path: Path, freeze_sha256: str, task_id: str) -> dict:
    """Run one task, leaving the second unprepared until the first is attested."""
    freeze = load_practice_freeze(freeze_path, freeze_sha256)
    if task_id not in PRACTICE_TASK_IDS:
        raise ValueError("only the authorized practice pair may run")
    donor = load_runtime_config(_path(freeze["donor_config"]))
    donor.verify_unchanged()
    selected = SelectedPracticeRegistry.load(
        _path(freeze["selected_manifest"]),
        expected_sha256=freeze["selected_manifest"]["sha256"],
    )
    paths = _paths(freeze, selected)
    observed_assets = verify_practice_assets(registry=selected, data_dir=paths.data_dir)
    if selected_assets_sha256(observed_assets) != freeze["selected_assets_sha256"]:
        raise RuntimeError("four official practice assets differ from frozen identities")
    private = donor.signing.load_private_key()
    controller_id = donor.signing.key_id
    signer = Ed25519Signer(private_key=private, key_id=controller_id)
    verifier = Ed25519Verifier({controller_id: private.public_key()})
    evaluator_signer, evaluator_verifier = _evaluator_signer(freeze)
    if freeze["evaluator_key_id"] == controller_id:
        raise RuntimeError("practice evaluator and controller must have distinct keys")
    authority = XeusCampaignAuthority({controller_id: private.public_key()})
    evidence_root = Path(freeze["evidence_root"])
    staging_root = Path(freeze["staging_root"])
    for root in (evidence_root, staging_root):
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if root.is_symlink() or root.resolve() != root:
            raise RuntimeError("practice controller root is linked or aliased")
    admission = {
        "schema_version": 1,
        "artifact_kind": "practice_admission",
        "scope": "native_practice_level1",
        "run_id": freeze["run_id"],
        "epoch": freeze["epoch"],
        "task_ids": list(PRACTICE_TASK_IDS),
        "max_parallel_tasks": 1,
        "freeze_sha256": freeze_sha256,
        "asset_hashes_sha256": freeze["asset_hashes"]["sha256"],
        "selected_assets_sha256": freeze["selected_assets_sha256"],
        "host_key_sha256": freeze["host_key_sha256"],
        "vscode_exe_sha256": freeze["vscode_exe_sha256"],
        "vscode_version": "1.140.0",
        "claude_extension_version": "2.1.289",
        "remote_host": "sunchaser-20260905.cinnamon-gamut.ts.net",
    }
    signed_admission = canonical_json(signer.sign(canonical_json(admission)).model_dump())
    state = admit_practice(
        signed_admission=signed_admission,
        authority=authority,
        run_id=freeze["run_id"],
        epoch=freeze["epoch"],
        evidence_root=evidence_root,
        expected_freeze_sha256=freeze_sha256,
        expected_asset_hashes_sha256=freeze["asset_hashes"]["sha256"],
        expected_selected_assets_sha256=freeze["selected_assets_sha256"],
        expected_host_key_sha256=freeze["host_key_sha256"],
        expected_vscode_exe_sha256=freeze["vscode_exe_sha256"],
    )
    if state.next_action().task_id != task_id:
        raise RuntimeError("requested practice task differs from signed ledger order")
    mailbox_root = evidence_root / "native-ui-mailbox"
    mailbox_root.mkdir(mode=0o700, exist_ok=True)
    mailbox = NativeUiMailbox(mailbox_root, run_id=state.run_id, signer=signer, verifier=verifier)

    def driver(current_task: str, *, on_prepared, stop):
        return run_native_practice(
            config_path=_path(freeze["donor_config"]),
            bindings_path=_path(freeze["bindings"]),
            public_ssh_key=_path(freeze["public_ssh_key"]),
            state=state,
            task_id=current_task,
            ssh_port=freeze["ssh_ports"][current_task],
            timeout=donor.budgets.task_wall_timeout_sec,
            controller_paths=paths,
            practice_freeze_sha256=freeze_sha256,
            signed_report_path=_path(freeze["signed_report"]),
            report_path=_path(freeze["report"]),
            signed_report_sha256=freeze["signed_report"]["sha256"],
            vulnerable_image_id=freeze["images"][current_task]["vulnerable"],
            fixed_image_id=freeze["images"][current_task]["fixed"],
            official_verifier_source=_path(freeze["official_verifier"]),
            official_verifier_sha256=freeze["official_verifier"]["sha256"],
            evaluator_signer=evaluator_signer,
            evaluator_verifier=evaluator_verifier,
            remote_alias=freeze["remote_alias"],
            on_prepared=on_prepared,
            stop=stop,
        )

    worker = PracticeNativeWorker(state=state, driver=driver)
    executor = NativePracticeTaskExecutor(
        state=state,
        worker=worker,
        mailbox=mailbox,
        signer=signer,
        verifier=verifier,
        remote_alias=freeze["remote_alias"],
    )
    try:
        run_campaign(
            state,
            executor,
            MailboxNativeUi(mailbox),
            action_for_state=lambda current: current.next_action(),
            stop_after_terminal_task_id=task_id,
        )
    finally:
        worker.abort()
    events = authority.read_verified_events(evidence_root, state.run_id)
    terminal = events[-1]
    if terminal.get("type") != "terminal" or terminal.get("task_id") != task_id:
        raise RuntimeError("practice segment lacks an independently verified terminal")
    return {
        "task_id": task_id,
        "run_id": state.run_id,
        "terminal_receipt_sha256": terminal["receipt_sha256"],
        "status": terminal["status"],
        "ledger_events": len(events),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--freeze", type=Path, required=True)
    parser.add_argument("--freeze-sha256", required=True)
    parser.add_argument("--task-id", choices=PRACTICE_TASK_IDS, required=True)
    args = parser.parse_args(argv)
    print(
        json.dumps(
            run_segment(
                freeze_path=args.freeze, freeze_sha256=args.freeze_sha256, task_id=args.task_id
            ),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
