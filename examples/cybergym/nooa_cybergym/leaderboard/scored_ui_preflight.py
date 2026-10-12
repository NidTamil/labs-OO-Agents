# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Construct the scored controller's dormant native-UI mailbox before admission."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .campaign_runner import MailboxNativeUi
from .native_ui_mailbox import NativeUiMailbox
from .scored_campaign_inputs import ScoredLaunchPreview
from .scored_launch_config import ScoredSignerPreflight


@dataclass(frozen=True, slots=True)
class ScoredUiPreflight:
    mailbox: NativeUiMailbox = field(repr=False)
    ui: MailboxNativeUi = field(repr=False)


def prepare_previewed_scored_ui(
    preview: ScoredLaunchPreview, signers: ScoredSignerPreflight
) -> ScoredUiPreflight:
    """Bind one signed run to the controller-custody UI channel without a Send."""
    if (
        type(preview) is not ScoredLaunchPreview
        or type(signers) is not ScoredSignerPreflight
        or preview.state.authority is not preview.authority
        or signers.config.get("run_id") != preview.state.run_id
        or signers.config.get("epoch") != preview.state.epoch
        or signers.config.get("paths", {}).get("evidence_root") != str(preview.state.evidence_root)
    ):
        raise RuntimeError("scored UI mailbox differs from signed run")
    root = Path(signers.config["paths"]["mailbox_root"])
    if not root.is_absolute() or root.is_symlink() or not root.is_dir() or root.resolve() != root:
        raise RuntimeError("absolute controller-custody UI mailbox root required")
    mailbox = NativeUiMailbox(
        root,
        run_id=preview.state.run_id,
        signer=signers.controller_signer,
        verifier=signers.controller_verifier,
    )
    return ScoredUiPreflight(mailbox, MailboxNativeUi(mailbox))
