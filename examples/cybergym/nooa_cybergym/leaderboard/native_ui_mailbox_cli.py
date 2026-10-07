# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Read-only SSH entrypoint for a signed, controller-custody native UI mailbox.

Only the POSIX controller publishes commands. The Windows poller invokes this
entrypoint over authenticated Tailscale SSH to fetch one signed command or to
return a bounded UI acknowledgement and its exact attempted-Send audit bytes.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from xeus_cybergym.canonical import canonical_json
from xeus_cybergym.ledger import Ed25519Verifier

from .native_ui_mailbox import NativeUiMailbox


def _public_key(path: Path) -> Ed25519PublicKey:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ValueError("absolute regular controller public key required")
    raw = path.read_bytes()
    if not 0 < len(raw) <= 4096:
        raise ValueError("bounded controller public key required")
    key = load_pem_public_key(raw)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Ed25519 controller public key required")
    return key


def _canonical_base64(value: str) -> bytes:
    if type(value) is not str:
        raise ValueError("Base64 audit bytes required")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("canonical Base64 audit bytes required") from None
    if base64.b64encode(raw).decode("ascii") != value:
        raise ValueError("canonical Base64 audit bytes required")
    return raw


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mailbox-root", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--public-key-pem", type=Path, required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("action", choices=("poll", "ack"))
    args = parser.parse_args(argv)
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9:_.-]{0,127}", args.key_id) is None:
        parser.error("bounded controller key ID required")
    box = NativeUiMailbox(
        args.mailbox_root,
        run_id=args.run_id,
        signer=None,
        verifier=Ed25519Verifier({args.key_id: _public_key(args.public_key_pem)}),
    )
    if args.action == "poll":
        envelope = box.pending()
        result = {
            "pending": envelope is not None,
            "envelope_base64": (
                base64.b64encode(envelope).decode("ascii") if envelope is not None else None
            ),
        }
    else:
        raw = sys.stdin.buffer.read(16385)
        if not 0 < len(raw) <= 16384:
            raise ValueError("bounded UI acknowledgement required")
        message = json.loads(raw)
        if (
            type(message) is not dict
            or canonical_json(message) != raw
            or set(message) != {"command_id", "status", "ui_audit_sha256", "ui_audit_base64"}
        ):
            raise ValueError("canonical UI acknowledgement request required")
        audit = message["ui_audit_base64"]
        result = box.acknowledge(
            message["command_id"],
            status=message["status"],
            ui_audit_sha256=message["ui_audit_sha256"],
            ui_audit_bytes=_canonical_base64(audit) if audit is not None else None,
        )
    sys.stdout.buffer.write(canonical_json(result) + b"\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
