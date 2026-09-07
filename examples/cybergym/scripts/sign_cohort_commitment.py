#!/usr/bin/env python3
"""Sign a reviewed canonical cohort request on the independent authority host."""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from nooa_cybergym.cohort_commitment import canonical_json


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--public-keys-output", type=Path, required=True)
    args = parser.parse_args()
    request_bytes = args.request.read_bytes()
    request = json.loads(request_bytes)
    if canonical_json(request) != request_bytes:
        raise SystemExit("commitment request must be exact canonical JSON")
    encoded_seed = os.environ.get("SUNCHASER_COHORT_AUTHORITY_SIGNING_SEED")
    key_id = os.environ.get("SUNCHASER_COHORT_AUTHORITY_KEY_ID", "sunchaser-cohort-authority-v1")
    if not encoded_seed:
        raise SystemExit("SUNCHASER_COHORT_AUTHORITY_SIGNING_SEED is not configured")
    seed = base64.b64decode(encoded_seed, validate=True)
    if len(seed) != 32:
        raise SystemExit("authority signing seed must encode exactly 32 bytes")
    private = Ed25519PrivateKey.from_private_bytes(seed)
    envelope = {
        "algorithm": "Ed25519",
        "key_id": key_id,
        "payload": base64.b64encode(request_bytes).decode("ascii"),
        "signature": base64.b64encode(private.sign(request_bytes)).decode("ascii"),
    }
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    for path, content in (
        (args.output, canonical_json(envelope)),
        (args.public_keys_output, canonical_json({key_id: base64.b64encode(public).decode()})),
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
