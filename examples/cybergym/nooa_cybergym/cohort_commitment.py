"""Verify an authority-issued commitment to a held-out cohort and harness policy."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class CohortCommitmentError(ValueError):
    """A held-out cohort commitment is absent, malformed, or untrusted."""


def canonical_json(value: object) -> bytes:
    """Encode the shared canonical JSON form used by commitment signatures."""
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise CohortCommitmentError(f"commitment contains invalid JSON values: {exc}") from exc


def commitment_payload(
    *,
    cohort_id: str,
    cohort_manifest_sha256: str,
    expected_task_ids: list[str] | tuple[str, ...],
    harness_revision: str,
    runner_image_id: str,
    harness_policy_sha256: str,
) -> dict[str, object]:
    """Build the exact payload an independent evaluation authority must sign."""
    return {
        "schema_version": 1,
        "commitment_type": "sunchaser-heldout-cohort",
        "cohort_id": cohort_id,
        "evaluation_mode": "heldout",
        "cohort_manifest_sha256": cohort_manifest_sha256,
        "expected_task_ids": list(expected_task_ids),
        "harness_revision": harness_revision,
        "runner_image_id": runner_image_id,
        "harness_policy_sha256": harness_policy_sha256,
    }


def _canonical_b64(value: object) -> bytes:
    if not isinstance(value, str):
        raise CohortCommitmentError("authority commitment contains invalid Base64")
    try:
        encoded = value.encode("ascii")
        decoded = base64.b64decode(encoded, validate=True)
    except (UnicodeError, binascii.Error, ValueError) as exc:
        raise CohortCommitmentError("authority commitment contains invalid Base64") from exc
    if base64.b64encode(decoded) != encoded:
        raise CohortCommitmentError("authority commitment contains noncanonical Base64")
    return decoded


def verify_cohort_commitment(
    commitment_path: Path,
    authority_keys_path: Path,
    *,
    expected_payload: dict[str, object],
) -> dict[str, str]:
    """Verify an Ed25519 envelope against externally supplied authority keys."""
    try:
        envelope = json.loads(commitment_path.read_text(encoding="utf-8"))
        registry = json.loads(authority_keys_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CohortCommitmentError(
            f"cannot load cohort authority material: {type(exc).__name__}"
        ) from exc
    if not isinstance(envelope, dict) or set(envelope) != {
        "algorithm",
        "key_id",
        "payload",
        "signature",
    }:
        raise CohortCommitmentError("authority commitment must be an exact signed envelope")
    if envelope["algorithm"] != "Ed25519":
        raise CohortCommitmentError("authority commitment algorithm must be Ed25519")
    key_id = envelope["key_id"]
    if not isinstance(key_id, str) or not key_id:
        raise CohortCommitmentError("authority commitment key_id must be nonempty")
    if not isinstance(registry, dict) or key_id not in registry:
        raise CohortCommitmentError("authority commitment key_id is not trusted")
    payload_bytes = _canonical_b64(envelope["payload"])
    signature = _canonical_b64(envelope["signature"])
    try:
        public_raw = _canonical_b64(registry[key_id])
        public = Ed25519PublicKey.from_public_bytes(public_raw)
        public.verify(signature, payload_bytes)
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise CohortCommitmentError("authority commitment signature verification failed") from exc
    try:
        payload = json.loads(payload_bytes)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CohortCommitmentError("authority commitment payload is not valid JSON") from exc
    if payload != expected_payload or payload_bytes != canonical_json(expected_payload):
        raise CohortCommitmentError("authority commitment does not match this cohort and policy")
    return {
        "cohort_commitment_sha256": hashlib.sha256(canonical_json(envelope)).hexdigest(),
        "cohort_authority_key_id": key_id,
    }
