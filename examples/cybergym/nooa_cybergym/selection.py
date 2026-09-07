# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Versioned final-selection metadata shared by writers and readers."""

from __future__ import annotations

from collections.abc import Mapping

SELECTION_GROUND_FIELDS = (
    "target_path",
    "unsafe_operation",
    "description_alignment",
    "crash_stability",
    "remaining_ambiguity",
)


def trim_selection_text(field_name: str, value: object) -> str:
    """Return normalized selection prose or fail closed on missing evidence."""
    if not isinstance(value, str) or not (trimmed := value.strip()):
        raise ValueError(f"{field_name} must be a trimmed non-empty string")
    return trimmed


def validate_selection_metadata(selection: Mapping[str, object]) -> None:
    """Validate versioned selection provenance while preserving v1 compatibility."""
    schema_version = selection.get("schema_version", 1)
    if type(schema_version) is not int or schema_version not in (1, 2):
        raise ValueError("selection schema_version must be 1 or 2")
    if schema_version == 1:
        return

    selection_source = selection.get("selection_source")
    grounds_status = selection.get("grounds_status")
    if selection_source not in ("model", "hard_timeout_recovery"):
        raise ValueError("selection_source must be 'model' or 'hard_timeout_recovery'")
    if grounds_status not in ("provided", "unavailable"):
        raise ValueError("grounds_status must be 'provided' or 'unavailable'")

    if (selection_source, grounds_status) == ("model", "provided"):
        for field_name in SELECTION_GROUND_FIELDS:
            value = selection.get(field_name)
            if not isinstance(value, str) or not value.strip() or value != value.strip():
                raise ValueError(f"{field_name} must be a trimmed non-empty string")
        return

    if (selection_source, grounds_status) == ("hard_timeout_recovery", "unavailable"):
        if any(field_name in selection for field_name in SELECTION_GROUND_FIELDS):
            raise ValueError("hard-timeout recovery must omit model selection grounds")
        return

    raise ValueError("invalid selection_source and grounds_status combination")
