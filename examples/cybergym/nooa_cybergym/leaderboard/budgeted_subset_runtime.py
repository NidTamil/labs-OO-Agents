# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Bind an exact subset preparation to verified donor tools and full metadata.

No task is staged or launched here. Only public donor inputs are revalidated.
Private donor acquisition remains a separate worker boundary that must validate
the independently pinned role and private paths before the eager donor loader.
The donor's signing key is never read, returned or promoted by this adapter.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType

from .budgeted_subset_admission import BudgetedSubsetState
from .budgeted_subset_capabilities import BudgetedSubsetCapabilityAdmission
from .budgeted_subset_material import BudgetedSubsetMaterial
from .campaign import _attest, _digest, _expect_hash
from .capabilities import CapabilityRegistry
from .capability_inventory import load_captured_native_schemas, load_scored_binding_provenance
from .cohort import _clean_git_commit, verify_harness_tree
from .deepseek import AlternateModelPolicy
from .model_gateway import PRIMARY_CODING_PLAN_BASE_URL, PRIMARY_MODEL, ModelPolicy
from .primary_takeover import PrimaryTakeoverPolicy
from .runtime_config import NativeRuntimeConfig, RuntimeConfigError, VerifiedFile, _harness_files
from .scored_image_registry import ScoredImageRegistry


def _source(donor: NativeRuntimeConfig, expected: str) -> None:
    try:
        actual = _clean_git_commit(donor.repo_root)
    except Exception:
        raise RuntimeError("subset donor source checkout is unavailable or dirty") from None
    if actual != expected:
        raise RuntimeError("subset donor source differs from signed source commit")


def _templates(donor: NativeRuntimeConfig) -> tuple[tuple[str, VerifiedFile], ...]:
    """Derive templates from the pinned manifest, never caller-provided hashes."""
    manifest = donor.artifacts.get("harness_manifest")
    if type(manifest) is not VerifiedFile:
        raise RuntimeError("pinned donor harness manifest required")
    actual = _harness_files(donor.repo_root, manifest)
    if donor.harness_files != actual:
        raise RuntimeError("donor harness inventory differs from pinned manifest")
    root = donor.repo_root / "examples/cybergym/leaderboard/agent-template"
    items = tuple(
        sorted(
            (pin.path.relative_to(root).as_posix(), pin)
            for pin in actual
            if pin.path.is_relative_to(root)
        )
    )
    if not items or "CLAUDE.md" not in dict(items):
        raise RuntimeError("frozen donor template inventory must include CLAUDE.md")
    verify_harness_tree(root, {name: pin.sha256 for name, pin in items})
    return items


@dataclass(frozen=True, slots=True, repr=False)
class BudgetedSubsetRuntimeBinding:
    """Read-only runtime inputs; reverify immediately before preparation effects."""

    state: BudgetedSubsetState = field(compare=False)
    material: BudgetedSubsetMaterial = field(compare=False)
    admission: BudgetedSubsetCapabilityAdmission = field(compare=False)
    task_id: str
    attempt_id: str
    preparation_id: str
    source_commit: str
    donor_configuration_sha256: str
    bindings_sha256: str
    registry: CapabilityRegistry
    bindings: tuple
    _captured_schemas: tuple[tuple[str, str], ...]
    _alternate_json: bytes
    _template_inventory: tuple[tuple[str, VerifiedFile], ...]
    _donor: NativeRuntimeConfig = field(compare=False)
    _bindings_path: Path
    _observed_image_id: str

    @property
    def images(self) -> ScoredImageRegistry:
        return self.material.images

    @property
    def captured_schemas(self) -> dict[str, str]:
        return dict(self._captured_schemas)

    @property
    def model_policy(self) -> ModelPolicy:
        return ModelPolicy(
            PRIMARY_MODEL,
            AlternateModelPolicy.model_validate_json(self._alternate_json),
            self.registry.digest,
            PRIMARY_CODING_PLAN_BASE_URL,
            primary_takeover=PrimaryTakeoverPolicy(),
        )

    @property
    def template_files(self) -> Mapping[str, tuple[Path, str]]:
        return MappingProxyType(
            {name: (pin.path, pin.sha256) for name, pin in self._template_inventory}
        )

    def verify_current(self) -> None:
        current = bind_budgeted_subset_runtime(
            donor=self._donor,
            state=self.state,
            material=self.material,
            task_id=self.task_id,
            attempt_id=self.attempt_id,
            admission=self.admission,
            registry=self.registry,
            bindings_path=self._bindings_path,
            observed_image_id=self._observed_image_id,
        )
        if current != self:
            raise RuntimeError("verified subset runtime changed")


def bind_budgeted_subset_runtime(
    *,
    donor: NativeRuntimeConfig,
    state: BudgetedSubsetState,
    material: BudgetedSubsetMaterial,
    task_id: str,
    attempt_id: str,
    admission: BudgetedSubsetCapabilityAdmission,
    registry: CapabilityRegistry,
    bindings_path: Path,
    observed_image_id: str,
) -> BudgetedSubsetRuntimeBinding:
    """Require actual source, signed preparation and independently captured tools."""
    if (
        type(donor) is not NativeRuntimeConfig
        or type(state) is not BudgetedSubsetState
        or type(material) is not BudgetedSubsetMaterial
        or type(admission) is not BudgetedSubsetCapabilityAdmission
        or type(registry) is not CapabilityRegistry
        or material.state is not state
        or admission._state is not state
        or admission.registry_sha256 != registry.digest
        or task_id not in material.allowed_task_ids
        or observed_image_id != donor.image_id
        or observed_image_id != admission.image_id
    ):
        raise RuntimeError(
            "exact matching subset donor, state, material and capability admission required"
        )
    if (
        donor.schema_version != 2
        or type(donor.primary_takeover_policy) is not PrimaryTakeoverPolicy
    ):
        raise RuntimeError("explicit schema-two donor with approved primary takeover required")
    material.verify_current(task_id)
    preparation = state.preparation_binding(task_id)
    admission.verify_runtime_current(
        task_id=task_id,
        attempt_id=attempt_id,
        registry=registry,
        observed_image_id=observed_image_id,
    )
    donor.verify_public_unchanged()
    _source(donor, state.preview.source_commit)
    policy = ModelPolicy(
        PRIMARY_MODEL,
        donor.alternate_policy,
        registry.digest,
        PRIMARY_CODING_PLAN_BASE_URL,
        primary_takeover=donor.primary_takeover_policy,
    )
    harness = _attest(state.authority, "harness_lock", state.signed_freeze)
    if (
        harness.get("source_commit") != state.preview.source_commit
        or harness.get("epoch") != state.epoch
        or harness.get("donor_configuration_sha256") != donor.freeze_sha256
        or harness.get("model_policy_sha256") != policy.digest
        or state.preview.budget.model_policy_sha256 != policy.digest
        or harness.get("capability_registry_sha256") != registry.digest
        or harness.get("scored_images_sha256") != material.scored_images_sha256
        or material.images.task_ids != material.cohort.task_ids
    ):
        raise RuntimeError(
            "signed subset source, donor, model, registry or full-image binding differs"
        )
    binding_sha = harness.get("capability_bindings_sha256")
    if not _digest(binding_sha):
        raise RuntimeError("signed subset binding pin required")
    try:
        source = Path(bindings_path)
        pin = VerifiedFile(source, binding_sha, source.stat().st_size)
        pin.verify()
    except (OSError, RuntimeConfigError):
        raise RuntimeError("subset binding differs from signed harness lock") from None
    bindings = load_scored_binding_provenance(
        source, component_registry=donor.registry, scored_registry=registry
    )
    schemas = load_captured_native_schemas(source, donor.registry)
    template_inventory = _templates(donor)
    pin.verify()
    donor.verify_public_unchanged()
    _source(donor, state.preview.source_commit)
    if _templates(donor) != template_inventory:
        raise RuntimeError("subset template inventory changed during binding")
    material.verify_current(task_id)
    admission.verify_runtime_current(
        task_id=task_id,
        attempt_id=attempt_id,
        registry=registry,
        observed_image_id=observed_image_id,
    )
    if state.preparation_binding(task_id) != preparation:
        raise RuntimeError("subset preparation changed during runtime binding")
    _expect_hash(
        policy.digest, state.preview.budget.model_policy_sha256, "subset runtime model policy"
    )
    return BudgetedSubsetRuntimeBinding(
        state=state,
        material=material,
        admission=admission,
        task_id=task_id,
        attempt_id=attempt_id,
        preparation_id=preparation["preparation_id"],
        source_commit=state.preview.source_commit,
        donor_configuration_sha256=donor.freeze_sha256,
        bindings_sha256=binding_sha,
        registry=registry,
        bindings=bindings,
        _captured_schemas=tuple(sorted(schemas.items())),
        _alternate_json=donor.alternate_policy.model_dump_json().encode(),
        _template_inventory=template_inventory,
        _donor=donor,
        _bindings_path=source,
        _observed_image_id=observed_image_id,
    )
