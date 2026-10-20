# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Full-cohort controller metadata for the explicitly budgeted ten-task path.

This boundary reads metadata and generic harness files only. It neither stages
task assets nor provides a launch entrypoint. The later signed launch-config and
worker adapters must bind these paths and call ``verify_current`` immediately
before preparing the task. Merely possessing a material object is not admission.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, replace
from pathlib import Path

from .budgeted_subset_admission import BudgetedSubsetState
from .campaign import _attest, _cohort_inputs, _digest, _expect_hash, _tasks_json_order
from .cohort import (
    FrozenAssetRegistry,
    FrozenTaskInput,
    read_harness_manifest,
    verify_harness_tree,
)
from .run_resource_budget import RunResourceBudget
from .scored_image_registry import ScoredImageRegistry, ScoredImages
from .scored_launch_config import _absolute, _hash_file
from .subset_dry_run_admission import OFFICIAL_SUBSET_TASK_IDS, PREVIOUSLY_EXPOSED_TASK_IDS
from .workspace import ControllerPaths


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True, slots=True)
class VerifiedSubsetCohort:
    """Actual signed full-cohort and tasks bytes with their immutable identities."""

    signed_cohort: bytes = field(repr=False)
    tasks_json: bytes = field(repr=False)
    cohort_sha256: str
    tasks_json_sha256: str
    task_ids: tuple[str, ...]
    asset_hashes_sha256: str
    benchmark_commit: str
    dataset_commit: str
    mask_map_sha256: str
    generator_sha256: str
    harness_manifest_sha256: str

    def reverify(self, state: BudgetedSubsetState) -> None:
        current = verify_subset_cohort(
            state, signed_cohort=self.signed_cohort, tasks_json=self.tasks_json
        )
        if current != self:
            raise RuntimeError("verified subset full-cohort identity changed")


def verify_subset_cohort(
    state: BudgetedSubsetState, *, signed_cohort: bytes, tasks_json: bytes
) -> VerifiedSubsetCohort:
    """Attest the complete 1,507-task cohort without creating or changing state."""
    if (
        type(state) is not BudgetedSubsetState
        or type(signed_cohort) is not bytes
        or not 0 < len(signed_cohort) <= 1024 * 1024
        or type(tasks_json) is not bytes
        or not 0 < len(tasks_json) <= 64 * 1024 * 1024
    ):
        raise RuntimeError("exact subset state and bounded actual cohort/tasks bytes required")
    state._readiness()
    digest = _sha(signed_cohort)
    _expect_hash(digest, state.preview.cohort_sha256, "subset full cohort")
    harness = _attest(state.authority, "harness_lock", state.signed_freeze)
    _expect_hash(harness.get("cohort_sha256"), digest, "freeze full cohort")
    payload = _attest(state.authority, "cohort", signed_cohort)
    task_ids = _tasks_json_order(tasks_json)
    _expect_hash(payload.get("tasks_json_sha256"), _sha(tasks_json), "tasks.json")
    if type(payload.get("task_ids")) is not list or tuple(payload["task_ids"]) != task_ids:
        raise RuntimeError("signed full cohort differs from tasks.json order")
    if (
        state.task_ids != OFFICIAL_SUBSET_TASK_IDS
        or state.preview.previously_exposed_task_ids != PREVIOUSLY_EXPOSED_TASK_IDS
        or not set(OFFICIAL_SUBSET_TASK_IDS).issubset(task_ids)
    ):
        raise RuntimeError("approved ten-task membership or exposure disclosure differs")
    asset_digest, benchmark, dataset, mask_digest = _cohort_inputs(payload)
    generator = payload.get("generator_sha256")
    manifest = payload.get("harness_manifest_sha256")
    if not _digest(generator) or not _digest(manifest):
        raise RuntimeError("signed cohort generator or harness identity is incomplete")
    return VerifiedSubsetCohort(
        signed_cohort=signed_cohort,
        tasks_json=tasks_json,
        cohort_sha256=digest,
        tasks_json_sha256=_sha(tasks_json),
        task_ids=task_ids,
        asset_hashes_sha256=asset_digest,
        benchmark_commit=benchmark,
        dataset_commit=dataset,
        mask_map_sha256=mask_digest,
        generator_sha256=generator,
        harness_manifest_sha256=manifest,
    )


def _paths(
    state: BudgetedSubsetState,
    cohort: VerifiedSubsetCohort,
    paths: ControllerPaths,
    asset_manifest: Path,
    image_manifest: Path,
) -> None:
    if type(paths) is not ControllerPaths or paths.official_registry is not None:
        raise RuntimeError("exact controller paths without a caller-supplied registry required")
    for root in (paths.data_dir, paths.staging_root, paths.evidence_root, paths.harness_dir):
        if not isinstance(root, Path) or _absolute(str(root)) != root or not root.is_dir():
            raise RuntimeError("available absolute unaliased controller directory required")
    files = (
        paths.mask_map_path,
        paths.generator_source,
        paths.harness_manifest_path,
        asset_manifest,
        image_manifest,
    )
    for path in files:
        if not isinstance(path, Path) or _absolute(str(path)) != path:
            raise RuntimeError("absolute unaliased controller metadata path required")
    if paths.evidence_root != state.evidence_root:
        raise RuntimeError("controller evidence root differs from signed subset admission")
    if paths.server != "http://registered-tool-gateway":
        raise RuntimeError("controller tool gateway route differs")
    for trusted in (paths.data_dir, paths.evidence_root, paths.harness_dir, *files):
        if (
            trusted == paths.staging_root
            or trusted.is_relative_to(paths.staging_root)
            or paths.staging_root.is_relative_to(trusted)
        ):
            raise RuntimeError("controller staging root overlaps trusted metadata or evidence")
    for path, supplied, expected, label in (
        (paths.mask_map_path, paths.mask_map_sha256, cohort.mask_map_sha256, "mask map"),
        (paths.generator_source, paths.generator_sha256, cohort.generator_sha256, "generator"),
        (
            paths.harness_manifest_path,
            paths.harness_manifest_sha256,
            cohort.harness_manifest_sha256,
            "harness manifest",
        ),
    ):
        _expect_hash(supplied, expected, label)
        _expect_hash(_hash_file(path, label), expected, label)
    # Registry loaders independently re-read and check their exact digest too.
    _expect_hash(
        _hash_file(asset_manifest, "asset manifest"), cohort.asset_hashes_sha256, "asset manifest"
    )
    manifest = read_harness_manifest(
        paths.harness_manifest_path, expected_sha256=cohort.harness_manifest_sha256
    )
    verify_harness_tree(paths.harness_dir, manifest)


def _registries(
    state: BudgetedSubsetState,
    cohort: VerifiedSubsetCohort,
    paths: ControllerPaths,
    asset_manifest: Path,
    image_manifest: Path,
) -> tuple[tuple[FrozenTaskInput, ...], tuple[tuple[str, ScoredImages], ...], str]:
    cohort.reverify(state)
    _paths(state, cohort, paths, asset_manifest, image_manifest)
    assets = FrozenAssetRegistry.load(
        asset_manifest,
        expected_sha256=cohort.asset_hashes_sha256,
        expected_benchmark_commit=cohort.benchmark_commit,
        expected_dataset_commit=cohort.dataset_commit,
    )
    if assets.task_ids != cohort.task_ids:
        raise RuntimeError("full asset manifest order differs from signed cohort")
    freeze = _attest(state.authority, "harness_lock", state.signed_freeze)
    images_digest = freeze.get("scored_images_sha256")
    if not _digest(images_digest):
        raise RuntimeError("signed full scored image manifest pin required")
    images = ScoredImageRegistry.load(
        image_manifest, expected_sha256=images_digest, task_ids=cohort.task_ids
    )
    return (
        tuple(assets.inputs_for(task) for task in cohort.task_ids),
        tuple((task, images.images_for(task)) for task in cohort.task_ids),
        images_digest,
    )


@dataclass(frozen=True, slots=True, repr=False)
class BudgetedSubsetMaterial:
    """Immutable complete metadata; defensive registry copies never grant launch."""

    state: BudgetedSubsetState
    cohort: VerifiedSubsetCohort
    asset_manifest_path: Path
    image_manifest_path: Path
    scored_images_sha256: str
    _controller_paths: ControllerPaths
    _asset_entries: tuple[FrozenTaskInput, ...]
    _image_rows: tuple[tuple[str, ScoredImages], ...]

    @property
    def resource_budget(self) -> RunResourceBudget:
        return self.state.resource_budget

    @property
    def allowed_task_ids(self) -> tuple[str, ...]:
        return OFFICIAL_SUBSET_TASK_IDS

    @property
    def previously_exposed_task_ids(self) -> tuple[str, ...]:
        return PREVIOUSLY_EXPOSED_TASK_IDS

    @property
    def assets(self) -> FrozenAssetRegistry:
        return FrozenAssetRegistry(self._asset_entries)

    @property
    def images(self) -> ScoredImageRegistry:
        return ScoredImageRegistry(self._image_rows)

    @property
    def paths(self) -> ControllerPaths:
        return replace(self._controller_paths, official_registry=self.assets)

    def _preparing(self, task_id: str) -> dict:
        if type(task_id) is not str or task_id not in self.allowed_task_ids:
            raise RuntimeError("only the approved committed preparation may stage")
        self.resource_budget.check_active()
        action = self.state.next_action()
        if action.kind != "observe_preparing" or action.task_id != task_id:
            raise RuntimeError("only the current committed preparation may stage")
        binding = self.state.preparation_binding(task_id)
        if binding["prepared"] is not None:
            raise RuntimeError("only the current committed preparation may stage")
        return binding

    def verify_current(self, task_id: str) -> ControllerPaths:
        """Re-attest current preparation ownership and all metadata before staging.

        This method does not consume the preparation commitment or grant a retry.
        The runner remains responsible for calling prepare only after its own
        freshly acknowledged commitment; recovery can only observe prior effects.
        """
        if (
            type(self.state) is not BudgetedSubsetState
            or type(self.resource_budget) is not RunResourceBudget
        ):
            raise RuntimeError("exact subset state and resource store required")
        if type(self.cohort) is not VerifiedSubsetCohort:
            raise RuntimeError("verified full subset cohort required")
        binding = self._preparing(task_id)
        entries, images, digest = _registries(
            self.state,
            self.cohort,
            self._controller_paths,
            self.asset_manifest_path,
            self.image_manifest_path,
        )
        if (entries, images, digest) != (
            self._asset_entries,
            self._image_rows,
            self.scored_images_sha256,
        ):
            raise RuntimeError("verified controller metadata changed")
        if self._preparing(task_id) != binding:
            raise RuntimeError("committed preparation changed during metadata verification")
        return self.paths


def load_budgeted_subset_material(
    state: BudgetedSubsetState,
    *,
    cohort: VerifiedSubsetCohort,
    paths: ControllerPaths,
    asset_manifest_path: Path,
    image_manifest_path: Path,
) -> BudgetedSubsetMaterial:
    """Load full registries without staging, dispatching or creating ledger events."""
    if (
        type(state) is not BudgetedSubsetState
        or type(state.resource_budget) is not RunResourceBudget
    ):
        raise RuntimeError("exact subset state and resource store required")
    if type(cohort) is not VerifiedSubsetCohort:
        raise RuntimeError("verified full subset cohort required")
    entries, images, digest = _registries(
        state, cohort, paths, asset_manifest_path, image_manifest_path
    )
    return BudgetedSubsetMaterial(
        state=state,
        cohort=cohort,
        asset_manifest_path=asset_manifest_path,
        image_manifest_path=image_manifest_path,
        scored_images_sha256=digest,
        _controller_paths=paths,
        _asset_entries=entries,
        _image_rows=images,
    )
