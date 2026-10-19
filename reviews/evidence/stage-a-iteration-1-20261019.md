# Stage A iteration 1 — evidence submission

Scope: D-09, D-10, D-05 bookkeeping, and review-tree hygiene only. This is an executor self-report for watcher read-back, not a certification receipt or a claim that a gate passed.

## D-09 — image manifest

**Claimed status: blocked; unsigned candidate remains.** The controller-only candidate at `D:\GLM\scored-image-candidate-20261014\images.candidate.json` is 293,258 bytes and has SHA-256 `dd8bf1f943c37a7916fd8a1b08bc27ed6713fef68aa4e2626d22395cbdb5df49`. The observation and drift directories each contain 3,014 tag files plus one identity file. The drift identity binds that candidate digest to cohort SHA-256 `a708e62a91d3abf179621961926f9ab15ae8de9f8a99307448a41f4a58ddfa57`.

The established scored procedure does not accept a freestanding signature made with a new local key. `ScoredImageRegistry` requires the manifest digest from a separately signed `harness_lock`; scored campaign input verification requires an Ed25519 public-key trust registry with an independently supplied SHA-256 pin. The operator controls that trust pin and the exact runtime/source pin. A holder of the authorized signing key must bind this candidate digest into the reconciled harness lock under the operator-pinned trust registry. Those authority and pin decisions are not on record for this scored freeze. No signature or certification claim was produced. The earlier full drift pass is historical and does not prove current tag state.

## D-10 — fixed archive hydration

**Claimed status: evidence submitted; watcher read-back pending.** The exact ten ordered tasks came from the official registry, SHA-256 `59d1fa85f6a681fc481f3ac4e14331586b7c9548972fd7ca661787da9995a7ad`. The dataset checkout was clean at `bde190ded494e52bc684b66073b436c9d992c7c6`. Each `repo-fix.tar.gz` LFS pointer matched the registry's expected object ID and byte length. Each object was materialized with `git lfs smudge` into an isolated controller-private cache and an archive outside the Git checkout. A separate pass rehashed all ten final archive files and checked their sizes against the registry. The ten total 1,900,189,544 bytes.

Per-asset identities and hydration statuses: `reviews/evidence/stage-a-d10-fixed-assets-20261019.json`, SHA-256 `d47741cfee4e67174264573e786f5e0f01e4afe4a9fd41570eff6c0672966091`.

The hydrated bytes remain outside Git under `D:\GLM\scored-fixed-assets-20261019`. Only hash evidence is committed. No fixed-side evaluation, exit-code claim, scored run, or certification pass occurred. The watcher should verify the evidence JSON and private files directly; this report does not attest archive contents or a future host delivery route.

## D-05 — pin bookkeeping

**Claimed status: awaiting operator; unchanged.** No operator pin decision is recorded in the repository review notes. The runtime source pin remains `a3805ca1`; this iteration did not advance it.

## Review-tree hygiene

The watcher's three new notes are included verbatim in this commit: `reviews/codex-loop-contract_2026-10-19_v1.md` (SHA-256 `10f8347fb12581ee5f62276998acf0b065cc2419ad7c4f8172b00f087027e1d2`), `reviews/readiness-defects_2026-10-19_v3.md` (SHA-256 `d93187364b79444ee8d44d1dd7e5360375f1bf941248fea15f1c3318c343746e`), and `reviews/readiness-defects_2026-10-19_v4.md` (SHA-256 `1e7512699efa1f859eadbbe8e24f169251eb7d684375df8fdbcd2a06023f1f57`). The existing `/.pytest-*/` ignore rule remains in place; those directories were not touched.

No Python source file changed in the repository, so the changed-Python Ruff gate does not apply.
