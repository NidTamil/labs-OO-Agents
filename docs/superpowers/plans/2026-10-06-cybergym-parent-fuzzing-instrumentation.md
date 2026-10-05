# Parent-fuzzing instrumentation (#1) — review notes

Branch: `review/cybergym-parent-fuzzing`. Two commits, both reviewable-only (no re-freeze
applied here):

1. **Surface Bash/fuzzing in the task contract** — `agent-template/CLAUDE.md`.
2. **Offline bottleneck report** — `scripts/fuzzing_bottleneck_report.py` +
   `tests/test_fuzzing_bottleneck_report.py`.

## Why

The capability registry already grants the parent the `Bash` tool in the isolated
container (`capability_inventory.py:211`), and the image ships `clang`+libFuzzer, `gdb`,
`python3`. But the contract routed all execution through `run_test`, so the agent
hand-crafts candidates instead of fuzzing to discover crashes. Commit 1 tells it to build
an instrumented harness and fuzz, with `run_test` still the authoritative check and
`finalizer` the single final.

That unlocks the capability. The open strategic question — do we also need parallel
execution children (#2)? — should be answered with data, not assumption. The decisive
datum is whether a single fuzzing lane already saturates the cores (a swarm would only
contend) or leaves them idle / is hypothesis-starved (a swarm could help). That datum
(fuzzer workers vs cores, exec/s, crash-found) is NOT in the audit evidence: the native
hook deliberately hashes raw tool I/O (`native-hook.js`), and `native-hooks.sqlite` keeps
ordering/counts only, no wall-clock or content. So the agent must emit it.

## What the agent emits (contract-required)

One JSON record per fuzzing campaign at `/workspace/output/fuzz-stats/<name>.json`
(inside the agent's existing write scope; harmless to scoring, which locks one candidate):

```json
{
  "schema_version": 1,
  "role": "parent",
  "name": "length-header-hypothesis",
  "workers": 8,
  "cores_available": 8,
  "elapsed_sec": 600.0,
  "total_execs": 48000000,
  "exec_per_sec": 80000.0,
  "crash_found": false
}
```

## The report

```
python -m scripts.fuzzing_bottleneck_report --evidence-dir <run-output-root> [--cores N] [--json]
```
(run with `PYTHONPATH=examples/cybergym`). `classify_bottleneck()` is pure and unit-tested;
verdicts:

| verdict | meaning | #2 implication |
|---|---|---|
| `no_fuzzing_observed` | no fuzz-stats written | agent isn't fuzzing; fix #1 wording/capability, not a swarm |
| `under_saturated_single_lane` | workers/cores < 0.75 | raise libFuzzer `-workers` first; swarm would only contend |
| `diversity_or_serialization_bound` | cores saturated, no crash, >=2 hypotheses | parallel exec lanes (#2) plausibly help |
| `single_saturated_lane_no_crash` | saturated, no crash, 1 hypothesis | try more diverse harnesses first, then maybe #2 |
| `not_bottlenecked` | a crash was found | #2 unnecessary for this profile |

Run it across the cohort; the distribution of verdicts is the #2 decision. Build #2 only
if `diversity_or_serialization_bound` dominates the unsolved tasks.

## To confirm in review

- Field names in the fuzz-stats schema are a proposal; keep them or rename, but keep
  CLAUDE.md and the loader's `_REQUIRED_FIELDS` in sync.
- `/workspace/output/fuzz-stats/` is within `_DEFAULT_WRITE_ROOTS` (`/workspace/output`), so
  no capability change is needed for the agent to write it. Confirm the oracle/finalizer
  ignore non-candidate files there (they select one candidate by path+hash, so extra files
  are inert).

## Certification note

`CLAUDE.md` is a certified template; its SHA is pinned in the signed launch manifest
(`file_hashes`). This branch is a reviewable diff only — apply through the normal
re-stage/re-freeze, and re-certify if the cohort was already certified against the prior
template hash. The analyzer and its test are tooling (`scripts/`, `tests/`), not staged
into the container, so they do not affect `harness_sha256` (= `sha256(stage.manifest_bytes)`).
