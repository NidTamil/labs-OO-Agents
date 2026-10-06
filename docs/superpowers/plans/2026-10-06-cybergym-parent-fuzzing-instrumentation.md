# Parent-fuzzing instrumentation (#1) — review notes

Branch: `review/cybergym-parent-fuzzing`. Reviewable only; no re-freeze applied here.

## Why

The capability registry grants the parent the `Bash` tool in the isolated container
(`capability_inventory.py:211`), and the image ships `clang`+libFuzzer, `gdb`, and
`python3`. The task contract previously routed all execution through `run_test`.
The template now directs the agent to build an instrumented harness and fuzz inside
the task container. `run_test` remains the authoritative vulnerable build-and-run
check; `finalizer` still selects exactly one final candidate and stops the solver.

The unresolved question is whether parallel execution children (#2) improve the
unsolved cohort. The agent can report worker counts and fuzzing progress, but a
configured worker count does not show that any core was busy. The agent writes
`/workspace/output/fuzz-stats/` itself, so even plausible CPU fields in those
records would not be trusted controller evidence. The native hook hashes raw tool
I/O, and its SQLite evidence records calls rather than CPU use. No controller-owned
CPU/cgroup usage series is currently available to this report.

## Agent-reported campaign diagnostics

The template asks for one JSON record per fuzzing campaign at
`/workspace/output/fuzz-stats/<name>.json`:

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

The loader requires every field the template names (`role`, `workers`,
`cores_available`, `elapsed_sec`, `total_execs`, `exec_per_sec`, `crash_found`)
and schema version 1. It skips unreadable or incomplete files. The values remain
self-reported diagnostics, including `crash_found`; an agent-reported crash does
not replace `run_test` or the private final evaluation.

## Offline report and current decision limit

```
python -m scripts.fuzzing_bottleneck_report --evidence-dir <run-output-root> [--cores N] [--json]
```

Run with `PYTHONPATH=examples/cybergym`. `--cores` is an operator capacity hint,
not a CPU measurement. The report exposes reported worker, crash, and execution
counts under `reported_*` metric names. Its `cpu_saturation` is `null`.

| verdict | meaning | #2 implication |
|---|---|---|
| `no_fuzzing_observed` | no valid agent stats records were found; this does not prove fuzzing did not run | inspect trusted execution evidence |
| `insufficient_telemetry` | agent stats exist, but actual CPU usage and trustworthiness are unknown | no recommendation yet |

The old workers/cores saturation formula and the verdicts derived from it were
removed. Neither `workers >= cores` nor multiple self-reported hypotheses shows
that the parent is CPU saturated or serialization bound. The report cannot decide
whether to build #2 from the current evidence.

To make that decision, add a controller-owned measurement outside the agent's
write scope: timestamped CPU/cgroup usage deltas over known fuzzing intervals,
the corresponding elapsed wall time, and the effective CPU quota/cpuset. Associate
measurements with the run and account for other processes in the task container.
Only then compare sustained actual CPU usage with available capacity and correlate
it with trusted execution and outcome evidence across the unsolved cohort. That
controller collection is not implemented in this branch.

## Boundaries and certification

`/workspace/output/fuzz-stats/` is within the existing agent write scope and its
records are telemetry, never candidates. Source and scratch stay under
`/workspace/src`; candidates and result files stay under `/workspace/output`.
The finalizer selects a single path and exact SHA-256/byte length, stops the
solver, and evaluates the locked candidate privately. Nothing in this report
changes leakage boundaries or finalizer behavior.

`CLAUDE.md` is a certified template whose SHA is pinned in the signed launch
manifest (`file_hashes`). Apply the template change through normal re-stage and
re-freeze, and re-certify if the cohort used the previous template hash. The
analyzer and its test are host tooling, not staged into the task container, so
they do not affect `harness_sha256` (= `sha256(stage.manifest_bytes)`).
