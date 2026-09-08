# SunChaser GLM-5.3 and Kimi K3 diagnostic retake

## Purpose

Run the two frozen v1 failures through an alternate model configuration without
changing the signed 12/14 result:

- Task 8: `arvo:3848`
- Task 13: `arvo:62886`

These runs are diagnostics. Their results must remain separate from both the
frozen v1 claim and the signed `l1-v2-heldout-001` cohort.

## Model configuration

- Primary control model: `glm-5.3` through the Z.AI Coding Plan endpoint.
- Primary reasoning mode: maximum, represented by enabled deep thinking and the
  run-level `reasoning_effort=max` record.
- Finder and expander lanes: the existing isolated DeepSeek V4 Flash aliases.
- Stagnation escalation reviewer: `kimi-k3` through the Moonshot international
  OpenAI-compatible endpoint, also at maximum reasoning effort.
- Kimi credential environment: `KIMI_API_KEY`, injected after worker creation.

## Isolation and evidence

Each retake runs on a separate DigitalOcean worker cloned from snapshot
`244504239`, with its own verifier, runtime credential file, shell owner, agent
container, and run root. The workers may not receive fixed images, patch data,
previous PoCs, or previous trajectories. The Kimi credential is stored in
Windows Credential Manager and is never committed or included in the snapshot.

The run record must capture the exact harness commit and image ID, both model
aliases and endpoints, reasoning mode, credential fingerprints, task input
hashes, timestamps, submission counts, crash-family counts, terminal state, and
post-run private fixed-build validation. Retake results are reported as a new
diagnostic comparison only.

## Acceptance checks

1. Unit tests prove that GLM-5.3 primary routing uses its own provider config.
2. Unit tests prove that Kimi K3 uses the Moonshot endpoint and `KIMI_API_KEY`.
3. `KIMI_API_KEY` is forwarded into the agent container and both provider hosts
   are present in the firewall allowlist.
4. A live Kimi K3 function-call smoke returns the expected tool call.
5. The immutable runner image has the exact new Git revision as its OCI label.
6. Both diagnostic workers start from clean task state and run concurrently.

## First diagnostic outcome

The first alternate run remains diagnostic evidence only. Task 8 produced seven
vulnerable-build crashes in one family, but its selected PoC also failed on the
fixed build. Task 13 produced 616 submissions and no crash family; after its
prompt exceeded 900,000 tokens, the requested output allowance eventually fell
to one token. Neither task changed the frozen 12/14 v1 result.

## Second diagnostic revision

The rerun uses the same GLM-5.3 primary, DeepSeek finder lanes, and Kimi K3
reviewer with four additional gates:

- fixed-build verification fails on HTTP errors and incomplete verifier rows;
- Kimi is invoked at 100 submissions even when no crash family exists;
- every eligible final stop needs a separate specific and unambiguous Kimi
  verdict;
- provider-reported context pressure forces archival before output room drops
  below 16,384 tokens.

Task 8 and Task 13 must run on clean workers with the new immutable image. The
result is a new diagnostic comparison and cannot revise earlier signed evidence.
