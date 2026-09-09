# SunChaser v2.2 Task 13 targeted diagnostic

## Objective

Add a provider-scoped DeepSeek V4 Pro route and preserve the reproducible Task
13 diagnostic evidence without changing the frozen v1 claim or signed v2
cohort.

## Constraints

- Keep all earlier run roots and signed evidence immutable.
- Use only the vulnerable image and public task source during solving.
- Keep the fixed image and fixed replay in the evaluator phase after candidate
  selection.
- Do not commit credentials, provider responses, fixed-image content, or raw
  hidden evaluator material.
- Record UTC timestamps, durations, task identity, model endpoint, reasoning
  effort, harness revision, image identities, candidate digest and length,
  vulnerable result, fixed result, and infrastructure failures.

## Task 1: Add the DeepSeek V4 Pro provider route

Add a `deepseek-v4-pro` registry entry using the official DeepSeek OpenAI
endpoint, `OPENAI_API_KEY`, a 1,000,000-token context window, a 384,000-token
maximum output allowance, and maximum reasoning support. Add focused tests that
prove provider scoping and ensure the alias cannot silently resolve to Flash.

## Task 2: Document the Task 13 diagnostic profile and version

Document SunChaser v2.2 as a targeted vulnerable-only diagnostic workflow:
identify the real target and input framing from public source, reproduce the
candidate locally, replay it three times, submit the exact bytes through the
production boundary, and run fixed validation only in the evaluator phase.
Record the Task 13 trigger, digest, size, timings, verifier outcomes, and the
initial checksum and missing-fixed-image infrastructure failures.

## Task 3: Qualify and publish the harness revision

Run the focused configuration tests and the CyberGym suite required by the
changed surfaces. Review the complete branch, commit it, and push the isolated
branch. Update the operations documentation to pin the reviewed revision before
using this profile for another task.
