# Approved extra WSL image download: stopped before import

Date: 21 October 2026 (Australia/Sydney). The operator directly approved **one more download attempt** for the same pinned Ubuntu 24.04.5 WSL image, capped at ten minutes and 512 MiB, with the first failure retained. The image pin was `bb415d824822c4b878125729af451a5d18fb13d1cf5cbed9a7393ad64ac6039e`. This authorized continuing the [previously approved local setup](scored-subset-disposable-linux-proposal_2026-10-21.md) only after image verification. It did not authorize the held probe or production actions.

## What happened

The retained first-attempt receipts and zero-byte image were rehashed before the second attempt. A separate create-once attempt-2 claim kept the original ten-minute download and fifteen-minute setup deadlines. Its first child exited in 0.194349 seconds on `RuntimeError: worker is not the claimed child`. The parent recorded exit 1 and a stopped-before-import result. Source order and the receipts establish that this guard ran before the worker marker, image open and HTTPS call. The worker marker and attempt-2 image were absent. A local source-only subprocess diagnostic reproduced the parent-PID mismatch.

An independently reviewed, create-once recovery of that **same authorization and deadlines** checked the exact prior receipts, source hashes, unchanged first-attempt files, absent image/worker marker, current principal and absent distribution name. It used a private one-use pipe challenge in place of the unsupported parent-PID assertion. The worker claim preceded the sole actual HTTPS download invocation. The owned downloader exited 1 after **80.386322 seconds**, with:

```text
URLError: <urlopen error [WinError 10054] An existing connection was forcibly closed by the remote host>
```

The attempt-2 image is **zero bytes**. No image digest was verified. The parent retained a stopped-before-import failure receipt. No real Ubuntu image archive parsing or rewrite, WSL import, boot, in-Linux inventory, target termination, native listener probe, SunChaser SSH or model-provider request, or scored task occurred. The original setup's five receipts and zero-byte placeholder remain byte-for-byte unchanged. Root separately rehashed all 32 previously held source/test files and found them unchanged.

## Retained evidence

The approved workspace remains `D:\GLM\cybergym-disposable-linux\listener-proof-20261021`. Both image placeholders in `images` have zero bytes. The original `evidence` receipts remain intact. The new exact receipts include:

| File under `evidence` | SHA-256 | Meaning |
| --- | --- | --- |
| `attempt-2-claim.json` | `a2cb964dd99da00a7b3c3b32d9a05f9cff4114bd7bf12826abf246d0130f7905` | Original second-attempt clock and one-use claim |
| `attempt-2-download-process.stderr` | `56732dc34fab76ff192c1485bee0bcac39a36d3952bb93dc5375d8504d28981c` | Pre-network parent-PID guard failure |
| `attempt-2-failed.json` | `3b33cd2aea0775106d87261044a3fc8438397a88dfe4ac4ccff0d62b34b4556c` | No image after the local guard failure |
| `attempt-2-recovery-claim.json` | `c2cedfb88097fea0cc73af8b973d9d7ff2d0572143e8145f27273323223d197c` | Single guarded continuation of the same authorization |
| `attempt-2-recovery-download-process.json` | `37f025f9f1a175ae4680a7dd9a115c4bba94b6a16e794c810218289d151d3da7` | Owned downloader exit 1 and 80.386322-second duration |
| `attempt-2-recovery-download-process.stderr` | `a9181777a74ab685e5538dd35594ec6ca44efcd8463fa6ecc81be76571d38bcf` | Connection-closed error |
| `attempt-2-recovery-worker-failed.json` | `735f6ba4b1e57e7633124b4dce3664f415270f50766bb59540a7b8672c08d2bb` | Zero-byte partial image |
| `attempt-2-recovery-failed.json` | `521d8d86c3bde09c85e1fcc8ad00481627961e29d5786678271ea12bbffafe5e` | Final `STOPPED_BEFORE_IMPORT` latch |

The worker claim, process stdout and other attempt-2 receipts are also retained. No `attempt-2-recovery-verified.json`, archive, registration or stopped-state receipt exists. The process exit receipt establishes the owned downloader ended; no WSL distribution was created, so there was no owned registration to terminate.

## Source and next boundary

The ignored retry helper (`retry_attempt2.py`, SHA-256 `315f5516b2bc4bfd1c3af247273c795b8fe5a5368736062e0436f879b56ec70a`) passed six focused synthetic cases and Ruff/format checks. Independent review found no P1/P2 within its one-shot local download scope before it was used. The ignored recovery helper (`recover_attempt2.py`, SHA-256 `55313c67500885ed257c5f80b5a75fd437cc04e5dd5606ad3bbecd490ed311c9`) passed three focused synthetic cases and Ruff/format checks; independent review corrected its worker and parent deadline checks and root absence guard, then found no remaining P1/P2 within the same narrow scope. These are source checks, not Linux or production evidence.

The separate ignored continuation (`continue_attempt2.py`, SHA-256 `8ff409995489d033c28a333906945744a56d39e99a095c2c910176797a42ff1a`) passed eleven focused synthetic cases with Ruff/format clean. Independent read-only review found no P1/P2 within its trusted local setup scope. It requires the missing verified-image receipt and a later actual-image archive/OOBE review before import; it was never invoked. Its procedural review receipt is not a cryptographic authority or production gate.

The approved additional download has now failed and is consumed. Preserve both failed attempts and all partial/zero-byte files. Do not retry, substitute an image or host, reset either deadline, remove a latch, import, boot or run the held probe under this approval. A further network attempt would need a new, separately bounded direct decision and retention-aware plan. This checkpoint establishes no Linux platform proof, twelve-gate PASS or scored readiness; the last reviewed committed source component remains `42a33385`.
