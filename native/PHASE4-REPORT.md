# Phase 4: Codex request proofs and ingress

The Rust worker now retains one bootstrapped provider socket or pair of TLS application epochs through Codex continuations. `crates/provider-protocol` owns the Codex upgrade, request claim, masked-frame audit and response identity checks. `crates/native` owns the QuickSilver helper, proved-record release, Sponsor audit association, local WebSocket ingress and turn queue. The helper uses the existing authenticated auxiliary tunnel; Sponsor's proxy records directional proof bytes. The local adapter sends each authenticated provider event as it arrives, so an active turn remains cancelable.

The bridge selects Rust only when `CONCURRO_NATIVE_RUST_WORKER` explicitly names the worker binary. Python remains the operational default. The Rust worker rejects Claude HTTP/2 until phase 5.

## Local fixture evidence

The fixture uses the accepted external native runtime and a synthetic TLS provider. `native/phase4_fixture.py` asserts one provider connection, matching role transcript and session IDs, three provider response IDs, three prompt and usage associations, Sponsor audit hashes, and the reference proof-record counts. The real Codex CLI read a local marker through its shell tool and returned `{"answer":"TOOL_LOOP_DONE"}` in each pairing.

| Pairing or case | Result | Evidence |
| ---- | ---- | ---- |
| Python Sponsor / Rust Concurro, real CLI | 7 proved records, 3 responses, 1 bootstrap and provider connection | `/private/tmp/concurro-phase4-frozen-pr-cli/` |
| Rust Sponsor / Python Concurro, real CLI | Same counts and answer | `/private/tmp/concurro-phase4-frozen-rp-cli/` |
| Rust Sponsor / Rust Concurro, real CLI | Same counts and answer | `/private/tmp/concurro-phase4-frozen-rr-cli/` |
| Rust/Rust preflight and fragmented local WebSocket messages | HTTP 204 preflight, 3 fragmented requests, 4 proved records, completed tool loop | `/private/tmp/concurro-phase4-frozen-frag/` |
| Rust/Rust active cancellation with queued successor | `NATIVE_CANCEL codex_cancel`, worker exited before completing the queued turn | `/private/tmp/concurro-phase4-frozen-cancel/` |
| Two simultaneous Rust/Rust sessions | Both completed; distinct session IDs, 4 proofs and 1 provider connection each | `/private/tmp/concurro-phase4-frozen-par-a/`, `/private/tmp/concurro-phase4-frozen-par-b/` |
| Rust/Rust idle reconnect | Two local CLI sockets shared one provider connection across three linked responses | `/private/tmp/concurro-phase4-final-mask-reuse/` |
| Rust/Rust bootstrap disconnect | CLI closed before provider upgrade; both workers exited and left no process group | `/private/tmp/concurro-phase4-corrected-disconnect-final/` |
| Fresh Rust/Rust session after disconnect | Completed three linked responses and four proved records | `/private/tmp/concurro-phase4-corrected-isolation/` |
| Corrected Rust/Rust and Python Sponsor/Rust Concurro, real CLI | Each completed seven proved records and the tool loop | `/private/tmp/concurro-phase4-corrected-rr-cli/`, `/private/tmp/concurro-phase4-corrected-pr-cli/` |

Each successful directory has `comparison.json`, CLI summary, provider result, role reports and proof/MPC logs. The real CLI runs matched the reference's seven proved records; the compact synthetic runs matched four. The provider's response IDs matched Concurro's report, and the Sponsor's three proved-prompt hashes matched its three `NATIVE_AUDIT` lines. Sponsor report prompt text is redacted by default; proof traffic and Concurro-reported usage remain attached to the corresponding prompt.

Failed development evidence remains under `/private/tmp/concurro-phase4-rr-1/` through `rr-4/` and `rp-1/`: a harness import path, system OpenSSL subject formatting, an overly strict sequence-number assumption, a harness provider-output wait, and Python's identity/prelude ordering were corrected in that order. The later fixture cases have no hidden retries. No paid provider call was made.

The review corrections scope proof stderr and proxy tasks in a `JoinSet`, which aborts them on cancellation or error; stderr draining starts before helper stdin is written. Fake helper tests cover cancellation before and after readiness, nonzero failure, and exit without `REQUEST_OK`. The first CLI socket is monitored with a nonconsuming peek during bootstrap and provider upgrade wait. A canceled bootstrap exited both worker process groups, and an independent following session passed. Ingress now forwards compact, ASCII-escaped JSON while preserving parsed object order. Differential vectors against Python cover whitespace, non-ASCII, DEL, duplicate keys, ordinary `temperature`/`top_p` values, exponent padding, Python's fixed/scientific cutoffs, arbitrary-size positive/negative integers, and `-0`. The local ordered visitor uses `serde_json`'s additive `raw_value` API to retain integer lexemes; it avoids the workspace-wide `preserve_order` and `arbitrary_precision` features that could affect established control serialization. Malformed `u64` WebSocket lengths return an error instead of overflowing.

## Checks and boundary

- `cargo nextest run --workspace --all-targets --locked --status-level fail`: 102 passed, 2 skipped external-runtime local fixture tests.
- `cargo nextest run -p concurro-relay-provider-protocol --locked --status-level fail`: 4 passed independently.
- After the final JSON parity correction, focused provider-protocol/native library tests passed 16/16, and focused Clippy with `-D warnings` passed.
- The raw-value correction passed four provider-protocol tests; a workspace-feature build passed both JSON parity and the existing control-wire fixture (2/2 targeted tests).
- The accepted phase-3 mixed/bootstrap fixture was rerun: 10 local sessions across Codex and Claude passed in one nextest test. It ran before the final source-only extraction of the Codex request-head encoder; the final Codex fixture exercised that encoder.
- `cargo clippy -p concurro-relay-provider-protocol -p concurro-relay-native --all-targets --locked -- -D warnings`: passed.
- `cargo clippy --workspace --all-targets --locked`: passed with existing warnings in `verifier` and `relay` outside this phase.
- Targeted `rustfmt --check`, `git diff --check`, three Python cancellation regressions and Python fixture syntax checks passed.

Workspace `cargo fmt --all -- --check` remains blocked by formatting in accepted staged files outside phase 4. The phase-4 Rust files pass targeted rustfmt checks.
- Toolchain: `rustc 1.100.0 (0ef1bc386 2026-11-09)`. Final development worker SHA-256: `f9eea4030b6b432f0b3070bb3f284327dcd7309337af5bf26ab86f2d84d4b6c9`.

The accepted staged index tree is still `5a9b5ba1f61942db3efa8ad7b64ca89618bd1d04`; phase-4 changes are unstaged. No commit, push, production runtime switch or phase-5 Claude implementation was made. The historical intermittent prefix-MPC startup failure remains unresolved. This phase qualifies local Codex fixture behavior, not live-provider or packaged Rust-only operation.

## Primary acceptance

Accepted after reviewing runtime sequencing, mixed-role CLI evidence and corrections for proof-task cleanup, bootstrap disconnects, JSON normalization and frame-length overflow. Similar-code review covered 66 initial definitions and 24 correction definitions. Independently reproduced all 16 native/provider library tests (nextest `bc9f5fc4-67cf-41d9-b5ef-3e7e4c0c8bb7`) and checked the recorded proof/bootstrap/response counts. The final normalization-only changes have focused parity coverage; earlier CLI evidence remains identified separately. Packaging and live qualification remain phase 6.
