# Phase 5: Claude HTTP/2 request proofs and ingress

The Rust worker now handles successive Claude requests on one authenticated HTTP/2 provider connection. The provider protocol module owns deterministic first-request HPACK encoding, indexed later HEADERS, HTTP/2 frame and flow-control state, bounded HPACK response decoding, and SSE extraction. The native worker retains the phase-4 TLS record proof path, associates each Sponsor audit with the matching request, and streams authenticated response fragments to local HTTP/1.1 clients. The operational default remains Python; `CONCURRO_NATIVE_RUST_WORKER` explicitly selects Rust per role.

## Local fixture evidence

`native/phase5_fixture.py` uses the accepted external native runtime, a local TLS fixture provider and local clients. Each successful run checks the matching session and transcript IDs, one protected bootstrap and provider connection, two requests on streams 1 and 3, one indexed later HEADERS, two Sponsor prompt/usage associations, matching usage across roles, and successful responses. No paid provider call was made.

| Pairing or case | Result | Evidence |
| ---- | ---- | ---- |
| Python Sponsor / Rust Concurro, synthetic Claude client | 2 responses, 8 proved records | `/private/tmp/concurro-phase5-pr-synthetic-1/` |
| Rust Sponsor / Python Concurro, synthetic Claude client | 2 responses, 8 Sponsor proofs | `/private/tmp/concurro-phase5-rp-synthetic-1/` |
| Rust Sponsor / Rust Concurro, synthetic Claude client | 2 responses, 8 proved records | `/private/tmp/concurro-phase5-rr-synthetic-3/` |
| Rust/Rust synthetic fixture with final cross-role assertions | 2 responses, 8 proved records; stream IDs, usage and status rechecked | `/private/tmp/concurro-phase5-rr-synthetic-final-2/` |
| Rust/Rust success after HPACK and error-response corrections | 2 responses, 8 proved records; one indexed later HEADERS | `/private/tmp/concurro-phase5-rr-corrected-1/` |
| Python Sponsor / Rust Concurro, real local Claude CLI | 2 responses, 8 proved records | `/private/tmp/concurro-phase5-pr-cli-2/` |
| Rust Sponsor / Python Concurro, real local Claude CLI | 2 responses, 8 Sponsor proofs | `/private/tmp/concurro-phase5-rp-cli-1/` |
| Rust Sponsor / Rust Concurro, real local Claude CLI | 2 responses, 8 proved records | `/private/tmp/concurro-phase5-rr-cli-1/` |
| Rust/Rust 70 KB first request | 2 responses, 13 proved records; HTTP/2 flow-control window exercised | `/private/tmp/concurro-phase5-rr-large-1/` |
| Rust/Rust bootstrap disconnect | Both workers exited nonzero; no worker process group remained | `/private/tmp/concurro-phase5-bootstrap-cancel-1/` |
| Rust/Rust streaming disconnect | 398 authenticated SSE bytes arrived before stream completion; both workers exited nonzero with no worker process group | `/private/tmp/concurro-phase5-stream-cancel-1/` |
| Fresh Rust/Rust session after cancellation | 2 responses, 8 proved records | `/private/tmp/concurro-phase5-after-cancel-1/` |
| Rust/Rust Codex CLI regression | Existing tool loop completed with `TOOL_LOOP_DONE`, 7 proved records | `/private/tmp/concurro-phase5-codex-regression-1/` |
| Rust/Rust provider JSON 401 | Client read complete chunked body; `provider-error.json` matched status, type and body SHA-256; both workers exited | `/private/tmp/concurro-phase5-error401-1/` |
| Rust/Rust provider JSON 429 | Same checks for rate-limit response | `/private/tmp/concurro-phase5-error429-1/` |

The HTTP/2 unit tests cover the phase-0 indexed request bytes, Sponsor audit, fragmented HEADERS/CONTINUATION with Huffman fields, DATA and control frames, flow-control windows, stream reset, invalid continuation, and the decoded header-list boundary. HPACK decoding checks each field with its 32-byte overhead before retaining it. The streaming cancellation and JSON error fixtures extend the existing delayed provider. Development failures remain in `/private/tmp/concurro-phase5-rr-synthetic-1/`, `rr-synthetic-2/`, and `pr-cli-1/`: the first two exposed a fixture Python dependency path; the third used an absent Claude CLI path. The corrected fixture runs are separate artifacts.

## Checks and boundary

- Before review corrections, `cargo nextest run --workspace --all-targets --locked --status-level fail`: 108 passed, 2 skipped external-runtime fixture tests.
- Focused provider-protocol and native library nextest after review corrections: 23 passed.
- Focused Clippy with `-D warnings`: passed.
- Corrected development worker SHA-256: `513d391e5596d4f51f756e0e15b94fa8f72d22e86a082ed29beab077fb4f163f`.

The accepted phase-4 index tree remains `a516bd9fc9efba1f076f72c6e100a83c899e54c1`; phase-5 changes are unstaged. No commit, push, production runtime switch, live-provider qualification, or phase-6 packaging was performed. The historical intermittent prefix-MPC startup failure remains unresolved. This phase qualifies local Claude and Codex behavior with the accepted external native runtime.

## Primary acceptance

Accepted after source and fixture review, including corrected incremental HPACK accounting and completed local framing for provider JSON errors. Similar-code review covered 69 initial and 21 correction definitions. Independently reproduced all 23 focused native/provider library tests (nextest `3f1144de-98ea-4e48-9efc-32ff2f0fd976`) and inspected corrected 401/429 and successful mixed-role evidence. Packaging, final concurrency and live parity remain phase 6.
