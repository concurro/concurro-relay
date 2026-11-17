# Rust port of the TLS 1.3 worker

Port the production Python worker to a Rust executable, preserving the current subprocess boundary, protocol, and native cryptographic helpers. Consolidate the duplicated TLS implementations and reuse the existing Rust ingress, WebSocket, and lifecycle components where their behavior fits. Do not combine this port with a new MPC protocol or proof optimization.

Analyzed baseline: `1d34016e88208e46afe1d1208fc8f1fbe75faaf1` on `main`. This is an implementation plan, not an additional security validation. [Extraction acceptance](ACCEPTANCE.md) records 72 passing Rust tests, four Python tests, and packaged offline CLI/concurrency checks. The historical intermittent prefix-MPC startup failure remains unresolved.

## Scope and current ownership

The seven files in `native/worker` contain 2,792 lines; `native/tunnel.py` adds 256. Some of those 3,048 lines are experimental harness code that should not enter the Rust runtime. The port is modest in size, but includes protocol state machines, not just subprocess calls.

Rust already owns Sponsor login, registration, authenticated links, link slots, ingress leases, audit presentation, and worker lifecycle. Python owns the joint TLS handshake coordination, TLS record handling, provider protocol adaptation, request proof coordination, and native TCP multiplexing.

| Current source | Responsibility | Rust destination or reuse |
| ---- | ---- | ---- |
| [protocol/native.rs](../crates/protocol/src/native.rs) | Worker launch, stdin credentials, sockets, events, process groups | Move into the new native crate; preserve public bridge behavior |
| [role.py](worker/role.py) | Session configuration, MASCOT identities, role startup | Worker entry point and session configuration |
| [tunnel.py](tunnel.py) | Multiplex native helper connections | Async tunnel module |
| [tls13_product_http_h2.py](worker/tls13_product_http_h2.py) | Helpers, bootstrap, proof coordination, both role loops; also experiments | Helper adapters and separate Sponsor/Concurro session coordinators |
| [tls13_joint.py](worker/tls13_joint.py), [tls13_joint_h2.py](worker/tls13_joint_h2.py) | Almost identical handshake codecs and authentication | One TLS implementation with an explicit ALPN profile |
| [tls13_product_native.py](worker/tls13_product_native.py) | Traffic epochs, AEAD, KeyUpdate, response records and WebSocket parsing | TLS records plus provider WebSocket adapter |
| [candidate_a.py](worker/candidate_a.py) | Indexed authorization, HTTP/2 framing, Sponsor audit, response decoding | HTTP/2 request encoder, connection state, audit and response decoder |
| [ingress.py](worker/ingress.py) | Local CLI ingress, pending turns and cancellation | Hyper/Tokio ingress and session-owned turn state |
| [protocol/ws.rs](../crates/protocol/src/ws.rs), [dev/gateway.rs](../crates/dev/src/gateway.rs) | Existing frame/event helpers and HTTP upgrade handling | Reuse compatible helpers; do not import TLSNotary proof execution |
| [package.py](package.py), fixtures and Python tests | Build assembly and reference tests | Keep initially; runtime Python removal does not require rewriting test tools |

The existing helper executables remain separate: `HandoffKeyShare`, `HandoffPartyKrrw`, `HandoffPrefix`, `mascot-party.x`, and `handoff-request-proof`. The last is already Rust; the others include C++/MP-SPDZ components. Keep their accepted binaries, circuits and interfaces unchanged during the port. Retain OpenSSL's ephemeral MASCOT certificate generation initially as well.

## Target structure

Use the existing Cargo workspace and its `crates/*` membership. Split clear-cut, independently testable logic into focused library crates under `crates/`; do not accumulate the entire port as modules in one orchestration crate. Start with these boundaries, adjusting names or combining small components where separation provides no useful encapsulation:

| Crate directory | Responsibility | Independent tests |
| ---- | ---- | ---- |
| `crates/tls13` | Handshake/transcript codecs, authentication, traffic epochs and records | Fixture bytes, certificate validation, record and KeyUpdate vectors; no helper processes or live provider required |
| `crates/native-transport` | Inner control codec and auxiliary tunnel | In-memory/loopback framing, multiplexing, readiness and EOF tests; no MPC required |
| `crates/provider-protocol` | Claude HTTP/2/HPACK state and Codex framing/event semantics | Request/response fixtures, flow control, indexed authorization and continuation state; no CLI or provider required |
| `crates/native` | Bridge, helper adapters, role coordinators, ingress and the `concurro-native-worker` binary | Fake-helper lifecycle tests plus cross-crate integration and packaged CLI tests |

Keep the CLI and worker entry points thin. Move the launcher out of the general protocol crate into `concurro-relay-native`. Library crates should own their behavior and tests, with small public APIs and private implementation modules. Production binaries compose them; libraries must not depend on those binaries.

```text
relay / dev verifier
    -> native::bridge -> concurro-native-worker (one process per session)
                            -> MPC / MASCOT / QuickSilver executables

native -> tls13 / native-transport / provider-protocol
native -> protocol (existing shared route and wire types)
leaf libraries must not depend on native or the application crates
protocol must not depend on native; keep the workspace dependency graph acyclic
```

Within those crate boundaries, use these modules where useful:

- `bridge`: parent-side launch, events, socket bridging and child cleanup.
- `session`: configuration, explicit Sponsor and Concurro coordinators, cancellation and audit association.
- `control` and `tunnel`: existing inner JSON messages and auxiliary binary framing.
- `helpers`: typed adapters for key sharing, arithmetic conversion, circuits and request proofs.
- `tls`: handshake codecs, transcript authentication, traffic epochs and record handling.
- `providers`: Codex WebSocket and Claude HTTP/2 adapters.
- `ingress`: local HTTP/WebSocket endpoints and pending-turn ownership.

Share codecs and transport mechanics; keep role-specific secrets and transitions explicit. Do not reproduce the large Python role loops as one Rust function controlled by role flags. Replace Python's environment mutation with session configuration and child-specific `Command::env` settings. Each connection owns its counters, keys, HTTP/2 tables, stream IDs and pending turns.

### Rust design and toolchain

Follow idiomatic Rust and SOLID/DRY/KISS throughout the port:

- Give each crate/type a cohesive responsibility. Separate protocol computation from process/network effects so libraries can be tested through their public APIs.
- Reuse existing implementations before adding helpers. Consolidate shared codecs and genuine common behavior, while retaining distinct role/provider semantics.
- Prefer ownership, enums, explicit state and composition. Use small traits at actual substitution boundaries, such as helper execution for tests; avoid one-implementation trait hierarchies and speculative frameworks.
- Keep APIs minimal, document public types and methods, and use module privacy and deliberate re-exports for encapsulation. Follow the repository's import and visibility conventions.
- Put unit and integration tests with the crate they validate; reserve workspace/package tests for behavior spanning crates. Each library must be testable with `cargo nextest run -p <package>` independently of live credentials, native helper installations and CLI sessions.

The workspace [toolchain file](../rust-toolchain.toml) pins **Rust 1.100.0**, with rustfmt and Clippy. This is the [stable release announced on November 12, 2026](https://blog.rust-lang.org/2026/11/12/Rust-1.100.0/). Keep edition 2024 and the existing workspace resolver; centralize shared dependency versions in `[workspace.dependencies]`. Use the pinned toolchain for development, CI, tests and package builds, including subprocess build commands that change into external source directories. Record `rustc --version` in build evidence. An exact toolchain pin is separate from a package's `rust-version` minimum; do not treat `rust-version` alone as a compiler pin.

Toolchain validation on November 17, 2026: `rustc 1.100.0 (0ef1bc386 2026-11-09)` compiled the existing workspace and all 72 nextest tests passed, with none skipped. The fixture suite required local loopback listeners outside the restricted sandbox. This verifies the current workspace, not the future port or a rebuild of the external native helpers.

The worker subprocess preserves lifecycle isolation and lets the existing bridge remain stable. It is not a credential isolation boundary: the Sponsor Rust application already obtains the credential. An in-process worker or FFI to the cryptographic helpers can be considered separately after parity.

## Contracts to preserve

### Links, helpers and lifecycle

- Keep outer protocol v4, signed link slots, random link pairing, and session ownership by `(relay, slot)`. Two registrations with slot 1 must remain distinct.
- Keep the inner control encoding: four-byte big-endian length followed by JSON with base64 binary fields; current receive limit is 1,000,000 bytes. The general protocol codec permits 16 MiB, so it is not an unchanged substitute.
- Keep auxiliary framing: one opcode byte, big-endian channel and length fields, and a 65,536-byte payload limit. Preserve registration acknowledgements, channel ordering and directional EOF. Waiting for one helper listener must not block unrelated channels.
- Preserve helper arguments, private stdin inputs, output lengths, public-output comparisons, readiness messages, completion markers and exit-status checks. A successful process exit alone is not the current acceptance condition.
- Preserve fresh per-session MASCOT identities and preprocessing, public-certificate exchange, private file permissions, and locked/atomic public-circuit cache publication. Public circuit caching does not permit reuse of private preprocessing.
- Preserve `NATIVE_READY`, `NATIVE_CANCEL`, `NATIVE_AUDIT` and parent readiness events until all consumers are migrated together. Audit `turn` currently identifies a TLS record; do not silently redefine it as a model turn.
- Preserve isolated process-group cleanup, per-link ingress, and the legacy single-owner ingress alias. Cancellation of one session must not stop another session or the application process group.

### TLS and request proofs

- Preserve the existing TLS 1.3 P-256/AES-128-GCM/SHA-256 profile and explicit ALPN selection, including transcript, certificate identity, CertificateVerify and Finished checks. The TCP destination override used by fixtures must remain separate from the expected provider certificate hostname.
- A conventional one-party Rust TLS client is not a drop-in replacement for the joint handshake. Reuse cryptographic and certificate verification libraries around the existing protocol.
- Preserve the ordering of committed outputs, key release, server-flight authentication, protected credential prefix, and application traffic. Consolidation must not move a provider write across its existing proof/audit prerequisite.
- Preserve directional sequence numbers, nonce derivation, TLS inner content and padding, and KeyUpdate epoch transitions. Do not broaden the supported handshake or post-handshake profile as part of translation.
- Concurro proves and Sponsor verifies each applicable application record with fresh request-proof state. This includes provider protocol control records, not only JSON prompt bodies. Keep claim bytes, record boundaries, sequence association and proof receipts consistent.
- `request_accepted` may precede the actual provider write because Sponsor buffers pending records. It is not a provider receipt or a first-response latency measurement.

### Provider behavior and audits

- Claude's initial HPACK insertion establishes authorization at dynamic index 62. Later public headers must not evict or shift that entry. Concurro references the entry without possessing its value; a generic HTTP/2 client cannot be assumed to reproduce this behavior.
- Preserve the current table-size handling, stream numbering, flow control, control-frame proofs, and connection termination when the indexed authorization state is no longer usable. Keep response HPACK state independent of request state.
- Preserve partial DATA handling and the existing Sponsor release decisions. Do not accidentally require a complete model response before flushing SSE, or claim the entire request is always buffered before forwarding.
- Claude connection reuse amortizes bootstrap; it does not itself reduce the context the CLI sends. Keep CLI request bodies and public request metadata intact.
- Codex must retain upgrade binding, masked client frames, fragmented response handling, control frames, `previous_response_id` chains, and `generate:false` preflight behavior. Preserve the current JSON normalization semantics rather than assuming raw CLI bytes are forwarded unchanged.
- Preserve idle Codex ingress reconnects on the same provider session, active cancellation behavior, and atomic pending-turn transitions. The cancellation regression tests cover a race where finishing one turn could erase a newly queued turn.
- Keep Sponsor prompt text/digest auditing and its association with completion events. Usage is currently reported by Concurro, not independently proved to Sponsor. Do not strengthen that claim or silently drop audits when usage is absent.

## Library choices

Reuse the workspace's Tokio, Hyper, tungstenite, serde, ring and Rust TLS dependencies before adding alternatives. Existing WebSocket helpers provide useful frame and response-ID handling, but their TLSNotary-specific assumptions must be checked before reuse.

Use ring's AEAD/HMAC/HKDF facilities for the existing record construction, with sequence/nonce ownership in the traffic epoch. Prefer its nonce-sequence APIs where they fit; explicit-nonce APIs require the caller to uphold uniqueness. See [ring AEAD documentation](https://docs.rs/ring/0.17.14/ring/aead/struct.LessSafeKey.html).

Use the existing Rust TLS/webpki stack for certificate-chain, hostname and signature validation, with a small API feasibility check against the locked versions. Preserve the configured CA behavior and supported signature schemes; do not implement X.509 verification from scratch.

For Claude, initially port the small deterministic request encoder and connection state. Select a Rust HPACK response decoder through fixture comparison. `hpack` 0.3.0 is a candidate, not a decided dependency: its documented decoder keeps state between header blocks but requires a complete block, so HEADERS/CONTINUATION assembly remains the caller's responsibility. Check Huffman, dynamic-table, error and size-limit behavior before choosing it. See [HPACK decoder documentation](https://docs.rs/hpack/0.3.0/hpack/decoder/struct.Decoder.html). Do not replace the request path with a high-level `h2` client without demonstrating its support for the credential-index invariant.

## Implementation sequence

Each phase should be a reviewable change with its own evidence. Keep the Python implementation available as an explicitly selected development reference until final parity; never switch implementations automatically within a session.

### 0. Freeze the reference and resolve dependencies

Record source, binary and circuit identities from the accepted packages. Map production imports from `role.py`; exclude standalone benchmark/login/harness branches from the runtime port. Document the actual helper stdin/stdout/exit/readiness contracts and all production environment settings.

Extract credential-free fixture vectors for control messages, tunnel frames, handshake/record parsing, request claims, HPACK state, audit projections and cancellation. Use fixture-only keys for crypto vectors. Compare semantic outputs where legitimate random values differ; do not reuse production randomness to make traces identical.

Resolve the certificate API and HPACK decoder choices with small executable checks. Confirm the proposed crate dependency graph and which existing helpers can be reused or moved without duplication. Record the external runtime source/build locations and hashes: the current package is not reproducible from this repository alone.

**Checkpoint:** a reference manifest, runnable comparison command, helper contract table and passing dependency checks. No new runtime is selected yet.

### 1. Extract the Rust boundary and implement transport

Move the existing Rust bridge into `crates/native`, updating relay/dev imports without changing behavior. Add the worker entry point, typed configuration and event serialization; implement the inner control codec and auxiliary tunnel in `crates/native-transport`. Reuse existing process cleanup rather than introducing a second lifecycle manager.

Keep bridge sockets in a short per-session directory independent of the potentially long evidence directory; the extraction already demonstrated the macOS socket-path failure. Test actual cleanup and permissions. Keep this fix separate from protocol behavior changes.

**Checkpoint:** existing workspace tests still pass; Python remains the working provider backend. Rust transport tests cover fragmented reads, frame limits, EOF, simultaneous channels, listener readiness, cancellation and independent session cleanup.

### 2. Consolidate TLS primitives and authentication

Port `Epoch`, the record codec, and one shared handshake implementation into `crates/tls13`, with explicit Codex/Claude ALPN settings. Integrate library certificate validation. Preserve server-flight buffering and authentication ordering, plus the currently supported post-handshake messages.

**Checkpoint:** fixture parity for both profiles, ciphertext/plaintext vectors and KeyUpdate transitions. Existing rejection behavior is covered for altered transcript/record bytes, wrong hostname or CA, invalid Finished and unsupported negotiation. This is component validation, not yet an end-to-end Rust claim.

### 3. Port helper coordination and bootstrap

Implement helper adapters, MASCOT identity exchange, circuit cache access and Sponsor/Concurro bootstrap coordinators. Reuse the binaries and circuits from phase 0. Consume readiness output directly where possible instead of polling whole log files; preserve timeout and completion semantics. Keep blocking filesystem/process preparation off the async I/O executor.

**Checkpoint:** complete fixture bootstrap with Rust on each role separately against the Python peer, then both Rust roles. Compare public outputs and ordered protocol events. Exercise parallel bootstraps and retain failed evidence; an intermittent prefix failure must remain visible rather than being hidden by retries.

### 4. Complete request proofs and Codex ingress

Port request claims, proof helper invocation, proved-record release, authenticated response handling and audit association. Put provider framing and event semantics in `crates/provider-protocol`; keep ingress and session orchestration in `crates/native`. Implement local WebSocket ingress using the existing Hyper/tungstenite patterns and compatible protocol helpers. Give pending-turn state one owner so completion, enqueue and disconnect cannot race.

**Checkpoint:** a real Codex CLI against the local fixture completes a multi-tool task, keeps one provider connection across continuations, and matches reference proof counts, audit projections and response IDs. Cover preflight, idle reconnect, active cancellation, fragmented frames and simultaneous Codex sessions. Run each mixed Python/Rust role pairing before retiring the reference path.

### 5. Complete Claude HTTP/2 and streaming ingress

Port the deterministic indexed request headers, Sponsor audit parser, stream/flow-control state and response decoder into `crates/provider-protocol`. Add local HTTP ingress and streaming SSE forwarding in `crates/native`. Keep bootstrap, request and response table state connection-local; separate sessions provide concurrency as today.

**Checkpoint:** a real Claude CLI against the local fixture completes successive requests with one bootstrap. Exercise indexed authorization, HEADERS/CONTINUATION and Huffman decoding, DATA/TLS boundary splits, window updates, settings changes, GOAWAY/reset, early SSE delivery and cancellation during bootstrap/streaming. Validate both mixed role pairings and the full Rust pair.

### 6. Package and qualify the Rust runtime

Switch bundle assembly to the Rust worker. Remove Python, its launcher, `cryptography`/CFFI and Python HPACK from production runtime dependencies once no runtime imports remain. Build scripts and reference fixtures may stay Python. Keep role-specific package manifests and the existing native helper provenance.

Run the concurrency matrix below and a bounded performance comparison using identical helpers, public circuits, fixtures and profiles. Use the established minimal-call budget for final live parity, rather than repeatedly invoking providers during development. Preserve the reference and accepted fixtures; leave `.worktrees/first-slice` untouched.

**Checkpoint:** both packaged roles operate without Python installed or a source checkout. No Python process is launched in a normal session. Publish source/binary identities, results, performance differences and remaining limitations before declaring the port complete.

## Acceptance and performance

Use Rust 1.100.0 for `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked`, and `cargo nextest run --workspace --all-targets --locked`; retain the current Python regression tests while they remain the reference. Also demonstrate each new library crate's isolated test command. Expand tests around behavior being moved, not a line-for-line mirror of its implementation.

The final matrix includes:

- Mixed Claude/Codex sessions, including at least two Claude and one Codex session concurrently.
- Two independent Sponsor registrations each using slot 1; two Codex tasks under one registration; idle reconnect and isolated active cancellation.
- SIGINT/SIGTERM, helper exit or missing completion marker, peer EOF, unavailable listener, and child/socket cleanup.
- Multi-turn continuation, proved prompt audit, authenticated response streaming, and consistent per-session usage association.
- Packaged operation with the accepted local providers and minimal live parity for both provider paths.

Measure cold bootstrap and warm continuation separately: bootstrap count, proof count, directional bytes, time to first authenticated response byte/SSE event, turn completion, helper/proof time, CPU and peak RSS. Repeat matched runs and report their spread; separate provider inference time and confirm which links the WAN shaper covers. Keep record boundaries and circuit choice fixed so an apparent gain is attributable to the port.

Expect packaging and maintainability improvements first. Rust alone will not reduce MPC communication, proof count or WAN round trips. Compare with the frozen baseline before attributing latency savings to async I/O, removal of polling, or process startup.

Existing qualification is macOS arm64. Rust orchestration does not automatically make MP-SPDZ, helper binaries, process groups or socket handling portable. Linux packaging/qualification is a distinct follow-up; Windows requires explicit process and IPC work. Do not claim either from compilation of the worker alone.

## Handoff and evidence

Daybreak should begin with phases 0 and 1, returning the contract inventory, dependency decisions, changed-file list, test results and next integration step. Proceed through the provider milestones as separate changes; leave MPC/proof redesign, FFI, additional TLS features and performance batching out of this port.

Local reference locations, relative to the parent Concurro workspace:

- `.artifacts/tls13-main-extraction-20261116T232740/`: manifests, review, nextest/Python logs and packaged extraction evidence.
- `.artifacts/concurro-relay-native-v16/`: accepted runtime/package artifacts.
- `concurro/.worktrees/sponsor-relay-design/docs/proposals/sponsor-relay/tls13-concurrent-v15/` and `tls13-concurrent-v16/`: concurrency, cancellation, reconnect and prior live parity reports/runners.
- `concurro/.worktrees/sponsor-relay-design/docs/proposals/sponsor-relay/tls13-runnable-mvp/`: helper source/build context and earlier benchmark material.

These external paths are local evidence, not portable build dependencies. Phase 0 must identify the exact required sources and revisions and give a clean-checkout build recipe or explicitly document the remaining external artifact requirement.
