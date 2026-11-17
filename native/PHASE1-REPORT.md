# Rust TLS worker port: phase 1 checkpoint

Date: 2026-11-17. Branch: `refactor/tls13-rust-worker`. Accepted phase-0 index tree: `9e93a14eba1d4e537f29bac67c1ced44ba78d3e3`. All phase-1 changes remain unstaged.

## Result

The existing Python worker remains the operational provider backend. Its Rust parent bridge moved from `crates/protocol/src/native.rs` to `crates/native/src/lib.rs`; relay and dev verifier now import it from the native crate. The bridge still launches the bundled `python worker/role.py` with the same arguments, credential stdin, stdout event handling, process-group termination, and authenticated link copying. Its Unix sockets now live in a short private directory under the system temporary directory; session evidence continues under `CONCURRO_NATIVE_OUTPUT` or the temporary root.

`crates/native-transport` adds the independent control codec and auxiliary tunnel. The control codec preserves four-byte big-endian JSON framing, base64 payloads, and the 1,000,000-byte body limit. The tunnel preserves the nine-byte opcode/channel/length header, 65,536-byte payload limit, registration acknowledgements, per-channel ordering, and directional EOF. TCP connection attempts run in separate tasks, so a delayed Sponsor target does not stall other channels. Cancellation wakes pending registration and target waits, including registrations blocked on the link writer or its lock. Active channel pumps release their TCP sockets when cancellation or a local I/O error occurs under backpressure; normal directional EOF still completes independently. A frame write interrupted after it starts fails the whole tunnel before another frame can use its possibly truncated stream. A frame write error marks the tunnel failed while still holding the writer lock, and each writer checks terminal state after acquiring that lock. Terminal cleanup drains pending replies, clears registrations and targets, stops listeners and channel pumps, and ends the link reader. The transport is not wired into the Python worker; later Rust role coordinators will consume it.

`crates/native/src/worker.rs` defines the future worker CLI and parent event lines. The `concurro-native-worker` binary parses that CLI and exits with an explicit unimplemented-session error. No launcher selects this binary in phase 1. Outer protocol v4, signed link slots, relay/slot identity, native helpers, and provider behavior are unchanged.

## Changed paths

| Path | Change |
| ---- | ---- |
| `crates/protocol/src/native.rs` → `crates/native/src/lib.rs` | Move bridge and lifecycle ownership; use short socket directory. |
| `crates/native/{Cargo.toml,src/worker.rs,src/bin/concurro-native-worker.rs}` | Native crate, typed worker CLI, event serialization, thin entry point. |
| `crates/native-transport/{Cargo.toml,src/lib.rs,src/control.rs,src/tunnel.rs,tests/tunnel.rs}` | Control and tunnel implementations with isolated tests. |
| `Cargo.toml`, `Cargo.lock`, `crates/protocol/src/lib.rs`, `crates/relay/Cargo.toml`, `crates/dev/Cargo.toml` | Workspace dependency graph and moved module export. |
| `crates/relay/src/{serve.rs,main.rs,events.rs}`, `crates/dev/src/bin/dev-verifier.rs` | Import the bridge and audit type from `concurro-relay-native`. |

`cargo metadata --locked --offline` confirms `native -> {native-transport, protocol}` and no reverse dependency. No new third-party package entered the main workspace lockfile.

## Checks

| Command or check | Result |
| ---- | ---- |
| `rustc --version` | `rustc 1.100.0 (0ef1bc386 2026-11-09)` |
| `cargo nextest run -p concurro-relay-native-transport --offline --locked` | 10/10 transport tests passed after the writer-lock ordering fix; run ID `a4d135df-51a7-4642-adef-ef6614303734`. Includes interrupted-frame terminal failure from caller abort and local channel error, blocked-write and writer-lock cancellation, backpressured pump cleanup, and normal half-close. The blocked-write test first reproduced the original failure (run ID `c4bce159-40f3-4003-ad43-465a180ed52b`). |
| `cargo nextest run --workspace --all-targets --offline --locked` | 85/85 passed, none skipped before the final writer-lock ordering adjustment; run ID `3973063f-9914-4e26-9d84-1433b3cf097f`. The affected transport suite was rerun afterward. |
| `cargo clippy -p concurro-relay-native -p concurro-relay-native-transport --all-targets --offline --locked -- -D warnings` | Passed. |
| `cargo clippy --workspace --all-targets --offline --locked` | Passed with existing warnings in relay and verifier. The stricter workspace `-D warnings` check fails on those existing warnings; no phase-1 crate warning was reported. |
| `rustfmt --check --edition 2024` on the seven new Rust source/test files; `git diff --check` | Passed. |
| Rust Analyzer diagnostics on moved bridge and new modules | No diagnostics. |

## Limits and recovery

Primary acceptance: the final writer-order correction was reviewed and the full workspace suite was rerun independently on the resulting source: 85 passed, none skipped. Phase 1 is accepted for staging; phase 2 is authorized. This supersedes the awaiting-review status recorded during execution above.

This checkpoint verifies transport components and the existing workspace, not a complete Rust provider session. The worker entry point is a scaffold. Phase 2 can add TLS primitives independently; helper invocation and live provider parity remain later milestones. No live provider or native helper run was made here.

Resume from the unstaged phase-1 files after review. Preserve the accepted index tree above, keep Python selected, and begin phase 2 only after explicit acceptance. No commit, push, or staging was performed by the phase-1 worker.
