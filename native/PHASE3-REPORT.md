# Phase 3: native helper and bootstrap adaptation

Rust now coordinates fresh MASCOT identities, committed P-256 key shares, checked arithmetic conversion, the handshake MPC, and the protected credential-prefix MPC. Sponsor writes the circuit-produced prefix only after both parties compare its public hash. Concurro constructs the client and server application traffic epochs after `prefix_forwarded`.

The MASCOT child keeps the reference's optional `HANDOFF_SPONSOR_HOST` setting. Private inputs go through helper stdin. Public circuit cache publication is locked and atomic; lock waits and generation now stop on cancellation. Each cold cache key gets its own helper workspace. MPC stdout and stderr drain while the child runs, and both reader tasks stop on early exit.

The Rust path is selected only by the ignored development fixture test. The operational bridge still launches Python. Request proofs, provider response handling, and CLI ingress remain later phases.

## Fixture result

The explicitly selected fixture ran five fresh sessions for each route: Rust Sponsor/Python Concurro, Python Sponsor/Rust Concurro, both Rust, and two parallel both-Rust sessions. All ten sessions passed with one attempt per session. Each pairing agreed on `h2`, authenticated `h3`, session ID, exact 193-byte handshake public output, protected-prefix public output, and application-key commitment. Ordered control events matched the Python role for both routes. Session IDs were distinct in parallel runs; both roles used fresh MASCOT directories. The local TLS provider decrypted the first protected request byte (`G` for Codex, `P` for Claude), after Sponsor's prefix write. Concurrent public-cache access produced the same locked circuit file.

- Codex evidence: `/var/folders/l3/3wx0yh1n26zbhpyw52mz2dtw0000gn/T/concurro-phase3/codex-1794877519055576000/`
- Claude evidence: `/var/folders/l3/3wx0yh1n26zbhpyw52mz2dtw0000gn/T/concurro-phase3/claude-1794877551853848000/`

Each case has `comparison.json`, role output, MPC/MASCOT logs, provider log, and `provider-prefix.json`. Earlier failed fixture runs remain under the same `concurro-phase3` parent: the first lacked loopback permission, the next used long Unix paths, and the first TLS fixtures lacked CA extensions required by Python's verifier. A later Claude rerun at `claude-1794877482899268000` failed because the fixture provider's 10-second read deadline expired before prefix MPC finished; both MPC logs show success and `prefix_forwarded` was exchanged. The fixture read deadline now covers bootstrap. These are retained failures, not retries hidden inside a case. The historical intermittent prefix startup failure was not reproduced; ten successes do not resolve it.

A separate both-Rust negative fixture used an unrelated CA. Concurro rejected the provider certificate, Sponsor terminated on peer closure, and no prefix reached the provider. Evidence: `/var/folders/l3/3wx0yh1n26zbhpyw52mz2dtw0000gn/T/concurro-phase3/codex-1794877599511728000/untrusted-provider/`.

These were local fixture executions. No live or paid provider call was made.

## Checks

- `CONCURRO_PHASE3_FIXTURE_BUNDLE=/Users/cylwit/Code/github.com/concurro/.artifacts/concurro-relay-native-v16/sponsor/native-runtime cargo nextest run -p concurro-relay-native --test bootstrap --run-ignored all --locked --status-level all -E 'test(mixed_and_rust_bootstrap)'` — passed, 66.921 seconds. This suite also ran two parallel sessions per route and concurrent prefix-cache access.
- `CONCURRO_PHASE3_FIXTURE_BUNDLE=/Users/cylwit/Code/github.com/concurro/.artifacts/concurro-relay-native-v16/sponsor/native-runtime cargo nextest run -p concurro-relay-native --test bootstrap --run-ignored all --locked --status-level all -E 'test(untrusted_provider_aborts_bootstrap)'` — passed; untrusted CA stopped both roles before prefix release.
- `cargo nextest run --workspace --all-targets --locked --status-level fail` — 96 passed, two ignored fixture tests. Loopback tests required sandbox escalation.
- `cargo clippy -p concurro-relay-native --all-targets --locked -- -D warnings` — passed.
- `cargo clippy --workspace --all-targets --locked` — passed with existing relay warnings.
- `rustfmt --check --edition 2024 crates/native/src/bootstrap.rs crates/native/src/bootstrap/prefix.rs crates/native/src/helpers.rs crates/native/tests/bootstrap.rs` — passed.
- `cargo fmt --all -- --check` — fails on formatting in accepted staged files outside phase 3. Those files were restored to their staged content; this phase does not reformat them.
- Fake-helper tests cover missing binary, failed offer output, active helper cancellation, cancellation during lock wait and generation, cold distinct-key cache races, one publication per key, large MPC stdout beyond pipe capacity, and child cleanup on readiness error. The untrusted-CA fixture confirms terminal bootstrap failure; phase-2 library tests cover altered record and transcript rejection.

Toolchain: `rustc 1.100.0 (0ef1bc386 2026-11-09)`. All 27 selected runtime files in each accepted Sponsor and Concurro package matched `native/port-reference/reference-manifest.json` SHA-256 entries. The accepted binary and circuit sources remain external to this checkout.

## Review boundary

Changed for phase 3: `Cargo.toml`, `Cargo.lock`, `crates/native/Cargo.toml`, `crates/native/src/lib.rs`, new `crates/native/src/bootstrap.rs`, `crates/native/src/bootstrap/prefix.rs`, `crates/native/src/helpers.rs`, `crates/native/tests/bootstrap.rs`, and `native/phase3_fixture.py`. This report is new. The index tree remains `7a5458f4a811333178f161e512553ac3cb5ca161`; no phase-3 file was staged, committed, or pushed.

Phase 4 must carry the provider socket, transcript, prefix state, and Concurro traffic epochs forward from this coordinator. The fixture result currently records public evidence and drops those live objects at the phase boundary; phase 4 should extend that result rather than run another bootstrap. The Codex/Claude prefix encoders here should move once into `provider-protocol` as provider work is extracted.

## Primary acceptance

Accepted after reviewing the bootstrap and helper contracts, mixed-role fixture evidence, and corrected cache/process lifetimes. Similar-code review covered the initial definitions and correction delta. Independently reproduced all ten native library tests, including cancellation, cold cache concurrency, and pipe backpressure (nextest `adb407ae-76d2-4cd2-81f0-41cc9406a3f2`). This accepts bootstrap integration, not a completed provider session or runtime switch.
