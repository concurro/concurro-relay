# Rust TLS worker port: phase 2 checkpoint

Date: 2026-11-17. Branch: `refactor/tls13-rust-worker`. Accepted phase-1 index tree: `a4ec4e9c11ff5f1f0331eaf1c3ec6a7dc7cba5ba`. All phase-2 changes remain unstaged.

## Result

`crates/tls13` is an independent library for the existing joint TLS 1.3 P-256/AES-128-GCM/SHA-256 profile. One `Profile` selects Codex's no-ALPN ClientHello or Claude's `h2` offer and required server selection. The library encodes and validates the public hellos, authenticates buffered encrypted EncryptedExtensions/Certificate/CertificateVerify/Finished messages, verifies the configured CA chain and route hostname with Rustls/WebPKI, and emits the matching client Finished record. It accepts the same ECDSA P-256 and RSA-PSS SHA-256 CertificateVerify schemes as the Python reference. Provider TCP destination is not part of certificate identity.

The record module owns directional AES-128-GCM traffic epochs, nonce/sequence derivation, inner content and zero-padding removal, tickets and server KeyUpdate transitions. No helper binary, worker launcher, production Python path, outer protocol or provider write ordering changed. The native crate does not consume this library yet; phase 3 composes it with helper coordination.

## Evidence and changed paths

| Path | Change |
| ---- | ---- |
| `crates/tls13/{Cargo.toml,src/lib.rs,src/handshake.rs,src/record.rs,tests/fixture.rs}` | New leaf library and isolated parity/rejection tests. |
| `Cargo.toml`, `Cargo.lock` | Shared dependency declarations and new crate lock entry. No new major cryptographic stack; P-256, Ring, Rustls and WebPKI were already resolved. `rustls-pemfile 2.2.0` is newly locked for configured PEM CA input. |
| `native/port-reference/{generate-tls13.py,tls13-fixture.json,README.md}` | Python reference fixture generator, frozen bytes and usage note. |

The fixture generator ran with the accepted packaged Sponsor Python and called the unchanged production `tls13_joint.py`, `tls13_joint_h2.py`, and `tls13_product_native.py`. It verifies each full server flight and negative ALPN case in Python before writing fixture bytes. The frozen fixture SHA-256 is `6c9526f73dbd1d6ffc545380fa4b3609ad4fe21c3e73f718f6b99fe6aa166b51`; the generator SHA-256 is `f851df9dd7338c50010399990aa4d4d952b557130b4b083124f38f9067cab42c`. Fixture certificates are valid from 2020-01-01 through 2035-01-01. Fixture keys are generated for this check and are not retained.

## Checks

| Command or check | Result |
| ---- | ---- |
| `../.artifacts/concurro-relay-native-v16/sponsor/native-runtime/python -B native/port-reference/generate-tls13.py` | Passed: Python accepted both complete profiles and rejected both unsupported ALPN selections. |
| `cargo nextest run -p concurro-relay-tls13 --offline --locked` | 4/4 passed; run ID `99307102-0787-447e-b9dd-a4e7527e7150`. Exact Python ClientHello/client Finished/ciphertext vectors; ECDSA and RSA-PSS full flights; fragmentation, wrong CA/hostname, altered transcript/ciphertext, invalid Finished, unsupported negotiation, padding and KeyUpdate. |
| `cargo nextest run --workspace --all-targets --offline --locked` | 89/89 passed, none skipped; run ID `b2f07727-1706-4fe0-b228-b50a8925fe3b`. |
| `cargo clippy -p concurro-relay-tls13 --all-targets --offline --locked -- -D warnings` | Passed. |
| Rust Analyzer diagnostics for new source and test files | No diagnostics. |
| `rustfmt --check --edition 2024` on the four new Rust source/test files; `git diff --check` | Passed. |

## Limits and recovery

Primary acceptance: reviewed the shared profile, transcript/signature/Finished validation, record epochs and reference generator, and reproduced all four isolated TLS tests (run `9402e30b-3022-4a15-8de2-386b853595b5`). Phase 2 is accepted for staging; phase 3 is authorized. This supersedes the awaiting-review status recorded during execution above.

This is component validation against fixture-only certificates and reference bytes, not a complete Rust provider session. No live provider, native helper, intermediate CA chain, or packaged Rust worker was exercised. The Python worker remains operational. Phase 3 can consume this library while preserving public-output comparisons and helper readiness/completion semantics.

Resume from the unstaged phase-2 paths after review. Preserve the accepted index tree above; do not stage, commit, push, or start phase 3 before explicit acceptance.
