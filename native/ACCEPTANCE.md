# TLS 1.3 extraction baseline

This source was extracted onto clean `main` at `b8afc730d9b8aeb977103f3df93b0354aada39d2` from the accepted v16 native relay work. The first-slice worktree was read only. Its v16 Sponsor and Concurro packages supplied the frozen native runtime for offline validation; only the newly built Rust binaries were substituted. No live provider call was made during extraction.

The extraction adds the native worker, packaging script, fixtures, and protocol bridge. It merges native startup, authenticated relay/slot ownership, audit events, and shutdown into the existing relay and development verifier. Main's TLSNotary policy and refusal behavior remain in place. The first-slice policy removal, unrelated TLSNotary optimizations, `dev-chain`, and `modes.rs` are outside this extraction.

| Check | Result |
| ---- | ---- |
| Rust workspace nextest | 72 passed, 0 skipped |
| Workspace `cargo check --all-targets` | Passed |
| Release relay and verifier binaries | Built |
| Python cancellation and tunnel tests | 4 passed |
| Offline real Claude + Codex CLI, local providers | 2 paired sessions, both CLI exits 0 |
| Offline two registrations, each slot 1 | 2 paired sessions and 2 provider connections |
| Offline one registration, two Codex links | 2 paired sessions and distinct reconnecting tool chains |

The two validation bundles each have 3,467 verified manifest members. Relative to frozen v16, only `bin/concurro-relay` differs in the Sponsor bundle and only `bin/dev-verifier` differs in the Concurro bundle. Their validation manifest SHA-256 values are `7bea1496a6a30d5d235386e08ec5ac66263435abada4787764d062809276ffdd` and `d1c9cdf97255e1dbed50f335d4da0d65d3e16c1f84f4ac53d43487b6ad4b6d83`. The credential-free paired role and audit projection has SHA-256 `c1a687ee26129feabf01648b78fd3543328c38e3d1a96c8666febff579ca1bb5`. Full local evidence is held outside this repository under `.artifacts/tls13-main-extraction-20261116T232740` in the parent workspace.

Packaging is not hermetic. `native/package.py` requires the external accepted runnable MVP runtime with DiStefano, MP-SPDZ, request proof, and Python dependencies; a local `hpack` installation, signed Python 3.13 framework, OpenSSL, and `clang` are also used. The ignored `upstream/` source tree must be prepared from the pinned repository script. For this validation it was populated from the read-only first-slice upstream Git heads after the network fetch returned HTTP 403; those heads matched the committed patch stack.

The first attempt at packaged validation used an output path too long for macOS Unix sockets. The same binaries passed when rerun from `/private/tmp`. This was a fixture path error before native startup. The historical intermittent first-link prefix-MPC failure remains unexplained; this extraction does not claim to fix it. The accepted v15/v16 reports hold the broader concurrency and single live parity evidence.
