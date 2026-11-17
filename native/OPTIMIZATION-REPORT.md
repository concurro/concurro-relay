# TLS-MPC native runtime optimization assessment

Baseline: signed commit `800a1d3ca94cb797ad4980ae54d2154968994c9d` and the accepted phase 6 v3 packages. All measurements used local synthetic providers. The full identities, per-run metrics, and raw output paths are in [OPTIMIZATION-BENCH.json](OPTIMIZATION-BENCH.json).

## Decision

Keep the current release profile. One codegen unit reduced the three Rust executable sizes by roughly 20–29%, but did not produce a repeatable end-to-end latency gain. Thin LTO with 16 units slightly increased binary size. In the matched fast-link comparison, Thin LTO with 16 units was within 0.2% of the accepted package on both routes. The measured cold path is largely native helper work and link transfer, so further Rust codegen tuning is unlikely to move the observed result.

The separate dependency cleanup pins the owned workspace's direct third-party dependencies to the existing lockfile versions and makes their features explicit. It changes no resolved package or effective feature other than removal of the `default` aliases. It was applied **after** the compiler matrix was frozen and is not part of those timing comparisons.

## Compiler matrix

Each profile built `concurro-relay`, `dev-verifier`, and `concurro-native-worker` into an isolated target directory with the same rustc 1.100.0 Apple Silicon toolchain. Effective `rustc` invocations in the retained verbose logs confirm the requested LTO and codegen-unit flags. The accepted v3 packages were a fifth, unchanged anchor. Runs alternated variant order across two repeats per route.

| Profile | LTO | Units | Build elapsed | Relay / verifier / worker bytes |
| ---- | ---- | ----: | ----: | ---- |
| Accepted v3 | existing | existing | — | 20,060,368 / 19,562,416 / 5,589,920 |
| default-16 | false (local ThinLTO) | 16 | 49.6 s | 20,160,384 / 19,630,096 / 5,610,144 |
| thin-16 | thin | 16 | 46.3 s | 20,193,792 / 19,681,232 / 5,612,992 |
| default-1 | false (no LTO at one unit) | 1 | 67.4 s | 16,161,680 / 15,809,808 / 3,961,104 |
| thin-1 | thin | 1 | 61.9 s | 16,228,976 / 15,827,136 / 3,988,720 |

The host uses `sccache`, so build elapsed times are cache-influenced and should not be read as clean CI build costs. The fresh `default-16` binaries differ in size and SHA-256 from the accepted v3 binaries despite the same signed source commit; the accepted package therefore remains an explicit, separately identified anchor.

Cargo's `lto = false` means local ThinLTO across a crate's codegen units, and no LTO with one unit; `"off"` is a distinct setting. See the [Cargo profile reference](https://doc.rust-lang.org/cargo/reference/profiles.html#lto). The original matrix build record captured the signed HEAD and binary hashes, before the dependency edit. A reproduction from this dirty tree has different manifest inputs; the build script now records a working-tree diff identity, untracked file hashes, and all owned manifest/lock hashes.

### Local path, milliseconds

| Profile | Claude cold | Claude warm | Codex total |
| ---- | ----: | ----: | ----: |
| Accepted v3 | 5,650–5,662 | 949–1,051 | 4,973–5,042 |
| default-16 | 5,607–7,069 | 951–1,043 | 4,969–5,056 |
| thin-16 | 5,592–6,544 | 947–948 | 4,947–4,997 |
| default-1 | 5,637–6,117 | 951–962 | 4,970–4,989 |
| thin-1 | 5,608–6,095 | 950–951 | 4,927–5,011 |

The first Claude cold run of several rebuilt variants drifted upward; the second repeats clustered around 5.6 s. The warm and Codex spreads overlap. All 20 runs passed the strengthened fixture gates: one bootstrap and provider connection; paired H2/H3/prefix commitments; matching reported usage; expected stream, response, and proof counts; and a valid Codex parent-response chain. The initial request digest is identical across all variants for each route. Later Codex digests vary because response IDs are generated per run.

### Fast link, milliseconds

The authenticated outer link was shaped to 100/100 Mbps and 20 ms RTT. Thin LTO with 16 units was compared directly to the accepted v3 anchor, twice per route.

| Package | Claude cold | Claude warm | Codex total |
| ---- | ----: | ----: | ----: |
| Accepted v3 | 36,941–37,059 | 5,087–5,088 | 33,088–33,091 |
| thin-16 | 37,052–37,080 | 5,086–5,097 | 33,085–33,124 |

Claude transferred about 188 MB upload and 174 MB download; Codex about 182 MB upload and 143 MB download. Counts, audit records, and fixture responses matched across all eight runs. With no fast-link benefit, slower-link promotion would not discriminate these compiler profiles usefully.

## Time and resource attribution

On the accepted local Claude run, the sponsor helper handshake took 1.70 s and prefix work 2.60 s, together about 4.3 s of the 5.66 s cold turn. Request-proof helper elapsed time summed to 1.92 s across 28 records, including work overlapping other phases. On the fast link, helper handshake and prefix took about 10.8 s and 20.3 s. Process-ancestry sampling observed helper peaks near 86–92% CPU and roughly 1.3–1.4 GiB RSS per role; worker peaks were about 19–31% CPU and 214–218 MiB RSS locally. These are sampled peaks, not CPU-time fractions or additive phase durations.

macOS `sample` traces from the accepted package showed the parent and Rust worker mostly parked in Tokio/`kevent` or waiting on helper I/O. The HandoffPartyKrrw traces entered FerretCOT refill/RCOT, LPN/MPCOT work, and SSL reads. Short-lived mascot and request-proof processes ended before useful call graphs were captured. Thus the traces identify a concrete helper hot path but do not rank all helper CPU costs.

## Native helper provenance

The pinned source recipe in `concurro/.worktrees/sponsor-relay-design/docs/proposals/sponsor-relay/tls13-runnable-mvp/build_sources.sh` built DiStefano commit `2ffc806`, MP-SPDZ `878813`, libOTe2 `fe6b2`, and cryptoTools `f70175` into `/private/tmp/concurro-source-build-v3`. The accepted v3 helper binaries match the v16 package hashes. Package assembly rewrote some library install names to `@loader_path` without evidence of an algorithm or compiler change.

The actual HandoffPartyKrrw flags include `-Ofast -DNDEBUG -mcpu=apple-m1` (and debug symbols); its blank `CMAKE_BUILD_TYPE` is therefore not evidence of an unoptimized target. libOTe2 was built Release with `-O3 -DNDEBUG`; MP-SPDZ `CONFIG` specifies `-O3` and clears x86 architecture flags on arm64. The request-proof helper was built with Cargo `--release --locked`; its original complete rustc command and version were not retained. Native binaries contain ARM AES instructions. There is no clear underoptimized helper build setting to change in this pass.

Several packaged helper libraries still refer to absolute `/opt/homebrew` paths. Runtime on a host without those paths has not been qualified. A future helper rebuild should retain effective compiler commands, toolchain versions, binary checksums, and a relocation check. Changing the helper algorithms or their packaging is outside this measured compiler comparison.

## Apple Silicon acceleration fit

The strongest CPU candidate is FerretCOT's LPN/MPCOT work inside HandoffPartyKrrw. Its sampled stacks include `LpnF2::__compute4` and universal-hash coefficient generation, alongside substantial SSL reads. The pinned `ferret_b13` parameters generate 10,485,760 16-byte blocks per extension; `LpnF2` uses ten AES-derived indices and ten indexed XORs per output block. That is enough independent work to *test* parallel compute, but the indexed reads, large working set, protocol synchronization, and 160 MiB output buffer complicate a GPU path. The sampled CPU stack is only a fraction of the multi-second handshake/prefix and fast-link wait, so a fast isolated kernel would not by itself prove lower turn latency.

The accepted Apple Silicon binaries already contain ARM `aese`/`aesmc`, `pmull`, and NEON instructions. Static disassembly found these in HandoffPartyKrrw, `mascot-party.x`, and `handoff-request-proof`; the EMP AES source explicitly uses `vaeseq_u8`/`vaesmcq_u8` on AArch64. This proves instruction availability in the artifacts, not that every sampled primitive uses the optimal implementation. `HandoffPrefix` itself contains no AES/PMULL instructions and is not a compelling target for an AES assembly rewrite. The Rust parent/worker traces mostly wait; their compiler-profile comparison likewise shows no payoff from general codegen changes.

Apple GPU memory is unified, with shared buffers accessible to both processors, but a Metal pipeline still needs command encoding, dispatch, completion synchronization, and a separate compute implementation. [Apple's compute guide](https://developer.apple.com/documentation/metal/performing-calculations-on-a-gpu.md) and [storage-mode guide](https://developer.apple.com/documentation/metal/choosing-a-resource-storage-mode-for-apple-gpus.md) describe those costs and capabilities. CPU AES/PMULL intrinsics cannot simply be reused as Metal kernels. Small request-proof jobs (4 Codex or 28 Claude records here) and serialized network exchanges are poor GPU targets. Many simultaneous sessions could amortize dispatch and create a throughput case, but these single-session fixtures do not establish one.

Next experiment: instrument HandoffPartyKrrw with CPU time and wall time around LPN, MPCOT, AES, hashing, and socket waits, then benchmark the unchanged LPN kernel in isolation at `ferret_b13` size. Compare current hardware-instruction code with a carefully validated CPU parallel/vector implementation first. Consider a Metal prototype only if the isolated kernel consumes a material fraction of turn time or concurrent-session throughput is the goal; measure end-to-end latency and bytes moved, not kernel time alone. Inline assembly has no evidence-backed target yet.

## Dependency cleanup and validation

The root `[workspace.dependencies]` now uses exact locked versions and `default-features = false` for crates.io dependencies, explicitly listing the previously enabled capabilities. All eight owned member manifests inherit their normal, dev, and build dependencies from the workspace. `provider-protocol` retains its local `serde_json/raw_value` addition. `upstream/`, vendored sources, and the legacy probe were not changed. Offline macOS arm64 metadata resolves the same 325 package IDs and the same effective features, ignoring only removed `default` aliases. `Cargo.lock` is unchanged. `cargo check --workspace --all-targets --locked --offline`, `cargo fmt --all -- --check`, and `cargo nextest run --workspace --all-targets --locked --offline` passed (109 tests, 2 skipped). A rebuilt default-release package passed one local Claude run (28 proofs, 6.92 s cold, 0.96 s warm) and one Codex run (4 proofs, 5.04 s total), with the expected bootstrap, connection, and response counts. The JSON artifact records these checks.

## Reproduction

```bash
python3 native/optimization_build.py --runtime /Users/cylwit/Code/github.com/concurro/.artifacts/concurro-relay-native-v16/sponsor/native-runtime/runtime --output /private/tmp/concurro-opt-builds-new
python3 native/optimization_bench.py --builds /private/tmp/concurro-opt-builds-new/builds.json --output /private/tmp/concurro-opt-local-new
python3 native/optimization_bench.py --builds /private/tmp/concurro-opt-builds-new/builds.json --output /private/tmp/concurro-opt-fast-new --profile fast --variants accepted-v3 thin-16
```

The benchmark runner, accepted packages, circuits, and Python dependency paths are fixed in `native/optimization_bench.py`; the JSON artifact records their identities and the raw run directories. The scripts use local synthetic providers and make no live provider calls.

## Primary review

Accepted after corrected dependency centralization, LTO attribution, build provenance and fixture checks. Independently reprojected all 28 retained matrix cases; timings, traffic, request audits, paired transcript/commitment fields, usage and continuation checks match the saved evidence. Verified effective worker compiler flags in all four build logs, current script hashes, exact locked workspace pins and the unchanged macOS arm64 resolved package/feature graph apart from default aliases. Reviewed five added harness functions and three revised definitions for reuse. Keep the existing release profile; no GPU or assembly speedup is established. Changes remain unstaged and uncommitted as requested.
