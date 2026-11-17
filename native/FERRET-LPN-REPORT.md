# Ferret LPN CPU experiment

**Decision: retain the 8-worker implementation as an experiment; do not promote it into the native runtime.** It improves one bootstrap-bound portion of a cold session by about 0.3 seconds on a 37-second fast-link Claude fixture. Warm turns showed no repeatable gain. The measured end-to-end benefit is small relative to the implementation and threading cost.

## What was measured

The pinned DiStefano Ferret LPN task was split into disjoint four-output groups, with a thread-local PRP per worker. The original tail operation remains after the workers join. Only `HandoffPartyKrrw` changed in the packaged candidate; the accepted Rust relay, worker, circuits, and other helpers stayed fixed. Separate helper binaries set the default to four or eight workers at compile time because the fixture sanitizes relay environment variables. The source patch also instruments LPN, MPCOT, preprocessing CPU, and aggregate SSL-call time.

The standalone harness compares every output byte against the original task on deterministic synthetic inputs, including 15 small and tail sizes per seed and production size `n=10,485,760`, `k=452,000` (160 MiB output). Two seeds, four repeats per seed and worker count, and alternating order yielded 48 production-size rows. All paired digests and full `memcmp` checks passed.

| LPN task | Original median wall | Parallel median wall | Parallel median CPU |
| ---- | ----: | ----: | ----: |
| 2 workers | 59.3 ms | 31.5 ms | 62.6 ms |
| 4 workers | 59.9 ms | 17.0 ms | 66.3 ms |
| 8 workers | 60.2 ms | 9.6 ms | 69.9 ms |

These are isolated task times, not end-to-end session savings. The extra `-funroll-loops` build gave 16.6 ms at four workers versus 17.0 ms without it, within observed variation. The accepted build already uses Apple arm64 AES/NEON code. We did not pursue manual vector code after this result.

## Complete fixture results

All 36 local and fast cases passed the existing transcript, response-chain, H2/H3, provider, bootstrap, prompt/usage, and proof-count checks. Each Claude fixture had one bootstrap, one provider connection, two turns and 28 proofs; each Codex tool loop had one provider connection, three responses and four proofs. Fast cases shaped the Sponsor–Concurro outer link to 100/100 Mbps and 20 ms RTT; the provider was synthetic.

| Profile / route | Accepted median | 8-worker median | Paired accepted minus 8-worker |
| ---- | ----: | ----: | ---- |
| Local Claude cold, 5 pairs | 5.830 s | 5.359 s | 0.118, 0.470, 0.439, 0.466, 0.445 s |
| Local Codex loop, 5 pairs | 4.952 s | 4.662 s | 0.365, 0.294, 0.299, 0.226, 0.407 s |
| Fast Claude cold, 3 pairs | 37.096 s | 36.794 s | 0.323, 0.304, 0.285 s |
| Fast Codex loop, 3 pairs | 33.123 s | 32.884 s | 0.377, 0.240, 2.949 s* |

*The third Codex accepted run took 36.232 s, including a 13.152 s helper handshake versus roughly 10.7–10.8 s in the other accepted runs. Its 2.949 s pair difference is a timing outlier, not an LPN gain. The other two fast Codex pairs differ by 0.24–0.38 s. Fast Claude warm complete times were 5.059–5.084 s accepted and 5.080–5.696 s with eight workers; the 5.696 s run was slow. There is no demonstrated warm-turn improvement. Fast directional bytes stayed within a few kilobytes across variants: about 188 MB up/174 MB down for Claude and 182 MB up/143 MB down for Codex. Sampled role RSS was about 1.5–1.7 GiB; 0.2-second CPU samples cannot resolve a roughly 10 ms parallel burst.

## Bound and other costs

In the instrumented local Claude run, Sponsor handshake and prefix together spent **335.7 ms** in LPN, split 162.3/173.4 ms; Concurro spent another **331.1 ms**, split 162.7/168.4 ms. Each stage had two full-size and two small extensions per role. The Sponsor sum estimates only Sponsor-side serial work, not the whole protocol's critical-path ceiling: either party can become critical, and phases overlap. Across both roles, the measured LPN intervals total 666.8 ms of work in this one local run. The roughly 0.44 s local paired gains can therefore exceed the Sponsor-only sum without implying that all of the difference is scheduling noise.

With eight workers, the fast Sponsor reports 21.3/20.9 ms of LPN in handshake/prefix and Concurro reports 22.0/21.0 ms. The **85.2 ms combined residual** is an optimistic zero-cost removal budget for those measured intervals, about 0.23% of the 37 s cold session; overlap can only reduce the direct critical-path saving under the measured schedule. This is an estimate from one instrumented case, not a demonstrated whole-protocol bound for other workloads. Together with the sub-1% observed cold gain and no warm gain, it does not justify a Metal port for this workload.

The same local Sponsor handshake/prefix measured 373/335 ms in MPCOT, 387/512 ms in aggregate SSL-call wall time, and 542/738 ms in preprocessing CPU. Those timers overlap and must not be added. On the fast link, the eight-worker Sponsor reported about 715 ms MPCOT per stage and 9.4/18.3 s aggregate SSL-call wall time, within helper stages of roughly 10.8/20.3 s. Link round trips and transfer dominate the observed fast path, but this experiment did not validate an alternative for them. Proof times also overlap the session timeline.

Concurrent-session throughput was **not tested** for the candidate. The complete fixtures ran one session per case; throughput and CPU contention under concurrent sessions remain unqualified. We stopped the matrix after the marginal bootstrap-only latency result.

The [compact measurements](FERRET-LPN-BENCH.json) include per-run timing, traffic, resources, and raw directory paths. The [reproduction notes](experimental/ferret_lpn/README.md), [source patch](experimental/ferret_lpn/experimental.patch), and [source hashes](experimental/ferret_lpn/source-hashes.json) retain the candidate. All changes remain unstaged. No live provider, commit, push, or deployment was involved.

## Primary review

Accepted as experimental evidence, without runtime promotion. Independently reprojected all 36 fixture cases, checked the 24 production-size output-digest pairs and reported medians, verified source/build hashes and that candidate manifests replace only KRRW, and ran a new full-output equivalence case at production size with seed 303 and eight workers. Reviewed the parallel group/tail partition, thread-local PRP, instrumentation and reproduction harness; similarity review covered three new functions. The byte-identical CPU result is credible, but it offers no demonstrated warm-turn gain or concurrent-throughput benefit. Leave the accepted helper unchanged and defer GPU work. All new artifacts remain unstaged and uncommitted.
