# Phase 6: Rust runtime package and qualification

The Sponsor and Concurro macOS arm64 packages launch the bundled Rust worker by default. Each package contains 27 manifested files (143.1 MB Sponsor; 142.6 MB Concurro) and no Python runtime, worker source, HPACK, CFFI, or `cryptography` files. `CONCURRO_NATIVE_RUST_WORKER` remains an explicit development override for reference comparisons. The existing native helpers and public circuit cache were reused.

The Rust pair now acknowledges completion after both role reports are written. This fixed a report-write race exposed by two simultaneous Sponsor registrations. The acknowledgment is negotiated in the existing control metadata, so mixed Python/Rust pairings remain compatible.

## Packaged behavior

All local rows used the packaged parent binaries, the same accepted helpers and circuits, and synthetic providers. The mixed-route row used real local Claude/Codex CLIs; the other rows used bounded synthetic clients. The normal Rust child process tree contained two Rust workers and native helpers, with no Python descendants. The package was launched from `/private/tmp`, outside the source checkout.

| Case | Result | Evidence |
| ---- | ---- | ---- |
| Two Claude and one Codex concurrently | Three distinct paired sessions; all CLIs passed | `/private/tmp/concurro-phase6-mixed-1/` |
| Two registrations, each on slot 1 | Two independent Codex tool loops; three responses and four proofs per session | `/private/tmp/concurro-phase6-two-registrations-final-1/summary.json` |
| Two Codex tasks under one registration | Both tool loops passed; two idle local reconnects per task | `/private/tmp/concurro-phase6-two-codex-one-registration-1/` |
| Isolated active Codex cancellation | Canceled link closed; Claude finished; replacement Codex tool loop passed | `/private/tmp/concurro-phase6-isolated-cancel-1/qualified.json` |
| Sponsor SIGINT / Concurro SIGTERM | Three workers and helpers per role gone; six sockets removed in each run | `/private/tmp/concurro-phase6-sigint-sponsor-2/summary.json`, `/private/tmp/concurro-phase6-sigterm-concurro-1/summary.json` |
| Worker never connects | 30-second bridge timeout; worker and sockets removed; verifier stays available | `/private/tmp/concurro-phase6-unavailable-worker-2/summary.json` |
| Final Rust worker against Python peer | Both role directions passed for Claude and Codex | `/private/tmp/concurro-phase6-mixed-{pr,rp}-{claude,codex}/` |

The completed Claude and Codex reports match session and transcript IDs, proved prompt and usage associations, and provider response counts. Native transport tests cover peer EOF, half-close, canceled tunnels, and unavailable listeners. Native helper tests cover early exits and missing completion markers. Earlier failed registration runs remain in `/private/tmp/concurro-phase6-two-registrations-{1,2}/` and `...-ack-1/`; the final three-way completion acknowledgment passed. The cancellation runner's incorrect provider-connection assertion was corrected in the separate `qualified.json` audit, without weakening its cancellation or replacement checks.

## Matched Claude WAN evidence

The local shaper covers the authenticated Sponsor–Concurro outer link, including control and auxiliary helper traffic. It does not shape CLI ingress or the provider connection. Synthetic provider response generation took about 0.1 ms between its first and last events, so these measurements do not model live inference, DNS, packet loss, or Internet connection setup. Every Claude run used the same 121-byte request body (SHA-256 `4c033c531e9d68fb6be3ea35789b62f5483ae056ae059c054215fe90af67242d`) and received 834 SSE body bytes per turn. All used the same circuit cache, one bootstrap, and streams 1 and 3. The fixture split HTTP/2 writes into short TLS records; each turn therefore required 14 proofs, or 28 total, for both Python and Rust. Earlier phase-5 fixtures used different response fragmentation and reported eight proofs, so those counts are not a port comparison. Directional traffic stayed at about 188.1 MB upload and 173.7 MB download for both workers.

| Profile / worker | Runs | Cold first body / complete | Warm first body / complete | Sampled CPU / peak RSS |
| ---- | ----: | ----: | ----: | ----: |
| Fast 100/100 Mbps, 20 ms RTT / Python | 2 | 32.757 / 38.373 s | 0.929 / 6.600 s | 106.8% / 2954 MiB |
| Fast / Rust | 2 | 32.476 / 37.028 s | 0.770 / 5.286 s | 105.6% / 2938 MiB |
| Home 10/100 Mbps, 40 ms RTT / Python | 1 | 167.520 / 176.678 s | 1.569 / 10.645 s | 91.0% / 2980 MiB |
| Home / Rust | 1 | 167.191 / 175.204 s | 1.361 / 9.378 s | 99.3% / 2890 MiB |
| Constrained 5/20 Mbps, 80 ms RTT / Python | 1 | 364.588 / 383.981 s | 3.304 / 22.842 s | 94.0% / 2846 MiB |
| Constrained / Rust | 1 | 364.175 / 382.517 s | 3.114 / 21.438 s | 92.4% / 2757 MiB |

Times and resources are medians when two runs exist. Fast cold-complete ranges were 38.372–38.375 s for Python and 37.015–37.040 s for Rust; warm-complete ranges were 6.552–6.648 s and 5.261–5.311 s. CPU is the highest aggregate `ps %cpu` observed in 0.2-second samples; RSS is the highest sampled aggregate. Both include the relay, verifier, workers, and native helpers by process ancestry, excluding the Python fixture and client. The Sponsor helper-reported handshake and prefix times were approximately 10.7/20.1 s (fast), 55/110 s (home), and 119/240 s (constrained); the two roles ran those phases concurrently. Proof elapsed times are retained per role and should not be summed into total latency. Full per-run timing, directional bytes, helper times, sampled CPU/RSS, and repeat spread are in [PHASE6-BENCH.json](PHASE6-BENCH.json).

The constrained benchmark initially failed under the synthetic client's 180-second timeout, then under the synthetic provider's 120-second socket timeout. Both failed directories are preserved as `...-constrained-rust-{1,2}/`. A benchmark-only provider copy raised that socket timeout to 600 seconds; the successful Rust and Python constrained runs used identical copies. An additional Rust home run passed with 175.254 s cold and 9.383 s warm completion (`/private/tmp/concurro-phase6-bench-home-rust-2/`); it was excluded from the matched table because no second Python home run was requested. The differences above are small relative to MPC transfer time and do not establish a general latency speedup.

## Matched Codex fast-WAN evidence

One Python/Rust pair used the same 100/100 Mbps, 20 ms RTT shaper and accepted synthetic Codex tool loop. Each client made two local WebSocket connections, completed three responses on one provider connection, preserved the parent response chain, and returned `TOOL_LOOP_DONE`. Provider request bodies were 78, 172, and 253 bytes; each role reported four proofs and three prompt/usage associations. The test did not record a comparable provider response byte total.

| Worker | Client time | Upload / download | Sampled CPU / peak RSS | Evidence |
| ---- | ----: | ----: | ----: | ---- |
| Python | 33.422 s | 182.064 / 142.749 MB | 98.6% / 2940 MiB | `/private/tmp/concurro-phase6-bench-fast-codex-python-1/` |
| Rust | 33.015 s | 182.068 / 142.754 MB | 109.4% / 2873 MiB | `/private/tmp/concurro-phase6-bench-fast-codex-rust-1/` |

This single pair supports Codex parity under the fast profile; it is not a speedup estimate. Its per-role helper times, proof times, process samples, and directional bytes are in [PHASE6-BENCH.json](PHASE6-BENCH.json).

## Live providers and checks

The minimal live Codex request passed with `gpt-6.1-terra` low effort: the CLI read `TOOL_OK` through one provider connection; both role reports agree on the session, two prompt/usage associations, and six proof records. Evidence: `/private/tmp/concurro-phase6-live-codex-1/summary.json`.

The final live Claude check passed with the real CLI and the relay-owned Keychain credential. The CLI returned `OK` and `YES`; both responses were HTTP 200 on streams 1 and 3. The paired reports match session, H2, H3 and prefix commitment, with two prompt audits, matching usage associations, 16 proof records, one protected bootstrap, one provider connection and one indexed later header. Evidence: `/private/tmp/concurro-phase6-live-claude-real-cli-1/summary.json` and both role reports. The calls took 8.632 and 1.529 seconds; these are local-host live-test elapsed times including inference, not WAN overhead measurements.

Earlier attempts are preserved: `/private/tmp/concurro-phase6-live-claude-1/` used an expired CLI token and received eight automatic HTTP 401 retries. To bound retries, the next harness substituted a synthetic 121-byte benchmark request, which changed the request being qualified. That request received HTTP 429 with both the refreshed CLI token and the relay-owned token (`...-live-claude-bounded-1/`, `...-live-claude-relay-keychain-1/`). One separately authorized ordinary-TLS control reproduced HTTP 429 with message `Error` and no retry timing headers (`/private/tmp/concurro-phase6-direct-control-1/summary.json`). These results do not establish a general usage limit or an MPC defect. The same relay-owned credential subsequently passed the real CLI check; the minimal request's 429 cause remains unresolved.

The representative CLI request uses `/v1/messages?beta=true`, Claude Code beta headers and the CLI's full body. The Rust ingress preserves the path including query, JSON body bytes and remaining public headers, replacing local authorization with Sponsor's credential. As in the Python reference, it strips host, content-length, connection, transfer-encoding, proxy-authorization, `accept-encoding` and `x-api-key`. A local-only capture is retained at `/private/tmp/concurro-phase6-claude-cli-capture-1/summary.json`.

The final harness used `CLAUDE_CODE_MAX_RETRIES=0` and first-error monitoring; a local-only HTTP 429 test confirmed one request with that setting. The user's Keychain entry remained present, the isolated test entry was removed, and an exact-byte scan found no credential in 96 evidence files up to 20 MB. Harness files: `/private/tmp/concurro-phase6-run-claude-cli-bounded.py` (SHA-256 `27ff8d8163b07c2db1f567ab240c68d5d8188aac9c4ed9ee20e7b4473f1e516b`) and `/private/tmp/concurro-phase6-live-claude-real-cli.py` (`2dcd7516440cdd5d24187ea8bc7e25219b32457e513a8b61b819e1bd89b424b2`). No runtime changes were needed for the corrected test.

- Rust 1.100.0: `cargo fmt --all -- --check` passed.
- `cargo clippy --workspace --all-targets --locked` passed with six pre-existing verifier/relay warnings. An additional `-D warnings` run stopped on the existing verifier warnings.
- `cargo nextest run --workspace --all-targets --locked --status-level fail`: 109 passed, two external-runtime tests skipped.
- Isolated nextest: TLS 1.3 4/4, native transport 10/10, provider protocol 9/9, native 14/14 with two external-runtime tests skipped.
- Retained Python regressions: 4/4 passed. `git diff --check` and the staged-tree check passed.

## Benchmark provenance

The final packages were `/private/tmp/concurro-phase6-rust-packages-v3/sponsor` and `/private/tmp/concurro-phase6-rust-packages-v3/concurro`. Both workers used the same accepted native helpers from `/Users/cylwit/Code/github.com/concurro/.artifacts/concurro-relay-native-v16` and the fixed public circuits in `/private/tmp/concurro-phase6-public-circuits`. The Python comparison explicitly selected the retained v16 reference worker through `/private/tmp/concurro-phase6-python-worker.sh`; Rust used the packaged default. The benchmark runner copied the accepted v16 mixed-session fixture and added WAN shaping, two-turn timing, and resource sampling. The modified Claude provider fixture only lengthened its socket timeout. SHA-256 for the runner, shaper, provider fixture, and reference shim is recorded in [PHASE6-BENCH.json](PHASE6-BENCH.json).

The retained local runner and package artifacts can reproduce a fresh fast-profile case with a new output path. Set `phase6_worker=python` for the matched reference; use `--claude 0 --codex 1 --synthetic-codex-reconnect` for Codex. Home and constrained Claude cases set `phase6_profile` accordingly.

```bash
phase6_worker=rust
phase6_profile=fast
phase6_output=/private/tmp/concurro-phase6-replay-fast-rust
CONCURRO_BENCH_PROFILE="$phase6_profile" CONCURRO_BENCH_WORKER="$phase6_worker" \
  python3 /private/tmp/concurro-phase6-bench-runner.py \
  --claude 1 --codex 0 --synthetic-claude --claude-delay 0 \
  --sponsor /private/tmp/concurro-phase6-rust-packages-v3/sponsor \
  --concurro /private/tmp/concurro-phase6-rust-packages-v3/concurro \
  --relay-source /Users/cylwit/Code/github.com/concurro/concurro-relay \
  --pydeps /Users/cylwit/Code/github.com/concurro/.artifacts/concurro-relay-native-v16/sponsor/native-runtime/pydeps \
  --h2-deps /private/tmp/concurro-h2-deps \
  --public-circuits /private/tmp/concurro-phase6-public-circuits \
  --output "$phase6_output"
```

Source base: `1d34016e88208e46afe1d1208fc8f1fbe75faaf1`; accepted phase-5 index tree: `442e2dff81709363d7380029c849b47dab0bfa69`. Packaged SHA-256: worker `d7efdc85cf89f6b76b0ad0773b1ce9557c0d34209e28a3a1762bebae91000b46`; Sponsor CLI `0dc7f801c0d7f5264e75d86dfacc75c8bb3d71255a931cc72c6426193c8e6675`; Concurro verifier `a2bc522ca872db9a5604f3409ff7de28016d9bb95f583c0ff1862360b4eecadf`; Sponsor/Concurro manifests `ebdcda098ab591eb88e84eeca1faa92e00f31f43e6233b87d3e03211834109af` / `3f89a503c62e992ce9037f34dbf8a33644369ed13e3fc6a34de6003bbcdde347`.

All phase-6 changes are accepted for staging with phases 0–5 on `refactor/tls13-rust-worker`. No commit, push, deployment, helper redesign, or Linux/Windows portability claim was made. The historical intermittent prefix startup issue is not resolved by this port.

## Primary review status

Source, packaging and available qualification evidence reviewed. Independently verified both 27-file package manifests and reproduced 109 workspace tests (nextest `beec0701-49bf-402c-94e6-bf6fc570de05`; two external-runtime fixtures skipped). Only four native Rust files contain semantic changes in this phase; the other Rust changes exactly match formatting the staged source. Similar-code review covered all 11 changed or added definitions. The revised benchmark data distinguishes Claude fragmentation from Codex workloads and records its sampling limits.

Accepted after final live evidence review. Independently checked both Claude role reports: matching H2/H3, session and prefix commitment; HTTP 200 on streams 1 and 3; matching usage values; one bootstrap/provider connection and 16 records on both roles. The real CLI returned `OK` and `YES`. Together with the previously reviewed live Codex, package, concurrency, cancellation, fixture and test evidence, this completes phases 0–6 of the port plan. Qualification is macOS arm64 with the accepted external native helpers; it is not a new cryptographic security proof or cross-platform qualification. No commits or pushes are authorized or made.
