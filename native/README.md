# Packaged native TLS 1.3 backend

Both role packages launch the bundled Rust worker by default.
`CONCURRO_NATIVE_RUST_WORKER` selects a development worker binary explicitly.
The worker handles Codex WebSocket continuations and successive Claude HTTP/2
requests over one protected session. Frozen TLS and control-wire test inputs are
in `native/fixtures`; the Python worker used during the port is retained in Git
history at `aa8c3d0`.

`package.py` assembles separate macOS arm64 Sponsor and Concurro bundles from
the accepted TLS 1.3 native helper runtime and three Rust binaries. OpenSSL,
its configuration, dynamic libraries, and public circuits are included.
The packager copies the full non-system Mach-O dependency closure, rewrites
loads and library identities to package-local paths, removes rpaths, signs the
images, and audits the result. Homebrew, the compiler, Python, and the source
checkout are build or test inputs; the packaged runtime does not need their
paths. This runtime claim is for macOS arm64.
Each package has a SHA-256 manifest. Private MASCOT transport keys and OT
preprocessing are generated for each session outside the bundle.

```bash
RUSTC_WRAPPER= cargo build --release -p concurro-relay -p concurro-relay-dev -p concurro-relay-native --bins --locked
python3 native/package.py --role sponsor --runtime "$MVP_RUNTIME" --relay target/release/concurro-relay --verifier target/release/dev-verifier --worker target/release/concurro-native-worker --output "$SPONSOR_PACKAGE"
python3 native/package.py --role concurro --runtime "$MVP_RUNTIME" --relay target/release/concurro-relay --verifier target/release/dev-verifier --worker target/release/concurro-native-worker --output "$CONCURRO_PACKAGE"
python3 -B -m unittest native.test_package -v
```

`MVP_RUNTIME` is an external accepted runnable MVP artifact containing
the DiStefano helpers and public circuits, MP-SPDZ program, and request-proof
binary. Set
`CONCURRO_NATIVE_OUTPUT` to keep session logs and fresh private state in a
chosen directory.

Start `dev-verifier` from the Concurro package with the desired `--route`
(TLS 1.3 is the default), then run the registered Sponsor package's
`concurro-relay run`.
Repeat `--route` to assign different routes to successive link slots. With one
route flag, all slots use that route. Each `NATIVE_SESSION_READY` line prints a
dedicated `ingress` for its `relay` and `link` slot; point each concurrent CLI
task at its own ingress. The shared `--listen` address remains a single-link
compatibility alias pinned to the first ready authenticated link. For an
offline provider, pass `--provider-host`, `--provider-port`, and
`--provider-ca` to `dev-verifier`, and set `CONCURRO_NATIVE_PROVIDER_CA` to the
same CA on Sponsor. The live default uses the route's provider host on port
443 and the system CA file.

Concurro keeps the H2 ingress open for successive Claude requests in one
session. Authenticated Claude response headers and DATA are forwarded to the
local CLI as chunked SSE while the provider stream is still open. Each proved
request and its Concurro-reported usage appear in the
Sponsor activity stream. Set `CONCURRO_NATIVE_AUDIT_TEXT=1` on Sponsor to print
the full proved request body and retain it in the session audit file; the
default session file stores only its digest. Keep the audit output local if
prompt text is sensitive.

Closing the local Claude connection during bootstrap or response forwarding,
or sending Codex `response.cancel` during a turn, ends that native session.
The verifier accepts a new registered link for the next request. SIGINT and
SIGTERM stop isolated native worker process groups and remove bridge sockets.

The current ignored bootstrap integration tests use `python3` for a loopback
TLS provider and `openssl` for fixture certificates. They also need sibling
Sponsor and Concurro packages containing the accepted native helpers:

```bash
CONCURRO_PHASE3_FIXTURE_BUNDLE="$SPONSOR_PACKAGE/native-runtime" \
  cargo nextest run -p concurro-relay-native --test bootstrap --run-ignored all --locked
```

`fixture_server.py` supports local offline CLI fixtures when the external
provider fixture source and certificates are supplied. Historical phase and
benchmark runners are available at the commits in [ARCHIVE.md](../ARCHIVE.md);
they are not part of the current package build.
For a single Codex CLI invocation with one tool iteration, use
`--route codex --tool-loop --calls 3` and set
`CONCURRO_NATIVE_TEST_TURNS=2` on Concurro. The preflight with
`generate:false` is counted separately from the two generated turns.
`CONCURRO_NATIVE_TEST_TURNS` bounds fixture runs only; omit it for a persistent
Claude ingress.

For an offline TLSNotary fixture, `fixture_provider` (built with
`cargo build --release -p concurro-relay-dev --example fixture_provider`) serves
the existing TLS 1.2 mock provider using `CONCURRO_FIXTURE_TOKEN`. Pass its
printed socket to `dev-verifier --backend tlsnotary --fixture-provider`, and
set `CONCURRO_TLSNOTARY_FIXTURE=1` for the Sponsor relay. These explicit
fixture settings select the mock certificate host and CA; without them,
TLSNotary uses the route host and Mozilla roots.
