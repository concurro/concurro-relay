# Packaged native TLS 1.3 backend

`package.py` assembles separate macOS arm64 Sponsor and Concurro bundles from
the accepted TLS 1.3 native runtime, a local `hpack` installation, and the two
Rust binaries. Python, OpenSSL, dynamic libraries, and public circuits are
included. The compiler, Homebrew, and a source checkout are build inputs only.
Each package has a SHA-256 manifest. Private MASCOT transport keys and OT
preprocessing are generated for each session outside the bundle.

```bash
RUSTC_WRAPPER= cargo build -p concurro-relay -p concurro-relay-dev --bins
python3 native/package.py --role sponsor --runtime "$MVP_RUNTIME" --hpack "$HPACK_DIR" --relay target/debug/concurro-relay --verifier target/debug/dev-verifier --output "$SPONSOR_PACKAGE"
python3 native/package.py --role concurro --runtime "$MVP_RUNTIME" --hpack "$HPACK_DIR" --relay target/debug/concurro-relay --verifier target/debug/dev-verifier --output "$CONCURRO_PACKAGE"
```

`MVP_RUNTIME` is an external accepted runnable MVP artifact containing
`DiStefano/build`, `MP-SPDZ`, `request-proof`, and `pydeps`. `HPACK_DIR`
contains the `hpack` Python package. The package script runs `clang` and
reads the local signed Python 3.13 framework during assembly. Set
`CONCURRO_NATIVE_OUTPUT` to keep session logs and fresh private state in a
chosen directory.

Start `dev-verifier` from the Concurro package with `--backend tls13` and the
desired `--route`, then run the registered Sponsor package's `concurro-relay run`.
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

The accepted synthetic fixtures can be started with `fixture_server.py`.
For a single Codex CLI invocation with one tool iteration, use
`--route codex --tool-loop --calls 3` and set
`CONCURRO_NATIVE_TEST_TURNS=2` on Concurro. The preflight with
`generate:false` is counted separately from the two generated turns.
`CONCURRO_NATIVE_TEST_TURNS` bounds fixture runs only; omit it for a persistent
Claude ingress.
