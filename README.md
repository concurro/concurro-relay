# concurro-relay

Securely sponsor [Concurro](https://github.com/concurro/concurro) tasks with your Claude or ChatGPT subscription using self-custodied provider credentials.

## Highlights

- 🔐 **Self-custodied provider credentials:** provider tokens stay on your machine and go only to the provider.
- ✅ **Verified requests and responses:** Concurro controls the request and authenticates the response through MPC-TLS. QuickSilver ZK proofs let the Sponsor verify the request before forwarding it.
- 🌐 **Use your own connection:** provider traffic leaves from your machine.
- 🔎 **See what you sponsor:** audit every prompt before it's sent, with the option to reject.

The project includes the Sponsor CLI, a hosted verifier, and local development tools.

## Supported providers

| Subscription | Works with | Connection mechanism |
| ---- | ---- | ---- |
| Claude | Claude Code | HTTP/2 |
| ChatGPT | Codex | WebSockets |

The relay keeps provider connections open between turns. Each new connection needs a cryptographic setup step, called a bootstrap. Use `--links` to choose how many sessions can run at once.

## Installation

Sponsor packages include the proof runtime and its libraries, so you don't need Rust, Python, or Homebrew to run the relay. You'll need the `claude` or `codex` CLI to sign in to that provider.

| Platform | Archive | Requirements |
| ---- | ---- | ---- |
| macOS, Apple Silicon | `concurro-relay-aarch64-apple-darwin.tar.gz` | — |
| Linux x86-64 | `concurro-relay-x86_64-unknown-linux-gnu.tar.gz` | glibc 2.38 or newer (tested on Ubuntu 24.04); an x86-64-v3 CPU with AES and PCLMUL |

Download packages from the [Releases page](https://github.com/concurro/concurro-relay/releases). See the [installation instructions](docs/releasing.md#the-sponsor-bundle-and-installing-it) for checking and installing the download, or [build from source](#development).

Keep `bin/` and `native-runtime/` together when installing a bundle. macOS bundles are ad hoc signed, not notarized. Linux bundles use the system's glibc and carry every other library. Each bundle lists its third-party components and their notices in `licenses/`. There are no Windows Sponsor packages yet. The hosted verifier has a separate Linux amd64 container build.

## Quick start

Run the relay in a terminal:

```bash
concurro-relay
```

The setup screen asks for your Concurro relay address and which providers you want to sponsor, then walks you through sign-in. Use the relay address from your Concurro instance. Open the approval link and enter the code in your Concurro account to start serving tasks.

Setup selects providers with a saved, usable login by default. You can change that selection before approving registration.

After setup, you can run without the full-screen view and allow three sessions at once:

```bash
concurro-relay run --links 3
```

The relay opens outbound connections to Concurro and the provider; you don't need to open an inbound port.

### Provider sign-in

| Provider | How to sign in |
| ---- | ---- |
| Claude | Run `claude setup-token` and paste the token into the relay's sign-in prompt |
| ChatGPT | The relay starts `codex login --device-auth` with its own temporary Codex home |

The relay keeps its own credentials without changing your existing CLI logins. On macOS, it stores provider credentials in Keychain; on Linux, in files only your user can read. If you set `CLAUDE_CODE_OAUTH_TOKEN`, the relay uses that token instead of the saved Claude credential.

Your Concurro registration and provider sign-ins are separate. If a provider login expires, use its `connect` command below to sign in again. Your Concurro registration stays in place. The relay doesn't refresh ChatGPT access tokens automatically.

## Commands

| Command | Purpose |
| ---- | ---- |
| `concurro-relay` | Open the interactive setup and activity view |
| `concurro-relay login` | Register with a Concurro account |
| `concurro-relay run --links N` | Run up to N sessions at once, printing activity to the terminal |
| `concurro-relay connect claude_subscription` | Sign in to Claude again |
| `concurro-relay connect chatgpt_subscription` | Sign in to ChatGPT again |
| `concurro-relay status` | Show registration and whether each provider is signed in |
| `concurro-relay logout` | Unregister the relay and delete its saved credentials and identity key |

## Auditing and status

Use the arrow keys to choose a request and Enter to open it. The activity view keeps recent request text in memory. When run outside an interactive terminal, the CLI uses text output, just like `run`.

You can see verified requests and usage reported by Concurro. A continuation shows the new request and a reference to the conversation so far.

The Sponsor doesn't independently verify the usage figures. The activity view doesn't show full provider responses.

Text mode prints request hashes by default. To print full request bodies and save them in session audit files:

```bash
CONCURRO_NATIVE_AUDIT_TEXT=1 concurro-relay run
```

`status` reads your saved settings and credentials; it doesn't check a running relay. Use Concurro's Sponsor view to see connection and task status.

## Reviewing requests

Concurro shows the relay each request, with its path and public headers, before any of it reaches the provider. The relay records the request and its decision first. Then it checks that every byte it forwards matches the request that was approved.

By default, the relay accepts each request. In the activity view:

| Key | Action |
| ---- | ---- |
| `a` | Switch between accepting each request and asking you about each one |
| `y` | Accept the waiting request you moved the cursor to |
| `n` | Reject the waiting request you moved the cursor to |

The cursor never moves onto a waiting request by itself, so you always answer the request you chose. The relay rejects a request that nobody answers within 5 minutes. `run` accepts each request unless a review hook rejects it.

A review hook is a command the relay runs, with `/bin/sh -c`, for each request. It can, for example, ask a local classifier model:

```bash
concurro-relay run --review-command ./review.sh
```

You can also set `CONCURRO_RELAY_REVIEW_COMMAND`. The hook gets the request as JSON on standard input, with the fields `route`, `link`, `request`, `session_id`, `sha256`, `path`, `headers` and `prompt`.

| Hook result | Effect |
| ---- | ---- |
| Exit 0 | Accept |
| Exit 1 | Reject |
| Any other exit, a crash, or more than 60 seconds | Ask you, or accept in `run` and when the view accepts each request |

A hook that fails or times out doesn't block requests, unless you've switched the view to asking about each one.

The first line the hook prints is shown as the reason. It's also sent to Concurro when the request is rejected.

A rejected request never reaches the provider. Claude Code gets an HTTP 403 error, and Codex gets an error event. Later requests continue on the same connection. A Claude session's first request is reviewed before the relay connects to the provider, and rejecting it ends that session.

## How it works

```text
GitHub runner → Concurro gateway and verifier → Sponsor relay → Provider
```

Concurro and the Sponsor set up TLS 1.3 with the provider together. The Sponsor sends its credential in a protected part of the connection, then hands off keys so Concurro can send requests and authenticate responses without learning the credential. A QuickSilver proof lets the Sponsor check that each encrypted request matches the text it shows for auditing. The provider uses ordinary TLS, with no protocol changes.

Claude uses HTTP/2 with compact Message Threads continuations by default. Codex uses WebSockets with `previous_response_id` continuations.

Concurro can see prompts, responses, and some account metadata, but not the provider token. The provider sees the Sponsor's IP address. Bootstrap costs CPU time and bandwidth; keeping connections open and sending only new conversation content helps keep later turns fast.

The relay saves its identity key in a file only your user can read, under `concurro-relay` in your system's configuration directory. Set `--state-dir` or `CONCURRO_RELAY_HOME` to use another directory. Provider credentials are stored separately: in Keychain on macOS, beside the key on Linux.

## Hosted verifier

Sponsor 0.2.0 and the verifier both use relay protocol 5. Protocol 4 Sponsors must
upgrade before they can connect. The Sponsor's TLS listener is separate from the
internal HTTP listener for Accounts, Gateway and Exchange.

| Flag | Value |
| ---- | ---- |
| `--owner-token` | Accounts bearer file for `/owner/v1/*` |
| `--inference-token` | Gateway bearer file for `/dispatch/v2/*` |
| `--release-token` | Exchange bearer file for `/release/v1/*` |
| `--exchange-public-keys` | Exchange Ed25519 public keys in a JSON Web Key Set, indexed by `kid` |
| `--registry` | Durable approved relay registry |
| `--claim-journal` | Durable call, token and revocation journal. Defaults to the registry path with `.claims` appended |
| `--certificate`, `--private-key` | Certificate and key for the public Sponsor TLS listener |
| `--relay-listen`, `--private-listen` | Bind addresses for the public TLS and internal HTTP listeners |
| `--verification-url` | Full URL of the owner page where the Sponsor's pairing code is entered |

Use three distinct token files containing the raw tokens. Each caller sends
`Authorization: Bearer <token>` to its own API. Keep the private listener on the
internal network. Provision the claim signing key only on Exchange and configure
its public key on the verifier. Keep the Exchange and verifier clocks synchronized
for claim issue and expiry checks. For rotation, include both active public keys
until every claim signed by the old one has expired. A JWKS contains entries of
the form `{"kty":"OKP","crv":"Ed25519","kid":"exchange-1","x":"<base64url-raw-public-key>"}`,
under the top-level `keys` array. Encode the 32-byte public key without padding.

Mount the registry and journal on durable storage. The journal records admission
before a call reaches native ingress and persists known provider input and output
usage before response completion. An interrupted response records the observed
lower bound when the provider reported partial usage. Known-expiry records are
removed after expiry.
A release received before dispatch fences the ID until the verifier learns its
expiry from a signed claim. An append failure stops admission and release
acknowledgements until the journal can be reopened after repairing storage.

The [hosted API crate](crates/hosted-api) defines the private wire types and JWS
codec. See [its API notes](crates/hosted-api/README.md) and the
[0.2.0 release sequence](docs/releasing.md#protocol-5-release).

## Development

The workspace uses Rust. Install [cargo-nextest](https://nexte.st), then fetch and patch the upstream dependencies before building or testing:

```bash
git clone https://github.com/concurro/concurro-relay.git
cd concurro-relay
./scripts/upstream.sh
cargo build --release --locked --workspace
cargo nextest run --workspace --locked
```

Cargo builds the Rust binaries. To run the Sponsor, you'll also need the native helpers: follow the [build and packaging guide](native/README.md).

The guide covers local test providers and both backends. Bootstrap integration tests need the built packages and must be enabled explicitly. The default tests use local fixtures.

An older TLSNotary backend is available for local development with `dev-verifier --backend tlsnotary`. Hosted Concurro supports only the TLS 1.3 backend.

The script creates `upstream/`, which is excluded from Git, and won't overwrite existing source directories. The root `Cargo.toml` defines shared dependencies and their features; `Cargo.lock` records the resolved versions.

| Path | Purpose |
| ---- | ---- |
| `crates/relay` | Sponsor CLI, provider sign-in, activity view, and relay links |
| `crates/hosted-api` | Shared owner, claim, dispatch and release contracts |
| `crates/hosted` | Hosted verifier, registration storage, session pool, and Responses bridge |
| `crates/verifier` | Shared verifier and TLSNotary integration |
| `crates/protocol` | Relay identity, messages, and provider routes |
| `crates/tls13` | TLS handshake authentication and record processing |
| `crates/provider-protocol` | Claude and Codex message formats and response handling |
| `crates/native` | Native helper control, bootstrap, request proofs, and provider sessions |
| `crates/native-transport` | Native worker transport |
| `crates/dev` | Development verifier, gateway, and mock provider tools |
| `native/` | Helper sources, build recipes, packaging, and integration fixtures |
| `patches/` | Patches applied to pinned upstream dependencies |
