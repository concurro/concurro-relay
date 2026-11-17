# concurro-relay

A relay a sponsor runs so that their provider subscription can fund Concurro tasks without
Concurro holding the token. The relay keeps the provider login on the sponsor's machine,
performs each request Concurro orders, and proves in zero knowledge that the provider
received exactly that request. The design is in Concurro's `docs/proposals/sponsor-relay.md`.

**Status: first slice.** The relay registers with and serves a development stand-in for
Concurro. Concurro itself has no relay support yet. This code has had no security review,
and it depends on a pre-release proof stack carrying local patches.

## Layout

| Path | Contents |
| ---- | ---- |
| `crates/protocol` | What relay and verifier share: messages, request encoding, relay identity |
| `crates/relay` | The `concurro-relay` program: policy, provider logins, links, commands, full-screen view |
| `crates/verifier` | Concurro's side: accepts relays' links, orders exchanges, checks proofs |
| `crates/dev` | Stand-ins for Concurro: `dev-verifier`, a gateway for a real harness, a mock provider |
| `patches/` | Local patches to TLSNotary, mpz and rangeset |
| `scripts/upstream.sh` | Fetches the pinned upstream sources into `upstream/` and applies the patches |

## Building

Owned crates inherit dependencies from the root workspace manifest. Pin crates.io
versions as `=x.y.z`, use `default-features = false`, and enable required features
explicitly. Keep the manifest pins and `Cargo.lock` consistent.

```bash
./scripts/upstream.sh
```

```bash
cargo nextest run --workspace
```

`upstream/` is not committed. The script refuses to overwrite a source directory; remove
it to prepare it again after a patch changes.

The tests are in `crates/dev/tests`, against a mock provider:

| File | Covers |
| ---- | ---- |
| `relay.rs` | The relay as shipped: registration, links, single requests, WebSocket connections, refusals |
| `adversarial.rs` | What a verifier rejects: relays which insert, omit, replay or misplace what they prove, hide more than the credential or smuggle a request into it, and providers which send stale, mixed or unfinished responses |

The dishonest relays are written in the tests. The relay library's one concession to
them is `Misproof`, a parameter by which a proof on an open connection can misstate
where the last one ended.

## The relay

```text
concurro-relay            full-screen view: signs in if needed, then serves
concurro-relay login      register this relay to a Concurro account
concurro-relay run        serve, printing one line per event
concurro-relay connect    sign in to a route's provider again
concurro-relay status     show the registration and whether each route is ready
concurro-relay logout     withdraw the registration and remove the relay's key
```

Without a command and outside a terminal it behaves as `run`.

- **Registration:** `login` generates a key pair, asks Concurro for a code and waits for
  the person to approve it. Concurro stores only the public key.
- **Links:** the relay dials out over TLS and proves it holds its key on each connection.
  `--links N` serves N requests or connections at once. A link which ends is opened again with backoff; a
  relay Concurro refuses stops. In the view, `r` registers a refused relay again and
  keeps its provider sign-ins; `concurro-relay login` does the same from the command
  line.
- **Provider credentials** are the relay's own, given to it at sign-in. It does not
  borrow the logins of Codex or Claude Code, and signing in does not disturb them:

  | Route | Credential |
  | ---- | ---- |
  | ChatGPT subscription | The relay runs `codex login --device-auth` with a private directory of its own as Codex's home, takes the login Codex is given and removes the directory |
  | Claude subscription | The token `claude setup-token` prints, pasted at sign-in; `CLAUDE_CODE_OAUTH_TOKEN` takes precedence if set |

  Credentials are kept in the macOS keychain, and elsewhere in files only the owner can
  read. They are read for every request and never sent to Concurro. A token which says
  it has expired is not used; `concurro-relay connect <route>` signs in to a provider
  again without registering again. `logout` removes them.
- **Routes:** Concurro orders either a single request, which gets a provider connection
  of its own, or a WebSocket connection, whose turns are each proven while it stays
  open. A WebSocket turn proves only its own request, which is far cheaper than proving
  a whole conversation again. Only the ChatGPT route has WebSocket connections.
- **Policy:** each route's allowlist of path, headers and body fields is built in
  (`crates/relay/src/routes.rs`). A request outside it is refused and nothing is sent.
- **State:** the registration and key are kept in the platform's configuration directory
  under `concurro-relay`, or in `CONCURRO_RELAY_HOME`. Only the owner can read the key.
- **The view** lists each request the relay proved. `↑`/`↓` move between them, `enter`
  opens one to show what it said, `tab` switches between its request and its response,
  and `pgup`/`pgdn` scroll a long one. What the newest fifty said is held in memory
  only, never written down.

## Trying it

The dev verifier approves every registration by itself and serves a harness on
`--listen`. It keeps its registered relays in `dev-verifier.json`, so a relay stays
registered when the dev verifier is started again.

```bash
cargo run --bin dev-verifier -- --route chatgpt_subscription
```

```bash
cargo run --bin concurro-relay -- --server localhost:7443 --server-ca dev-verifier.pem
```

Then point a harness at the dev verifier. Codex, over a WebSocket
(`supports_websockets=false` for single requests):

```bash
SPIKE_DUMMY_KEY=dummy codex exec --ignore-user-config --ephemeral --skip-git-repo-check -c 'model_provider="spike"' -c 'model_providers.spike={name="Dev verifier",base_url="http://127.0.0.1:7050/v1",wire_api="responses",supports_websockets=true,env_key="SPIKE_DUMMY_KEY"}' -c 'analytics.enabled=false' "Read README.md and say in one sentence what it is."
```

Claude Code, with `--route claude_subscription` on the dev verifier:

```bash
ANTHROPIC_BASE_URL=http://127.0.0.1:7050 claude -p "List the files in this directory"
```

## Native TLS 1.3 backend

`dev-verifier --backend tls13` serves packaged Sponsor and Concurro native
workers over the existing authenticated relay links. The default remains
TLSNotary. See [native/README.md](native/README.md) for packaging inputs,
per-link ingress leases, and offline fixtures. The accepted extraction and
its limits are recorded in [native/ACCEPTANCE.md](native/ACCEPTANCE.md).

## Not done

- Concurro's side: relay records, the real registration flow and the verifier in the
  gateway's request path. `dev-verifier` stands in for all three.
- A harness message other than a request while a response is in flight, such as a
  cancellation: the verifier reads the harness only between turns.
- Keeping the relay's key in the operating system's keychain.
- Showing live links and tasks from `status` while another process is serving.
- Renewing the ChatGPT sign-in without the person: the relay keeps the access token
  Codex was given and asks for a new sign-in when it expires.
- Cancellation of a request in flight, signed releases and updates.
