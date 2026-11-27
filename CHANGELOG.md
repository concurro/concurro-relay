# Changelog

User-facing changes to the Sponsor relay per release.

## [Unreleased]

## [0.1.3](https://github.com/concurro/concurro-relay/compare/v0.1.2...v0.1.3) - 2026-11-27

### Added

- add Antigravity subscription sponsorship and relay support

### Changed

- share TLS KeyUpdate transport across providers

## [0.1.2](https://github.com/concurro/concurro-relay/compare/v0.1.1...v0.1.2) - 2026-11-23

### Added

- cap the helper channels Concurro may hold open to a Sponsor
- let the Sponsor approve or reject each native request before it is sent
- *(relay)* implement phase 5 signed session admission and private APIs

### Fixed

- bound native helper tunnels, circuit cache and credential length
- let a link's TLSNotary session deliver its last proofs before it stops
- stop a link's TLSNotary session driver when the link ends
- end every link and its native session when the relay stops serving
- refuse native sessions for routes the relay is not registered for
- keep tunnel opens ordered and bound the circuit cache by size
- write each request's review record through before answering Concurro
- build and check Codex upgrade tails by one rule set, reading _ in header names as -
- answer Claude requests the relay does not serve and keep the session
- pin the Codex upgrade's account header to the Sponsor's own account
- stop channel socket I/O once closed and accept an End before Close
- buffer tunnel channels by bytes and end them on close or release
- stop connecting a tunnel channel once its peer closes it
- limit Claude templates to the Messages API and headers the relay does not set

- Sponsor uses relay protocol 5. Upgrade Sponsor and the hosted verifier together.

## [0.1.1](https://github.com/concurro/concurro-relay/compare/v0.1.0...v0.1.1) - 2026-11-18

Adds a Sponsor package for Linux.

- Install `concurro-relay-x86_64-unknown-linux-gnu.tar.gz` on Linux x86-64 with glibc 2.38 or newer, tested on Ubuntu 24.04. It needs an x86-64-v3 CPU with AES and PCLMUL.
- The Linux package carries every library it needs except glibc.
- Both packages list their third-party components, with upstream sources and license notices, in `licenses/`.
- Each release publishes the sources of the bundled copyleft libraries (GMP; on Linux also the GCC runtime) as `<archive>-third-party-sources.tar.gz`.

## [0.1.0](https://github.com/concurro/concurro-relay/releases/tag/v0.1.0) - 2026-11-18

Initial release of the Concurro Sponsor CLI for macOS on Apple Silicon.

- Sponsor Claude Code and Codex tasks using provider credentials kept on your machine.
- Connect to providers from your own machine, with joint TLS setup and request proofs.
- Reuse connections across turns with Claude HTTP/2 Message Threads and Codex WebSocket continuations.
- Run multiple Claude and Codex sessions at once.
- Register through your Concurro account and view request activity and reported usage in the terminal.
- Install a self-contained package with the native proof runtime and required libraries.

The package is ad hoc signed, not notarized. ChatGPT sign-in must be renewed manually when its access token expires.
