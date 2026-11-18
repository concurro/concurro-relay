# Changelog

User-facing changes to the Sponsor relay per release.

## [Unreleased]

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
