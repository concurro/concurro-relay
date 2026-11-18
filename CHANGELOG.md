# Changelog

User-facing changes to the Sponsor relay per release.

## [Unreleased]

## [0.1.0](https://github.com/concurro/concurro-relay/releases/tag/v0.1.0) - 2026-11-18

Initial release of the Concurro Sponsor CLI for macOS on Apple Silicon.

- Sponsor Claude Code and Codex tasks using provider credentials kept on your machine.
- Connect to providers from your own machine, with joint TLS setup and request proofs.
- Reuse connections across turns with Claude HTTP/2 Message Threads and Codex WebSocket continuations.
- Run multiple Claude and Codex sessions at once.
- Register through your Concurro account and view request activity and reported usage in the terminal.
- Install a self-contained package with the native proof runtime and required libraries.

The package is ad hoc signed, not notarized. ChatGPT sign-in must be renewed manually when its access token expires.
