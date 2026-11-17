# Hosted verifier Linux amd64

The local Linux amd64 image qualified on 2026-11-17 with the frozen macOS Sponsor,
synthetic providers and the pinned Gateway. It has not been pushed or deployed.

## Inputs and image

| Item | Identity |
| ---- | ---- |
| Rust source checkout | `5d57cfab313d69c16a3b3e39fda5eb721e83c070` plus the reviewed local changes |
| Native source archive | `../.artifacts/tls13-rust-port/hosted-linux-source.zip`, SHA-256 `8dfef5b370707d0fdf848d9d15b13c09d8c40c1fcb0d55a32262b76ab7dd0ed1` |
| Public handshake circuit | `../.artifacts/tls13-rust-port/handshake-circuit-v16.txt`, SHA-256 `6abe1747161ca22474ee1430920d667c7e55b308823028309a24c5453c56dc0d` |
| DiStefano | `2ffc80643c9c92f3fd9238d681643a2a2526e1a2` plus archive and `linux-amd64-patches/` |
| MP-SPDZ | `878813125a89f7414c2a23ec844a8c184e2784e9` plus archive changes |
| libOTe2 | `fe6b2ff82a976a5332b3a2efe325831588b1324a` |
| qualified image's amd64 builder | `concurro-native-builder:hosted-amd64-rust100`, image ID `sha256:b9fbca34c3df33f3bf25e8e73d87e0bbf805f407e9543e59a1b2c4992a1d404c` |
| incremental source rebuild's amd64 builder | same tag rebuilt with `python3-gmpy2`, image ID `sha256:1b9ebd7b0f8d7dcb5b264961ee8fc23397acc9b20c5a96f16a1bd55256388ad0` |
| clean one-shot source rebuild's amd64 builder | `concurro-native-builder:hosted-amd64-rust100`, image ID `sha256:a4112749ab1fd912ee40363377377fd45c719378be9d704a4b80c490df8d3377` |
| runtime base | `debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2` |
| qualified local image | `concurro-verifier:hosted-amd64-v3`, image ID `sha256:89ca8b41505bd1adb52204f7c0a954ccba61da6a4bf18acdc5bc1a7e2b2776c8` |
| incremental source-rebuild image | image ID `sha256:5e008afad0f3491d5fe6df45228383b52dd8b0b95d1df9412c05ff165fdd35f0` |
| clean one-shot source-rebuild image | `concurro-verifier:hosted-amd64-rebuilt`, image ID `sha256:dac32076cd647fb223861e7b6392c4c09e3fb0a8a44dd8c048315730ce925bc6` |

The source archive's `manifest.json` hashes its DiStefano, MP-SPDZ and
request-proof changes. The checked-in Linux patches remove host-specific
`-march=native` and unconditional RDSEED flags, expose the MPZ base OT
seeds, and connect request-proof to Linux libraries. The MP-SPDZ `CONFIG.mine` builds for **x86-64-v3**;
the deployment CPU must also support AES and PCLMUL. The package contains the Rust
hosted verifier, Responses bridge, native worker, DiStefano, MP-SPDZ and request-proof binaries. Its complete
ELF dependency closure and both CLI entrypoints passed inside the runtime image.
The public handshake circuit came from the frozen native v16 Concurro package,
SHA-256 `6abe1747161ca22474ee1430920d667c7e55b308823028309a24c5453c56dc0d`.
`package_linux.py` reproduced all 20 runtime files byte for byte from already
built inputs inside the pinned builder. That check was package assembly, not a
native source rebuild.

## Source rebuild

Run the checked-in [build script](build_linux_amd64.sh) from the reviewed Rust
checkout. It retrieves DiStefano and MP-SPDZ at the commits above, applies the
hashed source archive and checked-in Linux patches, compiles the helpers, MP-SPDZ,
request-proof, hosted verifier, Responses bridge and native worker, then assembles
the package and builds the image. The Rust checkout's `upstream/mpz2` is the
base for the request-proof patch. The script accepts an unused output directory:

```bash
native/build_linux_amd64.sh \
  ../.artifacts/tls13-rust-port/hosted-linux-source.zip \
  ../.artifacts/tls13-rust-port/handshake-circuit-v16.txt \
  /private/tmp/concurro-linux-amd64-rebuild
```

The output is `package-concurro-v3/` under the chosen directory and the local
`concurro-verifier:hosted-amd64-rebuilt` image. Docker Desktop must provide
Linux amd64 emulation or an amd64 builder. The archive and public circuit are
retained in `.artifacts/tls13-rust-port`; the script checks their SHA-256 values.

The runtime image uses [Dockerfile.amd64-runtime](Dockerfile.amd64-runtime).
Given an already qualified `package-concurro-v3/` in `<qualification-dir>`,
reassemble only the image with:

```bash
docker build --platform linux/amd64 \
  -f native/Dockerfile.amd64-runtime \
  -t concurro-verifier:hosted-amd64-v3 <qualification-dir>
```

## Offline acceptance

The owner/Gateway fixture in `concurro/gateway/tests/hosted_relay_spike.py` ran
the image's hosted verifier and Responses bridge against the frozen Sponsor.
All seven cases passed: `test_owner_gateway_relay` (cold and warm requests),
`test_two_links_two_turns`, `test_inflight_cancel`, `test_mixed_routes`,
`test_codex_tool_loop`, `test_codex_ws_cancel` and `test_codex_ws_denials`.
The fixture outputs are under `/private/tmp/concurro-linux-amd64-qual/image-*`.
No live provider credentials or endpoints were used.

The same seven fixtures passed with the source-rebuilt image. Their outputs are
under `/private/tmp/concurro-hosted-work/rebuilt-fixtures-v5/`. The Codex tool-loop
fixture initially hit a Docker wrapper shutdown timeout; its passing retry reads
the bridge's live turn records before teardown.

## Final requirement status

The [final evidence package](../../.artifacts/tls13-rust-port/hosted-v5-final/clean-acceptance.md)
records the checked-in recipe's one-shot run and the focused clean-image checks.

| Requirement | Status | Evidence |
| ---- | ---- | ---- |
| Exact Claude, ChatGPT and combined approval routes | Passed, including mismatched-route rejection | `test_portal_*_routes.log`, `portal-route-evidence/` |
| Portal route selector and owner-bound BFF | Passed | `sponsor-route-selector.png`, `sponsor-claude-only.png`, `bff-lifecycle.log` |
| Source-to-image recipe | Passed from a fresh output directory | `clean-build.log`, `clean-package-comparison.json` |
| Runtime image and native handshake | ELF/CLI smoke and owner/Gateway fixture passed | `clean-runtime-smoke.log`, `clean-owner-gateway.log` |
| Frontend and hosted unit checks | 26 frontend and 6 hosted Rust tests passed | `frontend-test.log`, `hosted-nextest.log` |

The clean package matched 19 of 20 files from the incrementally built package.
Only `mascot-party.x` changed: the clean MP-SPDZ make step rebuilt
`ref10/libSimplestOT.a` after the script copied the CMake-built archive, whereas
the incremental run linked the copied archive. The clean image passed the
focused native owner/Gateway fixture. No live provider was called.

For a deployed overlay, set `CONCURRO_VERIFIER_IMAGE` to a published image built
from this package and set `CONCURRO_RELAY_VERIFICATION_URL` to the full public
backoffice approval URL. The verifier prints this URL to Sponsor during login.
Provision the verifier certificate, key and shared private token as described in
the [Gateway guide](../../concurro/gateway/README.md#sponsorship-metadata-and-private-resolution).
