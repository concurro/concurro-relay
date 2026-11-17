# Ferret LPN experiment reproduction

This directory holds an experimental DiStefano patch, a pinned-helper build script, and a synthetic output-equivalence harness. It does not change the accepted runtime. Source and binary identities, raw output locations, and paired results are in [FERRET-LPN-BENCH.json](../../FERRET-LPN-BENCH.json).

The experiment used the existing macOS arm64 source build at `/private/tmp/concurro-source-build-v3/DiStefano` (DiStefano commit `2ffc80643c9c92f3fd9238d681643a2a2526e1a2`, plus the accepted build-recipe patches). The patch applies to that **built source state**, not a clean upstream checkout. Use a copy so the accepted build remains intact:

```bash
cp -a /private/tmp/concurro-source-build-v3/DiStefano /private/tmp/concurro-ferret-replay-source
cd /private/tmp/concurro-ferret-replay-source
git apply --check /Users/cylwit/Code/github.com/concurro/concurro-relay/native/experimental/ferret_lpn/experimental.patch
git apply /Users/cylwit/Code/github.com/concurro/concurro-relay/native/experimental/ferret_lpn/experimental.patch
python3 /Users/cylwit/Code/github.com/concurro/concurro-relay/native/experimental/ferret_lpn/build_helper.py \
  --source /private/tmp/concurro-ferret-replay-source \
  --reference /private/tmp/concurro-source-build-v3/DiStefano \
  --output /private/tmp/concurro-ferret-replay-helper8 \
  --workers-default 8
```

The build script reuses the pinned CMake compile/link commands for the KRRW translation unit and writes `build.json` with source hashes, commands, and binary hash. Check the four source hashes against `source-hashes.json`. The retained exact helper binaries and packages are under `/private/tmp/concurro-ferret-exp/helper{4,8}` and `/private/tmp/concurro-ferret-exp/package-helper{4,8}`. To package a new helper, copy the accepted runtime tree into a new temporary directory, replace only `DiStefano/build/HandoffPartyKrrw` with the built executable, and call `native/package.py` for each role with the same relay, verifier, worker, and OpenSSL inputs used for the accepted v3 packages.

Compile and run the standalone equivalence harness from the relay checkout:

```bash
cd /Users/cylwit/Code/github.com/concurro/concurro-relay
/usr/bin/c++ -std=gnu++17 -Ofast -mcpu=apple-m1 -arch arm64 -Wno-c++11-narrowing \
  -I/private/tmp/concurro-ferret-replay-source/src/emp-tool \
  -I/private/tmp/concurro-ferret-replay-source/src/emp-ot \
  -I/private/tmp/concurro-ferret-replay-source/src/include \
  -I/private/tmp/concurro-ferret-replay-source/src/boringssl/include \
  native/experimental/ferret_lpn/lpn_bench.cpp \
  -L/private/tmp/concurro-source-build-v3/DiStefano/build/emp-tool -lemp-tool \
  -o /private/tmp/concurro-ferret-replay-lpn-bench
/private/tmp/concurro-ferret-replay-lpn-bench 10485760 452000 101 8 4 \
  > /private/tmp/concurro-ferret-replay-lpn.jsonl
```

The harness exits nonzero on any full-output mismatch. For a matched end-to-end run, put the two replay package paths into the `builds-variants.json` shape in `/private/tmp/concurro-ferret-exp/`, then run `native/optimization_bench.py --builds FILE --output NEW_DIRECTORY --profile fast --repeats 3 --variants accepted-v3 helper8`. The script automatically adds the accepted v3 package, alternates order, and checks fixture correctness before writing each result. It relies on the retained local phase-6 fixture dependencies named in that script.
