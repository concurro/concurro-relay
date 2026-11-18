#!/usr/bin/env bash
# Build the hosted Linux amd64 native runtime package from pinned, checked-in source
# inputs. BUILD_DIR must not exist; the package is BUILD_DIR/package-concurro-v3, the
# context for native/Dockerfile.amd64-runtime. Run scripts/upstream.sh first.
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 BUILD_DIR" >&2
    exit 2
fi

relay_root=$(cd "$(dirname "$0")/.." && pwd)
build_dir=$(python3 -c 'import pathlib, sys; print(pathlib.Path(sys.argv[1]).resolve())' "$1")
"$relay_root/native/prepare_sources.sh" "$build_dir"
for patch in DiStefano-CMakeLists emp-base emp-block-stdint; do
    git -C "$build_dir/DiStefano" apply "$relay_root/native/linux-amd64-patches/$patch.patch"
done
cp "$relay_root/native/linux-amd64-patches/MP-SPDZ-CONFIG.mine" "$build_dir/MP-SPDZ/CONFIG.mine"

docker build --platform linux/amd64 -f "$relay_root/native/Dockerfile.amd64-builder" \
    -t concurro-native-builder:hosted-amd64-rust100 "$relay_root/native"
docker run --rm --platform linux/amd64 \
    -v "$build_dir:/work" -v "$relay_root:/repo" \
    -e CARGO_TARGET_DIR=/work/rust-target \
    -e HANDOFF_BUILD_ROOT=/work \
    -e HANDOFF_LIBOTE2_BUILD=/work/MP-SPDZ/deps/libOTe2/out/build/linux-clang19 \
    -e HANDOFF_LIBOTE2_INCLUDE=/work/MP-SPDZ/local/include \
    -e CXX=clang++-19 -e "HANDOFF_CXXFLAGS=-mssse3 -maes -mpclmul" \
    concurro-native-builder:hosted-amd64-rust100 bash -eux -c '
cmake -S /work/MP-SPDZ/deps/libOTe2 -B /work/MP-SPDZ/deps/libOTe2/out/build/linux-clang19 \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang-19 -DCMAKE_CXX_COMPILER=clang++-19 \
    -DLIBOTE_BUILD_DIR=/work/MP-SPDZ/deps/libOTe2/out/build/linux-clang19 \
    -DLIBOTE_STD_VER=20 -DENABLE_MRR=ON -DENABLE_SODIUM=ON -DENABLE_PIC=ON \
    -DENABLE_AVX=OFF -DENABLE_AVX2=OFF \
    -DENABLE_SPAN_LITE=ON -DFETCH_AUTO=ON -DFETCH_COPROTO=ON -DSODIUM_MONTGOMERY=OFF
cmake --build /work/MP-SPDZ/deps/libOTe2/out/build/linux-clang19 --parallel 4 --target libOTe
cmake -S /work/DiStefano/src -B /work/DiStefano/build-linux \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang-19 -DCMAKE_CXX_COMPILER=clang++-19 \
    "-DCMAKE_CXX_FLAGS=-mssse3 -maes -mpclmul" \
    -DHANDOFF_LIBOTE2_SOURCE=/work/MP-SPDZ/deps/libOTe2 \
    -DHANDOFF_LIBOTE2_BUILD=/work/MP-SPDZ/deps/libOTe2/out/build/linux-clang19 \
    -DHANDOFF_LIBOTE2_DEPS_BUILD=/work/MP-SPDZ/deps/libOTe2/out/build/linux-clang19 \
    -DHANDOFF_LIBOTE2_INSTALL_INCLUDE=/work/MP-SPDZ/deps/libOTe2/out/install/linux/include
cmake --build /work/DiStefano/build-linux --parallel 4 \
    --target HandoffKeyShare HandoffPartyKrrw HandoffPartyKrrwPrepared HandoffPrefix HandoffDeriveShares
/repo/native/generate_circuit.sh /work/DiStefano /work/DiStefano/build-linux/HandoffDeriveShares
cmake -S /work/MP-SPDZ/deps/SimplestOT_C/ref10 \
    -B /work/MP-SPDZ/deps/SimplestOT_C/ref10-linux -DCMAKE_C_COMPILER=clang-19
cmake --build /work/MP-SPDZ/deps/SimplestOT_C/ref10-linux --parallel 4
cp /work/MP-SPDZ/deps/SimplestOT_C/ref10-linux/libSimplestOT.a \
    /work/MP-SPDZ/deps/SimplestOT_C/ref10/libSimplestOT.a
make -C /work/MP-SPDZ -j4 mascot-party.x
cd /work/MP-SPDZ
python3 compile.py -P 115792089210356248762697446949407573530086143415290314195533631308867097853951 \
    concurro_ectf_field
cargo build --release --locked --manifest-path /work/request-proof/Cargo.toml \
    --target-dir /work/request-proof-target
cargo build --release --locked --manifest-path /repo/Cargo.toml \
    -p concurro-relay-hosted -p concurro-relay-native --bins
python3 /repo/native/package_linux.py --output /work/package-concurro-v3 \
    --hosted /work/rust-target/release/concurro-relay-hosted \
    --bridge /work/rust-target/release/responses-bridge \
    --worker /work/rust-target/release/concurro-native-worker \
    --distefano /work/DiStefano --distefano-build /work/DiStefano/build-linux \
    --handshake-circuit /work/DiStefano/handoff-handshake-shares-cached-hkdf.txt --mp-spdz /work/MP-SPDZ \
    --request-proof /work/request-proof-target/release/handoff-request-proof
'
