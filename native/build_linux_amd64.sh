#!/usr/bin/env bash
# Rebuild the hosted Linux amd64 native runtime and image from pinned source inputs.
set -euo pipefail

if [ "$#" -ne 3 ]; then
    echo "usage: $0 SOURCE_ARCHIVE HANDSHAKE_CIRCUIT BUILD_DIR" >&2
    exit 2
fi

source_archive=$(realpath "$1")
handshake_circuit=$(realpath "$2")
build_dir=$(python3 -c 'import pathlib, sys; print(pathlib.Path(sys.argv[1]).resolve())' "$3")
relay_root=$(cd "$(dirname "$0")/.." && pwd)
test "$(shasum -a 256 "$source_archive" | cut -d ' ' -f 1)" = 8dfef5b370707d0fdf848d9d15b13c09d8c40c1fcb0d55a32262b76ab7dd0ed1
test "$(shasum -a 256 "$handshake_circuit" | cut -d ' ' -f 1)" = 6abe1747161ca22474ee1430920d667c7e55b308823028309a24c5453c56dc0d
mkdir "$build_dir"
unzip -q "$source_archive" -d "$build_dir/input"
cp "$handshake_circuit" "$build_dir/handshake-circuit.txt"

git clone https://github.com/brave-experiments/DiStefano.git "$build_dir/DiStefano"
git -C "$build_dir/DiStefano" checkout --detach 2ffc80643c9c92f3fd9238d681643a2a2526e1a2
git -C "$build_dir/DiStefano" submodule update --init --recursive
git -C "$build_dir/DiStefano" apply "$build_dir/input/DiStefano/tracked.patch"
cp -a "$build_dir/input/DiStefano/added/." "$build_dir/DiStefano/"
git -C "$build_dir/DiStefano" apply "$relay_root/native/linux-amd64-patches/DiStefano-CMakeLists.patch"
git -C "$build_dir/DiStefano" apply "$relay_root/native/linux-amd64-patches/emp-base.patch"
git -C "$build_dir/DiStefano" apply "$relay_root/native/linux-amd64-patches/emp-block-stdint.patch"

git clone https://github.com/data61/MP-SPDZ.git "$build_dir/MP-SPDZ"
git -C "$build_dir/MP-SPDZ" checkout --detach 878813125a89f7414c2a23ec844a8c184e2784e9
git -C "$build_dir/MP-SPDZ" submodule update --init --recursive
git -C "$build_dir/MP-SPDZ/deps/libOTe2" checkout --detach fe6b2ff82a976a5332b3a2efe325831588b1324a
git -C "$build_dir/MP-SPDZ" apply "$build_dir/input/MP-SPDZ/tracked.patch"
cp -a "$build_dir/input/MP-SPDZ/added/." "$build_dir/MP-SPDZ/"

cp -a "$build_dir/input/request-proof" "$build_dir/request-proof"
patch -s -p1 -d "$build_dir/request-proof" < "$relay_root/native/linux-amd64-patches/request-proof-linux.patch"
cp -a "$relay_root/upstream/mpz2" "$build_dir/mpz2"
patch -s -p1 -d "$build_dir/mpz2" < "$relay_root/native/linux-amd64-patches/mpz2-base-seeds.patch"

docker build --platform linux/amd64 -f "$relay_root/native/Dockerfile.amd64-builder" \
    -t concurro-native-builder:hosted-amd64-rust100 "$relay_root/native"
docker run --rm --platform linux/amd64 \
    -v "$build_dir:/work" -v "$relay_root:/repo" \
    -e HANDOFF_BUILD_ROOT=/work -e CARGO_TARGET_DIR=/work/rust-target \
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
    --target HandoffKeyShare HandoffPartyKrrw HandoffPrefix
cmake -S /work/MP-SPDZ/deps/SimplestOT_C/ref10 \
    -B /work/MP-SPDZ/deps/SimplestOT_C/ref10-linux -DCMAKE_C_COMPILER=clang-19
cmake --build /work/MP-SPDZ/deps/SimplestOT_C/ref10-linux --parallel 4
cp /work/MP-SPDZ/deps/SimplestOT_C/ref10-linux/libSimplestOT.a \
    /work/MP-SPDZ/deps/SimplestOT_C/ref10/libSimplestOT.a
cmp -s /repo/native/linux-amd64-patches/MP-SPDZ-CONFIG.mine /work/MP-SPDZ/CONFIG.mine || \
    cp /repo/native/linux-amd64-patches/MP-SPDZ-CONFIG.mine /work/MP-SPDZ/CONFIG.mine
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
    --handshake-circuit /work/handshake-circuit.txt --mp-spdz /work/MP-SPDZ \
    --request-proof /work/request-proof-target/release/handoff-request-proof
'
docker build --platform linux/amd64 -f "$relay_root/native/Dockerfile.amd64-runtime" \
    -t concurro-verifier:hosted-amd64-rebuilt "$build_dir"
