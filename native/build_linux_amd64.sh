#!/usr/bin/env bash
# Build the Linux amd64 native runtime from pinned, checked-in source inputs, and package it:
#   BUILD_DIR/package-concurro-v3      the hosted verifier, the context for Dockerfile.amd64-runtime;
#   BUILD_DIR/packages/{sponsor,concurro}  self-contained Sponsor and Concurro role packages
#                                       (native/package.py), the Sponsor one for release;
#   BUILD_DIR/third-party-sources       the Debian source packages the Sponsor package's
#                                       copyleft libraries come from.
# BUILD_DIR must not exist. Run scripts/upstream.sh first.
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
# The container builds in /work (BUILD_DIR) and /repo (this checkout); the prefix maps keep
# both paths out of the packaged binaries. Outputs are handed back to the invoking user.
docker run --rm --platform linux/amd64 \
    -v "$build_dir:/work" -v "$relay_root:/repo" \
    -e CARGO_TARGET_DIR=/work/rust-target \
    -e HANDOFF_BUILD_ROOT=/work \
    -e HANDOFF_LIBOTE2_BUILD=/work/MP-SPDZ/deps/libOTe2/out/build/linux-clang19 \
    -e HANDOFF_LIBOTE2_INCLUDE=/work/MP-SPDZ/local/include \
    -e CXX=clang++-19 \
    -e "HANDOFF_CXXFLAGS=-mssse3 -maes -mpclmul -ffile-prefix-map=/work=/build -ffile-prefix-map=/repo=/build" \
    -e "RUSTFLAGS=--remap-path-prefix=/work=/build --remap-path-prefix=/repo=/build" \
    -e "OWNER=$(id -u):$(id -g)" \
    concurro-native-builder:hosted-amd64-rust100 bash -eux -c '
# The mounted sources belong to the invoking user, not the container root. Trust exactly their
# git repositories, so MP-SPDZ make can run git on its submodules.
find /work/DiStefano /work/MP-SPDZ -name .git -prune -printf "%h\n" | xargs -r -n 1 git config --global --add safe.directory
prefix_map="-ffile-prefix-map=/work=/build -ffile-prefix-map=/repo=/build"
cmake -S /work/MP-SPDZ/deps/libOTe2 -B /work/MP-SPDZ/deps/libOTe2/out/build/linux-clang19 \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang-19 -DCMAKE_CXX_COMPILER=clang++-19 \
    "-DCMAKE_C_FLAGS=$prefix_map" "-DCMAKE_CXX_FLAGS=$prefix_map" \
    -DLIBOTE_BUILD_DIR=/work/MP-SPDZ/deps/libOTe2/out/build/linux-clang19 \
    -DLIBOTE_STD_VER=20 -DENABLE_MRR=ON -DENABLE_SODIUM=ON -DENABLE_PIC=ON \
    -DENABLE_AVX=OFF -DENABLE_AVX2=OFF \
    -DENABLE_SPAN_LITE=ON -DFETCH_AUTO=ON -DFETCH_COPROTO=ON -DSODIUM_MONTGOMERY=OFF
cmake --build /work/MP-SPDZ/deps/libOTe2/out/build/linux-clang19 --parallel 4 --target libOTe
cmake -S /work/DiStefano/src -B /work/DiStefano/build \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang-19 -DCMAKE_CXX_COMPILER=clang++-19 \
    "-DCMAKE_C_FLAGS=$prefix_map" "-DCMAKE_CXX_FLAGS=-mssse3 -maes -mpclmul $prefix_map" \
    -DHANDOFF_LIBOTE2_SOURCE=/work/MP-SPDZ/deps/libOTe2 \
    -DHANDOFF_LIBOTE2_BUILD=/work/MP-SPDZ/deps/libOTe2/out/build/linux-clang19 \
    -DHANDOFF_LIBOTE2_DEPS_BUILD=/work/MP-SPDZ/deps/libOTe2/out/build/linux-clang19 \
    -DHANDOFF_LIBOTE2_INSTALL_INCLUDE=/work/MP-SPDZ/deps/libOTe2/out/install/linux/include
cmake --build /work/DiStefano/build --parallel 4 \
    --target HandoffKeyShare HandoffPartyKrrw HandoffPartyKrrwPrepared HandoffPrefix HandoffDeriveShares
/repo/native/generate_circuit.sh /work/DiStefano /work/DiStefano/build/HandoffDeriveShares
cmake -S /work/MP-SPDZ/deps/SimplestOT_C/ref10 \
    -B /work/MP-SPDZ/deps/SimplestOT_C/ref10-linux -DCMAKE_C_COMPILER=clang-19 \
    "-DCMAKE_C_FLAGS=$prefix_map"
cmake --build /work/MP-SPDZ/deps/SimplestOT_C/ref10-linux --parallel 4
cp /work/MP-SPDZ/deps/SimplestOT_C/ref10-linux/libSimplestOT.a \
    /work/MP-SPDZ/deps/SimplestOT_C/ref10/libSimplestOT.a
make -C /work/MP-SPDZ -j4 mascot-party.x
cd /work/MP-SPDZ
python3 compile.py -P 115792089210356248762697446949407573530086143415290314195533631308867097853951 \
    concurro_ectf_field
cargo build --release --locked --manifest-path /work/request-proof/Cargo.toml \
    --target-dir /work/request-proof/target
# Drop helper debug information, as the macOS recipe does.
strip --strip-debug /work/DiStefano/build/{HandoffKeyShare,HandoffPartyKrrw,HandoffPartyKrrwPrepared,HandoffPrefix} \
    /work/DiStefano/build/emp-tool/libemp-tool.so /work/MP-SPDZ/{mascot-party.x,libSPDZ.so} \
    /work/request-proof/target/release/handoff-request-proof
cargo build --release --locked --manifest-path /repo/Cargo.toml \
    -p concurro-relay-hosted -p concurro-relay-native -p concurro-relay -p concurro-relay-dev --bins
bin=/work/rust-target/release
python3 /repo/native/package_linux.py --output /work/package-concurro-v3 --runtime /work \
    --hosted $bin/concurro-relay-hosted --bridge $bin/responses-bridge --worker $bin/concurro-native-worker
# Source packages for the shipped copyleft libraries, at the installed versions.
sed -i "s/^Types: deb\$/Types: deb deb-src/" /etc/apt/sources.list.d/debian.sources
apt-get update -qq
python3 /repo/native/package.py --role sponsor --runtime /work --output /work/packages/sponsor \
    --relay $bin/concurro-relay --verifier $bin/dev-verifier --worker $bin/concurro-native-worker \
    --sources /work/third-party-sources
python3 /repo/native/package.py --role concurro --runtime /work --output /work/packages/concurro \
    --relay $bin/concurro-relay --verifier $bin/dev-verifier --worker $bin/concurro-native-worker
cd /repo
python3 -B -m unittest native.test_package -v
chown -R "$OWNER" /work/package-concurro-v3 /work/packages /work/third-party-sources
'
