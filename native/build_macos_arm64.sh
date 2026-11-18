#!/usr/bin/env bash
# Build the macOS arm64 native helper runtime from pinned, checked-in source inputs, in the
# layout native/package.py packages. BUILD_DIR must not exist. Requires Homebrew's cmake,
# boost, gmp, libsodium and openssl, Go (for BoringSSL), Python 3 and scripts/upstream.sh's
# upstream/mpz2.
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 BUILD_DIR" >&2
    exit 2
fi

relay_root=$(cd "$(dirname "$0")/.." && pwd)
build_dir=$(python3 -c 'import pathlib, sys; print(pathlib.Path(sys.argv[1]).resolve())' "$1")
brew=$(brew --prefix)
openssl=$(brew --prefix openssl)
jobs=$(sysctl -n hw.ncpu)
# Keep build-machine paths out of the packaged binaries' debug and assertion strings.
prefix_map="-ffile-prefix-map=$build_dir=/build"
export RUSTFLAGS="--remap-path-prefix=$build_dir=/build --remap-path-prefix=$HOME=/home"
"$relay_root/native/prepare_sources.sh" "$build_dir"

# One libOTe build with the MRR base OT links DiStefano, MP-SPDZ and request-proof;
# MP-SPDZ's own default libOTe build uses out/build/osx.
libote="$build_dir/MP-SPDZ/deps/libOTe2"
libote_build="$libote/out/build/osx-concurro"
cmake -S "$libote" -B "$libote_build" -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_PREFIX_PATH="$brew" -DLIBOTE_BUILD_DIR="$libote_build" \
    -DCMAKE_C_FLAGS="$prefix_map" -DCMAKE_CXX_FLAGS="$prefix_map" \
    -DLIBOTE_STD_VER=20 -DENABLE_MRR=ON -DENABLE_SODIUM=ON -DENABLE_PIC=ON \
    -DENABLE_SPAN_LITE=ON -DFETCH_AUTO=ON -DFETCH_COPROTO=ON -DSODIUM_MONTGOMERY=OFF
cmake --build "$libote_build" --parallel "$jobs" --target libOTe

distefano="$build_dir/DiStefano"
# DiStefano's bundled emp-tool predates CMake 4's minimum policy version.
cmake -S "$distefano/src" -B "$distefano/build" -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    -DCMAKE_PREFIX_PATH="$brew" -DOPENSSL_ROOT_DIR="$openssl" \
    -DCMAKE_C_FLAGS="$prefix_map" -DCMAKE_CXX_FLAGS="$prefix_map" \
    -DHANDOFF_LIBOTE2_SOURCE="$libote" -DHANDOFF_LIBOTE2_BUILD="$libote_build" \
    -DHANDOFF_LIBOTE2_DEPS_BUILD="$libote_build" \
    -DHANDOFF_LIBOTE2_INSTALL_INCLUDE="$libote/out/install/osx/include"
cmake --build "$distefano/build" --parallel "$jobs" \
    --target HandoffKeyShare HandoffPartyKrrw HandoffPartyKrrwPrepared HandoffPrefix HandoffDeriveShares
"$relay_root/native/generate_circuit.sh" "$distefano" "$distefano/build/HandoffDeriveShares"

cat > "$build_dir/MP-SPDZ/CONFIG.mine" <<EOF
MY_CFLAGS += -Wno-error=deprecated-literal-operator -DLONG_BIT_MAC_KEY
MY_CFLAGS += -DHANDOFF_MRR_BASE_OT -I$distefano/src/2pc $prefix_map
MASCOT_MRR_BASE_OT_OBJECT = $distefano/build/CMakeFiles/HandoffPartyKrrw.dir/2pc/HandoffBaseOT.cpp.o
MY_LDLIBS += $libote_build/libOTe/liblibOTe.a
MY_LDLIBS += $libote_build/cryptoTools/cryptoTools/libcryptoTools.a
MY_LDLIBS += $libote_build/coproto/coproto/libcoproto.a
MY_LDLIBS += $libote_build/macoro/macoro/libmacoro.a
OTE_OPTS += -DCMAKE_C_FLAGS=$prefix_map -DCMAKE_CXX_FLAGS=$prefix_map
EOF
make -C "$build_dir/MP-SPDZ" -j"$jobs" mascot-party.x
# MP-SPDZ names its library by bare filename; make the load resolvable beside the binary.
install_name_tool -id @loader_path/libSPDZ.so "$build_dir/MP-SPDZ/libSPDZ.so"
install_name_tool -change libSPDZ.so @loader_path/libSPDZ.so "$build_dir/MP-SPDZ/mascot-party.x"
python3 -m venv "$build_dir/mp-spdz-venv"
"$build_dir/mp-spdz-venv/bin/pip" install --quiet --require-hashes \
    -r "$relay_root/native/mp-spdz-requirements.txt"
(cd "$build_dir/MP-SPDZ" && "$build_dir/mp-spdz-venv/bin/python" compile.py \
    -P 115792089210356248762697446949407573530086143415290314195533631308867097853951 \
    concurro_ectf_field)

HANDOFF_BUILD_ROOT="$build_dir" HANDOFF_LIBOTE2_BUILD="$libote_build" \
    HANDOFF_LIBOTE2_INCLUDE="$libote/out/install/osx/include" \
    HANDOFF_CXXFLAGS="-I$brew/include $prefix_map" HANDOFF_LIBRARY_PATH="$brew/lib" \
    cargo build --release --locked --manifest-path "$build_dir/request-proof/Cargo.toml" \
    --target-dir "$build_dir/request-proof/target"

# Drop the linker's debug map, which records build-directory object paths.
strip -S "$distefano"/build/{HandoffKeyShare,HandoffPartyKrrw,HandoffPartyKrrwPrepared,HandoffPrefix} \
    "$distefano/build/emp-tool/libemp-tool.dylib" \
    "$build_dir"/MP-SPDZ/{mascot-party.x,libSPDZ.so} \
    "$build_dir/request-proof/target/release/handoff-request-proof"
