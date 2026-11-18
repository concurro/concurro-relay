#!/usr/bin/env bash
# Fetch the pinned native helper sources into a new BUILD_DIR and apply Concurro's
# checked-in source changes (native/sources and native/patches). Platform patches are
# applied by the platform build scripts. Requires scripts/upstream.sh to have prepared
# upstream/mpz2.
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 BUILD_DIR" >&2
    exit 2
fi

relay_root=$(cd "$(dirname "$0")/.." && pwd)
sources="$relay_root/native/sources"
build_dir=$(python3 -c 'import pathlib, sys; print(pathlib.Path(sys.argv[1]).resolve())' "$1")
test -d "$relay_root/upstream/mpz2" || {
    echo "upstream/mpz2 is missing; run scripts/upstream.sh first" >&2
    exit 1
}
mkdir "$build_dir"

# fetch DIRECTORY URL COMMIT: check out COMMIT and the submodules it records.
fetch() {
    git clone --quiet "$2" "$1"
    git -C "$1" checkout --quiet --detach "$3"
    git -C "$1" submodule --quiet update --init --recursive
}

fetch "$build_dir/DiStefano" https://github.com/brave-experiments/DiStefano.git \
    2ffc80643c9c92f3fd9238d681643a2a2526e1a2
git -C "$build_dir/DiStefano" apply "$sources/DiStefano/tracked.patch"
cp -a "$sources/DiStefano/added/." "$build_dir/DiStefano/"
patch -s -p1 -d "$build_dir/DiStefano" < "$relay_root/native/patches/DiStefano-Krrw-prepared.patch"

fetch "$build_dir/MP-SPDZ" https://github.com/data61/MP-SPDZ.git \
    878813125a89f7414c2a23ec844a8c184e2784e9
git -C "$build_dir/MP-SPDZ/deps/libOTe2" checkout --quiet --detach \
    fe6b2ff82a976a5332b3a2efe325831588b1324a
git -C "$build_dir/MP-SPDZ" apply "$sources/MP-SPDZ/tracked.patch"
cp -a "$sources/MP-SPDZ/added/." "$build_dir/MP-SPDZ/"

cp -a "$sources/request-proof" "$build_dir/request-proof"
cp -a "$relay_root/upstream/mpz2" "$build_dir/mpz2"
patch -s -p1 -d "$build_dir/mpz2" < "$relay_root/native/patches/mpz2-base-seeds.patch"
