#!/usr/bin/env bash
# Install a Linux x86-64 Sponsor archive the documented way in a clean Ubuntu 24.04 container
# (glibc 2.39, nothing else installed) and test it:
# - every packaged ELF loads only packaged libraries or glibc (`ldd`);
# - the installed relay, worker and bundled OpenSSL start;
# - the offline bootstrap (Codex and Claude HTTP/2 fixtures), the untrusted-provider abort and
#   two successive request proofs between the installed Sponsor and the Concurro package.
# BUILD_DIR is native/build_linux_amd64.sh's; ARCHIVE is the release archive, with its .sha256.
# The test binary is built in the builder; python3 and openssl are installed for the
# fixtures only after the load check.
set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: $0 BUILD_DIR ARCHIVE" >&2
    exit 2
fi

relay_root=$(cd "$(dirname "$0")/.." && pwd)
build_dir=$(cd "$1" && pwd)
archive=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
runtime_image=ubuntu:24.04@sha256:73b999393d07f2bf65a40373778a44dc9a6d54ad7718d29247d8ff9413c4d6a8

docker run --rm --platform linux/amd64 \
    -v "$build_dir:/work" -v "$relay_root:/repo" \
    -e CARGO_TARGET_DIR=/work/rust-target \
    -e "RUSTFLAGS=--remap-path-prefix=/work=/build --remap-path-prefix=/repo=/build" \
    -e "OWNER=$(id -u):$(id -g)" \
    concurro-native-builder:hosted-amd64-rust100 bash -eu -c '
test=$(cargo test --release --locked --manifest-path /repo/Cargo.toml -p concurro-relay-native \
    --test bootstrap --no-run --message-format=json \
    | python3 -c "import json, sys; print(*{m[\"executable\"] for m in map(json.loads, sys.stdin) if m.get(\"executable\") and m[\"target\"][\"name\"] == \"bootstrap\"})")
mkdir -p /work/tests && cp "$test" /work/tests/bootstrap && chown -R "$OWNER" /work/tests
'

# The test binary finds the provider fixture through its compile-time manifest directory,
# /repo/crates/native; only native/ is mounted there.
docker run --rm --platform linux/amd64 \
    -v "$(dirname "$archive"):/dist:ro" \
    -v "$build_dir/packages/concurro:/packages/concurro:ro" \
    -v "$build_dir/tests:/tests:ro" \
    -v "$relay_root/native:/repo/native:ro" \
    -e "ARCHIVE=$(basename "$archive")" \
    "$runtime_image" bash -eu -o pipefail -c '
flags=" $(grep -m1 "^flags" /proc/cpuinfo | cut -d: -f2) "
for flag in avx avx2 bmi1 bmi2 f16c fma movbe aes pclmulqdq; do
    [[ $flags == *" $flag "* ]] || { echo "CPU lacks $flag: x86-64-v3, AES and PCLMUL are required" >&2; exit 1; }
done
# x86-64-v3 also includes LZCNT (abm) and XSAVE, which some emulators run but do not report.
for flag in abm xsave; do
    [[ $flags == *" $flag "* ]] || echo "note: this CPU does not report $flag"
done
echo "glibc: $(ldd --version | head -1)"

# The documented install, into a relocated directory whose path has a space.
install="/opt/relocated install"
mkdir -p "$install" /check /repo/crates/native
(cd /dist && sha256sum -c "$ARCHIVE.sha256")
tar -xzf "/dist/$ARCHIVE" -C "$install"
sponsor="$install/${ARCHIVE%.tar.gz}"
ln -s "$sponsor" /check/sponsor
cp -R /packages/concurro /check/concurro

check_loads() {  # every packaged ELF resolves its libraries inside its package or to glibc
    local package=$1 count=0 file loads
    while IFS= read -r -d "" file; do
        [[ $(head -c 4 "$file" | od -An -c | tr -d " ") == 177ELF ]] || continue
        loads=$(ldd "$file")
        if grep -q "not found" <<<"$loads"; then echo "$file: $loads" >&2; return 1; fi
        if awk -v package="$package" "
            /=>/ { name = \$1; path = \$0
                   sub(/^[^=]*=> /, \"\", path); sub(/ \\(0x[0-9a-f]+\\)\$/, \"\", path)
                   if (name ~ /^(libc|libm|libmvec|libpthread|libdl|librt|libutil|libresolv|libanl)\\.so\\.[0-9]+\$/) next
                   if (index(path, package \"/\") != 1) { print; bad = 1 } }
            END { exit !bad }" <<<"$loads" >&2; then
            echo "$file loads a library from outside $package" >&2; return 1
        fi
        count=$((count + 1))
    done < <(find "$package/" -type f -print0)
    echo "$package: $count ELF images load only packaged libraries and glibc"
}
check_loads "$(readlink -f /check/sponsor)"
check_loads /check/concurro

/check/sponsor/bin/concurro-relay --version
/check/sponsor/bin/concurro-relay --help >/dev/null
/check/sponsor/native-runtime/concurro-native-worker --help >/dev/null
/check/concurro/bin/dev-verifier --help >/dev/null
OPENSSL_CONF=/check/sponsor/native-runtime/bin/openssl.cnf /check/sponsor/native-runtime/bin/openssl version
echo "installed Sponsor, worker, dev-verifier and bundled OpenSSL start"

apt-get update -qq && apt-get install -y -qq --no-install-recommends python3 openssl >/dev/null
check_loads "$(readlink -f /check/sponsor)"   # still packaged copies with system OpenSSL present
CONCURRO_PHASE3_FIXTURE_BUNDLE=/check/sponsor/native-runtime \
    /tests/bootstrap --ignored --test-threads 1
'
