#!/bin/sh
# Prepares upstream/ with the pinned upstream sources and the patches in
# patches/ applied. Refuses to touch a source directory which exists.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
identity="-c user.name=concurro-relay -c user.email=relay@concurro.invalid -c commit.gpgsign=false"

# apply NAME: commits the patches for NAME on top of its checkout.
apply() {
    # shellcheck disable=SC2086
    git -C "$root/upstream/$1" $identity am --quiet "$root"/patches/"$1"/*.patch
}

# from_git NAME URL REVISION
from_git() {
    target="$root/upstream/$1"
    [ ! -e "$target" ] || { echo "upstream/$1 exists; remove it to prepare it again" >&2; return 1; }
    git init --quiet "$target"
    git -C "$target" fetch --quiet --depth 1 "$2" "$3"
    git -C "$target" checkout --quiet FETCH_HEAD
    apply "$1"
}

# from_crate NAME VERSION SHA256
from_crate() {
    target="$root/upstream/$1"
    [ ! -e "$target" ] || { echo "upstream/$1 exists; remove it to prepare it again" >&2; return 1; }
    archive=$(mktemp)
    curl --fail --silent --show-error --location "https://static.crates.io/crates/$1/$1-$2.crate" --output "$archive"
    echo "$3  $archive" | shasum -a 256 --check --quiet
    mkdir -p "$target"
    tar -xzf "$archive" -C "$target" --strip-components 1
    rm "$archive"
    git init --quiet "$target"
    git -C "$target" add --all
    # shellcheck disable=SC2086
    git -C "$target" $identity commit --quiet --message "$1 $2 as published"
    apply "$1"
}

mkdir -p "$root/upstream"
from_git tlsn https://github.com/tlsnotary/tlsn ca12b4a9847fa9e7063caafc49ec356203fc35a6
from_git mpz2 https://github.com/tlsnotary/mpz2 23e2cc08ed11ae86d71f72fb968f1273d70c9e88
from_crate rangeset 0.4.1 6b18f9905582a6a9bbd5ae3106aea9a2a73edb452b30ac844f93f5a5f0eda217
