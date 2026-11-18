#!/bin/sh
# Prepares a CI checkout, after scripts/upstream.sh, for `release-plz release-pr`.
#
# release-pr runs cargo in a copy of the checkout that leaves out every path a .gitignore or
# .git/info/exclude ignores, so upstream/, which the [patch] table needs, would be missing.
# This removes the `upstream/` line from the working .gitignore, marked skip-worktree so git
# doesn't report it, and has git ignore upstream/ through core.excludesFile given in the
# environment (GIT_CONFIG_COUNT/KEY/VALUE), which the copy's walker never reads. The copy then
# includes upstream/; git, which release-plz runs in the copy with this environment, still
# ignores it, so it stays out of the release commit built from `git status`.
# Writes the environment to ENV_FILE ($GITHUB_ENV in Actions). Not for working checkouts.
# Usage: scripts/release-pr-checkout.sh EXCLUDES_FILE ENV_FILE (paths outside the checkout)
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
excludes=${1:?usage: $0 EXCLUDES_FILE ENV_FILE}
env_file=${2:?usage: $0 EXCLUDES_FILE ENV_FILE}
cd "$root"

[ -z "${GIT_CONFIG_COUNT:-}" ] || { echo "GIT_CONFIG_COUNT is already set" >&2; exit 1; }
[ -d upstream/rangeset ] || { echo "run scripts/upstream.sh first" >&2; exit 1; }
grep -qx 'upstream/' .gitignore || { echo ".gitignore has no 'upstream/' line" >&2; exit 1; }
[ -z "$(git status --porcelain)" ] || { echo "checkout is not clean" >&2; exit 1; }

printf '/upstream/\n' > "$excludes"
git update-index --skip-worktree .gitignore
grep -vx 'upstream/' .gitignore > "$excludes.gitignore"
cat "$excludes.gitignore" > .gitignore
rm "$excludes.gitignore"

export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.excludesFile GIT_CONFIG_VALUE_0="$excludes"
git check-ignore -q upstream/rangeset/Cargo.toml || { echo "upstream/ is not ignored" >&2; exit 1; }
[ -z "$(git status --porcelain)" ] || { echo "checkout is not clean after the change" >&2; exit 1; }
printf 'GIT_CONFIG_COUNT=1\nGIT_CONFIG_KEY_0=core.excludesFile\nGIT_CONFIG_VALUE_0=%s\n' "$excludes" >> "$env_file"
echo "upstream/ is ignored through core.excludesFile in the environment; release-pr's copy will include it."
