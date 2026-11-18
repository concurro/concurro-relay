#!/bin/sh
# Regenerates .github/workflows/release.yml: dist's own output, plus a step running
# scripts/upstream.sh after the checkout in each job that runs dist on the workspace (plan,
# build-global-artifacts, host). dist loads the full cargo metadata there, which needs the
# pinned upstream/ sources, and its `github-build-setup` reaches only build-local-artifacts.
# dist-workspace.toml marks the workflow `allow-dirty = ["ci"]` so that dist accepts the step;
# dist then generates no workflow, so this generates with that line removed and restores it.
# With --check, fails if the workflow differs from what this generates, and changes nothing.
# Needs upstream/ (scripts/upstream.sh) and the dist version in dist-workspace.toml.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
workflow=.github/workflows/release.yml
config=dist-workspace.toml
cd "$root"

saved=$(mktemp -d)
cp "$config" "$workflow" "$saved/"
restore_config() { cp "$saved/$config" "$config"; }
if [ "${1:-}" = --check ]; then
    trap 'restore_config; cp "$saved/release.yml" "$workflow"; rm -rf "$saved"' EXIT
else
    trap 'restore_config; rm -rf "$saved"' EXIT
fi

grep -q '^allow-dirty = \["ci"\]$' "$config" || { echo "$config lacks allow-dirty = [\"ci\"]" >&2; exit 1; }
grep -v '^allow-dirty = ' "$saved/$config" > "$config"
dist generate --mode=ci
restore_config
python3 - "$workflow" <<'EOF'
import re, sys

JOBS = {"plan", "build-global-artifacts", "host"}
STEP = ["      - name: Prepare pinned upstream sources\n",
        "        run: ./scripts/upstream.sh\n"]
path = sys.argv[1]
lines = open(path).readlines()
out, job, inserted, i = [], None, set(), 0
while i < len(lines):
    line = lines[i]
    out.append(line)
    i += 1
    if match := re.fullmatch(r"  ([a-z-]+):\n", line):
        job = match[1]
    elif job in JOBS and job not in inserted and re.fullmatch(r"      - uses: actions/checkout@\S+\n", line):
        while i < len(lines) and lines[i].startswith("        "):  # the step's `with:`
            out.append(lines[i])
            i += 1
        out.extend(STEP)
        inserted.add(job)
if inserted != JOBS:
    sys.exit(f"no checkout step found in: {sorted(JOBS - inserted)}")
open(path, "w").writelines(out)
EOF

if [ "${1:-}" = --check ]; then
    diff -u "$saved/release.yml" "$workflow" >&2 || { echo "$workflow is out of date; run scripts/dist-generate.sh" >&2; exit 1; }
    echo "$workflow is up to date."
fi
