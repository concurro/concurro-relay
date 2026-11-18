#!/usr/bin/env bash
# Generate the public handshake circuit with the built HandoffDeriveShares and check it
# against the accepted circuit's SHA-256. The generator reads DiStefano's Bristol circuits
# by paths relative to src/2pc.
set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: $0 DISTEFANO_DIR HANDOFF_DERIVE_SHARES" >&2
    exit 2
fi

accepted=6abe1747161ca22474ee1430920d667c7e55b308823028309a24c5453c56dc0d
distefano=$(cd "$1" && pwd)
generator=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
output="$distefano/handoff-handshake-shares-cached-hkdf.txt"
(cd "$distefano/src/2pc" && "$generator" "$output")
python3 - "$output" "$accepted" <<'EOF'
import hashlib, sys
digest = hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest()
if digest != sys.argv[2]:
    sys.exit(f"handshake circuit SHA-256 {digest} differs from accepted {sys.argv[2]}")
EOF
