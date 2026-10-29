#!/bin/sh
# Build the first synthetic snapshot from the tracked fixture files.
# Usage: ./setup.sh [WORKDIR]   (default: /tmp/gt-misleading-snapshots)
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
work=${1:-/tmp/gt-misleading-snapshots}

rm -rf "$work"
mkdir -p "$work/evidence"
cp "$here/fixture/alpha.txt" "$work/evidence/alpha.txt"
cp "$here/fixture/beta-v1.txt" "$work/evidence/beta.txt"
cp "$here/fixture/gamma.txt" "$work/evidence/gamma.txt"
cp "$here/fixture/secret.txt" "$work/evidence/secret.txt"

# Every regular file starts with the same recorded mtime: "nothing changed".
touch -d '2026-02-01 10:00:00' \
    "$work/evidence/alpha.txt" \
    "$work/evidence/beta.txt" \
    "$work/evidence/gamma.txt" \
    "$work/evidence/secret.txt"

printf 'workdir=%s\n' "$work"
