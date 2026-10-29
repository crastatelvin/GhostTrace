#!/bin/sh
# Mutate the first snapshot into the second one. Run after the first capture.
# Usage: ./mutate.sh [WORKDIR]   (default: /tmp/gt-misleading-snapshots)
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
work=${1:-/tmp/gt-misleading-snapshots}

# Same byte length, same recorded mtime, different bytes.
cp "$here/fixture/beta-v2.txt" "$work/evidence/beta.txt"
touch -d '2026-02-01 10:00:00' "$work/evidence/beta.txt"

# Same bytes at a different path; the diff calls this a move candidate only.
mv "$work/evidence/gamma.txt" "$work/evidence/gamma-renamed.txt"

# Same bytes, different mtime: metadata_changed, not content_changed.
touch -d '2026-03-01 12:00:00' "$work/evidence/alpha.txt"

# The later capture cannot read this path: a coverage gap, so absence is
# reported as unknown rather than "not present".
chmod 000 "$work/evidence/secret.txt"

# A new path that did not exist in the first snapshot.
cp "$here/fixture/delta.txt" "$work/evidence/delta.txt"

printf 'mutated=%s\n' "$work"
