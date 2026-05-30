#!/usr/bin/env bash
# Publish the anomalyx crates to crates.io in dependency order.
#
# Crates must be published bottom-up: each one has to be live on crates.io
# before a crate that depends on it can be verified and published. The internal
# `ax-validate` harness is `publish = false` and is intentionally skipped.
#
# Prerequisites:
#   1. A crates.io API token:  cargo login <token>   (separate from GitHub auth)
#   2. A clean, committed working tree on the release commit.
#
# cargo (1.66+) waits for each publish to propagate to the index before
# returning, so the next crate can resolve it. Pass --dry-run to rehearse
# (note: dry-run of the dependent crates only works once ax-core is actually
# published, since dry-run still resolves deps from the registry).
set -euo pipefail
cd "$(dirname "$0")/.."

DRY=""
[ "${1:-}" = "--dry-run" ] && DRY="--dry-run"

for crate in ax-core ax-normalize ax-detect ax-cli; do
    echo "==> cargo publish -p $crate $DRY"
    cargo publish -p "$crate" $DRY
done

echo "==> done: ax-core, ax-normalize, ax-detect, ax-cli"
