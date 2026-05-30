#!/usr/bin/env bash
# The strong gates for anomalyx. Run before every commit.
#
#   1. fmt      — canonical formatting
#   2. clippy   — lint, warnings are errors
#   3. test     — unit + property + integration tests
#   4. mutants  — mutation gate: 0 surviving mutants on src/ (equivalent
#                 mutants are documented in .cargo/mutants.toml)
#
# Property-based testing (proptest) and mutation testing (cargo-mutants) are the
# two load-bearing gates: PBT pins invariants across all inputs, mutation
# testing proves those tests actually have teeth.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> fmt";     cargo fmt --all --check
echo "==> clippy";  cargo clippy --workspace --all-targets -- -D warnings
echo "==> test";    cargo nextest run --workspace 2>/dev/null || cargo test --workspace

# Mutation gate: ZERO surviving (missed) mutants. cargo-mutants also exits
# non-zero on timeouts, but the only timeouts are loop-bound mutations that hang
# (detected, not survivors), so we gate on missed.txt and tolerate timeouts.
echo "==> mutants"
rm -rf mutants.out
set +e
cargo mutants --workspace ${MUTANTS_ARGS:-}
set -e
if [ ! -f mutants.out/missed.txt ]; then
    echo "mutants: no results (baseline or usage error)"; exit 1
fi
if [ -s mutants.out/missed.txt ]; then
    echo "mutants: SURVIVING mutants found:"; cat mutants.out/missed.txt; exit 1
fi
echo "==> all gates green (0 surviving mutants)"
