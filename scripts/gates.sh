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
echo "==> mutants"; cargo mutants --workspace ${MUTANTS_ARGS:-}
echo "==> all gates green"
