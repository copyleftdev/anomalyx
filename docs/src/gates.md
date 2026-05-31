# Quality gates

Two load-bearing test gates back every change, run locally by `scripts/gates.sh`
and in CI on every push.

## Property-based testing

Invariants are pinned across *all* inputs with [`proptest`], not just hand-picked
cases — for example:

- the point detector is shift-, scale-, and permutation-invariant;
- KS is symmetric and lies in `[0, 1]`; PSI is non-negative;
- Mahalanobis flagging is translation-invariant;
- reductions are order-independent and reproducible.

[`proptest`]: https://docs.rs/proptest

## Mutation testing

Property tests are only as good as their teeth. [`cargo-mutants`] mutates the
source and checks that some test fails for each change. The gate is **zero
*surviving* mutants** across the workspace.

[`cargo-mutants`]: https://mutants.rs

Getting there surfaced — and killed — real test gaps, and forced exact-value
pins (e.g. validating reductions against NIST). A handful of mutants are
genuinely **equivalent** (they cannot change observable behavior for any input —
a measure-zero `p == α` boundary, or a sign flip that the `Σ(deviations) == 0`
identity cancels); those are documented individually in `.cargo/mutants.toml`,
never blanket-suppressed. Loop-bound mutations that hang are detected as
timeouts (a hang is caught, not a survivor), so the gate is precisely "no
mutant survives."

## CI

`.github/workflows/ci.yml` runs the fast gates on every push and pull request:
`cargo fmt --check`, `cargo clippy -D warnings`, the full test suite, and the
text-only `--no-default-features` build.

The **mutation gate runs locally, not in CI** — `cargo mutants` is far too
minutes-expensive on hosted runners. It is enforced before pushing via:

```console
./scripts/gates.sh    # fmt · clippy · test · mutation (0 surviving mutants)
```

and is the contributor's responsibility (the `gate` workflow can fan it out
per-crate). Treat a green local mutation run as part of "done."
