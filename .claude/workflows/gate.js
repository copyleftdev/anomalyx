export const meta = {
  name: 'gate',
  description:
    'Run the anomalyx quality gates: fmt, clippy and tests, then per-crate mutation testing (0 surviving mutants) fanned out across agents in parallel.',
  phases: [
    { title: 'Static', detail: 'fmt --check, clippy -D warnings, test --workspace (+ no-default-features)' },
    { title: 'Mutation', detail: 'cargo mutants per crate, in parallel' },
  ],
}

// crates.io package names (what `cargo -p` expects)
const CRATES = ['anomalyx-core', 'anomalyx-normalize', 'anomalyx-detect', 'anomalyx', 'anomalyx-validate']

phase('Static')
const staticChecks = await agent(
  'At the anomalyx repo root, run in order and report each step pass/fail (include the first errors on ' +
    'failure), modifying no files: `cargo fmt --all --check`; `cargo clippy --workspace --all-targets -- ' +
    '-D warnings`; `cargo test --workspace`; `cargo test -p anomalyx-normalize --no-default-features`.',
  {
    label: 'fmt+clippy+test',
    schema: {
      type: 'object',
      properties: { passed: { type: 'boolean' }, summary: { type: 'string' } },
      required: ['passed', 'summary'],
    },
  },
)

phase('Mutation')
// The gate is "0 surviving (missed) mutants" — timeouts are loop-bound hangs and
// count as caught. Each crate is mutated by its own agent concurrently.
const mutation = await parallel(
  CRATES.map((c) => () =>
    agent(
      `At the anomalyx repo root run \`cargo mutants -p ${c}\`. After it finishes, the gate is that ` +
        `mutants.out/missed.txt is EMPTY (timeouts are acceptable). Report the caught/missed/timeout counts; ` +
        `if missed.txt is non-empty, paste its contents. Modify no files.`,
      {
        label: `mutants:${c}`,
        phase: 'Mutation',
        schema: {
          type: 'object',
          properties: {
            crate: { type: 'string' },
            missed: { type: 'integer' },
            survivors: { type: 'array', items: { type: 'string' } },
          },
          required: ['crate', 'missed'],
        },
      },
    ),
  ),
)

const withSurvivors = mutation.filter(Boolean).filter((m) => (m.missed || 0) > 0)
const green = !!staticChecks?.passed && withSurvivors.length === 0
log(green ? 'GATE GREEN — 0 surviving mutants' : `GATE FAILED — ${withSurvivors.length} crate(s) with survivors`)
return { staticChecks, mutation, green }
