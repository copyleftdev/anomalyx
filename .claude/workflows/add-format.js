export const meta = {
  name: 'add-format',
  description:
    'Implement a new input-format parser end-to-end from a `format` issue: plan it, implement it with the format-parser agent, then harden it to the 0-mutation gate with the mutation-hardener agent.',
  phases: [{ title: 'Plan' }, { title: 'Implement' }, { title: 'Harden' }],
}

// `args` is the format/issue to add (e.g. "logfmt", "#18", or an issue URL).
const target = typeof args === 'string' && args.trim() ? args.trim() : 'the next open `format` issue'

phase('Plan')
const plan = await agent(
  `Plan a new anomalyx format parser. Target: ${target}. If it names a GitHub issue, read it with ` +
    `\`gh issue view\`. Read crates/ax-normalize/src/parser.rs and the most similar existing parser ` +
    `(parsers/delimited.rs | json.rs | ndjson.rs | columnar.rs). Decide: parser id, file extensions, ` +
    `sniff strategy + confidence (MAGIC/STRONG/TEXT/FALLBACK), parsing approach, and the crate to use. ` +
    `Do NOT write code.`,
  {
    label: 'plan',
    schema: {
      type: 'object',
      properties: {
        id: { type: 'string' },
        extensions: { type: 'array', items: { type: 'string' } },
        crate: { type: 'string' },
        approach: { type: 'string' },
      },
      required: ['id', 'approach'],
    },
  },
)

phase('Implement')
const implemented = await agent(
  `Implement the new format parser per this plan:\n${JSON.stringify(plan, null, 2)}\n` +
    `Create crates/ax-normalize/src/parsers/${plan.id}.rs implementing FormatParser, register it in ` +
    `parsers/mod.rs::default_registry, add tests, and get \`cargo test -p anomalyx-normalize\` and ` +
    `\`cargo clippy -p anomalyx-normalize --all-targets -- -D warnings\` green. Touch only ax-normalize.`,
  { label: `implement:${plan.id}`, agentType: 'format-parser', phase: 'Implement' },
)

phase('Harden')
const hardened = await agent(
  `Run \`cargo mutants -p anomalyx-normalize\` and drive it to zero surviving (missed) mutants for the ` +
    `new ${plan.id} parser — add targeted tests, or document genuine equivalents in .cargo/mutants.toml. ` +
    `Report what each new test kills.`,
  { label: 'harden', agentType: 'mutation-hardener', phase: 'Harden' },
)

return { plan, implemented, hardened }
