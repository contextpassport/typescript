# Context Passport — TypeScript Reference Implementation

A reference implementation of the [Context Passport](https://github.com/contextpassport/spec) v1.0 specification in TypeScript.

**Specification:** https://github.com/contextpassport/spec
**License:** Apache-2.0

## Install

```bash
npm install @contextpassport/core@alpha
```

(The `@alpha` tag is required while v1.0 is in prerelease. After `1.0.0` stable ships, `npm install @contextpassport/core` will work without a tag.)

## Usage

```ts
import { makePassport, verifyChain } from "@contextpassport/core";

const root = makePassport({
  agentId:   "agent-researcher-01",
  agentName: "Research Agent",
  payload:   { input: "Analyze Q1 earnings", output: { summary: "APAC up 34%" } },
  role:      "researcher",
  provider:  "anthropic",
  model:     "claude-opus-4-6",
});

const child = makePassport({
  agentId:   "agent-writer-01",
  agentName: "Writer Agent",
  payload:   { input: root.payload.output, output: "Draft prepared." },
  parent:    root,
});

console.log(verifyChain([root, child])); // true
```

## Conformance

This implementation targets **Core conformance** with the [Context Passport v1.0 conformance test suite](https://github.com/contextpassport/conformance-tests). Signed conformance is planned.

## Contributing

See [CONTRIBUTING.md](https://github.com/contextpassport/spec/blob/main/CONTRIBUTING.md) in the spec repository.

## Related repositories

- [contextpassport/spec](https://github.com/contextpassport/spec) — the specification
- [contextpassport/python](https://github.com/contextpassport/python) — Python reference implementation
- [contextpassport/conformance-tests](https://github.com/contextpassport/conformance-tests) — conformance test suite
