# Context Passport — TypeScript Reference Implementation

A reference implementation of the [Context Passport](https://github.com/contextpassport/spec) v1.0 specification in TypeScript.

**Specification:** https://github.com/contextpassport/spec
**License:** Apache-2.0

## Install

```bash
npm install @contextpassport/core
```

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

### Signed records (Ed25519)

Produces records that are signature-verifiable by any conformant implementation, including the Python `context_passport.signing` module. Uses Node's built-in `crypto`; no external dependencies.

```ts
import {
  makePassport, verifyChain,
  signPassport, verifySignature, generateKeypair,
} from "@contextpassport/core";

const { privateKey, publicKey } = generateKeypair();

const p = makePassport({
  agentId:   "research-agent-01",
  agentName: "Research Agent",
  payload:   { input: "Analyze Q1 earnings", output: { summary: "APAC up 34%" } },
});
const signed = signPassport(p, privateKey, { keyId: "research-key-2026-05" });

console.log(verifySignature(signed));            // true
console.log(verifySignature(signed, publicKey)); // true (external public key)
```

## Conformance

This implementation passes both Core and Signed levels of the [Context Passport v1.0 conformance test suite](https://github.com/contextpassport/conformance-tests). Cross-implementation verification is exercised: signatures produced by the Python reference implementation verify under this TypeScript implementation byte-for-byte (and vice versa).

## Contributing

See [CONTRIBUTING.md](https://github.com/contextpassport/spec/blob/main/CONTRIBUTING.md) in the spec repository.

## Related repositories

- [contextpassport/spec](https://github.com/contextpassport/spec) — the specification
- [contextpassport/python](https://github.com/contextpassport/python) — Python reference implementation
- [contextpassport/conformance-tests](https://github.com/contextpassport/conformance-tests) — conformance test suite
