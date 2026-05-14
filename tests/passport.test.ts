import { test } from "node:test";
import assert from "node:assert/strict";
import { makePassport, verifyChain, payloadHash } from "../src/passport.js";

test("root passport has no parent", () => {
  const p = makePassport({
    agentId: "a1",
    agentName: "Agent One",
    payload: { input: "hello", output: "world" },
  });
  assert.equal(p.parent_id, null);
  assert.equal(p.integrity.parent_hash, null);
  assert.equal(p.schema_version, "1.0");
});

test("chain links correctly", () => {
  const a = makePassport({
    agentId: "a1", agentName: "Agent One",
    payload: { input: "x", output: "y" },
  });
  const b = makePassport({
    agentId: "a2", agentName: "Agent Two",
    payload: { input: "y", output: "z" },
    parent: a,
  });
  assert.equal(b.parent_id, a.id);
  assert.equal(b.integrity.parent_hash, a.integrity.integrity_hash);
  assert.ok(verifyChain([a, b]));
});

test("canonicalization is key-order independent", () => {
  const h1 = payloadHash({ a: 1, b: 2 });
  const h2 = payloadHash({ b: 2, a: 1 });
  assert.equal(h1, h2);
});

test("tampered payload breaks chain", () => {
  const a = makePassport({
    agentId: "a1", agentName: "Agent One",
    payload: { input: "x", output: "y" },
  });
  const b = makePassport({
    agentId: "a2", agentName: "Agent Two",
    payload: { input: "y", output: "z" },
    parent: a,
  });
  (b.payload as Record<string, unknown>).output = "TAMPERED";
  assert.equal(verifyChain([a, b]), false);
});
