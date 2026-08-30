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
  assert.equal(p.schema_version, "2.0");
});

test("accepts specified and namespaced event types", () => {
  const specifiedTypes = [
    "commit", "fork", "checkpoint", "revert", "branch", "merge", "spawn", "retry",
    "timeout", "error", "override", "consent", "escalate", "redact", "audit",
  ];
  for (const eventType of [...specifiedTypes, "tool_call", "acme.risk_review"]) {
    const passport = makePassport({
      agentId: "a1",
      agentName: "Agent One",
      payload: {},
      eventType,
    });
    assert.equal(passport.event.type, eventType);
  }

});

test("rejects event types outside the v2 schema pattern", () => {
  const invalidTypes = ["", "COMMIT", "commit-retry", "1commit", "commit\n", ".commit", "commit."];
  for (const eventType of invalidTypes) {
    assert.throws(
      () => makePassport({ agentId: "a1", agentName: "Agent One", payload: {}, eventType }),
      { name: "TypeError", message: /eventType must match/ },
    );
  }

  assert.throws(
    () => makePassport({
      agentId: "a1",
      agentName: "Agent One",
      payload: {},
      eventType: ["commit"] as unknown as string,
    }),
    { name: "TypeError", message: /eventType must match/ },
  );
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
