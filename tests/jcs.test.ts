import { test } from "node:test";
import assert from "node:assert/strict";
import { canonical, payloadHash } from "../src/passport.js";
import { payloadHash as payloadHashV1 } from "../src/compat/v1.js";

test("non-ASCII strings emitted raw", () => {
  assert.equal(canonical({ name: "François" }), '{"name":"François"}');
});

test("emoji emitted raw", () => {
  assert.equal(canonical({ msg: "hi 👋" }), '{"msg":"hi 👋"}');
});

test("integer-valued numbers are integers (JS native)", () => {
  // JS Number 1.0 === 1, JSON.stringify outputs "1".
  assert.equal(canonical({ x: 1.0 }), '{"x":1}');
});

test("NaN rejected", () => {
  assert.throws(() => canonical({ x: NaN }));
});

test("Infinity rejected", () => {
  assert.throws(() => canonical({ x: Infinity }));
});

test("BigInt rejected with clear error", () => {
  assert.throws(() => canonical({ x: 1n }), /BigInt/);
});

test("v1 compat hash matches v2 hash for ASCII (no-op upgrade)", () => {
  // TS JSON.stringify always emitted raw UTF-8, so v1 TS records with
  // non-ASCII payloads happen to be byte-compatible with v2 JCS already.
  // The v1 shim mainly exists for cross-impl chains containing Python v1
  // records, which v1.x-escaped their non-ASCII strings.
  const v1h = payloadHashV1({ name: "François" });
  const v2h = payloadHash({ name: "François" });
  assert.equal(v1h, v2h);
});
