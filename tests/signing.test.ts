import { test } from "node:test";
import assert from "node:assert/strict";
import {
  makePassport,
  signPassport,
  verifySignature,
  generateKeypair,
  publicKeyFromBase64,
  publicKeyToBase64,
} from "../src/index.js";

test("sign and verify roundtrip", () => {
  const { privateKey, publicKey } = generateKeypair();
  const p = makePassport({
    agentId: "a1",
    agentName: "Agent",
    payload: { input: "hello", output: "world" },
  });
  const signed = signPassport(p, privateKey, { keyId: "key-1", publicKey });
  assert.ok(signed.signature);
  assert.equal(signed.signature?.algorithm, "ed25519");
  assert.equal(signed.signature?.key_id, "key-1");
  assert.ok(signed.signature?.signature);
  assert.equal(verifySignature(signed), true);
});

test("tampering payload breaks signature", () => {
  const { privateKey } = generateKeypair();
  const p = makePassport({
    agentId: "a1", agentName: "Agent",
    payload: { input: "hello", output: "world" },
  });
  const signed = signPassport(p, privateKey, { keyId: "key-1" });
  const tampered: typeof signed = JSON.parse(JSON.stringify(signed));
  (tampered.payload as Record<string, unknown>).output = "TAMPERED";
  assert.equal(verifySignature(tampered), false);
});

test("tampering signature itself fails verification", () => {
  const { privateKey } = generateKeypair();
  const p = makePassport({
    agentId: "a1", agentName: "Agent",
    payload: { input: "x", output: "y" },
  });
  const signed = signPassport(p, privateKey, { keyId: "key-1" });
  const tampered: typeof signed = JSON.parse(JSON.stringify(signed));
  const sig = tampered.signature!.signature;
  tampered.signature!.signature = (sig[0] === "A" ? "B" : "A") + sig.slice(1);
  assert.equal(verifySignature(tampered), false);
});

test("verify with external public key", () => {
  const { privateKey, publicKey } = generateKeypair();
  const p = makePassport({
    agentId: "a1", agentName: "Agent",
    payload: { input: "x", output: "y" },
  });
  const signed = signPassport(p, privateKey, { keyId: "key-1" });
  assert.equal(verifySignature(signed, publicKey), true);
});

test("unsigned passport returns false", () => {
  const p = makePassport({
    agentId: "a1", agentName: "Agent",
    payload: { input: "x", output: "y" },
  });
  assert.equal(verifySignature(p), false);
});

test("public key base64 roundtrip", () => {
  const { publicKey } = generateKeypair();
  const b64 = publicKeyToBase64(publicKey);
  const restored = publicKeyFromBase64(b64);
  assert.equal(publicKeyToBase64(restored), b64);
});

test("deterministic vector v07 verifies cross-impl", () => {
  // This is the same vector from contextpassport/conformance-tests/vectors/signed/v07_ed25519_valid.json
  // produced by the Python reference implementation with a deterministic key.
  // If the TS implementation's canonicalization matches Python's, this verifies.
  const v07 = {
    "$schema": "https://contextpassport.com/schema/v1.json",
    "schema_version": "1.0",
    "id": "ctx_1700000000000_aaa111aaa111",
    "parent_id": null,
    "trace_id": null,
    "branch_key": "main",
    "created_by": {
      "agent_id": "agent-1",
      "agent_name": "Agent",
      "role": null,
      "provider": null,
      "model": null,
    },
    "event": { "type": "commit", "to_agent_id": null, "timestamp": "2026-01-01T00:00:00Z" },
    "payload": { "input": "hello", "output": "world" },
    "integrity": {
      "payload_hash":        "sha256:835d9bdaa3b54bf66362a7d85ce9b4bef1c177ba77ab7d87c98d8ae72903177e",
      "parent_hash":         null,
      "integrity_hash":      "sha256:4dd235f0e5eb22441e8d6ac67e01b560a4db986bccb8d8aa117cbd00679ba691",
      "verification_status": "valid" as const,
    },
    "lineage": { "fork_of": null, "fork_point": null, "lineage_root": null },
    "created_at": "2026-01-01T00:00:00Z",
    "signature": {
      "algorithm":  "ed25519",
      "key_id":     "test-key-1",
      "public_key": "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=",
      "signature":  "gjdsVNbszyuNFB90E+6RqpPgb6z4EI8amN7o079nxu+TRni2EVbGDhPKgQPttRHSzUMI6aQ0r72R94bA9OyUBQ==",
    },
  };
  assert.equal(verifySignature(v07), true, "Python-signed vector must verify in TS");
});
