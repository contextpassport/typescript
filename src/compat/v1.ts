/**
 * v1.x compatibility shim.
 *
 * Reproduces the v1.x canonicalization (sorted keys, no whitespace, no extra
 * normalization) so v2.x verifiers can validate v1.x records. The v1.x
 * TypeScript implementation relied on JSON.stringify with a sorted-keys
 * replacer; we keep that exact behavior here.
 */

import { createHash } from "node:crypto";

function sortedKeysReplacer(_key: string, val: unknown): unknown {
  if (val && typeof val === "object" && !Array.isArray(val)) {
    const sorted: Record<string, unknown> = {};
    for (const k of Object.keys(val as Record<string, unknown>).sort()) {
      sorted[k] = (val as Record<string, unknown>)[k];
    }
    return sorted;
  }
  return val;
}

export function canonicalV1(value: unknown): string {
  return JSON.stringify(value, sortedKeysReplacer);
}

export function payloadHash(payload: unknown): string {
  return "sha256:" + createHash("sha256").update(canonicalV1(payload)).digest("hex");
}

export function integrityHash(payHash: string, parentIntegrity: string | null): string {
  const chainInput = payHash + (parentIntegrity ?? "root");
  return "sha256:" + createHash("sha256").update(chainInput).digest("hex");
}
