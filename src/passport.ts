/**
 * Context Passport v2.0 — core passport construction and verification.
 *
 * Specification: https://github.com/contextpassport/spec
 * License: Apache-2.0
 *
 * v2.0 adopts RFC 8785 (JSON Canonicalization Scheme / JCS) for hashing
 * and signing. See proposals/canonical-json-jcs.md in the spec repo.
 */

import { createHash, randomBytes } from "node:crypto";
import { payloadHash as payloadHashV1 } from "./compat/v1.js";

export const SCHEMA_URL = "https://contextpassport.com/schema/v2.json";
export const SCHEMA_VERSION = "2.0";

export interface Passport {
  $schema: string;
  schema_version: string;
  id: string;
  parent_id: string | null;
  trace_id: string | null;
  branch_key: string;
  created_by: {
    agent_id: string;
    agent_name: string;
    role: string | null;
    provider: string | null;
    model: string | null;
  };
  event: {
    type: string;
    to_agent_id: string | null;
    timestamp: string;
  };
  payload: Record<string, unknown>;
  integrity: {
    payload_hash: string;
    parent_hash: string | null;
    integrity_hash: string;
    verification_status: "valid" | "broken" | "unverified";
  };
  lineage: {
    fork_of: string | null;
    fork_point: string | null;
    lineage_root: string | null;
  };
  signature?: {
    algorithm: string;
    key_id: string;
    public_key?: string;
    signature: string;
  };
  created_at: string;
}

export interface MakePassportInput {
  agentId: string;
  agentName: string;
  payload: Record<string, unknown>;
  parent?: Passport | null;
  toAgentId?: string | null;
  role?: string | null;
  provider?: string | null;
  model?: string | null;
  eventType?: string;
  traceId?: string | null;
  branchKey?: string;
}

/**
 * RFC 8785 (JCS) canonical JSON serialization.
 *
 * - Keys sorted lexicographically (UTF-16 code unit order, the JS default).
 * - No whitespace.
 * - Strings emitted raw UTF-8 (JS JSON.stringify already does this).
 * - Numbers per ECMAScript ToString (JS native — already conformant).
 * - NaN / Infinity rejected.
 */
export function canonical(value: unknown): string {
  return JSON.stringify(normalize(value));
}

function normalize(value: unknown): unknown {
  if (value === null) return null;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("JCS canonicalization does not permit NaN or Infinity");
    }
    return value;
  }
  if (typeof value === "string" || typeof value === "boolean") return value;
  if (Array.isArray(value)) return value.map(normalize);
  if (typeof value === "object") {
    const src = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(src).sort()) {
      out[k] = normalize(src[k]);
    }
    return out;
  }
  if (typeof value === "bigint") {
    // BigInt is not representable by JSON.stringify. JCS has no canonical
    // form for arbitrary-precision integers either; surface as an error.
    throw new Error("BigInt is not JSON-serializable; encode as a string in the payload");
  }
  throw new Error(`Value of type ${typeof value} is not JSON-serializable under JCS`);
}

export function payloadHash(payload: unknown): string {
  return "sha256:" + createHash("sha256").update(canonical(payload), "utf8").digest("hex");
}

export function integrityHash(payHash: string, parentIntegrity: string | null): string {
  const chainInput = payHash + (parentIntegrity ?? "root");
  return "sha256:" + createHash("sha256").update(chainInput).digest("hex");
}

export function makePassport(input: MakePassportInput): Passport {
  const ts = Date.now().toString();
  const hex = randomBytes(6).toString("hex");
  const id = `ctx_${ts}_${hex}`;

  const payHash = payloadHash(input.payload);
  const parentIntegrity = input.parent?.integrity.integrity_hash ?? null;
  const parentId = input.parent?.id ?? null;
  const intHash = integrityHash(payHash, parentIntegrity);
  const now = new Date().toISOString();

  return {
    $schema: SCHEMA_URL,
    schema_version: SCHEMA_VERSION,
    id,
    parent_id: parentId,
    trace_id: input.traceId ?? null,
    branch_key: input.branchKey ?? "main",
    created_by: {
      agent_id: input.agentId,
      agent_name: input.agentName,
      role: input.role ?? null,
      provider: input.provider ?? null,
      model: input.model ?? null,
    },
    event: {
      type: input.eventType ?? "commit",
      to_agent_id: input.toAgentId ?? null,
      timestamp: now,
    },
    payload: input.payload,
    integrity: {
      payload_hash: payHash,
      parent_hash: parentIntegrity,
      integrity_hash: intHash,
      verification_status: "valid",
    },
    lineage: {
      fork_of: null,
      fork_point: null,
      lineage_root: null,
    },
    created_at: now,
  };
}

export function verifyChain(passports: readonly Passport[]): boolean {
  let prev: Passport | null = null;
  for (const p of passports) {
    const version = String(p.schema_version ?? "2.0");
    const payHash = version.startsWith("1.")
      ? payloadHashV1(p.payload)
      : payloadHash(p.payload);
    const parentIntegrity = prev?.integrity.integrity_hash ?? null;
    const expected = integrityHash(payHash, parentIntegrity);
    if (p.integrity.integrity_hash !== expected) return false;
    prev = p;
  }
  return true;
}
