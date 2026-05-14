/**
 * Context Passport v1.0 — core passport construction and verification.
 *
 * Specification: https://github.com/contextpassport/spec
 * License: Apache-2.0
 */

import { createHash, randomBytes } from "node:crypto";

export const SCHEMA_URL = "https://contextpassport.com/schema/v1.json";
export const SCHEMA_VERSION = "1.0";

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

/** Canonical JSON: sorted keys at every level, no extra whitespace. */
function canonical(value: unknown): string {
  return JSON.stringify(value, sortedKeysReplacer);
}

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

export function payloadHash(payload: unknown): string {
  return "sha256:" + createHash("sha256").update(canonical(payload)).digest("hex");
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
    const payHash = payloadHash(p.payload);
    const parentIntegrity = prev?.integrity.integrity_hash ?? null;
    const expected = integrityHash(payHash, parentIntegrity);
    if (p.integrity.integrity_hash !== expected) return false;
    prev = p;
  }
  return true;
}
