/**
 * Optional Ed25519 signing for Context Passport.
 *
 * Implements SPEC.md §3.2.7. The signature is computed over the canonical
 * bytes of the envelope with the `signature.signature` field cleared.
 *
 * Uses Node's built-in `crypto` module. No external dependencies.
 *
 * Mirrors `context_passport.signing` in the Python SDK so records signed
 * by one implementation verify in the other (and vice versa).
 */

import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  KeyObject,
  sign,
  verify,
} from "node:crypto";

import type { Passport } from "./passport.js";
import { canonical as canonicalJcs } from "./passport.js";

// ----- Public API ---------------------------------------------------------

export interface KeyPair {
  privateKey: KeyObject;
  publicKey: KeyObject;
}

export function generateKeypair(): KeyPair {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return { privateKey, publicKey };
}

export function publicKeyToBase64(pub: KeyObject): string {
  // Export raw 32-byte public key, base64-encoded.
  const der = pub.export({ format: "der", type: "spki" });
  // SPKI for Ed25519 is a 44-byte structure with the last 32 bytes being the raw key.
  const raw = Uint8Array.from(der).slice(-32);
  return Buffer.from(raw).toString("base64");
}

export function publicKeyFromBase64(b64: string): KeyObject {
  const raw = Buffer.from(b64, "base64");
  if (raw.length !== 32) {
    throw new Error(`expected 32 raw Ed25519 public-key bytes, got ${raw.length}`);
  }
  // Build SPKI DER prefix for Ed25519
  const spkiPrefix = Buffer.from([
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
  ]);
  const der = Buffer.concat([spkiPrefix, raw]);
  return createPublicKey({ key: der, format: "der", type: "spki" });
}

/**
 * Return a copy of the passport with a `signature` block populated.
 *
 * The signature is Ed25519 over the canonical bytes of the envelope with
 * `signature.signature` cleared. Implementation must match SPEC.md §3.2.7
 * and the Python `context_passport.signing.sign_passport` byte-for-byte.
 */
export function signPassport(
  passport: Passport,
  privateKey: KeyObject,
  options: { keyId: string; publicKey?: KeyObject },
): Passport {
  const pub = options.publicKey ?? derivePublicKey(privateKey);
  const signed: Passport = JSON.parse(JSON.stringify(passport));
  signed.signature = {
    algorithm: "ed25519",
    key_id: options.keyId,
    public_key: publicKeyToBase64(pub),
    signature: "",
  };
  const msg = canonicalBytesForSigning(signed);
  const sigBytes = sign(null, msg, privateKey);
  signed.signature.signature = sigBytes.toString("base64");
  return signed;
}

/**
 * Verify the Ed25519 signature on a passport.
 *
 * If `publicKey` is undefined, the public key embedded in
 * `passport.signature.public_key` is used.
 *
 * Returns true if the signature is valid, false otherwise.
 */
export function verifySignature(passport: Passport, publicKey?: KeyObject): boolean {
  const sigBlock = passport.signature as
    | { algorithm: string; key_id: string; public_key?: string; signature: string }
    | undefined;
  if (!sigBlock) return false;
  if (sigBlock.algorithm !== "ed25519") return false;
  if (!sigBlock.signature) return false;

  let pubKey: KeyObject | undefined = publicKey;
  if (!pubKey) {
    if (!sigBlock.public_key) return false;
    try {
      pubKey = publicKeyFromBase64(sigBlock.public_key);
    } catch {
      return false;
    }
  }

  const msg = canonicalBytesForSigning(passport);
  try {
    return verify(null, msg, pubKey, Buffer.from(sigBlock.signature, "base64"));
  } catch {
    return false;
  }
}

// ----- internals ---------------------------------------------------------

/**
 * Canonical bytes over which the signature is computed.
 *
 * Per SPEC.md §3.2.7: signature is computed over the canonical envelope
 * with signature.signature cleared. Sorted-keys JSON, no whitespace, UTF-8.
 */
function canonicalBytesForSigning(passport: Passport): Buffer {
  const clone: Passport = JSON.parse(JSON.stringify(passport));
  if (clone.signature && typeof clone.signature === "object") {
    (clone.signature as Record<string, unknown>).signature = "";
  }
  return Buffer.from(canonicalJcs(clone), "utf-8");
}

function derivePublicKey(privateKey: KeyObject): KeyObject {
  const der = privateKey.export({ format: "der", type: "pkcs8" });
  const priv = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  return createPublicKey(priv);
}
