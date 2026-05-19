export {
  makePassport,
  verifyChain,
  payloadHash,
  integrityHash,
  SCHEMA_URL,
  SCHEMA_VERSION,
} from "./passport.js";

export type { Passport, MakePassportInput } from "./passport.js";

export {
  signPassport,
  verifySignature,
  generateKeypair,
  publicKeyToBase64,
  publicKeyFromBase64,
} from "./signing.js";

export type { KeyPair } from "./signing.js";
