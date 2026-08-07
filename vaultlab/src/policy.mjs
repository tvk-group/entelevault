import { timingSafeEqual } from "node:crypto";
import { VaultLabError } from "./errors.mjs";

export const ARTIFACT_SCHEMA = "entelevault.vaultlab.synthetic.v1";
export const ARTIFACT_PURPOSE = "security-assurance-only";
export const MAX_ARTIFACT_BYTES = 128 * 1024;
export const MAX_CIPHERTEXT_BYTES = 32 * 1024;

export const KDF_POLICY = Object.freeze({
  algorithm: "scrypt",
  minimumN: 1 << 14,
  maximumN: 1 << 18,
  requiredR: 8,
  minimumP: 1,
  maximumP: 4,
  keyLength: 32,
  maximumMemoryBytes: 256 * 1024 * 1024
});

const ROOT_FIELDS = new Set([
  "schema",
  "version",
  "purpose",
  "fixtureId",
  "createdAt",
  "kdf",
  "cipher",
  "attestation",
  "metadata"
]);
const KDF_FIELDS = new Set(["algorithm", "salt", "params"]);
const KDF_PARAM_FIELDS = new Set(["N", "r", "p", "keyLength", "maxmem"]);
const CIPHER_FIELDS = new Set(["algorithm", "iv", "tag", "ciphertext"]);
const ATTESTATION_FIELDS = new Set(["generator", "digest"]);
const METADATA_FIELDS = new Set(["scenario", "classification", "controlSet"]);

const PROHIBITED_FIELD = /(?:private.?key|mnemonic|seed.?phrase|wallet.?file|password.?list|candidate|target|brain.?wallet|recovery.?phrase|key.?store|blockchain.?address)/iu;
const HEX_ADDRESS = /\b0x[0-9a-f]{40}\b/iu;
const MNEMONIC_LIKE = /\b(?:[a-z]{3,12}\s+){11,23}[a-z]{3,12}\b/iu;

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function reject(code, message) {
  throw new VaultLabError(code, message);
}

function assertExactFields(value, allowed, label) {
  if (!isRecord(value)) {
    reject("VAULTLAB_INVALID_ARTIFACT", `${label} must be an object`);
  }

  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      reject("VAULTLAB_UNKNOWN_FIELD", `${label} contains an unsupported field`);
    }
  }
}

function decodeBase64Url(value, expectedBytes, label) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/u.test(value)) {
    reject("VAULTLAB_INVALID_ENCODING", `${label} must be base64url`);
  }

  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== expectedBytes) {
    reject("VAULTLAB_INVALID_LENGTH", `${label} has an invalid length`);
  }
  return bytes;
}

function inspectForForbiddenData(value, depth = 0) {
  if (depth > 8) {
    reject("VAULTLAB_NESTING_LIMIT", "Artifact nesting limit exceeded");
  }

  if (Array.isArray(value)) {
    if (value.length > 16) {
      reject("VAULTLAB_ARRAY_LIMIT", "Artifact array limit exceeded");
    }
    value.forEach((entry) => inspectForForbiddenData(entry, depth + 1));
    return;
  }

  if (isRecord(value)) {
    const entries = Object.entries(value);
    if (entries.length > 24) {
      reject("VAULTLAB_FIELD_LIMIT", "Artifact field limit exceeded");
    }
    for (const [key, entry] of entries) {
      if (PROHIBITED_FIELD.test(key)) {
        reject("VAULTLAB_PROHIBITED_INPUT", "Artifact contains a prohibited field");
      }
      inspectForForbiddenData(entry, depth + 1);
    }
    return;
  }

  if (typeof value === "string") {
    if (value.length > MAX_ARTIFACT_BYTES) {
      reject("VAULTLAB_STRING_LIMIT", "Artifact string limit exceeded");
    }
    if (HEX_ADDRESS.test(value) || MNEMONIC_LIKE.test(value)) {
      reject("VAULTLAB_PROHIBITED_INPUT", "Artifact resembles live wallet material");
    }
  }
}

export function parseSyntheticArtifact(input) {
  if (Array.isArray(input)) {
    reject("VAULTLAB_BULK_INPUT_REJECTED", "Bulk artifacts are not accepted");
  }

  let artifact = input;
  if (typeof input === "string") {
    if (Buffer.byteLength(input, "utf8") > MAX_ARTIFACT_BYTES) {
      reject("VAULTLAB_SIZE_LIMIT", "Artifact exceeds the size limit");
    }
    try {
      artifact = JSON.parse(input);
    } catch {
      reject("VAULTLAB_INVALID_JSON", "Artifact is not valid JSON");
    }
  }

  inspectForForbiddenData(artifact);
  assertExactFields(artifact, ROOT_FIELDS, "Artifact");

  if (
    artifact.schema !== ARTIFACT_SCHEMA ||
    artifact.version !== 1 ||
    artifact.purpose !== ARTIFACT_PURPOSE
  ) {
    reject("VAULTLAB_NOT_SYNTHETIC", "Only VaultLab synthetic artifacts are accepted");
  }

  if (typeof artifact.fixtureId !== "string" || !/^vlab_[0-9a-f]{32}$/u.test(artifact.fixtureId)) {
    reject("VAULTLAB_INVALID_FIXTURE_ID", "Fixture identifier is invalid");
  }

  if (typeof artifact.createdAt !== "string" || Number.isNaN(Date.parse(artifact.createdAt))) {
    reject("VAULTLAB_INVALID_TIMESTAMP", "Fixture timestamp is invalid");
  }

  assertExactFields(artifact.kdf, KDF_FIELDS, "KDF");
  assertExactFields(artifact.kdf.params, KDF_PARAM_FIELDS, "KDF parameters");
  if (artifact.kdf.algorithm !== KDF_POLICY.algorithm) {
    reject("VAULTLAB_KDF_REJECTED", "KDF algorithm is outside policy");
  }

  const { N, r, p, keyLength, maxmem } = artifact.kdf.params;
  const isPowerOfTwo = Number.isSafeInteger(N) && N > 1 && (N & (N - 1)) === 0;
  if (
    !isPowerOfTwo ||
    N < KDF_POLICY.minimumN ||
    N > KDF_POLICY.maximumN ||
    r !== KDF_POLICY.requiredR ||
    !Number.isSafeInteger(p) ||
    p < KDF_POLICY.minimumP ||
    p > KDF_POLICY.maximumP ||
    keyLength !== KDF_POLICY.keyLength ||
    !Number.isSafeInteger(maxmem) ||
    maxmem < 32 * 1024 * 1024 ||
    maxmem > KDF_POLICY.maximumMemoryBytes
  ) {
    reject("VAULTLAB_KDF_REJECTED", "KDF parameters are outside policy");
  }
  decodeBase64Url(artifact.kdf.salt, 16, "KDF salt");

  assertExactFields(artifact.cipher, CIPHER_FIELDS, "Cipher");
  if (artifact.cipher.algorithm !== "aes-256-gcm") {
    reject("VAULTLAB_CIPHER_REJECTED", "Cipher algorithm is outside policy");
  }
  decodeBase64Url(artifact.cipher.iv, 12, "Cipher IV");
  decodeBase64Url(artifact.cipher.tag, 16, "Authentication tag");
  if (typeof artifact.cipher.ciphertext !== "string") {
    reject("VAULTLAB_INVALID_ENCODING", "Ciphertext must be base64url");
  }
  const ciphertext = Buffer.from(artifact.cipher.ciphertext, "base64url");
  if (ciphertext.length < 32 || ciphertext.length > MAX_CIPHERTEXT_BYTES) {
    reject("VAULTLAB_INVALID_LENGTH", "Ciphertext length is outside policy");
  }

  assertExactFields(artifact.attestation, ATTESTATION_FIELDS, "Attestation");
  if (artifact.attestation.generator !== "EnteleVAULT VaultLab") {
    reject("VAULTLAB_NOT_SYNTHETIC", "Fixture generator is not trusted by policy");
  }
  if (typeof artifact.attestation.digest !== "string" || !/^[0-9a-f]{64}$/u.test(artifact.attestation.digest)) {
    reject("VAULTLAB_INVALID_ATTESTATION", "Fixture attestation is invalid");
  }

  assertExactFields(artifact.metadata, METADATA_FIELDS, "Metadata");
  if (
    artifact.metadata.classification !== "SYNTHETIC-NONVALUE" ||
    artifact.metadata.controlSet !== "ENTELE-VAULTLAB-1"
  ) {
    reject("VAULTLAB_NOT_SYNTHETIC", "Fixture classification is invalid");
  }
  if (typeof artifact.metadata.scenario !== "string" || !/^[a-z0-9-]{1,48}$/u.test(artifact.metadata.scenario)) {
    reject("VAULTLAB_INVALID_SCENARIO", "Fixture scenario is invalid");
  }

  return structuredClone(artifact);
}

export function validateCredential(credential) {
  if (Array.isArray(credential)) {
    reject("VAULTLAB_CANDIDATE_LIST_REJECTED", "Password candidate lists are prohibited");
  }
  if (typeof credential !== "string") {
    reject("VAULTLAB_CREDENTIAL_REJECTED", "Exactly one synthetic test credential is required");
  }
  if (credential.length < 12 || credential.length > 128) {
    reject("VAULTLAB_CREDENTIAL_REJECTED", "Synthetic test credential length is outside policy");
  }
  return credential;
}

export function constantTimeTextEqual(left, right) {
  const leftBytes = Buffer.from(left, "utf8");
  const rightBytes = Buffer.from(right, "utf8");
  if (leftBytes.length !== rightBytes.length) return false;
  return timingSafeEqual(leftBytes, rightBytes);
}
