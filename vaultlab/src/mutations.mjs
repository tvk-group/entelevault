import { parseSyntheticArtifact } from "./policy.mjs";
import { VaultLabError } from "./errors.mjs";

export const SAFE_MUTATIONS = Object.freeze([
  "truncate-ciphertext",
  "flip-auth-tag",
  "downgrade-kdf",
  "oversized-metadata",
  "unknown-field"
]);

function flipFirstByte(base64url) {
  const bytes = Buffer.from(base64url, "base64url");
  bytes[0] ^= 0x01;
  return bytes.toString("base64url");
}

export function mutateSyntheticFixture(input, mutation) {
  if (!SAFE_MUTATIONS.includes(mutation)) {
    throw new VaultLabError("VAULTLAB_MUTATION_REJECTED", "Mutation is not permitted");
  }

  const artifact = parseSyntheticArtifact(input);
  const mutated = structuredClone(artifact);

  switch (mutation) {
    case "truncate-ciphertext": {
      const bytes = Buffer.from(mutated.cipher.ciphertext, "base64url");
      mutated.cipher.ciphertext = bytes.subarray(0, Math.max(1, bytes.length - 8)).toString("base64url");
      break;
    }
    case "flip-auth-tag":
      mutated.cipher.tag = flipFirstByte(mutated.cipher.tag);
      break;
    case "downgrade-kdf":
      mutated.kdf.params.N = 1024;
      break;
    case "oversized-metadata":
      mutated.metadata.scenario = "x".repeat(512);
      break;
    case "unknown-field":
      mutated.importPath = "rejected-by-design";
      break;
  }

  return mutated;
}
