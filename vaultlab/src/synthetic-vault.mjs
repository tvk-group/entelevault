import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  scrypt as scryptCallback
} from "node:crypto";
import { promisify } from "node:util";
import {
  ARTIFACT_PURPOSE,
  ARTIFACT_SCHEMA,
  KDF_POLICY,
  parseSyntheticArtifact,
  validateCredential
} from "./policy.mjs";
import { VaultLabError } from "./errors.mjs";

const scrypt = promisify(scryptCallback);

function aadFor(artifact) {
  return Buffer.from(
    `${artifact.schema}|${artifact.version}|${artifact.purpose}|${artifact.fixtureId}`,
    "utf8"
  );
}

function attestationDigest(artifact) {
  const attested = {
    schema: artifact.schema,
    version: artifact.version,
    purpose: artifact.purpose,
    fixtureId: artifact.fixtureId,
    createdAt: artifact.createdAt,
    kdf: artifact.kdf,
    cipher: artifact.cipher,
    metadata: artifact.metadata
  };
  return createHash("sha256").update(JSON.stringify(attested)).digest("hex");
}

async function deriveKey(credential, kdf) {
  return scrypt(
    credential,
    Buffer.from(kdf.salt, "base64url"),
    kdf.params.keyLength,
    {
      N: kdf.params.N,
      r: kdf.params.r,
      p: kdf.params.p,
      maxmem: kdf.params.maxmem
    }
  );
}

export async function createSyntheticFixture({
  credential,
  scenario = "baseline",
  kdfN = KDF_POLICY.minimumN
} = {}) {
  validateCredential(credential);

  const fixtureId = `vlab_${randomBytes(16).toString("hex")}`;
  const kdf = {
    algorithm: KDF_POLICY.algorithm,
    salt: randomBytes(16).toString("base64url"),
    params: {
      N: kdfN,
      r: KDF_POLICY.requiredR,
      p: 1,
      keyLength: KDF_POLICY.keyLength,
      maxmem: 64 * 1024 * 1024
    }
  };
  const artifact = {
    schema: ARTIFACT_SCHEMA,
    version: 1,
    purpose: ARTIFACT_PURPOSE,
    fixtureId,
    createdAt: new Date().toISOString(),
    kdf,
    cipher: {
      algorithm: "aes-256-gcm",
      iv: randomBytes(12).toString("base64url"),
      tag: "",
      ciphertext: ""
    },
    attestation: {
      generator: "EnteleVAULT VaultLab",
      digest: ""
    },
    metadata: {
      scenario,
      classification: "SYNTHETIC-NONVALUE",
      controlSet: "ENTELE-VAULTLAB-1"
    }
  };

  const specimen = Buffer.from(
    JSON.stringify({
      fixtureId,
      classification: "SYNTHETIC-NONVALUE",
      statement: "Generated test data with no blockchain or monetary authority",
      randomSpecimen: randomBytes(32).toString("base64url")
    }),
    "utf8"
  );
  const key = await deriveKey(credential, kdf);
  try {
    const cipher = createCipheriv("aes-256-gcm", key, Buffer.from(artifact.cipher.iv, "base64url"));
    cipher.setAAD(aadFor(artifact));
    const ciphertext = Buffer.concat([cipher.update(specimen), cipher.final()]);
    artifact.cipher.ciphertext = ciphertext.toString("base64url");
    artifact.cipher.tag = cipher.getAuthTag().toString("base64url");
    artifact.attestation.digest = attestationDigest(artifact);
    return parseSyntheticArtifact(artifact);
  } finally {
    key.fill(0);
    specimen.fill(0);
  }
}

export async function verifySyntheticFixture(input, credential) {
  validateCredential(credential);
  const artifact = parseSyntheticArtifact(input);
  if (attestationDigest(artifact) !== artifact.attestation.digest) {
    throw new VaultLabError("VAULTLAB_ATTESTATION_FAILED", "Fixture integrity check failed");
  }

  const key = await deriveKey(credential, artifact.kdf);
  let plaintext;
  try {
    const decipher = createDecipheriv(
      "aes-256-gcm",
      key,
      Buffer.from(artifact.cipher.iv, "base64url")
    );
    decipher.setAAD(aadFor(artifact));
    decipher.setAuthTag(Buffer.from(artifact.cipher.tag, "base64url"));
    plaintext = Buffer.concat([
      decipher.update(Buffer.from(artifact.cipher.ciphertext, "base64url")),
      decipher.final()
    ]);
  } catch {
    throw new VaultLabError(
      "VAULTLAB_AUTHENTICATION_FAILED",
      "Synthetic fixture authentication failed"
    );
  } finally {
    key.fill(0);
  }

  try {
    const specimen = JSON.parse(plaintext.toString("utf8"));
    if (
      specimen.fixtureId !== artifact.fixtureId ||
      specimen.classification !== "SYNTHETIC-NONVALUE"
    ) {
      throw new VaultLabError("VAULTLAB_SPECIMEN_REJECTED", "Synthetic specimen is invalid");
    }
    return {
      ok: true,
      fixtureId: artifact.fixtureId,
      classification: specimen.classification,
      specimenDigest: createHash("sha256").update(plaintext).digest("hex")
    };
  } catch (error) {
    if (error instanceof VaultLabError) throw error;
    throw new VaultLabError("VAULTLAB_SPECIMEN_REJECTED", "Synthetic specimen is invalid");
  } finally {
    plaintext.fill(0);
  }
}

export function serializeSyntheticFixture(input) {
  return `${JSON.stringify(parseSyntheticArtifact(input), null, 2)}\n`;
}
