import assert from "node:assert/strict";
import test from "node:test";
import { createSyntheticFixture, verifySyntheticFixture } from "../src/synthetic-vault.mjs";
import { parseSyntheticArtifact } from "../src/policy.mjs";

const CREDENTIAL = "VaultLab-Synthetic-Test-Credential-2026";

test("generated fixtures pass the synthetic policy gate", async () => {
  const fixture = await createSyntheticFixture({ credential: CREDENTIAL });
  const parsed = parseSyntheticArtifact(JSON.stringify(fixture));
  assert.equal(parsed.purpose, "security-assurance-only");
  assert.equal(parsed.metadata.classification, "SYNTHETIC-NONVALUE");
});

test("a single known synthetic credential verifies without returning plaintext", async () => {
  const fixture = await createSyntheticFixture({ credential: CREDENTIAL });
  const result = await verifySyntheticFixture(fixture, CREDENTIAL);
  assert.equal(result.ok, true);
  assert.deepEqual(Object.keys(result).sort(), [
    "classification",
    "fixtureId",
    "ok",
    "specimenDigest"
  ]);
  assert.equal(JSON.stringify(result).includes(CREDENTIAL), false);
  assert.equal(JSON.stringify(result).includes("randomSpecimen"), false);
});

test("wrong credentials fail with a stable, redacted error", async () => {
  const fixture = await createSyntheticFixture({ credential: CREDENTIAL });
  await assert.rejects(
    verifySyntheticFixture(fixture, "VaultLab-Definitely-Wrong-Credential-2026"),
    (error) => {
      assert.equal(error.code, "VAULTLAB_AUTHENTICATION_FAILED");
      assert.equal(error.message.includes(CREDENTIAL), false);
      assert.equal("cause" in error, false);
      return true;
    }
  );
});

test("candidate lists and bulk artifacts are rejected", async () => {
  const fixture = await createSyntheticFixture({ credential: CREDENTIAL });
  await assert.rejects(
    verifySyntheticFixture(fixture, [CREDENTIAL, "second-candidate-value"]),
    (error) => error.code === "VAULTLAB_CANDIDATE_LIST_REJECTED"
  );
  assert.throws(
    () => parseSyntheticArtifact([fixture, fixture]),
    (error) => error.code === "VAULTLAB_BULK_INPUT_REJECTED"
  );
});

test("real-wallet-shaped and target-bearing objects are rejected", () => {
  assert.throws(
    () =>
      parseSyntheticArtifact({
        version: 3,
        address: "0x0000000000000000000000000000000000000000",
        crypto: {}
      }),
    (error) => error.code === "VAULTLAB_PROHIBITED_INPUT"
  );
  assert.throws(
    () => parseSyntheticArtifact({ target: "named-person", passwordCandidates: ["one"] }),
    (error) => error.code === "VAULTLAB_PROHIBITED_INPUT"
  );
});

test("unknown fields and KDF downgrades fail closed", async () => {
  const fixture = await createSyntheticFixture({ credential: CREDENTIAL });
  assert.throws(
    () => parseSyntheticArtifact({ ...fixture, importPath: "anything" }),
    (error) => error.code === "VAULTLAB_UNKNOWN_FIELD"
  );
  assert.throws(
    () =>
      parseSyntheticArtifact({
        ...fixture,
        kdf: { ...fixture.kdf, params: { ...fixture.kdf.params, N: 1024 } }
      }),
    (error) => error.code === "VAULTLAB_KDF_REJECTED"
  );
});
