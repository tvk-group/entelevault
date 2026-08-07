import assert from "node:assert/strict";
import test from "node:test";
import { createSyntheticFixture, verifySyntheticFixture } from "../src/synthetic-vault.mjs";
import { mutateSyntheticFixture, SAFE_MUTATIONS } from "../src/mutations.mjs";

const CREDENTIAL = "VaultLab-Mutation-Test-Credential-2026";

for (const mutation of SAFE_MUTATIONS) {
  test(`mutation fails closed: ${mutation}`, async () => {
    const fixture = await createSyntheticFixture({ credential: CREDENTIAL });
    const mutated = mutateSyntheticFixture(fixture, mutation);
    await assert.rejects(verifySyntheticFixture(mutated, CREDENTIAL));
  });
}

test("unapproved mutations cannot be requested", async () => {
  const fixture = await createSyntheticFixture({ credential: CREDENTIAL });
  assert.throws(
    () => mutateSyntheticFixture(fixture, "replace-credential"),
    (error) => error.code === "VAULTLAB_MUTATION_REJECTED"
  );
});
