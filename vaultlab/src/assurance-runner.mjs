import { performance } from "node:perf_hooks";
import { createSyntheticFixture, verifySyntheticFixture } from "./synthetic-vault.mjs";
import { mutateSyntheticFixture, SAFE_MUTATIONS } from "./mutations.mjs";
import { parseSyntheticArtifact } from "./policy.mjs";
import { publicError } from "./errors.mjs";

const CONTROL_SET = "ENTELE-VAULTLAB-1";

async function expectClosed(id, operation) {
  try {
    await operation();
    return { id, status: "FAIL", reason: "operation unexpectedly succeeded" };
  } catch (error) {
    const safe = publicError(error);
    return { id, status: "PASS", rejectionCode: safe.code };
  }
}

export async function runAssuranceSuite({ credential } = {}) {
  const started = performance.now();
  const checks = [];
  const fixture = await createSyntheticFixture({ credential });
  const verified = await verifySyntheticFixture(fixture, credential);
  checks.push({
    id: "VL-CRYPTO-001",
    status: verified.ok ? "PASS" : "FAIL",
    statement: "Authenticated encryption round trip succeeds for generated synthetic data"
  });

  checks.push(
    await expectClosed("VL-AUTH-001", () =>
      verifySyntheticFixture(fixture, "VaultLab-Wrong-Synthetic-Credential-0001")
    )
  );

  for (const mutation of SAFE_MUTATIONS) {
    checks.push(
      await expectClosed(`VL-MUTATION-${mutation.toUpperCase()}`, () =>
        verifySyntheticFixture(mutateSyntheticFixture(fixture, mutation), credential)
      )
    );
  }

  checks.push(
    await expectClosed("VL-BOUNDARY-CANDIDATE-LIST", () =>
      verifySyntheticFixture(fixture, [credential, "another-value"])
    )
  );
  checks.push(
    await expectClosed("VL-BOUNDARY-REAL-WALLET-SHAPE", () =>
      parseSyntheticArtifact({
        version: 3,
        address: "0x0000000000000000000000000000000000000000",
        crypto: {}
      })
    )
  );

  const passed = checks.filter((check) => check.status === "PASS").length;
  const report = {
    schema: "entelevault.vaultlab.assurance-report.v1",
    controlSet: CONTROL_SET,
    generatedAt: new Date().toISOString(),
    scope: "synthetic-only",
    fixtureId: fixture.fixtureId,
    result: passed === checks.length ? "PASS" : "FAIL",
    summary: { passed, failed: checks.length - passed, total: checks.length },
    durationMs: Number((performance.now() - started).toFixed(2)),
    checks
  };

  const serialized = JSON.stringify(report);
  if (serialized.includes(credential)) {
    throw new Error("Assurance report secret-leakage control failed");
  }
  return report;
}
