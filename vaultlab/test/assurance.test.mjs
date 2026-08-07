import assert from "node:assert/strict";
import test from "node:test";
import { runAssuranceSuite } from "../src/assurance-runner.mjs";

test("the complete assurance suite passes and emits no credential", async () => {
  const credential = "VaultLab-Assurance-Test-Credential-2026";
  const report = await runAssuranceSuite({ credential });
  assert.equal(report.result, "PASS");
  assert.equal(report.scope, "synthetic-only");
  assert.equal(report.summary.failed, 0);
  assert.equal(report.summary.total >= 9, true);
  assert.equal(JSON.stringify(report).includes(credential), false);
});
