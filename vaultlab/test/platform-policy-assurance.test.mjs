import assert from "node:assert/strict";
import test from "node:test";
import { runPlatformPolicyAssurance } from "../src/platform-policy-assurance.mjs";

test("platform policy assurance emits publishable, authority-free evidence", () => {
  const report = runPlatformPolicyAssurance({ generatedAt: "2026-08-07T00:00:00.000Z" });
  assert.equal(report.result, "PASS");
  assert.equal(report.scope, "sanitized-metadata-only");
  assert.equal(report.authorityGranted, false);
  assert.equal(report.schema, "enteleclos.platform-policy-assurance.v3");
  assert.deepEqual(report.summary, { passed: 9, failed: 0, total: 9 });
  assert.equal(report.checks.find((check) => check.id === "VL-PLATFORM-CUSTODY").evaluatedCases, 4096);
  assert.equal(
    report.checks.find((check) => check.id === "VL-PLATFORM-PROVENANCE").evaluatedCases,
    16384
  );
  assert.equal(
    report.checks.find((check) => check.id === "VL-PLATFORM-LEDGER").evaluatedCases,
    16384
  );
  assert.deepEqual(
    Object.keys(report).sort(),
    ["authorityGranted", "checks", "generatedAt", "result", "schema", "scope", "summary"]
  );
});
