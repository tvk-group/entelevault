import assert from "node:assert/strict";
import test from "node:test";
import { runPlatformPolicyAssurance } from "../src/platform-policy-assurance.mjs";

test("platform policy assurance emits publishable, authority-free evidence", () => {
  const report = runPlatformPolicyAssurance({ generatedAt: "2026-08-07T00:00:00.000Z" });
  assert.equal(report.result, "PASS");
  assert.equal(report.scope, "sanitized-metadata-only");
  assert.equal(report.authorityGranted, false);
  assert.equal(report.schema, "enteleclos.platform-policy-assurance.v11");
  assert.deepEqual(report.summary, { passed: 26, failed: 0, total: 26 });
  assert.equal(
    report.checks.find((check) => check.id === "VL-PLATFORM-ASSURANCE-SIGNER-GATEWAY")
      .evaluatedCases,
    21
  );
  assert.equal(report.checks.find((check) => check.id === "VL-PLATFORM-CUSTODY").evaluatedCases, 4096);
  assert.equal(
    report.checks.find((check) => check.id === "VL-PLATFORM-PROVENANCE").evaluatedCases,
    16384
  );
  assert.equal(
    report.checks.find((check) => check.id === "VL-PLATFORM-LEDGER").evaluatedCases,
    16384
  );
  assert.equal(
    report.checks.find((check) => check.id === "VL-PLATFORM-RESILIENCE").evaluatedCases,
    16384
  );
  assert.equal(
    report.checks.find((check) => check.id === "VL-PLATFORM-SECRET-LEAKAGE").evaluatedCases,
    4096
  );
  assert.equal(
    report.checks.find((check) => check.id === "VL-PLATFORM-AUDIT-INTEGRITY").evaluatedCases,
    16384
  );
  for (const id of ["VL-PLATFORM-CLIENT-INTEGRITY", "VL-PLATFORM-MARKET-DATA", "VL-PLATFORM-AVAILABILITY", "VL-PLATFORM-VULNERABILITY-REMEDIATION", "VL-PLATFORM-EXTERNAL-ASSESSMENT", "VL-PLATFORM-PRIVACY-MINIMIZATION", "VL-PLATFORM-CRYPTOGRAPHY-REVIEW", "VL-PLATFORM-SECURITY-DISCLOSURE", "VL-PLATFORM-THIRD-PARTY-RISK"]) {
    assert.equal(report.checks.find((check) => check.id === id).evaluatedCases, 16384);
  }
  assert.deepEqual(
    Object.keys(report).sort(),
    ["authorityGranted", "checks", "generatedAt", "result", "schema", "scope", "summary"]
  );
});
