import assert from "node:assert/strict";
import test from "node:test";
import { runPlatformPolicyAssurance } from "../src/platform-policy-assurance.mjs";
import { validatePlatformPolicyReport } from "../src/platform-policy-report.mjs";

function report() {
  return runPlatformPolicyAssurance({ generatedAt: "2026-08-07T00:00:00.000Z" });
}

test("the complete fifteen-gate platform report validates", () => {
  const validated = validatePlatformPolicyReport(report());
  assert.equal(validated.result, "PASS");
  assert.equal(validated.summary.total, 15);
  assert.equal(validated.authorityGranted, false);
});

test("missing, duplicated, renamed, or miscounted platform gates fail closed", () => {
  const base = report();
  const cases = [];
  const missing = structuredClone(base);
  missing.checks.pop();
  cases.push(missing);
  const duplicate = structuredClone(base);
  duplicate.checks[14] = structuredClone(duplicate.checks[13]);
  cases.push(duplicate);
  const renamed = structuredClone(base);
  renamed.checks[0].id = "VL-PLATFORM-UNKNOWN";
  cases.push(renamed);
  const miscounted = structuredClone(base);
  miscounted.checks[14].evaluatedCases = 1;
  cases.push(miscounted);
  for (const candidate of cases) assert.throws(() => validatePlatformPolicyReport(candidate));
});

test("inconsistent summaries and any authority claim are rejected", () => {
  const base = report();
  const inconsistent = structuredClone(base);
  inconsistent.summary.passed = 14;
  assert.throws(
    () => validatePlatformPolicyReport(inconsistent),
    (error) => error.code === "PLATFORM_REPORT_SUMMARY_REJECTED"
  );
  const authority = structuredClone(base);
  authority.authorityGranted = true;
  assert.throws(
    () => validatePlatformPolicyReport(authority),
    (error) => error.code === "PLATFORM_REPORT_AUTHORITY_REJECTED"
  );
});
