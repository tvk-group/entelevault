import { VaultLabError } from "./errors.mjs";

export const PLATFORM_POLICY_REPORT_SCHEMA = "enteleclos.platform-policy-assurance.v3";

export const PLATFORM_POLICY_EXPECTED_CASES = Object.freeze({
  "VL-PLATFORM-SIGNING": 5,
  "VL-PLATFORM-RECOVERY": 4,
  "VL-PLATFORM-CUSTODY": 4096,
  "VL-PLATFORM-WITHDRAWAL": 5,
  "VL-PLATFORM-PROVENANCE": 16384,
  "VL-PLATFORM-INCIDENT": 4,
  "VL-PLATFORM-PRIVILEGED": 5,
  "VL-PLATFORM-LEDGER": 16384,
  "VL-PLATFORM-BREAK-GLASS": 4
});

const ROOT_FIELDS = new Set([
  "schema",
  "generatedAt",
  "scope",
  "result",
  "authorityGranted",
  "summary",
  "checks"
]);
const SUMMARY_FIELDS = new Set(["passed", "failed", "total"]);
const CHECK_FIELDS = new Set(["id", "status", "evaluatedCases"]);

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function reject(code, message) {
  throw new VaultLabError(code, message);
}

function assertExactFields(value, allowed, label) {
  if (!isRecord(value)) reject("PLATFORM_REPORT_INVALID", `${label} must be an object`);
  if (Object.keys(value).length !== allowed.size) {
    reject("PLATFORM_REPORT_FIELDS_REJECTED", `${label} field set is incomplete or unknown`);
  }
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) reject("PLATFORM_REPORT_FIELDS_REJECTED", `${label} has an unknown field`);
  }
}

export function validatePlatformPolicyReport(input, { requirePass = true } = {}) {
  assertExactFields(input, ROOT_FIELDS, "Platform policy report");
  if (input.schema !== PLATFORM_POLICY_REPORT_SCHEMA) {
    reject("PLATFORM_REPORT_SCHEMA_REJECTED", "Platform policy report schema is unsupported");
  }
  if (typeof input.generatedAt !== "string" || Number.isNaN(Date.parse(input.generatedAt))) {
    reject("PLATFORM_REPORT_TIME_REJECTED", "Platform policy report time is invalid");
  }
  if (input.scope !== "sanitized-metadata-only") {
    reject("PLATFORM_REPORT_SCOPE_REJECTED", "Platform policy report scope is unsupported");
  }
  if (!new Set(["PASS", "FAIL"]).has(input.result)) {
    reject("PLATFORM_REPORT_RESULT_REJECTED", "Platform policy report result is unsupported");
  }
  if (input.authorityGranted !== false) {
    reject("PLATFORM_REPORT_AUTHORITY_REJECTED", "Platform policy report cannot grant authority");
  }

  assertExactFields(input.summary, SUMMARY_FIELDS, "Platform policy report summary");
  for (const field of SUMMARY_FIELDS) {
    if (!Number.isSafeInteger(input.summary[field]) || input.summary[field] < 0) {
      reject("PLATFORM_REPORT_SUMMARY_REJECTED", "Platform policy report summary is invalid");
    }
  }
  const expectedIds = Object.keys(PLATFORM_POLICY_EXPECTED_CASES);
  if (!Array.isArray(input.checks) || input.checks.length !== expectedIds.length) {
    reject("PLATFORM_REPORT_CHECK_REJECTED", "Platform policy report check set is incomplete");
  }
  for (const check of input.checks) {
    assertExactFields(check, CHECK_FIELDS, "Platform policy report check");
    if (!(check.id in PLATFORM_POLICY_EXPECTED_CASES)) {
      reject("PLATFORM_REPORT_CHECK_REJECTED", "Platform policy report check identifier is unsupported");
    }
    if (!new Set(["PASS", "FAIL"]).has(check.status)) {
      reject("PLATFORM_REPORT_CHECK_REJECTED", "Platform policy report check status is unsupported");
    }
    if (check.evaluatedCases !== PLATFORM_POLICY_EXPECTED_CASES[check.id]) {
      reject("PLATFORM_REPORT_CASE_COUNT_REJECTED", "Platform policy report case count is invalid");
    }
  }
  if (new Set(input.checks.map((check) => check.id)).size !== expectedIds.length) {
    reject("PLATFORM_REPORT_CHECK_REJECTED", "Platform policy report checks must be unique");
  }
  const passed = input.checks.filter((check) => check.status === "PASS").length;
  const failed = input.checks.length - passed;
  if (
    input.summary.passed !== passed ||
    input.summary.failed !== failed ||
    input.summary.total !== input.checks.length ||
    input.result !== (failed === 0 ? "PASS" : "FAIL")
  ) {
    reject("PLATFORM_REPORT_SUMMARY_REJECTED", "Platform policy report summary is inconsistent");
  }
  if (requirePass && input.result !== "PASS") {
    reject("PLATFORM_REPORT_FAILED", "Platform policy assurance did not pass");
  }
  return structuredClone(input);
}
