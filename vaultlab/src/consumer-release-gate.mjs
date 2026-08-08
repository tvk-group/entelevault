import { createHash } from "node:crypto";
import { VaultLabError } from "./errors.mjs";
import {
  PLATFORM_POLICY_EXPECTED_CASES,
  validatePlatformPolicyReport
} from "./platform-policy-report.mjs";

export const CONSUMER_RELEASE_MANIFEST_SCHEMA = "enteleclos.consumer-release-manifest.v1";
export const CONSUMER_RELEASE_ATTESTATION_SCHEMA = "enteleclos.consumer-release-attestation.v1";

const ROOT_FIELDS = new Set([
  "schema",
  "applicationId",
  "repository",
  "componentClass",
  "releaseEnvironment",
  "policyRevision",
  "maxReportAgeSeconds",
  "policy",
  "custodyBoundary",
  "cryptographyMigration",
  "requiredChecks"
]);
const POLICY_FIELDS = new Set([
  "failClosed",
  "humanAuthorizationRequired",
  "independentReviewRequired",
  "authorityGranted",
  "criticalFindingsAllowed",
  "highFindingsAllowed"
]);
const CUSTODY_FIELDS = new Set([
  "mode",
  "receivesSecretMaterial",
  "signingAuthority",
  "assetMovementAuthority",
  "custodyActivationAuthority"
]);
const MIGRATION_FIELDS = new Set([
  "inventoryStatus",
  "longLivedDataAssessment",
  "migrationArchitecture",
  "customCryptography",
  "productionMigration",
  "classicalControls"
]);
const COMPONENT_CLASSES = new Set(["wallet-client", "exchange-frontend"]);
const CUSTODY_MODES = Object.freeze({
  "wallet-client": "external-non-custodial",
  "exchange-frontend": "disabled"
});

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function reject(code, message) {
  throw new VaultLabError(code, message);
}

function assertExactFields(value, allowed, label) {
  if (!isRecord(value)) reject("CONSUMER_GATE_INVALID", `${label} must be an object`);
  if (Object.keys(value).length !== allowed.size) {
    reject("CONSUMER_GATE_FIELDS_REJECTED", `${label} field set is incomplete or unknown`);
  }
  for (const field of Object.keys(value)) {
    if (!allowed.has(field)) {
      reject("CONSUMER_GATE_FIELDS_REJECTED", `${label} has an unknown field`);
    }
  }
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value)
      .sort()
      .map((field) => `${JSON.stringify(field)}:${canonicalJson(value[field])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function digest(value) {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

function assertConstant(value, expected, code, message) {
  if (value !== expected) reject(code, message);
}

export function validateConsumerReleaseManifest(input) {
  assertExactFields(input, ROOT_FIELDS, "Consumer release manifest");
  assertConstant(
    input.schema,
    CONSUMER_RELEASE_MANIFEST_SCHEMA,
    "CONSUMER_GATE_SCHEMA_REJECTED",
    "Consumer release manifest schema is unsupported"
  );
  if (typeof input.applicationId !== "string" || !/^[a-z][a-z0-9-]{2,63}$/u.test(input.applicationId)) {
    reject("CONSUMER_GATE_APPLICATION_REJECTED", "Consumer application identifier is invalid");
  }
  if (typeof input.repository !== "string" || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(input.repository)) {
    reject("CONSUMER_GATE_REPOSITORY_REJECTED", "Consumer repository is invalid");
  }
  if (!COMPONENT_CLASSES.has(input.componentClass)) {
    reject("CONSUMER_GATE_COMPONENT_REJECTED", "Consumer component class is unsupported");
  }
  assertConstant(
    input.releaseEnvironment,
    "production-review",
    "CONSUMER_GATE_ENVIRONMENT_REJECTED",
    "Consumer release environment is unsupported"
  );
  if (typeof input.policyRevision !== "string" || !/^[0-9a-f]{40}$/u.test(input.policyRevision)) {
    reject("CONSUMER_GATE_POLICY_REVISION_REJECTED", "Consumer policy revision is invalid");
  }
  if (!Number.isSafeInteger(input.maxReportAgeSeconds) || input.maxReportAgeSeconds < 60 || input.maxReportAgeSeconds > 3600) {
    reject("CONSUMER_GATE_FRESHNESS_REJECTED", "Consumer report freshness policy is invalid");
  }

  assertExactFields(input.policy, POLICY_FIELDS, "Consumer release policy");
  for (const field of ["failClosed", "humanAuthorizationRequired", "independentReviewRequired"]) {
    assertConstant(input.policy[field], true, "CONSUMER_GATE_POLICY_REJECTED", "Consumer release policy is not fail closed");
  }
  assertConstant(
    input.policy.authorityGranted,
    false,
    "CONSUMER_GATE_AUTHORITY_REJECTED",
    "Consumer release policy cannot grant authority"
  );
  for (const field of ["criticalFindingsAllowed", "highFindingsAllowed"]) {
    assertConstant(input.policy[field], 0, "CONSUMER_GATE_FINDINGS_REJECTED", "Consumer release policy permits blocking findings");
  }

  assertExactFields(input.custodyBoundary, CUSTODY_FIELDS, "Consumer custody boundary");
  assertConstant(
    input.custodyBoundary.mode,
    CUSTODY_MODES[input.componentClass],
    "CONSUMER_GATE_CUSTODY_REJECTED",
    "Consumer custody mode is unsupported for the component"
  );
  for (const field of [
    "receivesSecretMaterial",
    "signingAuthority",
    "assetMovementAuthority",
    "custodyActivationAuthority"
  ]) {
    assertConstant(
      input.custodyBoundary[field],
      false,
      "CONSUMER_GATE_CUSTODY_REJECTED",
      "Consumer release gate cannot receive custody material or authority"
    );
  }

  assertExactFields(input.cryptographyMigration, MIGRATION_FIELDS, "Consumer cryptography-migration policy");
  const migrationConstants = Object.freeze({
    inventoryStatus: "complete",
    longLivedDataAssessment: "required",
    migrationArchitecture: "independent-review-required",
    customCryptography: "prohibited",
    productionMigration: "separately-authorized",
    classicalControls: "required"
  });
  for (const [field, expected] of Object.entries(migrationConstants)) {
    assertConstant(
      input.cryptographyMigration[field],
      expected,
      "CONSUMER_GATE_CRYPTO_MIGRATION_REJECTED",
      "Consumer cryptography-migration policy is incomplete"
    );
  }

  const expectedChecks = Object.keys(PLATFORM_POLICY_EXPECTED_CASES);
  if (!Array.isArray(input.requiredChecks) || input.requiredChecks.length !== expectedChecks.length) {
    reject("CONSUMER_GATE_CHECKS_REJECTED", "Consumer required-check set is incomplete");
  }
  if (
    new Set(input.requiredChecks).size !== expectedChecks.length ||
    expectedChecks.some((check) => !input.requiredChecks.includes(check))
  ) {
    reject("CONSUMER_GATE_CHECKS_REJECTED", "Consumer required-check set does not match policy");
  }
  return structuredClone(input);
}

export function evaluateConsumerReleaseGate(
  { manifest, report },
  { repository, sourceRevision, policyRevision, observedAt = new Date().toISOString() } = {}
) {
  const validatedManifest = validateConsumerReleaseManifest(manifest);
  const validatedReport = validatePlatformPolicyReport(report);
  if (typeof repository !== "string" || repository !== validatedManifest.repository) {
    reject("CONSUMER_GATE_REPOSITORY_MISMATCH", "Observed repository does not match the manifest");
  }
  if (typeof sourceRevision !== "string" || !/^[0-9a-f]{40}$/u.test(sourceRevision)) {
    reject("CONSUMER_GATE_SOURCE_REVISION_REJECTED", "Observed source revision is invalid");
  }
  if (typeof policyRevision !== "string" || policyRevision !== validatedManifest.policyRevision) {
    reject("CONSUMER_GATE_POLICY_REVISION_MISMATCH", "Observed policy revision does not match the manifest");
  }
  const observedTimestamp = Date.parse(observedAt);
  if (typeof observedAt !== "string" || Number.isNaN(observedTimestamp)) {
    reject("CONSUMER_GATE_TIME_REJECTED", "Consumer gate observation time is invalid");
  }
  const reportTimestamp = Date.parse(validatedReport.generatedAt);
  const ageSeconds = (observedTimestamp - reportTimestamp) / 1000;
  if (ageSeconds < -30 || ageSeconds > validatedManifest.maxReportAgeSeconds) {
    reject("CONSUMER_GATE_REPORT_STALE", "Platform policy report is outside the freshness window");
  }
  const reportIds = new Set(validatedReport.checks.map((check) => check.id));
  if (validatedManifest.requiredChecks.some((check) => !reportIds.has(check))) {
    reject("CONSUMER_GATE_CHECKS_REJECTED", "Platform report is missing a consumer-required check");
  }

  return {
    schema: CONSUMER_RELEASE_ATTESTATION_SCHEMA,
    status: "PASS",
    releaseDisposition: "ELIGIBLE_FOR_HUMAN_RELEASE_REVIEW",
    applicationId: validatedManifest.applicationId,
    repository: validatedManifest.repository,
    sourceRevision,
    policyRevision,
    evaluatedAt: observedAt,
    platformReportSchema: validatedReport.schema,
    platformChecks: validatedReport.summary.total,
    platformReportDigest: digest(validatedReport),
    manifestDigest: digest(validatedManifest),
    cryptographyMigrationStatus: "GOVERNANCE_PRESENT_NO_QUANTUM_SAFETY_CLAIM",
    humanAuthorizationRequired: true,
    independentReviewRequired: true,
    authorityGranted: false,
    deploymentAuthorized: false,
    custodyActivationAuthorized: false,
    signingAuthorized: false,
    assetMovementAuthorized: false
  };
}
