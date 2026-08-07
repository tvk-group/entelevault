import { createHash } from "node:crypto";
import { VaultLabError } from "./errors.mjs";

export const RELEASE_PROVENANCE_SCHEMA = "enteleclos.release-provenance.v1";
export const RELEASE_DECISION_SCHEMA = "enteleclos.release-provenance-decision.v1";

export const REQUIRED_RELEASE_CONTROLS = Object.freeze([
  "sourceRevisionBound",
  "reproducibleBuildMatched",
  "isolatedEphemeralBuilder",
  "workloadIdentityVerified",
  "artifactSignatureVerified",
  "attestationVerified",
  "sbomPresent",
  "dependencyLockVerified",
  "secretScanPassed",
  "staticAnalysisPassed",
  "dependencyAuditPassed",
  "branchProtectionVerified",
  "requiredReviewsVerified",
  "testEvidenceBound"
]);

const ROOT_FIELDS = new Set([
  "schema",
  "assessmentId",
  "assessedAt",
  "environment",
  "component",
  "sourceRevision",
  "artifactDigest",
  "builderIdentityDigest",
  "workflowDigest",
  "sbomDigest",
  "dependencyLockDigest",
  "controls",
  "findings",
  "evidenceDigest"
]);
const CONTROL_FIELDS = new Set(REQUIRED_RELEASE_CONTROLS);
const FINDING_FIELDS = new Set(["criticalOpen", "highOpen", "mediumOpen"]);
const ENVIRONMENTS = new Set(["ci", "staging"]);
const COMPONENTS = new Set([
  "enteleclos-assurance",
  "enteleexchange-api",
  "enteleexchange-web",
  "entelevault-service",
  "entelewallet-client"
]);
const CONTROL_REASON_CODES = Object.freeze({
  sourceRevisionBound: "SOURCE_REVISION_NOT_BOUND",
  reproducibleBuildMatched: "REPRODUCIBLE_BUILD_MISMATCH",
  isolatedEphemeralBuilder: "BUILDER_ISOLATION_MISSING",
  workloadIdentityVerified: "WORKLOAD_IDENTITY_UNVERIFIED",
  artifactSignatureVerified: "ARTIFACT_SIGNATURE_UNVERIFIED",
  attestationVerified: "ATTESTATION_UNVERIFIED",
  sbomPresent: "SBOM_MISSING",
  dependencyLockVerified: "DEPENDENCY_LOCK_UNVERIFIED",
  secretScanPassed: "SECRET_SCAN_FAILED",
  staticAnalysisPassed: "STATIC_ANALYSIS_FAILED",
  dependencyAuditPassed: "DEPENDENCY_AUDIT_FAILED",
  branchProtectionVerified: "BRANCH_PROTECTION_UNVERIFIED",
  requiredReviewsVerified: "REQUIRED_REVIEWS_MISSING",
  testEvidenceBound: "TEST_EVIDENCE_NOT_BOUND"
});
const PROHIBITED_FIELD = /(?:artifactContent|candidate|command|credential|deploy(?:ment)?Token|executable|key|mnemonic|password|private|rawPayload|seed|secretValue|signatureValue|target|transaction|wallet)/iu;

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function reject(code, message) {
  throw new VaultLabError(code, message);
}

function assertExactFields(value, allowed, label) {
  if (!isRecord(value)) reject("RELEASE_PROVENANCE_INVALID", `${label} must be an object`);
  for (const key of Object.keys(value)) {
    if (PROHIBITED_FIELD.test(key)) {
      reject("RELEASE_PROVENANCE_PROHIBITED_FIELD", `${label} contains a prohibited field`);
    }
    if (!allowed.has(key)) reject("RELEASE_PROVENANCE_UNKNOWN_FIELD", `${label} has an unknown field`);
  }
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

export function validateReleaseProvenance(input) {
  assertExactFields(input, ROOT_FIELDS, "Release provenance assessment");
  if (input.schema !== RELEASE_PROVENANCE_SCHEMA) {
    reject("RELEASE_PROVENANCE_SCHEMA_REJECTED", "Release provenance schema is unsupported");
  }
  if (typeof input.assessmentId !== "string" || !/^release_[0-9a-f]{32}$/u.test(input.assessmentId)) {
    reject("RELEASE_PROVENANCE_ID_REJECTED", "Release assessment identifier is invalid");
  }
  if (typeof input.assessedAt !== "string" || Number.isNaN(Date.parse(input.assessedAt))) {
    reject("RELEASE_PROVENANCE_TIME_REJECTED", "Release assessment time is invalid");
  }
  if (!ENVIRONMENTS.has(input.environment)) {
    reject("RELEASE_PROVENANCE_ENVIRONMENT_REJECTED", "Release assessment must run in CI or staging");
  }
  if (!COMPONENTS.has(input.component)) {
    reject("RELEASE_PROVENANCE_COMPONENT_REJECTED", "Release component is unsupported");
  }
  if (typeof input.sourceRevision !== "string" || !/^[0-9a-f]{40}$/u.test(input.sourceRevision)) {
    reject("RELEASE_PROVENANCE_REVISION_REJECTED", "Release source revision is invalid");
  }
  for (const field of [
    "artifactDigest",
    "builderIdentityDigest",
    "workflowDigest",
    "sbomDigest",
    "dependencyLockDigest",
    "evidenceDigest"
  ]) {
    if (typeof input[field] !== "string" || !/^[0-9a-f]{64}$/u.test(input[field])) {
      reject("RELEASE_PROVENANCE_DIGEST_REJECTED", "Release evidence digest is invalid");
    }
  }

  assertExactFields(input.controls, CONTROL_FIELDS, "Release controls");
  if (Object.keys(input.controls).length !== REQUIRED_RELEASE_CONTROLS.length) {
    reject("RELEASE_PROVENANCE_CONTROL_REJECTED", "Release control set is incomplete");
  }
  for (const control of REQUIRED_RELEASE_CONTROLS) {
    if (typeof input.controls[control] !== "boolean") {
      reject("RELEASE_PROVENANCE_CONTROL_REJECTED", "Release control value is invalid");
    }
  }

  assertExactFields(input.findings, FINDING_FIELDS, "Release findings");
  for (const field of FINDING_FIELDS) {
    if (
      !Number.isSafeInteger(input.findings[field]) ||
      input.findings[field] < 0 ||
      input.findings[field] > 1000
    ) {
      reject("RELEASE_PROVENANCE_FINDING_REJECTED", "Release finding count is invalid");
    }
  }
  return structuredClone(input);
}

export function evaluateReleaseProvenance(input) {
  const assessment = validateReleaseProvenance(input);
  const reasonCodes = REQUIRED_RELEASE_CONTROLS
    .filter((control) => !assessment.controls[control])
    .map((control) => CONTROL_REASON_CODES[control]);
  if (assessment.findings.criticalOpen > 0) reasonCodes.push("CRITICAL_FINDINGS_OPEN");
  if (assessment.findings.highOpen > 0) reasonCodes.push("HIGH_FINDINGS_OPEN");
  if (assessment.findings.mediumOpen > 0) reasonCodes.push("MEDIUM_FINDINGS_OPEN");

  const digest = createHash("sha256").update(canonicalJson(assessment)).digest("hex");
  return {
    schema: RELEASE_DECISION_SCHEMA,
    decisionId: `reldec_${digest.slice(0, 32)}`,
    assessmentId: assessment.assessmentId,
    readiness:
      reasonCodes.length === 0 ? "ELIGIBLE_FOR_INDEPENDENT_PROMOTION_REVIEW" : "NOT_READY",
    reasonCodes: reasonCodes.sort(),
    evidenceDigest: assessment.evidenceDigest,
    humanAuthorizationRequired: true,
    deploymentAuthorized: false,
    signingAuthorized: false,
    custodyActivationAuthorized: false,
    assetMovementAuthorized: false
  };
}
