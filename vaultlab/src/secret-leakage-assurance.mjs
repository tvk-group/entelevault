import { createHash } from "node:crypto";
import { VaultLabError } from "./errors.mjs";

export const SECRET_LEAKAGE_SCHEMA = "enteleclos.secret-leakage-assurance.v1";
export const SECRET_LEAKAGE_DECISION_SCHEMA = "enteleclos.secret-leakage-decision.v1";

export const REQUIRED_SECRET_LEAKAGE_CONTROLS = Object.freeze([
  "structuredLogScanPassed",
  "traceScanPassed",
  "crashReportScanPassed",
  "buildArtifactScanPassed",
  "supportExportScanPassed",
  "clientTelemetryScanPassed",
  "highEntropyDetectionEnabled",
  "secretPatternDetectionEnabled",
  "redactionVerificationPassed",
  "canaryDetectionPassed",
  "scannerRulesetPinned",
  "independentReviewComplete"
]);

const ROOT_FIELDS = new Set([
  "schema",
  "assessmentId",
  "assessedAt",
  "environment",
  "component",
  "scanClass",
  "policyRevision",
  "rulesetDigest",
  "controls",
  "findings",
  "evidenceDigest"
]);
const CONTROL_FIELDS = new Set(REQUIRED_SECRET_LEAKAGE_CONTROLS);
const FINDING_FIELDS = new Set([
  "credentialClassHits",
  "tokenClassHits",
  "keyMaterialClassHits",
  "walletMaterialClassHits",
  "unclassifiedEntropyHits"
]);
const ENVIRONMENTS = new Set(["ci", "staging", "production-observation"]);
const COMPONENTS = new Set([
  "enteleclos-assurance",
  "enteleexchange-api",
  "enteleexchange-web",
  "entelevault-service",
  "entelewallet-client"
]);
const SCAN_CLASSES = new Set([
  "release",
  "runtime-telemetry",
  "support-export",
  "incident-evidence"
]);
const CONTROL_REASON_CODES = Object.freeze({
  structuredLogScanPassed: "STRUCTURED_LOG_SCAN_FAILED",
  traceScanPassed: "TRACE_SCAN_FAILED",
  crashReportScanPassed: "CRASH_REPORT_SCAN_FAILED",
  buildArtifactScanPassed: "BUILD_ARTIFACT_SCAN_FAILED",
  supportExportScanPassed: "SUPPORT_EXPORT_SCAN_FAILED",
  clientTelemetryScanPassed: "CLIENT_TELEMETRY_SCAN_FAILED",
  highEntropyDetectionEnabled: "HIGH_ENTROPY_DETECTION_DISABLED",
  secretPatternDetectionEnabled: "SECRET_PATTERN_DETECTION_DISABLED",
  redactionVerificationPassed: "REDACTION_VERIFICATION_FAILED",
  canaryDetectionPassed: "CANARY_DETECTION_FAILED",
  scannerRulesetPinned: "SCANNER_RULESET_UNPINNED",
  independentReviewComplete: "INDEPENDENT_REVIEW_INCOMPLETE"
});
const FINDING_REASON_CODES = Object.freeze({
  credentialClassHits: "CREDENTIAL_CLASS_FINDINGS",
  tokenClassHits: "TOKEN_CLASS_FINDINGS",
  keyMaterialClassHits: "KEY_MATERIAL_CLASS_FINDINGS",
  walletMaterialClassHits: "WALLET_MATERIAL_CLASS_FINDINGS",
  unclassifiedEntropyHits: "UNCLASSIFIED_ENTROPY_FINDINGS"
});
const PROHIBITED_FIELD = /(?:address|candidate|command|credentialValue|crashContent|email|executable|keyValue|logContent|mnemonic|password|payload|privateKey|raw(?:Body|Data|Log|Message|Payload|Request|Trace|Value)|secretValue|seed|signatureValue|target|tokenValue|traceContent|transaction|walletData|walletFile)/iu;

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function reject(code, message) {
  throw new VaultLabError(code, message);
}

function assertExactFields(value, allowed, label) {
  if (!isRecord(value)) reject("SECRET_LEAKAGE_INVALID", `${label} must be an object`);
  for (const key of Object.keys(value)) {
    if (PROHIBITED_FIELD.test(key)) {
      reject("SECRET_LEAKAGE_PROHIBITED_FIELD", `${label} contains a prohibited field`);
    }
    if (!allowed.has(key)) reject("SECRET_LEAKAGE_UNKNOWN_FIELD", `${label} has an unknown field`);
  }
  if (Object.keys(value).length !== allowed.size) {
    reject("SECRET_LEAKAGE_UNKNOWN_FIELD", `${label} field set is incomplete or unknown`);
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

export function validateSecretLeakageAssessment(input) {
  assertExactFields(input, ROOT_FIELDS, "Secret-leakage assessment");
  if (input.schema !== SECRET_LEAKAGE_SCHEMA) {
    reject("SECRET_LEAKAGE_SCHEMA_REJECTED", "Secret-leakage schema is unsupported");
  }
  if (typeof input.assessmentId !== "string" || !/^leak_[0-9a-f]{32}$/u.test(input.assessmentId)) {
    reject("SECRET_LEAKAGE_ID_REJECTED", "Secret-leakage assessment identifier is invalid");
  }
  if (typeof input.assessedAt !== "string" || Number.isNaN(Date.parse(input.assessedAt))) {
    reject("SECRET_LEAKAGE_TIME_REJECTED", "Secret-leakage assessment time is invalid");
  }
  if (!ENVIRONMENTS.has(input.environment)) {
    reject("SECRET_LEAKAGE_ENVIRONMENT_REJECTED", "Secret-leakage environment is unsupported");
  }
  if (!COMPONENTS.has(input.component)) {
    reject("SECRET_LEAKAGE_COMPONENT_REJECTED", "Secret-leakage component is unsupported");
  }
  if (!SCAN_CLASSES.has(input.scanClass)) {
    reject("SECRET_LEAKAGE_SCAN_CLASS_REJECTED", "Secret-leakage scan class is unsupported");
  }
  if (typeof input.policyRevision !== "string" || !/^[0-9a-f]{40}$/u.test(input.policyRevision)) {
    reject("SECRET_LEAKAGE_REVISION_REJECTED", "Secret-leakage policy revision is invalid");
  }
  for (const field of ["rulesetDigest", "evidenceDigest"]) {
    if (typeof input[field] !== "string" || !/^[0-9a-f]{64}$/u.test(input[field])) {
      reject("SECRET_LEAKAGE_DIGEST_REJECTED", "Secret-leakage digest is invalid");
    }
  }

  assertExactFields(input.controls, CONTROL_FIELDS, "Secret-leakage controls");
  for (const control of REQUIRED_SECRET_LEAKAGE_CONTROLS) {
    if (typeof input.controls[control] !== "boolean") {
      reject("SECRET_LEAKAGE_CONTROL_REJECTED", "Secret-leakage control value is invalid");
    }
  }

  assertExactFields(input.findings, FINDING_FIELDS, "Secret-leakage findings");
  for (const field of FINDING_FIELDS) {
    if (!Number.isSafeInteger(input.findings[field]) || input.findings[field] < 0 || input.findings[field] > 100000) {
      reject("SECRET_LEAKAGE_FINDING_REJECTED", "Secret-leakage finding count is invalid");
    }
  }
  return structuredClone(input);
}

export function evaluateSecretLeakage(input) {
  const assessment = validateSecretLeakageAssessment(input);
  const reasonCodes = REQUIRED_SECRET_LEAKAGE_CONTROLS
    .filter((control) => !assessment.controls[control])
    .map((control) => CONTROL_REASON_CODES[control]);
  for (const field of FINDING_FIELDS) {
    if (assessment.findings[field] > 0) reasonCodes.push(FINDING_REASON_CODES[field]);
  }
  const digest = createHash("sha256").update(canonicalJson(assessment)).digest("hex");
  return {
    schema: SECRET_LEAKAGE_DECISION_SCHEMA,
    decisionId: `leakdec_${digest.slice(0, 32)}`,
    assessmentId: assessment.assessmentId,
    readiness: reasonCodes.length === 0 ? "ELIGIBLE_FOR_INDEPENDENT_LEAKAGE_REVIEW" : "BLOCK_AND_ESCALATE",
    reasonCodes: reasonCodes.sort(),
    evidenceDigest: assessment.evidenceDigest,
    humanAuthorizationRequired: true,
    remediationExecutionAuthorized: false,
    credentialRevocationAuthorized: false,
    artifactDeletionAuthorized: false,
    accessGrantAuthorized: false,
    deploymentAuthorized: false,
    signingAuthorized: false,
    assetMovementAuthorized: false
  };
}
