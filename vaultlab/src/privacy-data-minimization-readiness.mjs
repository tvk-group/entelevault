import { createHash } from "node:crypto";
import { VaultLabError } from "./errors.mjs";

export const PRIVACY_DATA_MINIMIZATION_SCHEMA = "enteleclos.privacy-data-minimization-readiness.v1";
export const PRIVACY_DATA_MINIMIZATION_DECISION_SCHEMA = "enteleclos.privacy-data-minimization-decision.v1";

export const REQUIRED_PRIVACY_DATA_MINIMIZATION_CONTROLS = Object.freeze([
  "dataInventoryComplete",
  "purposeLimitationVerified",
  "collectionMinimized",
  "fieldAllowlistVerified",
  "sensitiveDataClassificationVerified",
  "encryptionAtRestVerified",
  "encryptionInTransitVerified",
  "accessLeastPrivilegeVerified",
  "retentionScheduleVerified",
  "deletionWorkflowVerified",
  "backupRetentionAligned",
  "telemetryRedactionVerified",
  "subjectRightsProcessVerified",
  "independentPrivacyReviewComplete"
]);

const ROOT_FIELDS = new Set([
  "schema", "assessmentId", "assessedAt", "environment", "systemClass", "dataClass", "policyRevision",
  "dataFlowDigest", "retentionPolicyDigest", "controls", "findings", "evidenceDigest"
]);
const CONTROL_FIELDS = new Set(REQUIRED_PRIVACY_DATA_MINIMIZATION_CONTROLS);
const FINDING_FIELDS = new Set(["criticalOpen", "highOpen", "excessFields", "retentionBreaches", "deletionVerificationFailures"]);
const ENVIRONMENTS = new Set(["staging", "production-observation"]);
const SYSTEM_CLASSES = new Set(["wallet", "exchange", "vault", "security-platform"]);
const DATA_CLASSES = new Set(["customer-identity", "authentication-telemetry", "transaction-metadata", "security-observability"]);
const CONTROL_REASON_CODES = Object.freeze({
  dataInventoryComplete: "DATA_INVENTORY_INCOMPLETE",
  purposeLimitationVerified: "PURPOSE_LIMITATION_UNVERIFIED",
  collectionMinimized: "COLLECTION_NOT_MINIMIZED",
  fieldAllowlistVerified: "FIELD_ALLOWLIST_UNVERIFIED",
  sensitiveDataClassificationVerified: "SENSITIVE_DATA_CLASSIFICATION_UNVERIFIED",
  encryptionAtRestVerified: "ENCRYPTION_AT_REST_UNVERIFIED",
  encryptionInTransitVerified: "ENCRYPTION_IN_TRANSIT_UNVERIFIED",
  accessLeastPrivilegeVerified: "ACCESS_LEAST_PRIVILEGE_UNVERIFIED",
  retentionScheduleVerified: "RETENTION_SCHEDULE_UNVERIFIED",
  deletionWorkflowVerified: "DELETION_WORKFLOW_UNVERIFIED",
  backupRetentionAligned: "BACKUP_RETENTION_MISALIGNED",
  telemetryRedactionVerified: "TELEMETRY_REDACTION_UNVERIFIED",
  subjectRightsProcessVerified: "SUBJECT_RIGHTS_PROCESS_UNVERIFIED",
  independentPrivacyReviewComplete: "INDEPENDENT_PRIVACY_REVIEW_INCOMPLETE"
});
const FINDING_REASON_CODES = Object.freeze({
  criticalOpen: "CRITICAL_PRIVACY_FINDINGS_OPEN",
  highOpen: "HIGH_PRIVACY_FINDINGS_OPEN",
  excessFields: "EXCESS_FIELDS_DETECTED",
  retentionBreaches: "RETENTION_BREACHES_DETECTED",
  deletionVerificationFailures: "DELETION_VERIFICATION_FAILURES_DETECTED"
});
const PROHIBITED_FIELD = /(?:address|biometric|candidate|command|credential|email|key|mnemonic|name|password|payload|personalData|phone|private|raw(?:Body|Data|Message|Payload|Record|Request|Value)|requestBody|secret|seed|signatureValue|target|token|transaction|url|user|walletData|walletFile)/iu;

function isRecord(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
function reject(code, message) { throw new VaultLabError(code, message); }
function assertExactFields(value, allowed, label) {
  if (!isRecord(value)) reject("PRIVACY_MINIMIZATION_INVALID", `${label} must be an object`);
  for (const key of Object.keys(value)) {
    if (PROHIBITED_FIELD.test(key)) reject("PRIVACY_MINIMIZATION_PROHIBITED_FIELD", `${label} contains a prohibited field`);
    if (!allowed.has(key)) reject("PRIVACY_MINIMIZATION_UNKNOWN_FIELD", `${label} has an unknown field`);
  }
  if (Object.keys(value).length !== allowed.size) reject("PRIVACY_MINIMIZATION_UNKNOWN_FIELD", `${label} field set is incomplete or unknown`);
}
function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (isRecord(value)) return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}

export function validatePrivacyDataMinimization(input) {
  assertExactFields(input, ROOT_FIELDS, "Privacy data-minimization assessment");
  if (input.schema !== PRIVACY_DATA_MINIMIZATION_SCHEMA) reject("PRIVACY_MINIMIZATION_SCHEMA_REJECTED", "Privacy data-minimization schema is unsupported");
  if (typeof input.assessmentId !== "string" || !/^privacy_[0-9a-f]{32}$/u.test(input.assessmentId)) reject("PRIVACY_MINIMIZATION_ID_REJECTED", "Privacy data-minimization identifier is invalid");
  if (typeof input.assessedAt !== "string" || Number.isNaN(Date.parse(input.assessedAt))) reject("PRIVACY_MINIMIZATION_TIME_REJECTED", "Privacy data-minimization time is invalid");
  if (!ENVIRONMENTS.has(input.environment)) reject("PRIVACY_MINIMIZATION_ENVIRONMENT_REJECTED", "Privacy data-minimization environment is unsupported");
  if (!SYSTEM_CLASSES.has(input.systemClass) || !DATA_CLASSES.has(input.dataClass)) reject("PRIVACY_MINIMIZATION_CLASS_REJECTED", "Privacy system or data class is unsupported");
  if (typeof input.policyRevision !== "string" || !/^[0-9a-f]{40}$/u.test(input.policyRevision)) reject("PRIVACY_MINIMIZATION_REVISION_REJECTED", "Privacy policy revision is invalid");
  for (const field of ["dataFlowDigest", "retentionPolicyDigest", "evidenceDigest"]) {
    if (typeof input[field] !== "string" || !/^[0-9a-f]{64}$/u.test(input[field])) reject("PRIVACY_MINIMIZATION_DIGEST_REJECTED", "Privacy data-minimization digest is invalid");
  }
  assertExactFields(input.controls, CONTROL_FIELDS, "Privacy data-minimization controls");
  for (const control of REQUIRED_PRIVACY_DATA_MINIMIZATION_CONTROLS) {
    if (typeof input.controls[control] !== "boolean") reject("PRIVACY_MINIMIZATION_CONTROL_REJECTED", "Privacy data-minimization control value is invalid");
  }
  assertExactFields(input.findings, FINDING_FIELDS, "Privacy data-minimization findings");
  for (const field of FINDING_FIELDS) {
    if (!Number.isSafeInteger(input.findings[field]) || input.findings[field] < 0 || input.findings[field] > 100000) reject("PRIVACY_MINIMIZATION_FINDING_REJECTED", "Privacy data-minimization finding count is invalid");
  }
  return structuredClone(input);
}

export function evaluatePrivacyDataMinimization(input) {
  const assessment = validatePrivacyDataMinimization(input);
  const reasonCodes = REQUIRED_PRIVACY_DATA_MINIMIZATION_CONTROLS.filter((control) => !assessment.controls[control]).map((control) => CONTROL_REASON_CODES[control]);
  for (const field of FINDING_FIELDS) if (assessment.findings[field] > 0) reasonCodes.push(FINDING_REASON_CODES[field]);
  const digest = createHash("sha256").update(canonicalJson(assessment)).digest("hex");
  return {
    schema: PRIVACY_DATA_MINIMIZATION_DECISION_SCHEMA,
    decisionId: `privacydec_${digest.slice(0, 32)}`,
    assessmentId: assessment.assessmentId,
    readiness: reasonCodes.length === 0 ? "ELIGIBLE_FOR_INDEPENDENT_PRIVACY_REVIEW" : "NOT_READY",
    reasonCodes: reasonCodes.sort(),
    evidenceDigest: assessment.evidenceDigest,
    humanAuthorizationRequired: true,
    rawDataAccessAuthorized: false,
    dataDeletionAuthorized: false,
    retentionMutationAuthorized: false,
    accessGrantAuthorized: false,
    remediationExecutionAuthorized: false,
    dataMutationAuthorized: false,
    deploymentAuthorized: false,
    signingAuthorized: false,
    assetMovementAuthorized: false
  };
}
