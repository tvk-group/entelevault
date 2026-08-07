import { createHash } from "node:crypto";
import { VaultLabError } from "./errors.mjs";

export const AUDIT_INTEGRITY_SCHEMA = "enteleclos.audit-integrity-readiness.v1";
export const AUDIT_INTEGRITY_DECISION_SCHEMA = "enteleclos.audit-integrity-decision.v1";

export const REQUIRED_AUDIT_INTEGRITY_CONTROLS = Object.freeze([
  "appendOnlyStorageVerified",
  "hashChainVerified",
  "sequenceContinuityVerified",
  "trustedTimestampVerified",
  "clockDriftWithinPolicy",
  "writerIdentityAttested",
  "leastPrivilegeWriteAccessVerified",
  "readAccessMonitoringVerified",
  "retentionLockVerified",
  "independentReplicationVerified",
  "exportIntegrityVerified",
  "schemaVersionPinned",
  "tamperAlertRehearsed",
  "independentReviewComplete"
]);

const ROOT_FIELDS = new Set([
  "schema",
  "assessmentId",
  "assessedAt",
  "environment",
  "systemClass",
  "streamClass",
  "policyRevision",
  "streamDigest",
  "anchorDigest",
  "controls",
  "findings",
  "evidenceDigest"
]);
const CONTROL_FIELDS = new Set(REQUIRED_AUDIT_INTEGRITY_CONTROLS);
const FINDING_FIELDS = new Set([
  "criticalOpen",
  "highOpen",
  "sequenceGaps",
  "duplicateEvents",
  "integrityMismatches"
]);
const ENVIRONMENTS = new Set(["staging", "production-observation"]);
const SYSTEM_CLASSES = new Set(["wallet", "exchange", "custody", "vault", "identity", "infrastructure"]);
const STREAM_CLASSES = new Set([
  "security-events",
  "custody-events",
  "ledger-events",
  "access-events",
  "release-events",
  "incident-events"
]);
const CONTROL_REASON_CODES = Object.freeze({
  appendOnlyStorageVerified: "APPEND_ONLY_STORAGE_UNVERIFIED",
  hashChainVerified: "HASH_CHAIN_UNVERIFIED",
  sequenceContinuityVerified: "SEQUENCE_CONTINUITY_UNVERIFIED",
  trustedTimestampVerified: "TRUSTED_TIMESTAMP_UNVERIFIED",
  clockDriftWithinPolicy: "CLOCK_DRIFT_OUTSIDE_POLICY",
  writerIdentityAttested: "WRITER_IDENTITY_UNATTESTED",
  leastPrivilegeWriteAccessVerified: "LEAST_PRIVILEGE_WRITE_ACCESS_UNVERIFIED",
  readAccessMonitoringVerified: "READ_ACCESS_MONITORING_UNVERIFIED",
  retentionLockVerified: "RETENTION_LOCK_UNVERIFIED",
  independentReplicationVerified: "INDEPENDENT_REPLICATION_UNVERIFIED",
  exportIntegrityVerified: "EXPORT_INTEGRITY_UNVERIFIED",
  schemaVersionPinned: "SCHEMA_VERSION_UNPINNED",
  tamperAlertRehearsed: "TAMPER_ALERT_UNREHEARSED",
  independentReviewComplete: "INDEPENDENT_REVIEW_INCOMPLETE"
});
const FINDING_REASON_CODES = Object.freeze({
  criticalOpen: "CRITICAL_FINDINGS_OPEN",
  highOpen: "HIGH_FINDINGS_OPEN",
  sequenceGaps: "SEQUENCE_GAPS_DETECTED",
  duplicateEvents: "DUPLICATE_EVENTS_DETECTED",
  integrityMismatches: "INTEGRITY_MISMATCHES_DETECTED"
});
const PROHIBITED_FIELD = /(?:address|candidate|command|credential|email|eventContent|eventPayload|executable|key|logContent|mnemonic|password|payload|private|raw(?:Body|Data|Event|Log|Message|Payload|Request|Value)|secret|seed|signatureValue|target|token|transaction|walletData|walletFile)/iu;

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function reject(code, message) {
  throw new VaultLabError(code, message);
}

function assertExactFields(value, allowed, label) {
  if (!isRecord(value)) reject("AUDIT_INTEGRITY_INVALID", `${label} must be an object`);
  for (const key of Object.keys(value)) {
    if (PROHIBITED_FIELD.test(key)) {
      reject("AUDIT_INTEGRITY_PROHIBITED_FIELD", `${label} contains a prohibited field`);
    }
    if (!allowed.has(key)) reject("AUDIT_INTEGRITY_UNKNOWN_FIELD", `${label} has an unknown field`);
  }
  if (Object.keys(value).length !== allowed.size) {
    reject("AUDIT_INTEGRITY_UNKNOWN_FIELD", `${label} field set is incomplete or unknown`);
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

export function validateAuditIntegrityAssessment(input) {
  assertExactFields(input, ROOT_FIELDS, "Audit-integrity assessment");
  if (input.schema !== AUDIT_INTEGRITY_SCHEMA) {
    reject("AUDIT_INTEGRITY_SCHEMA_REJECTED", "Audit-integrity schema is unsupported");
  }
  if (typeof input.assessmentId !== "string" || !/^audit_[0-9a-f]{32}$/u.test(input.assessmentId)) {
    reject("AUDIT_INTEGRITY_ID_REJECTED", "Audit-integrity assessment identifier is invalid");
  }
  if (typeof input.assessedAt !== "string" || Number.isNaN(Date.parse(input.assessedAt))) {
    reject("AUDIT_INTEGRITY_TIME_REJECTED", "Audit-integrity assessment time is invalid");
  }
  if (!ENVIRONMENTS.has(input.environment)) {
    reject("AUDIT_INTEGRITY_ENVIRONMENT_REJECTED", "Audit-integrity environment is unsupported");
  }
  if (!SYSTEM_CLASSES.has(input.systemClass)) {
    reject("AUDIT_INTEGRITY_SYSTEM_REJECTED", "Audit-integrity system class is unsupported");
  }
  if (!STREAM_CLASSES.has(input.streamClass)) {
    reject("AUDIT_INTEGRITY_STREAM_REJECTED", "Audit-integrity stream class is unsupported");
  }
  if (typeof input.policyRevision !== "string" || !/^[0-9a-f]{40}$/u.test(input.policyRevision)) {
    reject("AUDIT_INTEGRITY_REVISION_REJECTED", "Audit-integrity policy revision is invalid");
  }
  for (const field of ["streamDigest", "anchorDigest", "evidenceDigest"]) {
    if (typeof input[field] !== "string" || !/^[0-9a-f]{64}$/u.test(input[field])) {
      reject("AUDIT_INTEGRITY_DIGEST_REJECTED", "Audit-integrity digest is invalid");
    }
  }

  assertExactFields(input.controls, CONTROL_FIELDS, "Audit-integrity controls");
  for (const control of REQUIRED_AUDIT_INTEGRITY_CONTROLS) {
    if (typeof input.controls[control] !== "boolean") {
      reject("AUDIT_INTEGRITY_CONTROL_REJECTED", "Audit-integrity control value is invalid");
    }
  }

  assertExactFields(input.findings, FINDING_FIELDS, "Audit-integrity findings");
  for (const field of FINDING_FIELDS) {
    if (!Number.isSafeInteger(input.findings[field]) || input.findings[field] < 0 || input.findings[field] > 100000) {
      reject("AUDIT_INTEGRITY_FINDING_REJECTED", "Audit-integrity finding count is invalid");
    }
  }
  return structuredClone(input);
}

export function evaluateAuditIntegrity(input) {
  const assessment = validateAuditIntegrityAssessment(input);
  const reasonCodes = REQUIRED_AUDIT_INTEGRITY_CONTROLS
    .filter((control) => !assessment.controls[control])
    .map((control) => CONTROL_REASON_CODES[control]);
  for (const field of FINDING_FIELDS) {
    if (assessment.findings[field] > 0) reasonCodes.push(FINDING_REASON_CODES[field]);
  }
  const digest = createHash("sha256").update(canonicalJson(assessment)).digest("hex");
  return {
    schema: AUDIT_INTEGRITY_DECISION_SCHEMA,
    decisionId: `auditdec_${digest.slice(0, 32)}`,
    assessmentId: assessment.assessmentId,
    readiness: reasonCodes.length === 0 ? "ELIGIBLE_FOR_INDEPENDENT_AUDIT_REVIEW" : "NOT_READY",
    reasonCodes: reasonCodes.sort(),
    evidenceDigest: assessment.evidenceDigest,
    humanAuthorizationRequired: true,
    auditWriteAuthorized: false,
    auditDeleteAuthorized: false,
    logAccessAuthorized: false,
    remediationExecutionAuthorized: false,
    dataMutationAuthorized: false,
    deploymentAuthorized: false,
    signingAuthorized: false,
    assetMovementAuthorized: false
  };
}
