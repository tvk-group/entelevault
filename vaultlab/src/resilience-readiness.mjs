import { createHash } from "node:crypto";
import { VaultLabError } from "./errors.mjs";

export const RESILIENCE_READINESS_SCHEMA = "enteleclos.resilience-readiness.v1";
export const RESILIENCE_DECISION_SCHEMA = "enteleclos.resilience-readiness-decision.v1";

export const REQUIRED_RESILIENCE_CONTROLS = Object.freeze([
  "recoveryObjectivesApproved",
  "backupEncryptionVerified",
  "backupImmutabilityVerified",
  "geographicSeparationVerified",
  "leastPrivilegeRestoreAccessVerified",
  "ransomwareIsolationVerified",
  "backupIntegrityVerified",
  "restoreRehearsalPassed",
  "dependencyRestoreOrderTested",
  "queueReplayAndIdempotencyTested",
  "ledgerReconciliationPassed",
  "failoverAndFailbackTested",
  "monitoringAndAlertingTested",
  "independentReviewApproved"
]);

const ROOT_FIELDS = new Set([
  "schema",
  "assessmentId",
  "assessedAt",
  "environment",
  "scope",
  "evidence",
  "controls",
  "findings",
  "evidenceDigest"
]);
const SCOPE_FIELDS = new Set(["systemClass", "recoveryTier", "exerciseClass", "dataClass"]);
const EVIDENCE_FIELDS = new Set([
  "planDigest",
  "backupPolicyDigest",
  "restoreEvidenceDigest",
  "dependencyMapDigest",
  "reconciliationDigest",
  "exerciseRevision",
  "recoveryPointClass",
  "recoveryTimeClass"
]);
const CONTROL_FIELDS = new Set(REQUIRED_RESILIENCE_CONTROLS);
const FINDING_FIELDS = new Set(["criticalOpen", "highOpen", "mediumOpen", "unreconciledItems"]);
const SYSTEM_CLASSES = new Set(["wallet", "exchange", "vault", "custody", "identity", "infrastructure"]);
const RECOVERY_TIERS = new Set(["tier-0", "tier-1", "tier-2"]);
const EXERCISE_CLASSES = new Set(["tabletop", "isolated-restore", "failover-rehearsal"]);
const DATA_CLASSES = new Set(["encrypted-state", "ledger-state", "configuration", "metadata"]);
const OBJECTIVE_CLASSES = new Set(["within-objective", "outside-objective", "unknown"]);
const CONTROL_REASON_CODES = Object.freeze({
  recoveryObjectivesApproved: "RECOVERY_OBJECTIVES_UNAPPROVED",
  backupEncryptionVerified: "BACKUP_ENCRYPTION_UNVERIFIED",
  backupImmutabilityVerified: "BACKUP_IMMUTABILITY_UNVERIFIED",
  geographicSeparationVerified: "GEOGRAPHIC_SEPARATION_UNVERIFIED",
  leastPrivilegeRestoreAccessVerified: "RESTORE_ACCESS_LEAST_PRIVILEGE_UNVERIFIED",
  ransomwareIsolationVerified: "RANSOMWARE_ISOLATION_UNVERIFIED",
  backupIntegrityVerified: "BACKUP_INTEGRITY_UNVERIFIED",
  restoreRehearsalPassed: "RESTORE_REHEARSAL_NOT_PASSED",
  dependencyRestoreOrderTested: "DEPENDENCY_RESTORE_ORDER_UNTESTED",
  queueReplayAndIdempotencyTested: "QUEUE_REPLAY_IDEMPOTENCY_UNTESTED",
  ledgerReconciliationPassed: "LEDGER_RECONCILIATION_NOT_PASSED",
  failoverAndFailbackTested: "FAILOVER_FAILBACK_UNTESTED",
  monitoringAndAlertingTested: "RESILIENCE_MONITORING_UNTESTED",
  independentReviewApproved: "INDEPENDENT_REVIEW_UNAPPROVED"
});
const PROHIBITED_FIELD = /(?:address|backupData|backupPayload|candidate|command|credential|databaseDump|email|executable|key|mnemonic|password|payload|private|(?:^raw$|raw(?:Backup|Body|Data|Dump|Payload|Record|Snapshot|Transaction|Value))|secret|seed|signature|target|token|transaction|user|walletFile)/iu;

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function reject(code, message) {
  throw new VaultLabError(code, message);
}

function assertExactFields(value, allowed, label) {
  if (!isRecord(value)) reject("RESILIENCE_INVALID", `${label} must be an object`);
  for (const key of Object.keys(value)) {
    if (PROHIBITED_FIELD.test(key)) reject("RESILIENCE_PROHIBITED_FIELD", `${label} contains a prohibited field`);
    if (!allowed.has(key)) reject("RESILIENCE_UNKNOWN_FIELD", `${label} has an unknown field`);
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

export function validateResilienceAssessment(input) {
  assertExactFields(input, ROOT_FIELDS, "Resilience assessment");
  if (input.schema !== RESILIENCE_READINESS_SCHEMA) reject("RESILIENCE_SCHEMA_REJECTED", "Resilience schema is unsupported");
  if (typeof input.assessmentId !== "string" || !/^resilience_[0-9a-f]{32}$/u.test(input.assessmentId)) {
    reject("RESILIENCE_ID_REJECTED", "Resilience assessment identifier is invalid");
  }
  if (typeof input.assessedAt !== "string" || Number.isNaN(Date.parse(input.assessedAt))) {
    reject("RESILIENCE_TIME_REJECTED", "Resilience assessment time is invalid");
  }
  if (input.environment !== "staging") reject("RESILIENCE_ENVIRONMENT_REJECTED", "Resilience assurance is staging-only");

  assertExactFields(input.scope, SCOPE_FIELDS, "Resilience scope");
  if (!SYSTEM_CLASSES.has(input.scope.systemClass)) reject("RESILIENCE_SCOPE_REJECTED", "Resilience system class is unsupported");
  if (!RECOVERY_TIERS.has(input.scope.recoveryTier)) reject("RESILIENCE_SCOPE_REJECTED", "Resilience recovery tier is unsupported");
  if (!EXERCISE_CLASSES.has(input.scope.exerciseClass)) reject("RESILIENCE_SCOPE_REJECTED", "Resilience exercise class is unsupported");
  if (!DATA_CLASSES.has(input.scope.dataClass)) reject("RESILIENCE_SCOPE_REJECTED", "Resilience data class is unsupported");

  assertExactFields(input.evidence, EVIDENCE_FIELDS, "Resilience evidence");
  for (const field of [
    "planDigest",
    "backupPolicyDigest",
    "restoreEvidenceDigest",
    "dependencyMapDigest",
    "reconciliationDigest"
  ]) {
    if (typeof input.evidence[field] !== "string" || !/^[0-9a-f]{64}$/u.test(input.evidence[field])) {
      reject("RESILIENCE_EVIDENCE_REJECTED", "Resilience evidence digest is invalid");
    }
  }
  if (typeof input.evidence.exerciseRevision !== "string" || !/^[0-9a-f]{40}$/u.test(input.evidence.exerciseRevision)) {
    reject("RESILIENCE_EVIDENCE_REJECTED", "Resilience exercise revision is invalid");
  }
  if (
    !OBJECTIVE_CLASSES.has(input.evidence.recoveryPointClass) ||
    !OBJECTIVE_CLASSES.has(input.evidence.recoveryTimeClass)
  ) {
    reject("RESILIENCE_EVIDENCE_REJECTED", "Resilience objective class is unsupported");
  }

  assertExactFields(input.controls, CONTROL_FIELDS, "Resilience controls");
  if (Object.keys(input.controls).length !== REQUIRED_RESILIENCE_CONTROLS.length) {
    reject("RESILIENCE_CONTROL_REJECTED", "Resilience control set is incomplete");
  }
  for (const control of REQUIRED_RESILIENCE_CONTROLS) {
    if (typeof input.controls[control] !== "boolean") reject("RESILIENCE_CONTROL_REJECTED", "Resilience control value is invalid");
  }

  assertExactFields(input.findings, FINDING_FIELDS, "Resilience findings");
  for (const field of FINDING_FIELDS) {
    if (!Number.isSafeInteger(input.findings[field]) || input.findings[field] < 0 || input.findings[field] > 1_000_000) {
      reject("RESILIENCE_FINDING_REJECTED", "Resilience finding count is invalid");
    }
  }
  if (typeof input.evidenceDigest !== "string" || !/^[0-9a-f]{64}$/u.test(input.evidenceDigest)) {
    reject("RESILIENCE_EVIDENCE_REJECTED", "Resilience assessment digest is invalid");
  }
  return structuredClone(input);
}

export function evaluateResilienceReadiness(input) {
  const assessment = validateResilienceAssessment(input);
  const reasonCodes = REQUIRED_RESILIENCE_CONTROLS
    .filter((control) => !assessment.controls[control])
    .map((control) => CONTROL_REASON_CODES[control]);
  if (assessment.evidence.recoveryPointClass !== "within-objective") reasonCodes.push("RECOVERY_POINT_OBJECTIVE_NOT_MET");
  if (assessment.evidence.recoveryTimeClass !== "within-objective") reasonCodes.push("RECOVERY_TIME_OBJECTIVE_NOT_MET");
  if (assessment.findings.criticalOpen > 0) reasonCodes.push("CRITICAL_FINDINGS_OPEN");
  if (assessment.findings.highOpen > 0) reasonCodes.push("HIGH_FINDINGS_OPEN");
  if (assessment.findings.mediumOpen > 0) reasonCodes.push("MEDIUM_FINDINGS_OPEN");
  if (assessment.findings.unreconciledItems > 0) reasonCodes.push("UNRECONCILED_ITEMS_OPEN");
  const readiness =
    reasonCodes.length === 0
      ? "ELIGIBLE_FOR_INDEPENDENT_RESILIENCE_REVIEW"
      : "NOT_READY";
  const digest = createHash("sha256").update(canonicalJson(assessment)).digest("hex");
  return {
    schema: RESILIENCE_DECISION_SCHEMA,
    decisionId: `resdec_${digest.slice(0, 32)}`,
    assessmentId: assessment.assessmentId,
    readiness,
    reasonCodes: reasonCodes.sort(),
    evidenceDigest: assessment.evidenceDigest,
    humanAuthorizationRequired: true,
    restorationAuthorized: false,
    failoverAuthorized: false,
    dataMutationAuthorized: false,
    balanceMutationAuthorized: false,
    deploymentAuthorized: false,
    signingAuthorized: false,
    assetMovementAuthorized: false
  };
}
