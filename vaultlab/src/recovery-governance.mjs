import { createHash } from "node:crypto";
import { VaultLabError } from "./errors.mjs";

export const RECOVERY_CASE_SCHEMA = "enteleclos.recovery-governance.v1";
export const RECOVERY_DECISION_SCHEMA = "enteleclos.recovery-decision.v1";

const ROOT_FIELDS = new Set([
  "schema",
  "caseId",
  "phase",
  "openedAt",
  "lastTransitionAt",
  "environment",
  "authority",
  "approvals",
  "waitingPeriod",
  "notifications",
  "findings",
  "evidenceDigest"
]);
const AUTHORITY_FIELDS = new Set([
  "verified",
  "subjectMatch",
  "scopeApproved",
  "counselReviewed"
]);
const APPROVAL_FIELDS = new Set(["role", "approverId", "approvedAt", "attestationDigest"]);
const WAITING_FIELDS = new Set(["requiredHours", "elapsedHours", "emergencyOverride"]);
const NOTIFICATION_FIELDS = new Set([
  "requesterNotified",
  "securityNotified",
  "custodyNotified"
]);
const FINDING_FIELDS = new Set(["criticalOpen", "highOpen"]);
const PHASES = new Set([
  "intake",
  "authority-verified",
  "cooling-period",
  "quorum-approved",
  "migration-prepared",
  "completed",
  "cancelled"
]);
const REQUIRED_ROLES = Object.freeze(["custody", "legal", "security"]);
const APPROVAL_ROLES = new Set([...REQUIRED_ROLES, "privacy"]);
const ENVIRONMENTS = new Set(["staging", "production-observation"]);
const PROHIBITED_FIELD = /(?:address|candidate|credential|key|mnemonic|password|private|raw|seed|signature|target|transaction|wallet)/iu;
const TRANSITIONS = Object.freeze({
  intake: new Set(["authority-verified", "cancelled"]),
  "authority-verified": new Set(["cooling-period", "cancelled"]),
  "cooling-period": new Set(["quorum-approved", "cancelled"]),
  "quorum-approved": new Set(["migration-prepared", "cancelled"]),
  "migration-prepared": new Set(["completed", "cancelled"]),
  completed: new Set(),
  cancelled: new Set()
});

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function reject(code, message) {
  throw new VaultLabError(code, message);
}

function assertExactFields(value, allowed, label) {
  if (!isRecord(value)) reject("RECOVERY_CASE_INVALID", `${label} must be an object`);
  for (const key of Object.keys(value)) {
    if (PROHIBITED_FIELD.test(key)) {
      reject("RECOVERY_CASE_PROHIBITED_FIELD", `${label} contains a prohibited field`);
    }
    if (!allowed.has(key)) reject("RECOVERY_CASE_UNKNOWN_FIELD", `${label} has an unknown field`);
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

export function validateRecoveryCase(input) {
  assertExactFields(input, ROOT_FIELDS, "Recovery case");
  if (input.schema !== RECOVERY_CASE_SCHEMA) {
    reject("RECOVERY_CASE_SCHEMA_REJECTED", "Recovery case schema is unsupported");
  }
  if (typeof input.caseId !== "string" || !/^case_[0-9a-f]{32}$/u.test(input.caseId)) {
    reject("RECOVERY_CASE_ID_REJECTED", "Recovery case identifier is invalid");
  }
  if (!PHASES.has(input.phase)) reject("RECOVERY_CASE_PHASE_REJECTED", "Recovery phase is unsupported");
  if (
    typeof input.openedAt !== "string" ||
    Number.isNaN(Date.parse(input.openedAt)) ||
    typeof input.lastTransitionAt !== "string" ||
    Number.isNaN(Date.parse(input.lastTransitionAt)) ||
    Date.parse(input.lastTransitionAt) < Date.parse(input.openedAt)
  ) {
    reject("RECOVERY_CASE_TIME_REJECTED", "Recovery timestamps are invalid");
  }
  if (!ENVIRONMENTS.has(input.environment)) {
    reject("RECOVERY_CASE_ENVIRONMENT_REJECTED", "Recovery environment is unsupported");
  }

  assertExactFields(input.authority, AUTHORITY_FIELDS, "Recovery authority");
  for (const field of AUTHORITY_FIELDS) {
    if (typeof input.authority[field] !== "boolean") {
      reject("RECOVERY_AUTHORITY_REJECTED", "Recovery authority value is invalid");
    }
  }

  if (!Array.isArray(input.approvals) || input.approvals.length > 4) {
    reject("RECOVERY_APPROVAL_REJECTED", "Recovery approvals are outside policy");
  }
  for (const approval of input.approvals) {
    assertExactFields(approval, APPROVAL_FIELDS, "Recovery approval");
    if (!APPROVAL_ROLES.has(approval.role)) {
      reject("RECOVERY_APPROVAL_REJECTED", "Recovery approval role is unsupported");
    }
    if (typeof approval.approverId !== "string" || !/^approver_[0-9a-f]{16}$/u.test(approval.approverId)) {
      reject("RECOVERY_APPROVAL_REJECTED", "Recovery approver identifier is invalid");
    }
    if (
      typeof approval.approvedAt !== "string" ||
      Number.isNaN(Date.parse(approval.approvedAt)) ||
      Date.parse(approval.approvedAt) < Date.parse(input.openedAt) ||
      Date.parse(approval.approvedAt) > Date.parse(input.lastTransitionAt)
    ) {
      reject("RECOVERY_APPROVAL_REJECTED", "Recovery approval time is invalid");
    }
    if (
      typeof approval.attestationDigest !== "string" ||
      !/^[0-9a-f]{64}$/u.test(approval.attestationDigest)
    ) {
      reject("RECOVERY_APPROVAL_REJECTED", "Recovery approval attestation is invalid");
    }
  }
  if (new Set(input.approvals.map((approval) => approval.role)).size !== input.approvals.length) {
    reject("RECOVERY_APPROVAL_REJECTED", "Recovery approval roles must be unique");
  }
  if (new Set(input.approvals.map((approval) => approval.approverId)).size !== input.approvals.length) {
    reject("RECOVERY_APPROVAL_REJECTED", "Recovery approvers must be independent");
  }

  assertExactFields(input.waitingPeriod, WAITING_FIELDS, "Recovery waiting period");
  if (
    !Number.isSafeInteger(input.waitingPeriod.requiredHours) ||
    input.waitingPeriod.requiredHours < 24 ||
    input.waitingPeriod.requiredHours > 720 ||
    !Number.isSafeInteger(input.waitingPeriod.elapsedHours) ||
    input.waitingPeriod.elapsedHours < 0 ||
    input.waitingPeriod.elapsedHours > 8760 ||
    typeof input.waitingPeriod.emergencyOverride !== "boolean"
  ) {
    reject("RECOVERY_WAIT_REJECTED", "Recovery waiting period is outside policy");
  }
  const observedElapsedHours = Math.floor(
    (Date.parse(input.lastTransitionAt) - Date.parse(input.openedAt)) / 3_600_000
  );
  if (input.waitingPeriod.elapsedHours > observedElapsedHours) {
    reject("RECOVERY_WAIT_REJECTED", "Recovery elapsed time exceeds the observed case timeline");
  }

  assertExactFields(input.notifications, NOTIFICATION_FIELDS, "Recovery notifications");
  for (const field of NOTIFICATION_FIELDS) {
    if (typeof input.notifications[field] !== "boolean") {
      reject("RECOVERY_NOTIFICATION_REJECTED", "Recovery notification value is invalid");
    }
  }

  assertExactFields(input.findings, FINDING_FIELDS, "Recovery findings");
  for (const field of FINDING_FIELDS) {
    if (
      !Number.isSafeInteger(input.findings[field]) ||
      input.findings[field] < 0 ||
      input.findings[field] > 100
    ) {
      reject("RECOVERY_FINDING_REJECTED", "Recovery finding count is invalid");
    }
  }
  if (typeof input.evidenceDigest !== "string" || !/^[0-9a-f]{64}$/u.test(input.evidenceDigest)) {
    reject("RECOVERY_EVIDENCE_REJECTED", "Recovery evidence digest is invalid");
  }
  return structuredClone(input);
}

function recoveryControlReasons(recoveryCase) {
  const reasonCodes = [];
  if (Object.values(recoveryCase.authority).some((value) => value !== true)) {
    reasonCodes.push("AUTHORITY_INCOMPLETE");
  }
  const approvedRoles = new Set(recoveryCase.approvals.map((approval) => approval.role));
  if (REQUIRED_ROLES.some((role) => !approvedRoles.has(role))) reasonCodes.push("QUORUM_INCOMPLETE");
  if (recoveryCase.waitingPeriod.emergencyOverride) reasonCodes.push("EMERGENCY_OVERRIDE_REJECTED");
  if (recoveryCase.waitingPeriod.elapsedHours < recoveryCase.waitingPeriod.requiredHours) {
    reasonCodes.push("COOLING_PERIOD_ACTIVE");
  }
  if (Object.values(recoveryCase.notifications).some((value) => value !== true)) {
    reasonCodes.push("NOTIFICATIONS_INCOMPLETE");
  }
  if (recoveryCase.findings.criticalOpen > 0) reasonCodes.push("CRITICAL_FINDINGS_OPEN");
  if (recoveryCase.findings.highOpen > 0) reasonCodes.push("HIGH_FINDINGS_OPEN");
  return reasonCodes;
}

export function evaluateRecoveryCase(input) {
  const recoveryCase = validateRecoveryCase(input);
  const reasonCodes = recoveryControlReasons(recoveryCase);

  if (recoveryCase.phase === "cancelled" || recoveryCase.phase === "completed") {
    reasonCodes.push("CASE_CLOSED");
  }
  if (!new Set(["quorum-approved", "migration-prepared"]).has(recoveryCase.phase)) {
    reasonCodes.push("PHASE_NOT_READY");
  }

  const recommendation = reasonCodes.includes("CASE_CLOSED")
    ? "CLOSED"
    : reasonCodes.length > 0
      ? "BLOCK"
      : "READY_FOR_SEPARATE_CUSTODY_REVIEW";
  const digest = createHash("sha256").update(canonicalJson(recoveryCase)).digest("hex");
  return {
    schema: RECOVERY_DECISION_SCHEMA,
    decisionId: `recdec_${digest.slice(0, 32)}`,
    caseId: recoveryCase.caseId,
    recommendation,
    reasonCodes: reasonCodes.sort(),
    evidenceDigest: recoveryCase.evidenceDigest,
    humanAuthorizationRequired: true,
    executionAuthorized: false,
    signingAuthorized: false,
    assetMovementAuthorized: false
  };
}

export function validateRecoveryTransition(currentInput, nextInput) {
  const current = validateRecoveryCase(currentInput);
  const next = validateRecoveryCase(nextInput);
  if (
    current.caseId !== next.caseId ||
    current.openedAt !== next.openedAt ||
    current.environment !== next.environment
  ) {
    reject("RECOVERY_TRANSITION_IDENTITY_REJECTED", "Recovery case identity cannot change");
  }
  if (!TRANSITIONS[current.phase].has(next.phase)) {
    reject("RECOVERY_TRANSITION_REJECTED", "Recovery phase transition is not permitted");
  }
  if (Date.parse(next.lastTransitionAt) < Date.parse(current.lastTransitionAt)) {
    reject("RECOVERY_TRANSITION_TIME_REJECTED", "Recovery transition time cannot move backward");
  }
  if (next.waitingPeriod.requiredHours !== current.waitingPeriod.requiredHours) {
    reject("RECOVERY_TRANSITION_CONTROL_REJECTED", "Recovery waiting policy cannot change");
  }
  for (const field of AUTHORITY_FIELDS) {
    if (current.authority[field] && !next.authority[field]) {
      reject("RECOVERY_TRANSITION_CONTROL_REJECTED", "Verified authority cannot be weakened");
    }
  }
  for (const currentApproval of current.approvals) {
    const nextApproval = next.approvals.find((approval) => approval.role === currentApproval.role);
    if (!nextApproval || canonicalJson(nextApproval) !== canonicalJson(currentApproval)) {
      reject("RECOVERY_TRANSITION_CONTROL_REJECTED", "Recovery approvals are append-only");
    }
  }
  if (next.phase === "authority-verified" && Object.values(next.authority).some((value) => !value)) {
    reject("RECOVERY_TRANSITION_CONTROL_REJECTED", "Authority controls are incomplete");
  }
  if (new Set(["quorum-approved", "migration-prepared", "completed"]).has(next.phase)) {
    if (recoveryControlReasons(next).length > 0) {
      reject("RECOVERY_TRANSITION_CONTROL_REJECTED", "Recovery controls are incomplete");
    }
  }
  return {
    accepted: true,
    from: current.phase,
    to: next.phase,
    executionAuthorized: false,
    assetMovementAuthorized: false
  };
}
