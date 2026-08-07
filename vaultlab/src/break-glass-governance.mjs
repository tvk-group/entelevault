import { createHash } from "node:crypto";
import { VaultLabError } from "./errors.mjs";

export const BREAK_GLASS_CASE_SCHEMA = "enteleclos.break-glass-governance.v1";
export const BREAK_GLASS_DECISION_SCHEMA = "enteleclos.break-glass-decision.v1";

export const BREAK_GLASS_CONTROL_FIELDS = Object.freeze([
  "normalAccessUnavailable",
  "emergencyJustificationReviewed",
  "phishingResistantMfaVerified",
  "hardwareBoundIdentityVerified",
  "sessionRecordingPlanned",
  "realTimeMonitoringPlanned",
  "automaticRevocationPlanned",
  "postEventReviewPlanned",
  "revocationVerified",
  "sessionEvidenceSealed",
  "independentClosureApproved"
]);

const ROOT_FIELDS = new Set([
  "schema",
  "caseId",
  "phase",
  "openedAt",
  "lastTransitionAt",
  "environment",
  "scope",
  "authority",
  "controls",
  "approvals",
  "findings",
  "evidenceDigest"
]);
const SCOPE_FIELDS = new Set(["systemClass", "riskClass", "accessClass"]);
const AUTHORITY_FIELDS = new Set([
  "incidentLinked",
  "legalBasisReviewed",
  "ownerVerified",
  "leastPrivilegeReviewed"
]);
const CONTROL_FIELDS = new Set([...BREAK_GLASS_CONTROL_FIELDS, "timeLimitMinutes"]);
const APPROVAL_FIELDS = new Set(["role", "approverId", "approvedAt", "attestationDigest"]);
const FINDING_FIELDS = new Set(["criticalOpen", "highOpen", "mediumOpen"]);
const PHASES = Object.freeze([
  "requested",
  "authority-verified",
  "quorum-approved",
  "active-window",
  "revoked",
  "reviewed",
  "closed"
]);
const PHASE_INDEX = Object.freeze(Object.fromEntries(PHASES.map((phase, index) => [phase, index])));
const TRANSITIONS = Object.freeze({
  requested: new Set(["authority-verified"]),
  "authority-verified": new Set(["quorum-approved"]),
  "quorum-approved": new Set(["active-window"]),
  "active-window": new Set(["revoked"]),
  revoked: new Set(["reviewed"]),
  reviewed: new Set(["closed"]),
  closed: new Set()
});
const PRE_REQUEST_CONTROLS = Object.freeze([
  "normalAccessUnavailable",
  "emergencyJustificationReviewed"
]);
const PRE_ACCESS_CONTROLS = Object.freeze([
  ...PRE_REQUEST_CONTROLS,
  "phishingResistantMfaVerified",
  "hardwareBoundIdentityVerified",
  "sessionRecordingPlanned",
  "realTimeMonitoringPlanned",
  "automaticRevocationPlanned",
  "postEventReviewPlanned"
]);
const ALLOWED_CONTROLS_BY_PHASE = Object.freeze({
  requested: PRE_REQUEST_CONTROLS,
  "authority-verified": PRE_REQUEST_CONTROLS,
  "quorum-approved": PRE_ACCESS_CONTROLS,
  "active-window": PRE_ACCESS_CONTROLS,
  revoked: [...PRE_ACCESS_CONTROLS, "revocationVerified"],
  reviewed: BREAK_GLASS_CONTROL_FIELDS,
  closed: BREAK_GLASS_CONTROL_FIELDS
});
const REQUIRED_CONTROLS_BY_PHASE = Object.freeze({
  requested: [],
  "authority-verified": PRE_REQUEST_CONTROLS,
  "quorum-approved": PRE_ACCESS_CONTROLS,
  "active-window": PRE_ACCESS_CONTROLS,
  revoked: [...PRE_ACCESS_CONTROLS, "revocationVerified"],
  reviewed: BREAK_GLASS_CONTROL_FIELDS,
  closed: BREAK_GLASS_CONTROL_FIELDS
});
const CONTROL_REASON_CODES = Object.freeze({
  normalAccessUnavailable: "NORMAL_ACCESS_STILL_AVAILABLE",
  emergencyJustificationReviewed: "EMERGENCY_JUSTIFICATION_UNREVIEWED",
  phishingResistantMfaVerified: "PHISHING_RESISTANT_MFA_UNVERIFIED",
  hardwareBoundIdentityVerified: "HARDWARE_BOUND_IDENTITY_UNVERIFIED",
  sessionRecordingPlanned: "SESSION_RECORDING_NOT_PLANNED",
  realTimeMonitoringPlanned: "REAL_TIME_MONITORING_NOT_PLANNED",
  automaticRevocationPlanned: "AUTOMATIC_REVOCATION_NOT_PLANNED",
  postEventReviewPlanned: "POST_EVENT_REVIEW_NOT_PLANNED",
  revocationVerified: "REVOCATION_UNVERIFIED",
  sessionEvidenceSealed: "SESSION_EVIDENCE_NOT_SEALED",
  independentClosureApproved: "INDEPENDENT_CLOSURE_UNAPPROVED"
});
const NEXT_PHASE_REASON = Object.freeze({
  requested: "AUTHORITY_VERIFICATION_REQUIRED",
  "authority-verified": "QUORUM_APPROVAL_REQUIRED",
  "quorum-approved": "SEPARATE_ACCESS_AUTHORIZATION_REQUIRED",
  "active-window": "REVOCATION_EVIDENCE_REQUIRED",
  revoked: "POST_EVENT_REVIEW_REQUIRED"
});
const ENVIRONMENTS = new Set(["staging", "production-observation"]);
const SYSTEM_CLASSES = new Set(["wallet", "exchange", "custody", "vault", "infrastructure", "identity"]);
const RISK_CLASSES = Object.freeze(["high", "critical"]);
const RISK_INDEX = Object.freeze(Object.fromEntries(RISK_CLASSES.map((value, index) => [value, index])));
const ACCESS_CLASSES = new Set(["read-only", "bounded-admin"]);
const APPROVAL_ROLES = new Set(["security", "operations", "custody", "legal", "independent-review"]);
const QUORUM_ROLES = Object.freeze(["security", "operations", "custody"]);
const PROHIBITED_FIELD = /(?:address|candidate|command|credential|email|executable|key|mnemonic|password|payload|private|(?:^raw$|raw(?:Body|Data|Message|Payload|Request|Value))|secret|seed|signature|target|token|transaction|user|walletFile)/iu;

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function reject(code, message) {
  throw new VaultLabError(code, message);
}

function assertExactFields(value, allowed, label) {
  if (!isRecord(value)) reject("BREAK_GLASS_CASE_INVALID", `${label} must be an object`);
  for (const key of Object.keys(value)) {
    if (PROHIBITED_FIELD.test(key)) {
      reject("BREAK_GLASS_PROHIBITED_FIELD", `${label} contains a prohibited field`);
    }
    if (!allowed.has(key)) reject("BREAK_GLASS_UNKNOWN_FIELD", `${label} has an unknown field`);
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

export function validateBreakGlassCase(input) {
  assertExactFields(input, ROOT_FIELDS, "Break-glass case");
  if (input.schema !== BREAK_GLASS_CASE_SCHEMA) {
    reject("BREAK_GLASS_SCHEMA_REJECTED", "Break-glass schema is unsupported");
  }
  if (typeof input.caseId !== "string" || !/^bgcase_[0-9a-f]{32}$/u.test(input.caseId)) {
    reject("BREAK_GLASS_ID_REJECTED", "Break-glass case identifier is invalid");
  }
  if (!PHASES.includes(input.phase)) reject("BREAK_GLASS_PHASE_REJECTED", "Break-glass phase is unsupported");
  if (
    typeof input.openedAt !== "string" ||
    Number.isNaN(Date.parse(input.openedAt)) ||
    typeof input.lastTransitionAt !== "string" ||
    Number.isNaN(Date.parse(input.lastTransitionAt)) ||
    Date.parse(input.lastTransitionAt) < Date.parse(input.openedAt)
  ) {
    reject("BREAK_GLASS_TIME_REJECTED", "Break-glass timestamps are invalid");
  }
  if (!ENVIRONMENTS.has(input.environment)) {
    reject("BREAK_GLASS_ENVIRONMENT_REJECTED", "Break-glass environment is unsupported");
  }

  assertExactFields(input.scope, SCOPE_FIELDS, "Break-glass scope");
  if (!SYSTEM_CLASSES.has(input.scope.systemClass)) {
    reject("BREAK_GLASS_SCOPE_REJECTED", "Break-glass system class is unsupported");
  }
  if (!RISK_CLASSES.includes(input.scope.riskClass)) {
    reject("BREAK_GLASS_SCOPE_REJECTED", "Break-glass risk class is unsupported");
  }
  if (!ACCESS_CLASSES.has(input.scope.accessClass)) {
    reject("BREAK_GLASS_SCOPE_REJECTED", "Break-glass access class is unsupported");
  }

  assertExactFields(input.authority, AUTHORITY_FIELDS, "Break-glass authority evidence");
  for (const field of AUTHORITY_FIELDS) {
    if (typeof input.authority[field] !== "boolean") {
      reject("BREAK_GLASS_AUTHORITY_REJECTED", "Break-glass authority evidence is invalid");
    }
  }
  if (input.phase === "requested" && Object.values(input.authority).some(Boolean)) {
    reject("BREAK_GLASS_AUTHORITY_REJECTED", "Authority evidence cannot precede verification");
  }

  assertExactFields(input.controls, CONTROL_FIELDS, "Break-glass controls");
  if (Object.keys(input.controls).length !== BREAK_GLASS_CONTROL_FIELDS.length + 1) {
    reject("BREAK_GLASS_CONTROL_REJECTED", "Break-glass control set is incomplete");
  }
  for (const field of BREAK_GLASS_CONTROL_FIELDS) {
    if (typeof input.controls[field] !== "boolean") {
      reject("BREAK_GLASS_CONTROL_REJECTED", "Break-glass control value is invalid");
    }
  }
  if (
    !Number.isSafeInteger(input.controls.timeLimitMinutes) ||
    input.controls.timeLimitMinutes < 5 ||
    input.controls.timeLimitMinutes > 60
  ) {
    reject("BREAK_GLASS_CONTROL_REJECTED", "Break-glass time limit is outside policy");
  }
  const allowedControls = new Set(ALLOWED_CONTROLS_BY_PHASE[input.phase]);
  if (BREAK_GLASS_CONTROL_FIELDS.some((field) => input.controls[field] && !allowedControls.has(field))) {
    reject("BREAK_GLASS_CONTROL_REJECTED", "Break-glass controls cannot be completed before their phase");
  }

  if (!Array.isArray(input.approvals) || input.approvals.length > 5) {
    reject("BREAK_GLASS_APPROVAL_REJECTED", "Break-glass approvals are outside policy");
  }
  for (const approval of input.approvals) {
    assertExactFields(approval, APPROVAL_FIELDS, "Break-glass approval");
    if (!APPROVAL_ROLES.has(approval.role)) {
      reject("BREAK_GLASS_APPROVAL_REJECTED", "Break-glass approval role is unsupported");
    }
    if (typeof approval.approverId !== "string" || !/^approver_[0-9a-f]{16}$/u.test(approval.approverId)) {
      reject("BREAK_GLASS_APPROVAL_REJECTED", "Break-glass approver identifier is invalid");
    }
    if (
      typeof approval.approvedAt !== "string" ||
      Number.isNaN(Date.parse(approval.approvedAt)) ||
      Date.parse(approval.approvedAt) < Date.parse(input.openedAt) ||
      Date.parse(approval.approvedAt) > Date.parse(input.lastTransitionAt)
    ) {
      reject("BREAK_GLASS_APPROVAL_REJECTED", "Break-glass approval time is invalid");
    }
    if (typeof approval.attestationDigest !== "string" || !/^[0-9a-f]{64}$/u.test(approval.attestationDigest)) {
      reject("BREAK_GLASS_APPROVAL_REJECTED", "Break-glass approval attestation is invalid");
    }
  }
  if (new Set(input.approvals.map((approval) => approval.role)).size !== input.approvals.length) {
    reject("BREAK_GLASS_APPROVAL_REJECTED", "Break-glass approval roles must be unique");
  }
  if (new Set(input.approvals.map((approval) => approval.approverId)).size !== input.approvals.length) {
    reject("BREAK_GLASS_APPROVAL_REJECTED", "Break-glass approvers must be independent");
  }
  if (PHASE_INDEX[input.phase] < PHASE_INDEX["quorum-approved"] && input.approvals.length > 0) {
    reject("BREAK_GLASS_APPROVAL_REJECTED", "Break-glass approvals cannot precede quorum review");
  }
  if (
    PHASE_INDEX[input.phase] < PHASE_INDEX.reviewed &&
    input.approvals.some((approval) => approval.role === "independent-review")
  ) {
    reject("BREAK_GLASS_APPROVAL_REJECTED", "Closure approval cannot precede post-event review");
  }

  assertExactFields(input.findings, FINDING_FIELDS, "Break-glass findings");
  for (const field of FINDING_FIELDS) {
    if (!Number.isSafeInteger(input.findings[field]) || input.findings[field] < 0 || input.findings[field] > 1000) {
      reject("BREAK_GLASS_FINDING_REJECTED", "Break-glass finding count is invalid");
    }
  }
  if (typeof input.evidenceDigest !== "string" || !/^[0-9a-f]{64}$/u.test(input.evidenceDigest)) {
    reject("BREAK_GLASS_EVIDENCE_REJECTED", "Break-glass evidence digest is invalid");
  }
  return structuredClone(input);
}

function phaseReasonCodes(breakGlassCase) {
  const reasonCodes = REQUIRED_CONTROLS_BY_PHASE[breakGlassCase.phase]
    .filter((control) => !breakGlassCase.controls[control])
    .map((control) => CONTROL_REASON_CODES[control]);
  if (PHASE_INDEX[breakGlassCase.phase] >= PHASE_INDEX["authority-verified"]) {
    if (Object.values(breakGlassCase.authority).some((value) => !value)) {
      reasonCodes.push("AUTHORITY_EVIDENCE_INCOMPLETE");
    }
  }
  if (PHASE_INDEX[breakGlassCase.phase] >= PHASE_INDEX["quorum-approved"]) {
    const roles = new Set(breakGlassCase.approvals.map((approval) => approval.role));
    if (QUORUM_ROLES.some((role) => !roles.has(role))) reasonCodes.push("EMERGENCY_QUORUM_INCOMPLETE");
  }
  if (PHASE_INDEX[breakGlassCase.phase] >= PHASE_INDEX.reviewed) {
    const roles = new Set(breakGlassCase.approvals.map((approval) => approval.role));
    if (!roles.has("independent-review")) reasonCodes.push("INDEPENDENT_REVIEW_MISSING");
    if (breakGlassCase.findings.criticalOpen > 0) reasonCodes.push("CRITICAL_FINDINGS_OPEN");
    if (breakGlassCase.findings.highOpen > 0) reasonCodes.push("HIGH_FINDINGS_OPEN");
    if (breakGlassCase.findings.mediumOpen > 0) reasonCodes.push("MEDIUM_FINDINGS_OPEN");
  }
  return reasonCodes;
}

export function evaluateBreakGlassCase(input) {
  const breakGlassCase = validateBreakGlassCase(input);
  const reasonCodes = phaseReasonCodes(breakGlassCase);
  if (NEXT_PHASE_REASON[breakGlassCase.phase]) reasonCodes.push(NEXT_PHASE_REASON[breakGlassCase.phase]);
  const recommendation =
    breakGlassCase.phase === "closed"
      ? reasonCodes.length === 0
        ? "CLOSED"
        : "INVALID_CLOSURE_RECORD"
      : breakGlassCase.phase === "reviewed" && reasonCodes.length === 0
        ? "READY_FOR_SEPARATE_CLOSURE_REVIEW"
        : "ACTIVE_GOVERNANCE_REQUIRED";
  const digest = createHash("sha256").update(canonicalJson(breakGlassCase)).digest("hex");
  return {
    schema: BREAK_GLASS_DECISION_SCHEMA,
    decisionId: `bgdec_${digest.slice(0, 32)}`,
    caseId: breakGlassCase.caseId,
    recommendation,
    reasonCodes: reasonCodes.sort(),
    evidenceDigest: breakGlassCase.evidenceDigest,
    humanAuthorizationRequired: true,
    accessGrantAuthorized: false,
    sessionStartAuthorized: false,
    revocationExecutionAuthorized: false,
    deploymentAuthorized: false,
    signingAuthorized: false,
    assetMovementAuthorized: false
  };
}

export function validateBreakGlassTransition(currentInput, nextInput) {
  const current = validateBreakGlassCase(currentInput);
  const next = validateBreakGlassCase(nextInput);
  if (
    current.caseId !== next.caseId ||
    current.openedAt !== next.openedAt ||
    current.environment !== next.environment ||
    current.scope.systemClass !== next.scope.systemClass ||
    current.scope.accessClass !== next.scope.accessClass
  ) {
    reject("BREAK_GLASS_TRANSITION_IDENTITY_REJECTED", "Break-glass case identity and scope cannot change");
  }
  if (!TRANSITIONS[current.phase].has(next.phase)) {
    reject("BREAK_GLASS_TRANSITION_REJECTED", "Break-glass phase transition is not permitted");
  }
  if (Date.parse(next.lastTransitionAt) <= Date.parse(current.lastTransitionAt)) {
    reject("BREAK_GLASS_TRANSITION_TIME_REJECTED", "Break-glass transition time must move forward");
  }
  if (RISK_INDEX[next.scope.riskClass] < RISK_INDEX[current.scope.riskClass]) {
    reject("BREAK_GLASS_TRANSITION_CONTROL_REJECTED", "Break-glass risk cannot be silently downgraded");
  }
  for (const field of AUTHORITY_FIELDS) {
    if (current.authority[field] && !next.authority[field]) {
      reject("BREAK_GLASS_TRANSITION_CONTROL_REJECTED", "Break-glass authority evidence cannot be weakened");
    }
  }
  for (const control of BREAK_GLASS_CONTROL_FIELDS) {
    if (current.controls[control] && !next.controls[control]) {
      reject("BREAK_GLASS_TRANSITION_CONTROL_REJECTED", "Break-glass controls cannot be weakened");
    }
  }
  if (
    PHASE_INDEX[current.phase] >= PHASE_INDEX["authority-verified"] &&
    current.controls.timeLimitMinutes !== next.controls.timeLimitMinutes
  ) {
    reject("BREAK_GLASS_TRANSITION_CONTROL_REJECTED", "Break-glass time limit is immutable after authority verification");
  }
  for (const currentApproval of current.approvals) {
    const nextApproval = next.approvals.find((approval) => approval.role === currentApproval.role);
    if (!nextApproval || canonicalJson(nextApproval) !== canonicalJson(currentApproval)) {
      reject("BREAK_GLASS_TRANSITION_CONTROL_REJECTED", "Break-glass approvals are append-only");
    }
  }
  if (phaseReasonCodes(next).length > 0) {
    reject("BREAK_GLASS_TRANSITION_CONTROL_REJECTED", "Required break-glass governance evidence is incomplete");
  }
  return {
    accepted: true,
    from: current.phase,
    to: next.phase,
    humanAuthorizationRequired: true,
    accessGrantAuthorized: false,
    sessionStartAuthorized: false,
    revocationExecutionAuthorized: false,
    deploymentAuthorized: false,
    signingAuthorized: false,
    assetMovementAuthorized: false
  };
}
