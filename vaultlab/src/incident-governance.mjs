import { createHash } from "node:crypto";
import { VaultLabError } from "./errors.mjs";

export const INCIDENT_CASE_SCHEMA = "enteleclos.incident-governance.v1";
export const INCIDENT_DECISION_SCHEMA = "enteleclos.incident-decision.v1";

export const INCIDENT_CONTROL_FIELDS = Object.freeze([
  "incidentCommanderAssigned",
  "evidencePreserved",
  "securityNotified",
  "legalNotified",
  "custodyNotified",
  "containmentVerified",
  "accessRevocationVerified",
  "rotationVerified",
  "reconciliationVerified",
  "customerCommunicationReviewed",
  "regulatoryAssessmentCompleted",
  "rootCauseReviewed",
  "remediationPlanApproved",
  "independentClosureApproved"
]);

const ROOT_FIELDS = new Set([
  "schema",
  "incidentId",
  "phase",
  "openedAt",
  "lastTransitionAt",
  "environment",
  "classification",
  "controls",
  "approvals",
  "findings",
  "evidenceDigest"
]);
const CLASSIFICATION_FIELDS = new Set(["severity", "domain", "customerImpact", "assetImpact"]);
const CONTROL_FIELDS = new Set(INCIDENT_CONTROL_FIELDS);
const APPROVAL_FIELDS = new Set(["role", "approverId", "approvedAt", "attestationDigest"]);
const FINDING_FIELDS = new Set(["criticalOpen", "highOpen", "mediumOpen"]);
const PHASES = Object.freeze([
  "detected",
  "triaged",
  "contained",
  "access-revoked",
  "assets-reconciled",
  "recovery-reviewed",
  "closed"
]);
const PHASE_INDEX = Object.freeze(Object.fromEntries(PHASES.map((phase, index) => [phase, index])));
const TRANSITIONS = Object.freeze({
  detected: new Set(["triaged"]),
  triaged: new Set(["contained"]),
  contained: new Set(["access-revoked"]),
  "access-revoked": new Set(["assets-reconciled"]),
  "assets-reconciled": new Set(["recovery-reviewed"]),
  "recovery-reviewed": new Set(["closed"]),
  closed: new Set()
});
const REQUIRED_CONTROLS_BY_PHASE = Object.freeze({
  detected: [],
  triaged: [
    "incidentCommanderAssigned",
    "evidencePreserved",
    "securityNotified",
    "legalNotified",
    "custodyNotified"
  ],
  contained: [
    "incidentCommanderAssigned",
    "evidencePreserved",
    "securityNotified",
    "legalNotified",
    "custodyNotified",
    "containmentVerified"
  ],
  "access-revoked": [
    "incidentCommanderAssigned",
    "evidencePreserved",
    "securityNotified",
    "legalNotified",
    "custodyNotified",
    "containmentVerified",
    "accessRevocationVerified"
  ],
  "assets-reconciled": [
    "incidentCommanderAssigned",
    "evidencePreserved",
    "securityNotified",
    "legalNotified",
    "custodyNotified",
    "containmentVerified",
    "accessRevocationVerified",
    "rotationVerified",
    "reconciliationVerified"
  ],
  "recovery-reviewed": INCIDENT_CONTROL_FIELDS,
  closed: INCIDENT_CONTROL_FIELDS
});
const CONTROL_REASON_CODES = Object.freeze({
  incidentCommanderAssigned: "INCIDENT_COMMANDER_MISSING",
  evidencePreserved: "EVIDENCE_NOT_PRESERVED",
  securityNotified: "SECURITY_NOTIFICATION_MISSING",
  legalNotified: "LEGAL_NOTIFICATION_MISSING",
  custodyNotified: "CUSTODY_NOTIFICATION_MISSING",
  containmentVerified: "CONTAINMENT_UNVERIFIED",
  accessRevocationVerified: "ACCESS_REVOCATION_UNVERIFIED",
  rotationVerified: "ROTATION_UNVERIFIED",
  reconciliationVerified: "RECONCILIATION_UNVERIFIED",
  customerCommunicationReviewed: "CUSTOMER_COMMUNICATION_UNREVIEWED",
  regulatoryAssessmentCompleted: "REGULATORY_ASSESSMENT_INCOMPLETE",
  rootCauseReviewed: "ROOT_CAUSE_UNREVIEWED",
  remediationPlanApproved: "REMEDIATION_PLAN_UNAPPROVED",
  independentClosureApproved: "INDEPENDENT_CLOSURE_UNAPPROVED"
});
const ENVIRONMENTS = new Set(["staging", "production-observation"]);
const SEVERITIES = Object.freeze(["low", "medium", "high", "critical"]);
const SEVERITY_INDEX = Object.freeze(Object.fromEntries(SEVERITIES.map((value, index) => [value, index])));
const DOMAINS = new Set(["custody", "exchange", "identity", "infrastructure", "supply-chain", "wallet"]);
const IMPACTS = new Set(["confirmed", "none", "suspected", "unknown"]);
const APPROVAL_ROLES = new Set(["custody", "independent-review", "legal", "operations", "security"]);
const CLOSURE_ROLES = Object.freeze(["independent-review", "operations", "security"]);
const NEXT_PHASE_REASONS = Object.freeze({
  detected: "TRIAGE_REQUIRED",
  triaged: "CONTAINMENT_REQUIRED",
  contained: "ACCESS_REVOCATION_REVIEW_REQUIRED",
  "access-revoked": "ASSET_RECONCILIATION_REQUIRED",
  "assets-reconciled": "RECOVERY_REVIEW_REQUIRED"
});
const PROHIBITED_FIELD = /(?:address|candidate|(?:^command$|command(?:Body|Payload|Text|Value)|(?:execute|response)Command)|credential|executable|key|mnemonic|password|payload|private|raw|seed|secret|signature|target|token|transaction|wallet)/iu;

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function reject(code, message) {
  throw new VaultLabError(code, message);
}

function assertExactFields(value, allowed, label) {
  if (!isRecord(value)) reject("INCIDENT_CASE_INVALID", `${label} must be an object`);
  for (const key of Object.keys(value)) {
    if (PROHIBITED_FIELD.test(key)) {
      reject("INCIDENT_CASE_PROHIBITED_FIELD", `${label} contains a prohibited field`);
    }
    if (!allowed.has(key)) reject("INCIDENT_CASE_UNKNOWN_FIELD", `${label} has an unknown field`);
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

export function validateIncidentCase(input) {
  assertExactFields(input, ROOT_FIELDS, "Incident case");
  if (input.schema !== INCIDENT_CASE_SCHEMA) {
    reject("INCIDENT_CASE_SCHEMA_REJECTED", "Incident case schema is unsupported");
  }
  if (typeof input.incidentId !== "string" || !/^inc_[0-9a-f]{32}$/u.test(input.incidentId)) {
    reject("INCIDENT_CASE_ID_REJECTED", "Incident identifier is invalid");
  }
  if (!PHASES.includes(input.phase)) reject("INCIDENT_CASE_PHASE_REJECTED", "Incident phase is unsupported");
  if (
    typeof input.openedAt !== "string" ||
    Number.isNaN(Date.parse(input.openedAt)) ||
    typeof input.lastTransitionAt !== "string" ||
    Number.isNaN(Date.parse(input.lastTransitionAt)) ||
    Date.parse(input.lastTransitionAt) < Date.parse(input.openedAt)
  ) {
    reject("INCIDENT_CASE_TIME_REJECTED", "Incident timestamps are invalid");
  }
  if (!ENVIRONMENTS.has(input.environment)) {
    reject("INCIDENT_CASE_ENVIRONMENT_REJECTED", "Incident environment is unsupported");
  }

  assertExactFields(input.classification, CLASSIFICATION_FIELDS, "Incident classification");
  if (!SEVERITIES.includes(input.classification.severity)) {
    reject("INCIDENT_CLASSIFICATION_REJECTED", "Incident severity is unsupported");
  }
  if (!DOMAINS.has(input.classification.domain)) {
    reject("INCIDENT_CLASSIFICATION_REJECTED", "Incident domain is unsupported");
  }
  if (!IMPACTS.has(input.classification.customerImpact) || !IMPACTS.has(input.classification.assetImpact)) {
    reject("INCIDENT_CLASSIFICATION_REJECTED", "Incident impact classification is unsupported");
  }

  assertExactFields(input.controls, CONTROL_FIELDS, "Incident controls");
  if (Object.keys(input.controls).length !== INCIDENT_CONTROL_FIELDS.length) {
    reject("INCIDENT_CONTROL_REJECTED", "Incident control set is incomplete");
  }
  for (const field of INCIDENT_CONTROL_FIELDS) {
    if (typeof input.controls[field] !== "boolean") {
      reject("INCIDENT_CONTROL_REJECTED", "Incident control value is invalid");
    }
  }
  const phaseControls = new Set(REQUIRED_CONTROLS_BY_PHASE[input.phase]);
  if (INCIDENT_CONTROL_FIELDS.some((field) => input.controls[field] && !phaseControls.has(field))) {
    reject("INCIDENT_CONTROL_REJECTED", "Incident controls cannot be completed before their phase");
  }

  if (!Array.isArray(input.approvals) || input.approvals.length > 5) {
    reject("INCIDENT_APPROVAL_REJECTED", "Incident approvals are outside policy");
  }
  for (const approval of input.approvals) {
    assertExactFields(approval, APPROVAL_FIELDS, "Incident approval");
    if (!APPROVAL_ROLES.has(approval.role)) {
      reject("INCIDENT_APPROVAL_REJECTED", "Incident approval role is unsupported");
    }
    if (typeof approval.approverId !== "string" || !/^approver_[0-9a-f]{16}$/u.test(approval.approverId)) {
      reject("INCIDENT_APPROVAL_REJECTED", "Incident approver identifier is invalid");
    }
    if (
      typeof approval.approvedAt !== "string" ||
      Number.isNaN(Date.parse(approval.approvedAt)) ||
      Date.parse(approval.approvedAt) < Date.parse(input.openedAt) ||
      Date.parse(approval.approvedAt) > Date.parse(input.lastTransitionAt)
    ) {
      reject("INCIDENT_APPROVAL_REJECTED", "Incident approval time is invalid");
    }
    if (
      typeof approval.attestationDigest !== "string" ||
      !/^[0-9a-f]{64}$/u.test(approval.attestationDigest)
    ) {
      reject("INCIDENT_APPROVAL_REJECTED", "Incident approval attestation is invalid");
    }
  }
  if (new Set(input.approvals.map((approval) => approval.role)).size !== input.approvals.length) {
    reject("INCIDENT_APPROVAL_REJECTED", "Incident approval roles must be unique");
  }
  if (new Set(input.approvals.map((approval) => approval.approverId)).size !== input.approvals.length) {
    reject("INCIDENT_APPROVAL_REJECTED", "Incident approvers must be independent");
  }
  if (PHASE_INDEX[input.phase] < PHASE_INDEX["recovery-reviewed"] && input.approvals.length > 0) {
    reject("INCIDENT_APPROVAL_REJECTED", "Closure approvals cannot precede recovery review");
  }

  assertExactFields(input.findings, FINDING_FIELDS, "Incident findings");
  for (const field of FINDING_FIELDS) {
    if (
      !Number.isSafeInteger(input.findings[field]) ||
      input.findings[field] < 0 ||
      input.findings[field] > 1000
    ) {
      reject("INCIDENT_FINDING_REJECTED", "Incident finding count is invalid");
    }
  }
  if (typeof input.evidenceDigest !== "string" || !/^[0-9a-f]{64}$/u.test(input.evidenceDigest)) {
    reject("INCIDENT_EVIDENCE_REJECTED", "Incident evidence digest is invalid");
  }
  return structuredClone(input);
}

function phaseReasonCodes(incident) {
  const reasonCodes = REQUIRED_CONTROLS_BY_PHASE[incident.phase]
    .filter((control) => !incident.controls[control])
    .map((control) => CONTROL_REASON_CODES[control]);
  if (PHASE_INDEX[incident.phase] >= PHASE_INDEX["recovery-reviewed"]) {
    const approvedRoles = new Set(incident.approvals.map((approval) => approval.role));
    if (CLOSURE_ROLES.some((role) => !approvedRoles.has(role))) reasonCodes.push("CLOSURE_QUORUM_INCOMPLETE");
    if (incident.findings.criticalOpen > 0) reasonCodes.push("CRITICAL_FINDINGS_OPEN");
    if (incident.findings.highOpen > 0) reasonCodes.push("HIGH_FINDINGS_OPEN");
    if (incident.findings.mediumOpen > 0) reasonCodes.push("MEDIUM_FINDINGS_OPEN");
  }
  return reasonCodes;
}

export function evaluateIncidentCase(input) {
  const incident = validateIncidentCase(input);
  const reasonCodes = phaseReasonCodes(incident);
  if (NEXT_PHASE_REASONS[incident.phase]) reasonCodes.push(NEXT_PHASE_REASONS[incident.phase]);
  const recommendation =
    incident.phase === "closed"
      ? reasonCodes.length === 0
        ? "CLOSED"
        : "INVALID_CLOSURE_RECORD"
      : incident.phase === "recovery-reviewed" && reasonCodes.length === 0
        ? "READY_FOR_SEPARATE_CLOSURE_REVIEW"
        : "ACTIVE_RESPONSE_REQUIRED";
  const digest = createHash("sha256").update(canonicalJson(incident)).digest("hex");
  return {
    schema: INCIDENT_DECISION_SCHEMA,
    decisionId: `incdec_${digest.slice(0, 32)}`,
    incidentId: incident.incidentId,
    recommendation,
    reasonCodes: reasonCodes.sort(),
    evidenceDigest: incident.evidenceDigest,
    humanAuthorizationRequired: true,
    containmentAuthorized: false,
    accessRevocationAuthorized: false,
    deploymentAuthorized: false,
    signingAuthorized: false,
    assetMovementAuthorized: false
  };
}

export function validateIncidentTransition(currentInput, nextInput) {
  const current = validateIncidentCase(currentInput);
  const next = validateIncidentCase(nextInput);
  if (
    current.incidentId !== next.incidentId ||
    current.openedAt !== next.openedAt ||
    current.environment !== next.environment ||
    current.classification.domain !== next.classification.domain
  ) {
    reject("INCIDENT_TRANSITION_IDENTITY_REJECTED", "Incident identity cannot change");
  }
  if (!TRANSITIONS[current.phase].has(next.phase)) {
    reject("INCIDENT_TRANSITION_REJECTED", "Incident phase transition is not permitted");
  }
  if (Date.parse(next.lastTransitionAt) <= Date.parse(current.lastTransitionAt)) {
    reject("INCIDENT_TRANSITION_TIME_REJECTED", "Incident transition time must move forward");
  }
  if (SEVERITY_INDEX[next.classification.severity] < SEVERITY_INDEX[current.classification.severity]) {
    reject("INCIDENT_TRANSITION_CONTROL_REJECTED", "Incident severity cannot be silently downgraded");
  }
  for (const control of INCIDENT_CONTROL_FIELDS) {
    if (current.controls[control] && !next.controls[control]) {
      reject("INCIDENT_TRANSITION_CONTROL_REJECTED", "Incident controls cannot be weakened");
    }
  }
  for (const currentApproval of current.approvals) {
    const nextApproval = next.approvals.find((approval) => approval.role === currentApproval.role);
    if (!nextApproval || canonicalJson(nextApproval) !== canonicalJson(currentApproval)) {
      reject("INCIDENT_TRANSITION_CONTROL_REJECTED", "Incident approvals are append-only");
    }
  }
  if (phaseReasonCodes(next).length > 0) {
    reject("INCIDENT_TRANSITION_CONTROL_REJECTED", "Required incident controls are incomplete");
  }
  return {
    accepted: true,
    from: current.phase,
    to: next.phase,
    humanAuthorizationRequired: true,
    containmentAuthorized: false,
    accessRevocationAuthorized: false,
    deploymentAuthorized: false,
    signingAuthorized: false,
    assetMovementAuthorized: false
  };
}
