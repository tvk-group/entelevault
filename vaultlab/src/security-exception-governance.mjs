import { createHash } from "node:crypto";
import { VaultLabError } from "./errors.mjs";

export const SECURITY_EXCEPTION_SCHEMA = "enteleclos.security-exception-governance.v1";
export const SECURITY_EXCEPTION_DECISION_SCHEMA = "enteleclos.security-exception-decision.v1";

export const SECURITY_EXCEPTION_CONTROL_FIELDS = Object.freeze([
  "scopeBound",
  "ownerAssigned",
  "customerImpactAssessed",
  "regulatoryImpactAssessed",
  "remediationPlanApproved",
  "compensatingControlsVerified",
  "monitoringPlanVerified",
  "expiryEnforced",
  "rollbackPlanVerified",
  "remediationVerified",
  "independentClosureApproved"
]);

const ROOT_FIELDS = new Set([
  "schema",
  "exceptionId",
  "phase",
  "requestedAt",
  "lastTransitionAt",
  "expiresAt",
  "environment",
  "scope",
  "controls",
  "approvals",
  "findings",
  "evidenceDigest"
]);
const SCOPE_FIELDS = new Set(["component", "controlFamily", "riskClass", "exceptionClass"]);
const CONTROL_FIELDS = new Set([...SECURITY_EXCEPTION_CONTROL_FIELDS, "maxDurationHours"]);
const APPROVAL_FIELDS = new Set(["role", "approverId", "approvedAt", "attestationDigest"]);
const FINDING_FIELDS = new Set(["criticalOpen", "highOpen", "mediumOpen"]);
const PHASES = Object.freeze([
  "requested",
  "triaged",
  "compensating-controls-verified",
  "risk-review-approved",
  "monitoring-active",
  "remediated",
  "independently-closed"
]);
const PHASE_INDEX = Object.freeze(Object.fromEntries(PHASES.map((phase, index) => [phase, index])));
const TRANSITIONS = Object.freeze({
  requested: new Set(["triaged"]),
  triaged: new Set(["compensating-controls-verified"]),
  "compensating-controls-verified": new Set(["risk-review-approved"]),
  "risk-review-approved": new Set(["monitoring-active"]),
  "monitoring-active": new Set(["remediated"]),
  remediated: new Set(["independently-closed"]),
  "independently-closed": new Set()
});
const TRIAGE_CONTROLS = Object.freeze([
  "scopeBound",
  "ownerAssigned",
  "customerImpactAssessed",
  "regulatoryImpactAssessed"
]);
const RISK_REVIEW_CONTROLS = Object.freeze([
  ...TRIAGE_CONTROLS,
  "remediationPlanApproved",
  "compensatingControlsVerified",
  "monitoringPlanVerified",
  "expiryEnforced",
  "rollbackPlanVerified"
]);
const ALLOWED_CONTROLS_BY_PHASE = Object.freeze({
  requested: [],
  triaged: TRIAGE_CONTROLS,
  "compensating-controls-verified": RISK_REVIEW_CONTROLS,
  "risk-review-approved": RISK_REVIEW_CONTROLS,
  "monitoring-active": RISK_REVIEW_CONTROLS,
  remediated: [...RISK_REVIEW_CONTROLS, "remediationVerified"],
  "independently-closed": SECURITY_EXCEPTION_CONTROL_FIELDS
});
const REQUIRED_CONTROLS_BY_PHASE = ALLOWED_CONTROLS_BY_PHASE;
const CONTROL_REASON_CODES = Object.freeze({
  scopeBound: "EXCEPTION_SCOPE_UNBOUND",
  ownerAssigned: "EXCEPTION_OWNER_UNASSIGNED",
  customerImpactAssessed: "CUSTOMER_IMPACT_UNASSESSED",
  regulatoryImpactAssessed: "REGULATORY_IMPACT_UNASSESSED",
  remediationPlanApproved: "REMEDIATION_PLAN_UNAPPROVED",
  compensatingControlsVerified: "COMPENSATING_CONTROLS_UNVERIFIED",
  monitoringPlanVerified: "MONITORING_PLAN_UNVERIFIED",
  expiryEnforced: "EXPIRY_ENFORCEMENT_UNVERIFIED",
  rollbackPlanVerified: "ROLLBACK_PLAN_UNVERIFIED",
  remediationVerified: "REMEDIATION_UNVERIFIED",
  independentClosureApproved: "INDEPENDENT_CLOSURE_UNAPPROVED"
});
const NEXT_PHASE_REASON = Object.freeze({
  requested: "TRIAGE_REQUIRED",
  triaged: "COMPENSATING_CONTROL_VERIFICATION_REQUIRED",
  "compensating-controls-verified": "RISK_REVIEW_REQUIRED",
  "risk-review-approved": "SEPARATE_EXCEPTION_AUTHORIZATION_REQUIRED",
  "monitoring-active": "REMEDIATION_REQUIRED"
});
const ENVIRONMENTS = new Set(["staging", "production-observation"]);
const COMPONENTS = new Set([
  "enteleclos-assurance",
  "enteleexchange-api",
  "enteleexchange-web",
  "entelevault-service",
  "entelewallet-client"
]);
const CONTROL_FAMILIES = new Set([
  "authentication",
  "authorization",
  "custody",
  "cryptography",
  "supply-chain",
  "resilience",
  "monitoring",
  "privacy"
]);
const RISK_CLASSES = Object.freeze(["low", "moderate", "high", "critical"]);
const RISK_INDEX = Object.freeze(Object.fromEntries(RISK_CLASSES.map((value, index) => [value, index])));
const EXCEPTION_CLASSES = new Set([
  "temporary-operational",
  "vendor-dependency",
  "migration",
  "false-positive-investigation"
]);
const APPROVAL_ROLES = new Set(["security", "risk", "control-owner", "privacy", "compliance", "independent-review"]);
const AUTHORIZATION_QUORUM = Object.freeze(["security", "risk", "control-owner"]);
const PROHIBITED_FIELD = /(?:address|candidate|command|credential|email|executable|identityValue|key|mnemonic|password|payload|private|raw(?:Body|Data|Log|Message|Payload|Request|Value)|secret|seed|signatureValue|target|token|transaction|user|walletData|walletFile)/iu;

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function reject(code, message) {
  throw new VaultLabError(code, message);
}

function assertExactFields(value, allowed, label) {
  if (!isRecord(value)) reject("SECURITY_EXCEPTION_INVALID", `${label} must be an object`);
  for (const key of Object.keys(value)) {
    if (PROHIBITED_FIELD.test(key)) {
      reject("SECURITY_EXCEPTION_PROHIBITED_FIELD", `${label} contains a prohibited field`);
    }
    if (!allowed.has(key)) reject("SECURITY_EXCEPTION_UNKNOWN_FIELD", `${label} has an unknown field`);
  }
  if (Object.keys(value).length !== allowed.size) {
    reject("SECURITY_EXCEPTION_UNKNOWN_FIELD", `${label} field set is incomplete or unknown`);
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

export function validateSecurityExceptionCase(input) {
  assertExactFields(input, ROOT_FIELDS, "Security-exception case");
  if (input.schema !== SECURITY_EXCEPTION_SCHEMA) {
    reject("SECURITY_EXCEPTION_SCHEMA_REJECTED", "Security-exception schema is unsupported");
  }
  if (typeof input.exceptionId !== "string" || !/^exception_[0-9a-f]{32}$/u.test(input.exceptionId)) {
    reject("SECURITY_EXCEPTION_ID_REJECTED", "Security-exception identifier is invalid");
  }
  if (!PHASES.includes(input.phase)) {
    reject("SECURITY_EXCEPTION_PHASE_REJECTED", "Security-exception phase is unsupported");
  }
  const requestedAt = Date.parse(input.requestedAt);
  const lastTransitionAt = Date.parse(input.lastTransitionAt);
  const expiresAt = Date.parse(input.expiresAt);
  if (
    typeof input.requestedAt !== "string" || Number.isNaN(requestedAt) ||
    typeof input.lastTransitionAt !== "string" || Number.isNaN(lastTransitionAt) ||
    typeof input.expiresAt !== "string" || Number.isNaN(expiresAt) ||
    lastTransitionAt < requestedAt || expiresAt <= requestedAt
  ) {
    reject("SECURITY_EXCEPTION_TIME_REJECTED", "Security-exception timestamps are invalid");
  }
  if (!ENVIRONMENTS.has(input.environment)) {
    reject("SECURITY_EXCEPTION_ENVIRONMENT_REJECTED", "Security-exception environment is unsupported");
  }

  assertExactFields(input.scope, SCOPE_FIELDS, "Security-exception scope");
  if (!COMPONENTS.has(input.scope.component) || !CONTROL_FAMILIES.has(input.scope.controlFamily)) {
    reject("SECURITY_EXCEPTION_SCOPE_REJECTED", "Security-exception scope is unsupported");
  }
  if (!RISK_CLASSES.includes(input.scope.riskClass) || !EXCEPTION_CLASSES.has(input.scope.exceptionClass)) {
    reject("SECURITY_EXCEPTION_SCOPE_REJECTED", "Security-exception classification is unsupported");
  }

  assertExactFields(input.controls, CONTROL_FIELDS, "Security-exception controls");
  for (const control of SECURITY_EXCEPTION_CONTROL_FIELDS) {
    if (typeof input.controls[control] !== "boolean") {
      reject("SECURITY_EXCEPTION_CONTROL_REJECTED", "Security-exception control value is invalid");
    }
  }
  if (!Number.isSafeInteger(input.controls.maxDurationHours) || input.controls.maxDurationHours < 1 || input.controls.maxDurationHours > 720) {
    reject("SECURITY_EXCEPTION_DURATION_REJECTED", "Security-exception duration is outside policy");
  }
  const actualDurationHours = (expiresAt - requestedAt) / 3_600_000;
  if (actualDurationHours > input.controls.maxDurationHours) {
    reject("SECURITY_EXCEPTION_DURATION_REJECTED", "Security-exception expiry exceeds the approved maximum duration");
  }
  const allowedControls = new Set(ALLOWED_CONTROLS_BY_PHASE[input.phase]);
  if (SECURITY_EXCEPTION_CONTROL_FIELDS.some((control) => input.controls[control] && !allowedControls.has(control))) {
    reject("SECURITY_EXCEPTION_CONTROL_REJECTED", "Security-exception controls cannot be completed before their phase");
  }

  if (!Array.isArray(input.approvals) || input.approvals.length > 6) {
    reject("SECURITY_EXCEPTION_APPROVAL_REJECTED", "Security-exception approvals are outside policy");
  }
  for (const approval of input.approvals) {
    assertExactFields(approval, APPROVAL_FIELDS, "Security-exception approval");
    if (!APPROVAL_ROLES.has(approval.role)) {
      reject("SECURITY_EXCEPTION_APPROVAL_REJECTED", "Security-exception approval role is unsupported");
    }
    if (typeof approval.approverId !== "string" || !/^approver_[0-9a-f]{16}$/u.test(approval.approverId)) {
      reject("SECURITY_EXCEPTION_APPROVAL_REJECTED", "Security-exception approver identifier is invalid");
    }
    const approvedAt = Date.parse(approval.approvedAt);
    if (
      typeof approval.approvedAt !== "string" || Number.isNaN(approvedAt) ||
      approvedAt < requestedAt || approvedAt > lastTransitionAt
    ) {
      reject("SECURITY_EXCEPTION_APPROVAL_REJECTED", "Security-exception approval time is invalid");
    }
    if (typeof approval.attestationDigest !== "string" || !/^[0-9a-f]{64}$/u.test(approval.attestationDigest)) {
      reject("SECURITY_EXCEPTION_APPROVAL_REJECTED", "Security-exception approval attestation is invalid");
    }
  }
  if (new Set(input.approvals.map((approval) => approval.role)).size !== input.approvals.length) {
    reject("SECURITY_EXCEPTION_APPROVAL_REJECTED", "Security-exception approval roles must be unique");
  }
  if (new Set(input.approvals.map((approval) => approval.approverId)).size !== input.approvals.length) {
    reject("SECURITY_EXCEPTION_APPROVAL_REJECTED", "Security-exception approvers must be independent");
  }
  if (PHASE_INDEX[input.phase] < PHASE_INDEX["risk-review-approved"] && input.approvals.length > 0) {
    reject("SECURITY_EXCEPTION_APPROVAL_REJECTED", "Security-exception approvals cannot precede risk review");
  }
  if (
    input.phase !== "independently-closed" &&
    input.approvals.some((approval) => approval.role === "independent-review")
  ) {
    reject("SECURITY_EXCEPTION_APPROVAL_REJECTED", "Closure approval cannot precede independent closure");
  }

  assertExactFields(input.findings, FINDING_FIELDS, "Security-exception findings");
  for (const field of FINDING_FIELDS) {
    if (!Number.isSafeInteger(input.findings[field]) || input.findings[field] < 0 || input.findings[field] > 1000) {
      reject("SECURITY_EXCEPTION_FINDING_REJECTED", "Security-exception finding count is invalid");
    }
  }
  if (typeof input.evidenceDigest !== "string" || !/^[0-9a-f]{64}$/u.test(input.evidenceDigest)) {
    reject("SECURITY_EXCEPTION_EVIDENCE_REJECTED", "Security-exception evidence digest is invalid");
  }
  return structuredClone(input);
}

function phaseReasonCodes(exceptionCase) {
  const reasonCodes = REQUIRED_CONTROLS_BY_PHASE[exceptionCase.phase]
    .filter((control) => !exceptionCase.controls[control])
    .map((control) => CONTROL_REASON_CODES[control]);
  if (exceptionCase.scope.riskClass === "critical") {
    reasonCodes.push("CRITICAL_RISK_EXCEPTION_PROHIBITED");
  }
  if (
    PHASE_INDEX[exceptionCase.phase] >= PHASE_INDEX["risk-review-approved"] &&
    PHASE_INDEX[exceptionCase.phase] <= PHASE_INDEX["monitoring-active"] &&
    Date.parse(exceptionCase.lastTransitionAt) >= Date.parse(exceptionCase.expiresAt)
  ) {
    reasonCodes.push("EXCEPTION_EXPIRED");
  }
  if (PHASE_INDEX[exceptionCase.phase] >= PHASE_INDEX["risk-review-approved"]) {
    const roles = new Set(exceptionCase.approvals.map((approval) => approval.role));
    if (AUTHORIZATION_QUORUM.some((role) => !roles.has(role))) reasonCodes.push("AUTHORIZATION_QUORUM_INCOMPLETE");
    if (exceptionCase.findings.criticalOpen > 0) reasonCodes.push("CRITICAL_FINDINGS_OPEN");
    if (exceptionCase.findings.highOpen > 0) reasonCodes.push("HIGH_FINDINGS_OPEN");
  }
  if (exceptionCase.phase === "independently-closed") {
    const roles = new Set(exceptionCase.approvals.map((approval) => approval.role));
    if (!roles.has("independent-review")) reasonCodes.push("INDEPENDENT_REVIEW_MISSING");
    if (exceptionCase.findings.mediumOpen > 0) reasonCodes.push("MEDIUM_FINDINGS_OPEN");
  }
  return reasonCodes;
}

export function evaluateSecurityException(input) {
  const exceptionCase = validateSecurityExceptionCase(input);
  const governanceReasons = phaseReasonCodes(exceptionCase);
  const reasonCodes = [...governanceReasons];
  if (NEXT_PHASE_REASON[exceptionCase.phase]) reasonCodes.push(NEXT_PHASE_REASON[exceptionCase.phase]);
  let recommendation = "ACTIVE_EXCEPTION_GOVERNANCE_REQUIRED";
  if (exceptionCase.phase === "risk-review-approved" && governanceReasons.length === 0) {
    recommendation = "READY_FOR_SEPARATE_EXCEPTION_AUTHORIZATION";
  } else if (exceptionCase.phase === "monitoring-active" && governanceReasons.length === 0) {
    recommendation = "ACTIVE_MONITORING_REQUIRED";
  } else if (exceptionCase.phase === "remediated" && governanceReasons.length === 0) {
    recommendation = "READY_FOR_SEPARATE_CLOSURE_REVIEW";
  } else if (exceptionCase.phase === "independently-closed") {
    recommendation = governanceReasons.length === 0 ? "CLOSED" : "INVALID_CLOSURE_RECORD";
  }
  const digest = createHash("sha256").update(canonicalJson(exceptionCase)).digest("hex");
  return {
    schema: SECURITY_EXCEPTION_DECISION_SCHEMA,
    decisionId: `exceptiondec_${digest.slice(0, 32)}`,
    exceptionId: exceptionCase.exceptionId,
    recommendation,
    reasonCodes: reasonCodes.sort(),
    evidenceDigest: exceptionCase.evidenceDigest,
    humanAuthorizationRequired: true,
    exceptionGrantAuthorized: false,
    policyBypassAuthorized: false,
    accessGrantAuthorized: false,
    remediationExecutionAuthorized: false,
    deploymentAuthorized: false,
    signingAuthorized: false,
    assetMovementAuthorized: false
  };
}

export function validateSecurityExceptionTransition(currentInput, nextInput) {
  const current = validateSecurityExceptionCase(currentInput);
  const next = validateSecurityExceptionCase(nextInput);
  if (
    current.exceptionId !== next.exceptionId ||
    current.requestedAt !== next.requestedAt ||
    current.expiresAt !== next.expiresAt ||
    current.environment !== next.environment ||
    current.scope.component !== next.scope.component ||
    current.scope.controlFamily !== next.scope.controlFamily ||
    current.scope.exceptionClass !== next.scope.exceptionClass
  ) {
    reject("SECURITY_EXCEPTION_TRANSITION_IDENTITY_REJECTED", "Security-exception identity, scope, and expiry cannot change");
  }
  if (!TRANSITIONS[current.phase].has(next.phase)) {
    reject("SECURITY_EXCEPTION_TRANSITION_REJECTED", "Security-exception phase transition is not permitted");
  }
  if (Date.parse(next.lastTransitionAt) <= Date.parse(current.lastTransitionAt)) {
    reject("SECURITY_EXCEPTION_TRANSITION_TIME_REJECTED", "Security-exception transition time must move forward");
  }
  if (RISK_INDEX[next.scope.riskClass] < RISK_INDEX[current.scope.riskClass]) {
    reject("SECURITY_EXCEPTION_TRANSITION_CONTROL_REJECTED", "Security-exception risk cannot be silently downgraded");
  }
  if (current.controls.maxDurationHours !== next.controls.maxDurationHours) {
    reject("SECURITY_EXCEPTION_TRANSITION_CONTROL_REJECTED", "Security-exception maximum duration is immutable");
  }
  for (const control of SECURITY_EXCEPTION_CONTROL_FIELDS) {
    if (current.controls[control] && !next.controls[control]) {
      reject("SECURITY_EXCEPTION_TRANSITION_CONTROL_REJECTED", "Security-exception controls cannot be weakened");
    }
  }
  for (const currentApproval of current.approvals) {
    const nextApproval = next.approvals.find((approval) => approval.role === currentApproval.role);
    if (!nextApproval || canonicalJson(nextApproval) !== canonicalJson(currentApproval)) {
      reject("SECURITY_EXCEPTION_TRANSITION_CONTROL_REJECTED", "Security-exception approvals are append-only");
    }
  }
  if (phaseReasonCodes(next).length > 0) {
    reject("SECURITY_EXCEPTION_TRANSITION_CONTROL_REJECTED", "Required security-exception governance evidence is incomplete");
  }
  return {
    accepted: true,
    from: current.phase,
    to: next.phase,
    humanAuthorizationRequired: true,
    exceptionGrantAuthorized: false,
    policyBypassAuthorized: false,
    accessGrantAuthorized: false,
    remediationExecutionAuthorized: false,
    deploymentAuthorized: false,
    signingAuthorized: false,
    assetMovementAuthorized: false
  };
}
