import { createHash } from "node:crypto";
import { VaultLabError } from "./errors.mjs";

export const PRIVILEGED_ACCESS_SCHEMA = "enteleclos.privileged-access.v1";
export const PRIVILEGED_ACCESS_DECISION_SCHEMA = "enteleclos.privileged-access-decision.v1";

const ROOT_FIELDS = new Set([
  "schema",
  "requestId",
  "observedAt",
  "environment",
  "principal",
  "session",
  "action",
  "controls",
  "evidenceDigest"
]);
const PRINCIPAL_FIELDS = new Set([
  "roleClass",
  "employmentStatus",
  "privilegeTier",
  "separationOfDutiesConflict",
  "recentRoleChange"
]);
const SESSION_FIELDS = new Set([
  "assurance",
  "deviceTrust",
  "sessionAgeMinutes",
  "networkTrust",
  "anomalyClass"
]);
const ACTION_FIELDS = new Set(["resourceClass", "riskClass", "changeWindow", "scopeClass"]);
const CONTROL_FIELDS = new Set([
  "phishingResistantMfaSatisfied",
  "freshReauthenticationSatisfied",
  "ticketBound",
  "justInTimeGrant",
  "maxSessionAgeMinutes",
  "grantExpiresMinutes",
  "dualApprovalRequired",
  "dualApprovalSatisfied",
  "breakGlassDeclared",
  "postActionReviewRequired"
]);
const ENVIRONMENTS = new Set(["ci", "staging", "production-observation"]);
const ROLE_CLASSES = new Set(["security", "custody", "operations", "compliance", "support", "automation"]);
const EMPLOYMENT_STATUSES = new Set(["active", "leave", "terminated", "unknown"]);
const PRIVILEGE_TIERS = new Set(["standard", "elevated", "break-glass"]);
const SESSION_ASSURANCE = new Set(["phishing-resistant", "standard", "degraded", "unknown"]);
const DEVICE_TRUST = new Set(["managed", "new", "blocked", "unknown"]);
const NETWORK_TRUST = new Set(["corporate", "approved-remote", "untrusted", "unknown"]);
const ANOMALY_CLASSES = new Set(["none", "elevated", "critical", "unknown"]);
const RESOURCE_CLASSES = new Set([
  "custody-policy",
  "release",
  "withdrawal-policy",
  "user-access",
  "ledger-config",
  "infrastructure",
  "configuration"
]);
const RISK_CLASSES = new Set(["low", "medium", "high", "critical"]);
const CHANGE_WINDOWS = new Set(["approved", "emergency", "outside", "unknown"]);
const SCOPE_CLASSES = new Set(["read-only", "bounded-write", "broad-write", "unknown"]);
const PROHIBITED_FIELD = /(?:address|candidate|command|credential|email|executable|(?:^ip$|ipAddress)|key|mnemonic|name|password|payload|phone|private|raw|secret|seed|signature|target|token|transaction|userId|username|wallet)/iu;

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function reject(code, message) {
  throw new VaultLabError(code, message);
}

function assertExactFields(value, allowed, label) {
  if (!isRecord(value)) reject("PRIVILEGED_ACCESS_INVALID", `${label} must be an object`);
  for (const key of Object.keys(value)) {
    if (PROHIBITED_FIELD.test(key)) {
      reject("PRIVILEGED_ACCESS_PROHIBITED_FIELD", `${label} contains a prohibited field`);
    }
    if (!allowed.has(key)) reject("PRIVILEGED_ACCESS_UNKNOWN_FIELD", `${label} has an unknown field`);
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

export function validatePrivilegedAccessRequest(input) {
  assertExactFields(input, ROOT_FIELDS, "Privileged access request");
  if (input.schema !== PRIVILEGED_ACCESS_SCHEMA) {
    reject("PRIVILEGED_ACCESS_SCHEMA_REJECTED", "Privileged access schema is unsupported");
  }
  if (typeof input.requestId !== "string" || !/^pareq_[0-9a-f]{32}$/u.test(input.requestId)) {
    reject("PRIVILEGED_ACCESS_ID_REJECTED", "Privileged access request identifier is invalid");
  }
  if (typeof input.observedAt !== "string" || Number.isNaN(Date.parse(input.observedAt))) {
    reject("PRIVILEGED_ACCESS_TIME_REJECTED", "Privileged access observation time is invalid");
  }
  if (!ENVIRONMENTS.has(input.environment)) {
    reject("PRIVILEGED_ACCESS_ENVIRONMENT_REJECTED", "Privileged access environment is unsupported");
  }

  assertExactFields(input.principal, PRINCIPAL_FIELDS, "Privileged principal classification");
  if (!ROLE_CLASSES.has(input.principal.roleClass)) {
    reject("PRIVILEGED_ACCESS_PRINCIPAL_REJECTED", "Principal role class is unsupported");
  }
  if (!EMPLOYMENT_STATUSES.has(input.principal.employmentStatus)) {
    reject("PRIVILEGED_ACCESS_PRINCIPAL_REJECTED", "Principal employment status is unsupported");
  }
  if (!PRIVILEGE_TIERS.has(input.principal.privilegeTier)) {
    reject("PRIVILEGED_ACCESS_PRINCIPAL_REJECTED", "Principal privilege tier is unsupported");
  }
  for (const field of ["separationOfDutiesConflict", "recentRoleChange"]) {
    if (typeof input.principal[field] !== "boolean") {
      reject("PRIVILEGED_ACCESS_PRINCIPAL_REJECTED", "Principal classification boolean is invalid");
    }
  }

  assertExactFields(input.session, SESSION_FIELDS, "Privileged session classification");
  if (!SESSION_ASSURANCE.has(input.session.assurance)) {
    reject("PRIVILEGED_ACCESS_SESSION_REJECTED", "Session assurance is unsupported");
  }
  if (!DEVICE_TRUST.has(input.session.deviceTrust)) {
    reject("PRIVILEGED_ACCESS_SESSION_REJECTED", "Device trust is unsupported");
  }
  if (!NETWORK_TRUST.has(input.session.networkTrust)) {
    reject("PRIVILEGED_ACCESS_SESSION_REJECTED", "Network trust is unsupported");
  }
  if (!ANOMALY_CLASSES.has(input.session.anomalyClass)) {
    reject("PRIVILEGED_ACCESS_SESSION_REJECTED", "Session anomaly class is unsupported");
  }
  if (
    !Number.isSafeInteger(input.session.sessionAgeMinutes) ||
    input.session.sessionAgeMinutes < 0 ||
    input.session.sessionAgeMinutes > 1440
  ) {
    reject("PRIVILEGED_ACCESS_SESSION_REJECTED", "Session age is outside policy");
  }

  assertExactFields(input.action, ACTION_FIELDS, "Privileged action classification");
  if (!RESOURCE_CLASSES.has(input.action.resourceClass)) {
    reject("PRIVILEGED_ACCESS_ACTION_REJECTED", "Resource class is unsupported");
  }
  if (!RISK_CLASSES.has(input.action.riskClass)) {
    reject("PRIVILEGED_ACCESS_ACTION_REJECTED", "Action risk class is unsupported");
  }
  if (!CHANGE_WINDOWS.has(input.action.changeWindow)) {
    reject("PRIVILEGED_ACCESS_ACTION_REJECTED", "Change-window class is unsupported");
  }
  if (!SCOPE_CLASSES.has(input.action.scopeClass)) {
    reject("PRIVILEGED_ACCESS_ACTION_REJECTED", "Action scope class is unsupported");
  }

  assertExactFields(input.controls, CONTROL_FIELDS, "Privileged access controls");
  for (const field of [
    "phishingResistantMfaSatisfied",
    "freshReauthenticationSatisfied",
    "ticketBound",
    "justInTimeGrant",
    "dualApprovalRequired",
    "dualApprovalSatisfied",
    "breakGlassDeclared",
    "postActionReviewRequired"
  ]) {
    if (typeof input.controls[field] !== "boolean") {
      reject("PRIVILEGED_ACCESS_CONTROL_REJECTED", "Privileged access control boolean is invalid");
    }
  }
  if (
    !Number.isSafeInteger(input.controls.maxSessionAgeMinutes) ||
    input.controls.maxSessionAgeMinutes < 5 ||
    input.controls.maxSessionAgeMinutes > 720 ||
    !Number.isSafeInteger(input.controls.grantExpiresMinutes) ||
    input.controls.grantExpiresMinutes < 5 ||
    input.controls.grantExpiresMinutes > 60 ||
    input.controls.grantExpiresMinutes > input.controls.maxSessionAgeMinutes
  ) {
    reject("PRIVILEGED_ACCESS_CONTROL_REJECTED", "Privileged session limits are outside policy");
  }
  if (typeof input.evidenceDigest !== "string" || !/^[0-9a-f]{64}$/u.test(input.evidenceDigest)) {
    reject("PRIVILEGED_ACCESS_EVIDENCE_REJECTED", "Privileged access evidence digest is invalid");
  }
  return structuredClone(input);
}

export function evaluatePrivilegedAccessRequest(input) {
  const request = validatePrivilegedAccessRequest(input);
  const reasonCodes = [];
  if (request.principal.employmentStatus !== "active") reasonCodes.push("PRINCIPAL_STATUS_NOT_ACTIVE");
  if (request.principal.separationOfDutiesConflict) reasonCodes.push("SEPARATION_OF_DUTIES_CONFLICT");
  if (request.session.assurance === "degraded") reasonCodes.push("SESSION_ASSURANCE_DEGRADED");
  if (request.session.deviceTrust === "blocked") reasonCodes.push("DEVICE_BLOCKED");
  if (request.session.networkTrust === "untrusted") reasonCodes.push("NETWORK_UNTRUSTED");
  if (request.session.anomalyClass === "critical") reasonCodes.push("CRITICAL_SESSION_ANOMALY");
  if (request.session.sessionAgeMinutes > request.controls.maxSessionAgeMinutes) {
    reasonCodes.push("SESSION_MAX_AGE_EXCEEDED");
  }
  if (!request.controls.phishingResistantMfaSatisfied) reasonCodes.push("PHISHING_RESISTANT_MFA_REQUIRED");
  if (!request.controls.freshReauthenticationSatisfied) reasonCodes.push("FRESH_REAUTHENTICATION_REQUIRED");
  if (!request.controls.ticketBound) reasonCodes.push("TICKET_BINDING_REQUIRED");
  if (!request.controls.justInTimeGrant) reasonCodes.push("JUST_IN_TIME_GRANT_REQUIRED");
  if (request.controls.dualApprovalRequired && !request.controls.dualApprovalSatisfied) {
    reasonCodes.push("DUAL_APPROVAL_INCOMPLETE");
  }
  if (
    new Set(["high", "critical"]).has(request.action.riskClass) &&
    !request.controls.dualApprovalRequired
  ) {
    reasonCodes.push("DUAL_APPROVAL_POLICY_MISSING");
  }
  if (request.action.scopeClass === "broad-write" && !request.controls.dualApprovalRequired) {
    reasonCodes.push("BROAD_WRITE_DUAL_APPROVAL_MISSING");
  }
  if (request.principal.privilegeTier === "break-glass" && !request.controls.breakGlassDeclared) {
    reasonCodes.push("BREAK_GLASS_DECLARATION_REQUIRED");
  }
  if (request.controls.breakGlassDeclared && !request.controls.postActionReviewRequired) {
    reasonCodes.push("BREAK_GLASS_REVIEW_REQUIRED");
  }
  if (new Set(["outside", "unknown"]).has(request.action.changeWindow)) {
    reasonCodes.push("CHANGE_WINDOW_NOT_APPROVED");
  }
  if (request.action.scopeClass === "unknown") reasonCodes.push("ACTION_SCOPE_UNKNOWN");

  const reviewRequired =
    request.principal.recentRoleChange ||
    request.principal.privilegeTier !== "standard" ||
    request.session.assurance !== "phishing-resistant" ||
    request.session.deviceTrust !== "managed" ||
    request.session.networkTrust !== "corporate" ||
    request.session.anomalyClass !== "none" ||
    request.action.riskClass !== "low" ||
    request.action.scopeClass !== "read-only" ||
    request.action.changeWindow === "emergency" ||
    request.controls.breakGlassDeclared;
  const recommendation =
    reasonCodes.length > 0
      ? "BLOCK_AND_ESCALATE"
      : reviewRequired
        ? "REQUIRE_HUMAN_PRIVILEGE_REVIEW"
        : "PROCEED_TO_SEPARATE_ACCESS_AUTHORIZATION";
  const digest = createHash("sha256").update(canonicalJson(request)).digest("hex");
  return {
    schema: PRIVILEGED_ACCESS_DECISION_SCHEMA,
    decisionId: `padec_${digest.slice(0, 32)}`,
    requestId: request.requestId,
    recommendation,
    reasonCodes: [...new Set(reasonCodes)].sort(),
    evidenceDigest: request.evidenceDigest,
    humanAuthorizationRequired: true,
    accessGrantAuthorized: false,
    privilegedActionAuthorized: false,
    deploymentAuthorized: false,
    signingAuthorized: false,
    assetMovementAuthorized: false
  };
}
