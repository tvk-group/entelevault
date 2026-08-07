import { createHash } from "node:crypto";
import { VaultLabError } from "./errors.mjs";

export const API_SESSION_SCHEMA = "enteleclos.api-session-security.v1";
export const API_SESSION_DECISION_SCHEMA = "enteleclos.api-session-decision.v1";

const ROOT_FIELDS = new Set([
  "schema",
  "requestId",
  "observedAt",
  "environment",
  "client",
  "session",
  "request",
  "controls",
  "evidenceDigest"
]);
const CLIENT_FIELDS = new Set([
  "clientClass",
  "registrationStatus",
  "authMaterialAgeClass",
  "scopeClass",
  "ownerStatus"
]);
const SESSION_FIELDS = new Set([
  "assurance",
  "deviceTrust",
  "networkTrust",
  "ageMinutes",
  "anomalyClass"
]);
const REQUEST_FIELDS = new Set([
  "operationClass",
  "riskClass",
  "replayStatus",
  "originStatus",
  "rateClass"
]);
const CONTROL_FIELDS = new Set([
  "clientRegistrationVerified",
  "leastPrivilegeVerified",
  "mutualTlsRequired",
  "mutualTlsSatisfied",
  "requestSignatureRequired",
  "requestSignatureVerified",
  "nonceVerified",
  "timestampWindowVerified",
  "rateLimitApplied",
  "schemaValidated",
  "idempotencyVerified",
  "sessionRevocationChecked",
  "maxSessionAgeMinutes",
  "dualApprovalRequired",
  "dualApprovalSatisfied"
]);
const ENVIRONMENTS = new Set(["ci", "staging", "production-observation"]);
const CLIENT_CLASSES = new Set(["first-party-service", "partner-service", "user-device", "automation"]);
const REGISTRATION_STATUSES = new Set(["approved", "pending", "revoked", "unknown"]);
const AUTH_MATERIAL_AGE = new Set(["current", "rotation-due", "expired", "unknown"]);
const SCOPE_CLASSES = new Set(["read-only", "bounded-write", "privileged", "unknown"]);
const OWNER_STATUSES = new Set(["active", "suspended", "unknown"]);
const SESSION_ASSURANCE = new Set([
  "phishing-resistant",
  "mutual-tls",
  "signed-request",
  "standard",
  "degraded",
  "unknown"
]);
const DEVICE_TRUST = new Set(["managed", "attested", "new", "blocked", "unknown"]);
const NETWORK_TRUST = new Set(["private", "approved-public", "untrusted", "unknown"]);
const ANOMALY_CLASSES = new Set(["none", "elevated", "critical", "unknown"]);
const OPERATION_CLASSES = new Set([
  "read",
  "quote",
  "order-submit",
  "withdrawal-request",
  "admin-config",
  "unknown"
]);
const RISK_CLASSES = new Set(["low", "medium", "high", "critical", "unknown"]);
const REPLAY_STATUSES = new Set(["fresh", "replayed", "unknown"]);
const ORIGIN_STATUSES = new Set(["allowlisted", "new", "blocked", "unknown"]);
const RATE_CLASSES = new Set(["normal", "elevated", "limit-exceeded", "unknown"]);
const WRITE_OPERATIONS = new Set(["order-submit", "withdrawal-request", "admin-config"]);
const PROHIBITED_FIELD = /(?:address|apiKey|body|candidate|command|credential|email|executable|ipAddress|keyMaterial|mnemonic|password|payload|private|(?:^raw$|raw(?:Body|Data|Message|Payload|Request|Signature|Transaction|Value))|secret|seed|signatureValue|target|token|transaction|userId|username|wallet)/iu;

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function reject(code, message) {
  throw new VaultLabError(code, message);
}

function assertExactFields(value, allowed, label) {
  if (!isRecord(value)) reject("API_SESSION_INVALID", `${label} must be an object`);
  for (const key of Object.keys(value)) {
    if (PROHIBITED_FIELD.test(key)) {
      reject("API_SESSION_PROHIBITED_FIELD", `${label} contains a prohibited field`);
    }
    if (!allowed.has(key)) reject("API_SESSION_UNKNOWN_FIELD", `${label} has an unknown field`);
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

export function validateApiSessionRequest(input) {
  assertExactFields(input, ROOT_FIELDS, "API/session request");
  if (input.schema !== API_SESSION_SCHEMA) {
    reject("API_SESSION_SCHEMA_REJECTED", "API/session schema is unsupported");
  }
  if (typeof input.requestId !== "string" || !/^apireq_[0-9a-f]{32}$/u.test(input.requestId)) {
    reject("API_SESSION_ID_REJECTED", "API/session request identifier is invalid");
  }
  if (typeof input.observedAt !== "string" || Number.isNaN(Date.parse(input.observedAt))) {
    reject("API_SESSION_TIME_REJECTED", "API/session observation time is invalid");
  }
  if (!ENVIRONMENTS.has(input.environment)) {
    reject("API_SESSION_ENVIRONMENT_REJECTED", "API/session environment is unsupported");
  }

  assertExactFields(input.client, CLIENT_FIELDS, "API client classification");
  if (!CLIENT_CLASSES.has(input.client.clientClass)) reject("API_CLIENT_REJECTED", "API client class is unsupported");
  if (!REGISTRATION_STATUSES.has(input.client.registrationStatus)) {
    reject("API_CLIENT_REJECTED", "API client registration status is unsupported");
  }
  if (!AUTH_MATERIAL_AGE.has(input.client.authMaterialAgeClass)) {
    reject("API_CLIENT_REJECTED", "API authentication-material age class is unsupported");
  }
  if (!SCOPE_CLASSES.has(input.client.scopeClass)) reject("API_CLIENT_REJECTED", "API scope class is unsupported");
  if (!OWNER_STATUSES.has(input.client.ownerStatus)) reject("API_CLIENT_REJECTED", "API owner status is unsupported");

  assertExactFields(input.session, SESSION_FIELDS, "API session classification");
  if (!SESSION_ASSURANCE.has(input.session.assurance)) reject("API_SESSION_REJECTED", "API session assurance is unsupported");
  if (!DEVICE_TRUST.has(input.session.deviceTrust)) reject("API_SESSION_REJECTED", "API device trust is unsupported");
  if (!NETWORK_TRUST.has(input.session.networkTrust)) reject("API_SESSION_REJECTED", "API network trust is unsupported");
  if (!ANOMALY_CLASSES.has(input.session.anomalyClass)) reject("API_SESSION_REJECTED", "API anomaly class is unsupported");
  if (!Number.isSafeInteger(input.session.ageMinutes) || input.session.ageMinutes < 0 || input.session.ageMinutes > 1440) {
    reject("API_SESSION_REJECTED", "API session age is outside policy");
  }

  assertExactFields(input.request, REQUEST_FIELDS, "API request classification");
  if (!OPERATION_CLASSES.has(input.request.operationClass)) reject("API_REQUEST_REJECTED", "API operation class is unsupported");
  if (!RISK_CLASSES.has(input.request.riskClass)) reject("API_REQUEST_REJECTED", "API request risk class is unsupported");
  if (!REPLAY_STATUSES.has(input.request.replayStatus)) reject("API_REQUEST_REJECTED", "API replay status is unsupported");
  if (!ORIGIN_STATUSES.has(input.request.originStatus)) reject("API_REQUEST_REJECTED", "API origin status is unsupported");
  if (!RATE_CLASSES.has(input.request.rateClass)) reject("API_REQUEST_REJECTED", "API rate class is unsupported");

  assertExactFields(input.controls, CONTROL_FIELDS, "API/session controls");
  for (const field of CONTROL_FIELDS) {
    if (field !== "maxSessionAgeMinutes" && typeof input.controls[field] !== "boolean") {
      reject("API_CONTROL_REJECTED", "API/session control value is invalid");
    }
  }
  if (
    !Number.isSafeInteger(input.controls.maxSessionAgeMinutes) ||
    input.controls.maxSessionAgeMinutes < 5 ||
    input.controls.maxSessionAgeMinutes > 720
  ) {
    reject("API_CONTROL_REJECTED", "API maximum session age is outside policy");
  }
  if (typeof input.evidenceDigest !== "string" || !/^[0-9a-f]{64}$/u.test(input.evidenceDigest)) {
    reject("API_EVIDENCE_REJECTED", "API/session evidence digest is invalid");
  }
  return structuredClone(input);
}

export function evaluateApiSessionRequest(input) {
  const request = validateApiSessionRequest(input);
  const reasonCodes = [];
  if (request.client.registrationStatus !== "approved" || !request.controls.clientRegistrationVerified) {
    reasonCodes.push("CLIENT_REGISTRATION_UNVERIFIED");
  }
  if (request.client.ownerStatus !== "active") reasonCodes.push("CLIENT_OWNER_NOT_ACTIVE");
  if (new Set(["expired", "unknown"]).has(request.client.authMaterialAgeClass)) reasonCodes.push("AUTH_MATERIAL_NOT_CURRENT");
  if (request.client.scopeClass === "unknown") reasonCodes.push("CLIENT_SCOPE_UNKNOWN");
  if (WRITE_OPERATIONS.has(request.request.operationClass) && request.client.scopeClass === "read-only") {
    reasonCodes.push("WRITE_SCOPE_INSUFFICIENT");
  }
  if (!request.controls.leastPrivilegeVerified) reasonCodes.push("LEAST_PRIVILEGE_UNVERIFIED");
  if (request.session.assurance === "degraded" || request.session.assurance === "unknown") {
    reasonCodes.push("SESSION_ASSURANCE_INSUFFICIENT");
  }
  if (request.session.deviceTrust === "blocked" || request.session.deviceTrust === "unknown") reasonCodes.push("DEVICE_TRUST_INSUFFICIENT");
  if (request.session.networkTrust === "untrusted" || request.session.networkTrust === "unknown") reasonCodes.push("NETWORK_TRUST_INSUFFICIENT");
  if (request.session.anomalyClass === "critical" || request.session.anomalyClass === "unknown") reasonCodes.push("SESSION_ANOMALY_UNRESOLVED");
  if (request.session.ageMinutes > request.controls.maxSessionAgeMinutes) reasonCodes.push("SESSION_MAX_AGE_EXCEEDED");
  if (request.request.replayStatus !== "fresh" || !request.controls.nonceVerified || !request.controls.timestampWindowVerified) {
    reasonCodes.push("REPLAY_PROTECTION_INCOMPLETE");
  }
  if (request.request.originStatus === "blocked" || request.request.originStatus === "unknown") reasonCodes.push("REQUEST_ORIGIN_UNTRUSTED");
  if (request.request.rateClass === "limit-exceeded" || request.request.rateClass === "unknown") reasonCodes.push("RATE_POLICY_VIOLATION");
  if (!request.controls.rateLimitApplied) reasonCodes.push("RATE_LIMIT_NOT_APPLIED");
  if (!request.controls.schemaValidated) reasonCodes.push("REQUEST_SCHEMA_UNVALIDATED");
  if (!request.controls.idempotencyVerified) reasonCodes.push("IDEMPOTENCY_UNVERIFIED");
  if (!request.controls.sessionRevocationChecked) reasonCodes.push("SESSION_REVOCATION_UNCHECKED");
  if (request.controls.mutualTlsRequired && !request.controls.mutualTlsSatisfied) reasonCodes.push("MUTUAL_TLS_INCOMPLETE");
  if (
    new Set(["partner-service", "automation"]).has(request.client.clientClass) &&
    !request.controls.mutualTlsRequired
  ) {
    reasonCodes.push("MUTUAL_TLS_POLICY_MISSING");
  }
  if (request.controls.requestSignatureRequired && !request.controls.requestSignatureVerified) {
    reasonCodes.push("REQUEST_SIGNATURE_UNVERIFIED");
  }
  if (WRITE_OPERATIONS.has(request.request.operationClass) && !request.controls.requestSignatureRequired) {
    reasonCodes.push("REQUEST_SIGNATURE_POLICY_MISSING");
  }
  if (request.controls.dualApprovalRequired && !request.controls.dualApprovalSatisfied) reasonCodes.push("DUAL_APPROVAL_INCOMPLETE");
  if (
    (new Set(["high", "critical"]).has(request.request.riskClass) ||
      request.client.scopeClass === "privileged" ||
      new Set(["withdrawal-request", "admin-config"]).has(request.request.operationClass)) &&
    !request.controls.dualApprovalRequired
  ) {
    reasonCodes.push("DUAL_APPROVAL_POLICY_MISSING");
  }

  const reviewRequired =
    request.client.authMaterialAgeClass === "rotation-due" ||
    request.client.clientClass === "user-device" ||
    request.session.assurance === "standard" ||
    request.session.deviceTrust === "new" ||
    request.session.networkTrust === "approved-public" ||
    request.session.anomalyClass === "elevated" ||
    request.request.originStatus === "new" ||
    request.request.rateClass === "elevated" ||
    request.request.riskClass !== "low" ||
    request.request.operationClass !== "read" ||
    request.client.scopeClass !== "read-only";
  const recommendation =
    reasonCodes.length > 0
      ? "BLOCK_AND_ESCALATE"
      : reviewRequired
        ? "REQUIRE_HUMAN_API_RISK_REVIEW"
        : "PROCEED_TO_SEPARATE_API_AUTHORIZATION";
  const digest = createHash("sha256").update(canonicalJson(request)).digest("hex");
  return {
    schema: API_SESSION_DECISION_SCHEMA,
    decisionId: `apidec_${digest.slice(0, 32)}`,
    requestId: request.requestId,
    recommendation,
    reasonCodes: [...new Set(reasonCodes)].sort(),
    evidenceDigest: request.evidenceDigest,
    humanAuthorizationRequired: true,
    requestExecutionAuthorized: false,
    accessGrantAuthorized: false,
    sessionStartAuthorized: false,
    tradingAuthorized: false,
    withdrawalAuthorized: false,
    balanceMutationAuthorized: false,
    signingAuthorized: false,
    assetMovementAuthorized: false
  };
}
