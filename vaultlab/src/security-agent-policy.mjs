import { createHash } from "node:crypto";
import { VaultLabError } from "./errors.mjs";

export const SECURITY_EVENT_SCHEMA = "enteleclos.security-event.v1";
export const SECURITY_DECISION_SCHEMA = "enteleclos.security-decision.v1";

export const SUPPORTED_EVENT_TYPES = Object.freeze([
  "dependency.provenance-failed",
  "recovery.governance-failed",
  "session.account-takeover-suspected",
  "signing.intent-mismatch",
  "vault.integrity-failure",
  "vault.policy-downgrade",
  "withdrawal.risk-elevated"
]);

const ROOT_FIELDS = new Set([
  "schema",
  "eventId",
  "occurredAt",
  "type",
  "severity",
  "resource",
  "evidenceDigest",
  "signals"
]);
const RESOURCE_FIELDS = new Set(["kind", "id", "environment"]);
const SIGNAL_FIELDS = new Set(["code", "value"]);
const SEVERITIES = new Set(["low", "medium", "high", "critical"]);
const RESOURCE_KINDS = new Set([
  "build",
  "recovery-case",
  "session",
  "signing-request",
  "vault-policy",
  "withdrawal-request"
]);
const ENVIRONMENTS = new Set(["ci", "staging", "production-observation"]);
const PROHIBITED_FIELD = /(?:action|address|candidate|command|credential|key|mnemonic|password|payload|seed|signature|target|transaction)/iu;

const RESPONSE_BY_SEVERITY = Object.freeze({
  low: "REVIEW",
  medium: "REQUIRE_HUMAN_REVIEW",
  high: "QUARANTINE_AND_REVIEW",
  critical: "BLOCK_AND_ESCALATE"
});

function reject(code, message) {
  throw new VaultLabError(code, message);
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function assertExactFields(value, fields, label) {
  if (!isRecord(value)) reject("SECURITY_EVENT_INVALID", `${label} must be an object`);
  for (const key of Object.keys(value)) {
    if (PROHIBITED_FIELD.test(key)) {
      reject("SECURITY_EVENT_PROHIBITED_FIELD", `${label} contains a prohibited field`);
    }
    if (!fields.has(key)) reject("SECURITY_EVENT_UNKNOWN_FIELD", `${label} has an unknown field`);
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

export function validateSecurityEvent(input) {
  if (!isRecord(input)) reject("SECURITY_EVENT_INVALID", "Security event must be an object");
  assertExactFields(input, ROOT_FIELDS, "Security event");

  if (input.schema !== SECURITY_EVENT_SCHEMA) {
    reject("SECURITY_EVENT_SCHEMA_REJECTED", "Security event schema is unsupported");
  }
  if (typeof input.eventId !== "string" || !/^evt_[0-9a-f]{32}$/u.test(input.eventId)) {
    reject("SECURITY_EVENT_ID_REJECTED", "Security event identifier is invalid");
  }
  if (typeof input.occurredAt !== "string" || Number.isNaN(Date.parse(input.occurredAt))) {
    reject("SECURITY_EVENT_TIME_REJECTED", "Security event time is invalid");
  }
  if (!SUPPORTED_EVENT_TYPES.includes(input.type)) {
    reject("SECURITY_EVENT_TYPE_REJECTED", "Security event type is unsupported");
  }
  if (!SEVERITIES.has(input.severity)) {
    reject("SECURITY_EVENT_SEVERITY_REJECTED", "Security event severity is unsupported");
  }

  assertExactFields(input.resource, RESOURCE_FIELDS, "Security event resource");
  if (!RESOURCE_KINDS.has(input.resource.kind)) {
    reject("SECURITY_EVENT_RESOURCE_REJECTED", "Security event resource kind is unsupported");
  }
  if (typeof input.resource.id !== "string" || !/^res_[0-9a-f]{16}$/u.test(input.resource.id)) {
    reject("SECURITY_EVENT_RESOURCE_REJECTED", "Security event resource identifier is invalid");
  }
  if (!ENVIRONMENTS.has(input.resource.environment)) {
    reject("SECURITY_EVENT_ENVIRONMENT_REJECTED", "Security event environment is unsupported");
  }
  if (typeof input.evidenceDigest !== "string" || !/^[0-9a-f]{64}$/u.test(input.evidenceDigest)) {
    reject("SECURITY_EVENT_EVIDENCE_REJECTED", "Security event evidence digest is invalid");
  }

  if (!Array.isArray(input.signals) || input.signals.length === 0 || input.signals.length > 16) {
    reject("SECURITY_EVENT_SIGNALS_REJECTED", "Security event signals are outside policy");
  }
  for (const signal of input.signals) {
    assertExactFields(signal, SIGNAL_FIELDS, "Security event signal");
    if (typeof signal.code !== "string" || !/^[A-Z][A-Z0-9_]{2,47}$/u.test(signal.code)) {
      reject("SECURITY_EVENT_SIGNAL_REJECTED", "Security event signal code is invalid");
    }
    const allowedValue =
      typeof signal.value === "boolean" ||
      (typeof signal.value === "number" && Number.isFinite(signal.value));
    if (!allowedValue) {
      reject("SECURITY_EVENT_SIGNAL_REJECTED", "Security event signal values must be boolean or numeric");
    }
  }

  return structuredClone(input);
}

export function evaluateSecurityEvent(input) {
  const event = validateSecurityEvent(input);
  const decisionDigest = createHash("sha256").update(canonicalJson(event)).digest("hex");
  return {
    schema: SECURITY_DECISION_SCHEMA,
    decisionId: `dec_${decisionDigest.slice(0, 32)}`,
    eventId: event.eventId,
    eventType: event.type,
    severity: event.severity,
    recommendation: RESPONSE_BY_SEVERITY[event.severity],
    evidenceDigest: event.evidenceDigest,
    humanAuthorizationRequired: true,
    executionAuthorized: false,
    signingAuthorized: false,
    assetMovementAuthorized: false
  };
}
