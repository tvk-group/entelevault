import { createHash } from "node:crypto";
import { VaultLabError } from "./errors.mjs";

export const WITHDRAWAL_REQUEST_SCHEMA = "enteleexchange.withdrawal-risk.v1";
export const WITHDRAWAL_DECISION_SCHEMA = "enteleexchange.withdrawal-decision.v1";

const ROOT_FIELDS = new Set([
  "schema",
  "requestId",
  "observedAt",
  "environment",
  "subject",
  "withdrawal",
  "controls",
  "evidenceDigest"
]);
const SUBJECT_FIELDS = new Set([
  "accountAgeClass",
  "sessionAssurance",
  "deviceTrust",
  "recentCredentialChange",
  "accountTakeoverSuspected"
]);
const WITHDRAWAL_FIELDS = new Set([
  "assetClass",
  "amountClass",
  "destinationTrust",
  "velocityClass",
  "crossBorderRisk",
  "complianceStatus",
  "networkRisk"
]);
const CONTROL_FIELDS = new Set([
  "phishingResistantMfaSatisfied",
  "freshReauthenticationSatisfied",
  "cooldownRequiredHours",
  "cooldownElapsedHours",
  "dualApprovalRequired",
  "dualApprovalSatisfied",
  "travelRuleRequired",
  "travelRuleSatisfied"
]);
const ENVIRONMENTS = new Set(["ci", "staging", "production-observation"]);
const ACCOUNT_AGE = new Set(["established", "new", "unknown"]);
const SESSION_ASSURANCE = new Set(["degraded", "phishing-resistant", "standard", "unknown"]);
const DEVICE_TRUST = new Set(["blocked", "new", "trusted", "unknown"]);
const ASSET_CLASS = new Set(["fungible", "native", "other", "stable", "unknown"]);
const AMOUNT_CLASS = new Set(["elevated", "limit-exceeding", "micro", "standard", "unknown"]);
const DESTINATION_TRUST = new Set(["allowlisted", "blocked", "known", "new", "unknown"]);
const VELOCITY_CLASS = new Set(["elevated", "limit-exceeding", "normal", "unknown"]);
const RISK_CLASS = new Set(["high", "low", "medium", "unknown"]);
const COMPLIANCE_STATUS = new Set(["blocked", "clear", "review", "unavailable"]);
const PROHIBITED_FIELD = /(?:address|amountValue|candidate|command|credentialValue|email|ip|key|mnemonic|name|password|phone|private|(?:^raw$|raw(?:Body|Data|Message|Payload|Request|Transaction|Value))|recipient|seed|signature|target|tokenValue|transaction|user|wallet)/iu;

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function reject(code, message) {
  throw new VaultLabError(code, message);
}

function assertExactFields(value, allowed, label) {
  if (!isRecord(value)) reject("WITHDRAWAL_REQUEST_INVALID", `${label} must be an object`);
  for (const key of Object.keys(value)) {
    if (PROHIBITED_FIELD.test(key)) {
      reject("WITHDRAWAL_PROHIBITED_FIELD", `${label} contains a prohibited field`);
    }
    if (!allowed.has(key)) reject("WITHDRAWAL_UNKNOWN_FIELD", `${label} has an unknown field`);
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

export function validateWithdrawalRequest(input) {
  assertExactFields(input, ROOT_FIELDS, "Withdrawal request");
  if (input.schema !== WITHDRAWAL_REQUEST_SCHEMA) {
    reject("WITHDRAWAL_SCHEMA_REJECTED", "Withdrawal request schema is unsupported");
  }
  if (typeof input.requestId !== "string" || !/^wdreq_[0-9a-f]{32}$/u.test(input.requestId)) {
    reject("WITHDRAWAL_ID_REJECTED", "Withdrawal request identifier is invalid");
  }
  if (typeof input.observedAt !== "string" || Number.isNaN(Date.parse(input.observedAt))) {
    reject("WITHDRAWAL_TIME_REJECTED", "Withdrawal observation time is invalid");
  }
  if (!ENVIRONMENTS.has(input.environment)) {
    reject("WITHDRAWAL_ENVIRONMENT_REJECTED", "Withdrawal environment is unsupported");
  }

  assertExactFields(input.subject, SUBJECT_FIELDS, "Withdrawal subject summary");
  if (!ACCOUNT_AGE.has(input.subject.accountAgeClass)) {
    reject("WITHDRAWAL_SUBJECT_REJECTED", "Account age class is unsupported");
  }
  if (!SESSION_ASSURANCE.has(input.subject.sessionAssurance)) {
    reject("WITHDRAWAL_SUBJECT_REJECTED", "Session assurance class is unsupported");
  }
  if (!DEVICE_TRUST.has(input.subject.deviceTrust)) {
    reject("WITHDRAWAL_SUBJECT_REJECTED", "Device trust class is unsupported");
  }
  for (const field of ["recentCredentialChange", "accountTakeoverSuspected"]) {
    if (typeof input.subject[field] !== "boolean") {
      reject("WITHDRAWAL_SUBJECT_REJECTED", "Withdrawal subject boolean is invalid");
    }
  }

  assertExactFields(input.withdrawal, WITHDRAWAL_FIELDS, "Withdrawal risk summary");
  if (!ASSET_CLASS.has(input.withdrawal.assetClass)) {
    reject("WITHDRAWAL_CLASS_REJECTED", "Withdrawal asset class is unsupported");
  }
  if (!AMOUNT_CLASS.has(input.withdrawal.amountClass)) {
    reject("WITHDRAWAL_CLASS_REJECTED", "Withdrawal amount class is unsupported");
  }
  if (!DESTINATION_TRUST.has(input.withdrawal.destinationTrust)) {
    reject("WITHDRAWAL_CLASS_REJECTED", "Withdrawal destination class is unsupported");
  }
  if (!VELOCITY_CLASS.has(input.withdrawal.velocityClass)) {
    reject("WITHDRAWAL_CLASS_REJECTED", "Withdrawal velocity class is unsupported");
  }
  if (!RISK_CLASS.has(input.withdrawal.crossBorderRisk) || !RISK_CLASS.has(input.withdrawal.networkRisk)) {
    reject("WITHDRAWAL_CLASS_REJECTED", "Withdrawal risk class is unsupported");
  }
  if (!COMPLIANCE_STATUS.has(input.withdrawal.complianceStatus)) {
    reject("WITHDRAWAL_CLASS_REJECTED", "Withdrawal compliance status is unsupported");
  }

  assertExactFields(input.controls, CONTROL_FIELDS, "Withdrawal controls");
  for (const field of [
    "phishingResistantMfaSatisfied",
    "freshReauthenticationSatisfied",
    "dualApprovalRequired",
    "dualApprovalSatisfied",
    "travelRuleRequired",
    "travelRuleSatisfied"
  ]) {
    if (typeof input.controls[field] !== "boolean") {
      reject("WITHDRAWAL_CONTROL_REJECTED", "Withdrawal control boolean is invalid");
    }
  }
  if (
    !Number.isSafeInteger(input.controls.cooldownRequiredHours) ||
    input.controls.cooldownRequiredHours < 0 ||
    input.controls.cooldownRequiredHours > 720 ||
    !Number.isSafeInteger(input.controls.cooldownElapsedHours) ||
    input.controls.cooldownElapsedHours < 0 ||
    input.controls.cooldownElapsedHours > 8760
  ) {
    reject("WITHDRAWAL_CONTROL_REJECTED", "Withdrawal cooldown is outside policy");
  }
  if (input.subject.recentCredentialChange && input.controls.cooldownRequiredHours < 24) {
    reject("WITHDRAWAL_CONTROL_REJECTED", "Recent credential changes require at least 24 hours cooldown");
  }
  if (typeof input.evidenceDigest !== "string" || !/^[0-9a-f]{64}$/u.test(input.evidenceDigest)) {
    reject("WITHDRAWAL_EVIDENCE_REJECTED", "Withdrawal evidence digest is invalid");
  }
  return structuredClone(input);
}

export function evaluateWithdrawalRequest(input) {
  const request = validateWithdrawalRequest(input);
  const reasonCodes = [];
  if (request.subject.accountTakeoverSuspected) reasonCodes.push("ACCOUNT_TAKEOVER_SUSPECTED");
  if (request.subject.deviceTrust === "blocked") reasonCodes.push("DEVICE_BLOCKED");
  if (request.subject.sessionAssurance === "degraded") reasonCodes.push("SESSION_ASSURANCE_DEGRADED");
  if (request.withdrawal.destinationTrust === "blocked") reasonCodes.push("DESTINATION_BLOCKED");
  if (request.withdrawal.amountClass === "limit-exceeding") reasonCodes.push("AMOUNT_LIMIT_EXCEEDED");
  if (request.withdrawal.velocityClass === "limit-exceeding") reasonCodes.push("VELOCITY_LIMIT_EXCEEDED");
  if (request.withdrawal.complianceStatus === "blocked") reasonCodes.push("COMPLIANCE_BLOCKED");
  if (request.withdrawal.complianceStatus === "unavailable") reasonCodes.push("COMPLIANCE_UNAVAILABLE");
  if (request.withdrawal.crossBorderRisk === "high") reasonCodes.push("CROSS_BORDER_RISK_HIGH");
  if (request.withdrawal.networkRisk === "high") reasonCodes.push("NETWORK_RISK_HIGH");
  if (!request.controls.phishingResistantMfaSatisfied) reasonCodes.push("PHISHING_RESISTANT_MFA_REQUIRED");
  if (!request.controls.freshReauthenticationSatisfied) reasonCodes.push("FRESH_REAUTHENTICATION_REQUIRED");
  if (
    request.subject.recentCredentialChange &&
    request.controls.cooldownElapsedHours < request.controls.cooldownRequiredHours
  ) {
    reasonCodes.push("CREDENTIAL_CHANGE_COOLDOWN_ACTIVE");
  }
  if (request.controls.dualApprovalRequired && !request.controls.dualApprovalSatisfied) {
    reasonCodes.push("DUAL_APPROVAL_REQUIRED");
  }
  if (
    (request.withdrawal.amountClass === "elevated" ||
      new Set(["new", "unknown"]).has(request.withdrawal.destinationTrust)) &&
    !request.controls.dualApprovalRequired
  ) {
    reasonCodes.push("DUAL_APPROVAL_POLICY_MISSING");
  }
  if (request.controls.travelRuleRequired && !request.controls.travelRuleSatisfied) {
    reasonCodes.push("TRAVEL_RULE_INCOMPLETE");
  }
  if (request.withdrawal.crossBorderRisk !== "low" && !request.controls.travelRuleRequired) {
    reasonCodes.push("TRAVEL_RULE_POLICY_MISSING");
  }

  const reviewRequired =
    request.subject.accountAgeClass !== "established" ||
    request.subject.sessionAssurance !== "phishing-resistant" ||
    request.subject.deviceTrust !== "trusted" ||
    request.withdrawal.assetClass === "unknown" ||
    request.withdrawal.amountClass === "elevated" ||
    request.withdrawal.amountClass === "unknown" ||
    request.withdrawal.destinationTrust !== "allowlisted" ||
    request.withdrawal.velocityClass !== "normal" ||
    request.withdrawal.crossBorderRisk !== "low" ||
    request.withdrawal.networkRisk !== "low" ||
    request.withdrawal.complianceStatus === "review";
  const recommendation =
    reasonCodes.length > 0
      ? "HOLD_AND_ESCALATE"
      : reviewRequired
        ? "REQUIRE_HUMAN_RISK_REVIEW"
        : "PROCEED_TO_SEPARATE_AUTHORIZATION";
  const digest = createHash("sha256").update(canonicalJson(request)).digest("hex");
  return {
    schema: WITHDRAWAL_DECISION_SCHEMA,
    decisionId: `wddec_${digest.slice(0, 32)}`,
    requestId: request.requestId,
    recommendation,
    reasonCodes: reasonCodes.sort(),
    evidenceDigest: request.evidenceDigest,
    humanAuthorizationRequired: true,
    holdExecutionAuthorized: false,
    withdrawalAuthorized: false,
    signingAuthorized: false,
    assetMovementAuthorized: false
  };
}
