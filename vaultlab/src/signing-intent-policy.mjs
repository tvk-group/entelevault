import { createHash } from "node:crypto";
import { VaultLabError } from "./errors.mjs";

export const SIGNING_INTENT_SCHEMA = "entelewallet.signing-intent.v1";
export const SIGNING_DECISION_SCHEMA = "entelewallet.signing-decision.v1";

const ROOT_FIELDS = new Set([
  "schema",
  "requestId",
  "observedAt",
  "environment",
  "network",
  "intent",
  "policy",
  "evidenceDigest"
]);
const NETWORK_FIELDS = new Set(["family", "chainReference"]);
const INTENT_FIELDS = new Set([
  "operation",
  "assetClass",
  "amountClass",
  "destinationTrust",
  "decoded",
  "simulation",
  "unlimitedApproval",
  "valueDirection",
  "riskScore"
]);
const POLICY_FIELDS = new Set([
  "requireDecoded",
  "requireSimulation",
  "maxRiskScore",
  "allowUnlimitedApproval",
  "allowNewDestination"
]);
const ENVIRONMENTS = new Set(["ci", "staging", "production-observation"]);
const NETWORK_FAMILIES = new Set(["bitcoin", "evm", "solana"]);
const OPERATIONS = new Set([
  "approval",
  "contract-call",
  "message",
  "network-switch",
  "transfer",
  "typed-data"
]);
const ASSET_CLASSES = new Set(["fungible", "native", "nft", "not-applicable", "unknown"]);
const AMOUNT_CLASSES = new Set(["bounded", "not-applicable", "unbounded", "zero"]);
const DESTINATION_TRUST = new Set(["allowlisted", "blocked", "known", "new", "not-applicable"]);
const SIMULATION_RESULTS = new Set(["match", "mismatch", "not-applicable", "unavailable"]);
const VALUE_DIRECTIONS = new Set(["credit", "debit", "mixed", "none", "unknown"]);
const PROHIBITED_FIELD = /(?:address|calldata|candidate|command|credential|key|mnemonic|password|private|raw|recipient|seed|signature|target|transaction)/iu;

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function reject(code, message) {
  throw new VaultLabError(code, message);
}

function assertExactFields(value, allowed, label) {
  if (!isRecord(value)) reject("SIGNING_INTENT_INVALID", `${label} must be an object`);
  for (const key of Object.keys(value)) {
    if (PROHIBITED_FIELD.test(key)) {
      reject("SIGNING_INTENT_PROHIBITED_FIELD", `${label} contains a prohibited field`);
    }
    if (!allowed.has(key)) reject("SIGNING_INTENT_UNKNOWN_FIELD", `${label} has an unknown field`);
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

export function validateSigningIntent(input) {
  assertExactFields(input, ROOT_FIELDS, "Signing intent");
  if (input.schema !== SIGNING_INTENT_SCHEMA) {
    reject("SIGNING_INTENT_SCHEMA_REJECTED", "Signing intent schema is unsupported");
  }
  if (typeof input.requestId !== "string" || !/^req_[0-9a-f]{32}$/u.test(input.requestId)) {
    reject("SIGNING_INTENT_ID_REJECTED", "Signing request identifier is invalid");
  }
  if (typeof input.observedAt !== "string" || Number.isNaN(Date.parse(input.observedAt))) {
    reject("SIGNING_INTENT_TIME_REJECTED", "Signing intent time is invalid");
  }
  if (!ENVIRONMENTS.has(input.environment)) {
    reject("SIGNING_INTENT_ENVIRONMENT_REJECTED", "Signing intent environment is unsupported");
  }

  assertExactFields(input.network, NETWORK_FIELDS, "Signing network");
  if (!NETWORK_FAMILIES.has(input.network.family)) {
    reject("SIGNING_INTENT_NETWORK_REJECTED", "Signing network family is unsupported");
  }
  if (
    typeof input.network.chainReference !== "string" ||
    !/^[a-z0-9][a-z0-9:-]{1,63}$/u.test(input.network.chainReference)
  ) {
    reject("SIGNING_INTENT_NETWORK_REJECTED", "Signing chain reference is invalid");
  }

  assertExactFields(input.intent, INTENT_FIELDS, "Signing intent summary");
  if (!OPERATIONS.has(input.intent.operation)) {
    reject("SIGNING_INTENT_OPERATION_REJECTED", "Signing operation is unsupported");
  }
  if (!ASSET_CLASSES.has(input.intent.assetClass)) {
    reject("SIGNING_INTENT_ASSET_REJECTED", "Signing asset class is unsupported");
  }
  if (!AMOUNT_CLASSES.has(input.intent.amountClass)) {
    reject("SIGNING_INTENT_AMOUNT_REJECTED", "Signing amount class is unsupported");
  }
  if (!DESTINATION_TRUST.has(input.intent.destinationTrust)) {
    reject("SIGNING_INTENT_DESTINATION_REJECTED", "Destination trust class is unsupported");
  }
  if (typeof input.intent.decoded !== "boolean" || typeof input.intent.unlimitedApproval !== "boolean") {
    reject("SIGNING_INTENT_BOOLEAN_REJECTED", "Signing intent boolean fields are invalid");
  }
  if (!SIMULATION_RESULTS.has(input.intent.simulation)) {
    reject("SIGNING_INTENT_SIMULATION_REJECTED", "Simulation result is unsupported");
  }
  if (!VALUE_DIRECTIONS.has(input.intent.valueDirection)) {
    reject("SIGNING_INTENT_VALUE_REJECTED", "Value direction is unsupported");
  }
  if (
    !Number.isSafeInteger(input.intent.riskScore) ||
    input.intent.riskScore < 0 ||
    input.intent.riskScore > 100
  ) {
    reject("SIGNING_INTENT_RISK_REJECTED", "Signing risk score is outside policy");
  }

  assertExactFields(input.policy, POLICY_FIELDS, "Signing policy");
  for (const field of [
    "requireDecoded",
    "requireSimulation",
    "allowUnlimitedApproval",
    "allowNewDestination"
  ]) {
    if (typeof input.policy[field] !== "boolean") {
      reject("SIGNING_POLICY_REJECTED", "Signing policy boolean is invalid");
    }
  }
  if (
    !Number.isSafeInteger(input.policy.maxRiskScore) ||
    input.policy.maxRiskScore < 0 ||
    input.policy.maxRiskScore > 100
  ) {
    reject("SIGNING_POLICY_REJECTED", "Signing policy risk limit is invalid");
  }
  if (typeof input.evidenceDigest !== "string" || !/^[0-9a-f]{64}$/u.test(input.evidenceDigest)) {
    reject("SIGNING_INTENT_EVIDENCE_REJECTED", "Signing evidence digest is invalid");
  }
  return structuredClone(input);
}

export function evaluateSigningIntent(input) {
  const request = validateSigningIntent(input);
  const reasons = [];
  if (request.intent.destinationTrust === "blocked") reasons.push("BLOCKED_DESTINATION");
  if (request.intent.riskScore > request.policy.maxRiskScore) reasons.push("RISK_SCORE_EXCEEDED");
  if (request.policy.requireDecoded && !request.intent.decoded) reasons.push("INTENT_NOT_DECODED");
  if (request.intent.simulation === "mismatch") reasons.push("SIMULATION_MISMATCH");
  if (request.policy.requireSimulation && request.intent.simulation === "unavailable") {
    reasons.push("SIMULATION_REQUIRED");
  }
  if (request.intent.unlimitedApproval && !request.policy.allowUnlimitedApproval) {
    reasons.push("UNLIMITED_APPROVAL");
  }
  if (request.intent.destinationTrust === "new" && !request.policy.allowNewDestination) {
    reasons.push("NEW_DESTINATION");
  }

  const needsReview =
    request.intent.destinationTrust === "new" ||
    request.intent.assetClass === "unknown" ||
    request.intent.valueDirection === "unknown" ||
    request.intent.riskScore >= Math.ceil(request.policy.maxRiskScore * 0.8);
  const recommendation =
    reasons.length > 0
      ? "BLOCK"
      : needsReview
        ? "REQUIRE_HUMAN_REVIEW"
        : "PROCEED_TO_HUMAN_CONFIRMATION";
  const digest = createHash("sha256").update(canonicalJson(request)).digest("hex");

  return {
    schema: SIGNING_DECISION_SCHEMA,
    decisionId: `sigdec_${digest.slice(0, 32)}`,
    requestId: request.requestId,
    recommendation,
    reasonCodes: reasons.sort(),
    evidenceDigest: request.evidenceDigest,
    humanConfirmationRequired: true,
    executionAuthorized: false,
    signingAuthorized: false,
    assetMovementAuthorized: false
  };
}
