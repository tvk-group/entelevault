import { createHash } from "node:crypto";
import { VaultLabError } from "./errors.mjs";

export const MARKET_DATA_INTEGRITY_SCHEMA = "enteleclos.market-data-integrity-readiness.v1";
export const MARKET_DATA_INTEGRITY_DECISION_SCHEMA = "enteleclos.market-data-integrity-decision.v1";

export const REQUIRED_MARKET_DATA_CONTROLS = Object.freeze([
  "multipleIndependentSourcesVerified",
  "sourceIdentityVerified",
  "transportAuthenticityVerified",
  "schemaValidated",
  "timestampFreshnessVerified",
  "sequenceContinuityVerified",
  "outlierDetectionVerified",
  "crossSourceQuorumVerified",
  "staleDataCircuitBreakerVerified",
  "divergenceCircuitBreakerVerified",
  "failoverFeedVerified",
  "replayProtectionVerified",
  "consumerIsolationVerified",
  "independentReviewComplete"
]);

const ROOT_FIELDS = new Set([
  "schema", "assessmentId", "assessedAt", "environment", "marketClass", "feedClass",
  "policyRevision", "observationDigest", "quorumDigest", "controls", "findings", "evidenceDigest"
]);
const CONTROL_FIELDS = new Set(REQUIRED_MARKET_DATA_CONTROLS);
const FINDING_FIELDS = new Set(["criticalOpen", "highOpen", "staleObservations", "divergentObservations", "sequenceGaps"]);
const ENVIRONMENTS = new Set(["staging", "production-observation"]);
const MARKET_CLASSES = new Set(["spot", "derivatives", "reference-rate", "risk-pricing"]);
const FEED_CLASSES = new Set(["consolidated", "primary-secondary", "signed-oracle", "exchange-aggregate"]);
const CONTROL_REASON_CODES = Object.freeze({
  multipleIndependentSourcesVerified: "INDEPENDENT_SOURCES_UNVERIFIED",
  sourceIdentityVerified: "SOURCE_IDENTITY_UNVERIFIED",
  transportAuthenticityVerified: "TRANSPORT_AUTHENTICITY_UNVERIFIED",
  schemaValidated: "SCHEMA_VALIDATION_FAILED",
  timestampFreshnessVerified: "TIMESTAMP_FRESHNESS_UNVERIFIED",
  sequenceContinuityVerified: "SEQUENCE_CONTINUITY_UNVERIFIED",
  outlierDetectionVerified: "OUTLIER_DETECTION_UNVERIFIED",
  crossSourceQuorumVerified: "CROSS_SOURCE_QUORUM_UNVERIFIED",
  staleDataCircuitBreakerVerified: "STALE_DATA_CIRCUIT_BREAKER_UNVERIFIED",
  divergenceCircuitBreakerVerified: "DIVERGENCE_CIRCUIT_BREAKER_UNVERIFIED",
  failoverFeedVerified: "FAILOVER_FEED_UNVERIFIED",
  replayProtectionVerified: "REPLAY_PROTECTION_UNVERIFIED",
  consumerIsolationVerified: "CONSUMER_ISOLATION_UNVERIFIED",
  independentReviewComplete: "INDEPENDENT_REVIEW_INCOMPLETE"
});
const FINDING_REASON_CODES = Object.freeze({
  criticalOpen: "CRITICAL_FINDINGS_OPEN",
  highOpen: "HIGH_FINDINGS_OPEN",
  staleObservations: "STALE_OBSERVATIONS_DETECTED",
  divergentObservations: "DIVERGENT_OBSERVATIONS_DETECTED",
  sequenceGaps: "SEQUENCE_GAPS_DETECTED"
});
const PROHIBITED_FIELD = /(?:address|candidate|command|credential|email|executable|feedContent|key|mnemonic|order|password|payload|priceValue|private|raw(?:Body|Data|Feed|Message|Payload|Request|Value)|secret|seed|signatureValue|symbolValue|target|token|trade|transaction|user|walletData|walletFile)/iu;

function isRecord(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
function reject(code, message) { throw new VaultLabError(code, message); }
function assertExactFields(value, allowed, label) {
  if (!isRecord(value)) reject("MARKET_DATA_INVALID", `${label} must be an object`);
  for (const key of Object.keys(value)) {
    if (PROHIBITED_FIELD.test(key)) reject("MARKET_DATA_PROHIBITED_FIELD", `${label} contains a prohibited field`);
    if (!allowed.has(key)) reject("MARKET_DATA_UNKNOWN_FIELD", `${label} has an unknown field`);
  }
  if (Object.keys(value).length !== allowed.size) reject("MARKET_DATA_UNKNOWN_FIELD", `${label} field set is incomplete or unknown`);
}
function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (isRecord(value)) return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}

export function validateMarketDataAssessment(input) {
  assertExactFields(input, ROOT_FIELDS, "Market-data assessment");
  if (input.schema !== MARKET_DATA_INTEGRITY_SCHEMA) reject("MARKET_DATA_SCHEMA_REJECTED", "Market-data schema is unsupported");
  if (typeof input.assessmentId !== "string" || !/^market_[0-9a-f]{32}$/u.test(input.assessmentId)) reject("MARKET_DATA_ID_REJECTED", "Market-data identifier is invalid");
  if (typeof input.assessedAt !== "string" || Number.isNaN(Date.parse(input.assessedAt))) reject("MARKET_DATA_TIME_REJECTED", "Market-data time is invalid");
  if (!ENVIRONMENTS.has(input.environment)) reject("MARKET_DATA_ENVIRONMENT_REJECTED", "Market-data environment is unsupported");
  if (!MARKET_CLASSES.has(input.marketClass) || !FEED_CLASSES.has(input.feedClass)) reject("MARKET_DATA_CLASS_REJECTED", "Market-data classification is unsupported");
  if (typeof input.policyRevision !== "string" || !/^[0-9a-f]{40}$/u.test(input.policyRevision)) reject("MARKET_DATA_REVISION_REJECTED", "Market-data policy revision is invalid");
  for (const field of ["observationDigest", "quorumDigest", "evidenceDigest"]) {
    if (typeof input[field] !== "string" || !/^[0-9a-f]{64}$/u.test(input[field])) reject("MARKET_DATA_DIGEST_REJECTED", "Market-data digest is invalid");
  }
  assertExactFields(input.controls, CONTROL_FIELDS, "Market-data controls");
  for (const control of REQUIRED_MARKET_DATA_CONTROLS) {
    if (typeof input.controls[control] !== "boolean") reject("MARKET_DATA_CONTROL_REJECTED", "Market-data control value is invalid");
  }
  assertExactFields(input.findings, FINDING_FIELDS, "Market-data findings");
  for (const field of FINDING_FIELDS) {
    if (!Number.isSafeInteger(input.findings[field]) || input.findings[field] < 0 || input.findings[field] > 100000) reject("MARKET_DATA_FINDING_REJECTED", "Market-data finding count is invalid");
  }
  return structuredClone(input);
}

export function evaluateMarketDataIntegrity(input) {
  const assessment = validateMarketDataAssessment(input);
  const reasonCodes = REQUIRED_MARKET_DATA_CONTROLS.filter((control) => !assessment.controls[control]).map((control) => CONTROL_REASON_CODES[control]);
  for (const field of FINDING_FIELDS) if (assessment.findings[field] > 0) reasonCodes.push(FINDING_REASON_CODES[field]);
  const digest = createHash("sha256").update(canonicalJson(assessment)).digest("hex");
  return {
    schema: MARKET_DATA_INTEGRITY_DECISION_SCHEMA,
    decisionId: `marketdec_${digest.slice(0, 32)}`,
    assessmentId: assessment.assessmentId,
    readiness: reasonCodes.length === 0 ? "ELIGIBLE_FOR_INDEPENDENT_MARKET_DATA_REVIEW" : "NOT_READY",
    reasonCodes: reasonCodes.sort(),
    evidenceDigest: assessment.evidenceDigest,
    humanAuthorizationRequired: true,
    pricePublicationAuthorized: false,
    tradingAuthorized: false,
    orderExecutionAuthorized: false,
    riskLimitMutationAuthorized: false,
    financialClaimAuthorized: false,
    deploymentAuthorized: false,
    signingAuthorized: false,
    assetMovementAuthorized: false
  };
}
