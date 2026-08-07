import { createHash } from "node:crypto";
import { VaultLabError } from "./errors.mjs";

export const AVAILABILITY_CHAOS_SCHEMA = "enteleclos.availability-chaos-readiness.v1";
export const AVAILABILITY_CHAOS_DECISION_SCHEMA = "enteleclos.availability-chaos-decision.v1";

export const REQUIRED_AVAILABILITY_CONTROLS = Object.freeze([
  "isolatedEnvironmentVerified",
  "syntheticTrafficOnlyVerified",
  "blastRadiusBounded",
  "rateLimitsVerified",
  "backpressureVerified",
  "queueBoundsVerified",
  "circuitBreakersVerified",
  "loadSheddingVerified",
  "degradedModeVerified",
  "dependencyTimeoutsVerified",
  "failoverRehearsed",
  "recoveryObjectivesMet",
  "observabilityVerified",
  "independentReviewComplete"
]);

const ROOT_FIELDS = new Set([
  "schema", "assessmentId", "assessedAt", "environment", "systemClass", "scenarioClass",
  "policyRevision", "topologyDigest", "exerciseDigest", "controls", "findings", "evidenceDigest"
]);
const CONTROL_FIELDS = new Set(REQUIRED_AVAILABILITY_CONTROLS);
const FINDING_FIELDS = new Set(["criticalOpen", "highOpen", "availabilityBreaches", "unrecoveredDependencies", "dataIntegrityMismatches"]);
const ENVIRONMENTS = new Set(["isolated-test", "staging"]);
const SYSTEM_CLASSES = new Set(["wallet", "exchange", "custody", "vault", "identity", "infrastructure"]);
const SCENARIO_CLASSES = new Set(["ddos-surge", "queue-exhaustion", "dependency-failure", "regional-failover", "market-volatility", "signer-unavailable"]);
const CONTROL_REASON_CODES = Object.freeze({
  isolatedEnvironmentVerified: "ISOLATED_ENVIRONMENT_UNVERIFIED",
  syntheticTrafficOnlyVerified: "SYNTHETIC_TRAFFIC_UNVERIFIED",
  blastRadiusBounded: "BLAST_RADIUS_UNBOUNDED",
  rateLimitsVerified: "RATE_LIMITS_UNVERIFIED",
  backpressureVerified: "BACKPRESSURE_UNVERIFIED",
  queueBoundsVerified: "QUEUE_BOUNDS_UNVERIFIED",
  circuitBreakersVerified: "CIRCUIT_BREAKERS_UNVERIFIED",
  loadSheddingVerified: "LOAD_SHEDDING_UNVERIFIED",
  degradedModeVerified: "DEGRADED_MODE_UNVERIFIED",
  dependencyTimeoutsVerified: "DEPENDENCY_TIMEOUTS_UNVERIFIED",
  failoverRehearsed: "FAILOVER_UNREHEARSED",
  recoveryObjectivesMet: "RECOVERY_OBJECTIVES_UNMET",
  observabilityVerified: "OBSERVABILITY_UNVERIFIED",
  independentReviewComplete: "INDEPENDENT_REVIEW_INCOMPLETE"
});
const FINDING_REASON_CODES = Object.freeze({
  criticalOpen: "CRITICAL_FINDINGS_OPEN",
  highOpen: "HIGH_FINDINGS_OPEN",
  availabilityBreaches: "AVAILABILITY_BREACHES_DETECTED",
  unrecoveredDependencies: "UNRECOVERED_DEPENDENCIES_DETECTED",
  dataIntegrityMismatches: "DATA_INTEGRITY_MISMATCHES_DETECTED"
});
const PROHIBITED_FIELD = /(?:address|candidate|command|credential|email|executable|host|ipAddress|key|mnemonic|password|payload|private|raw(?:Body|Data|Message|Payload|Request|Traffic|Value)|secret|seed|signatureValue|target|token|trafficContent|transaction|url|user|walletData|walletFile)/iu;

function isRecord(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
function reject(code, message) { throw new VaultLabError(code, message); }
function assertExactFields(value, allowed, label) {
  if (!isRecord(value)) reject("AVAILABILITY_CHAOS_INVALID", `${label} must be an object`);
  for (const key of Object.keys(value)) {
    if (PROHIBITED_FIELD.test(key)) reject("AVAILABILITY_CHAOS_PROHIBITED_FIELD", `${label} contains a prohibited field`);
    if (!allowed.has(key)) reject("AVAILABILITY_CHAOS_UNKNOWN_FIELD", `${label} has an unknown field`);
  }
  if (Object.keys(value).length !== allowed.size) reject("AVAILABILITY_CHAOS_UNKNOWN_FIELD", `${label} field set is incomplete or unknown`);
}
function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (isRecord(value)) return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}

export function validateAvailabilityAssessment(input) {
  assertExactFields(input, ROOT_FIELDS, "Availability assessment");
  if (input.schema !== AVAILABILITY_CHAOS_SCHEMA) reject("AVAILABILITY_CHAOS_SCHEMA_REJECTED", "Availability schema is unsupported");
  if (typeof input.assessmentId !== "string" || !/^availability_[0-9a-f]{32}$/u.test(input.assessmentId)) reject("AVAILABILITY_CHAOS_ID_REJECTED", "Availability identifier is invalid");
  if (typeof input.assessedAt !== "string" || Number.isNaN(Date.parse(input.assessedAt))) reject("AVAILABILITY_CHAOS_TIME_REJECTED", "Availability assessment time is invalid");
  if (!ENVIRONMENTS.has(input.environment)) reject("AVAILABILITY_CHAOS_ENVIRONMENT_REJECTED", "Availability exercises must remain isolated or in staging");
  if (!SYSTEM_CLASSES.has(input.systemClass) || !SCENARIO_CLASSES.has(input.scenarioClass)) reject("AVAILABILITY_CHAOS_CLASS_REJECTED", "Availability classification is unsupported");
  if (typeof input.policyRevision !== "string" || !/^[0-9a-f]{40}$/u.test(input.policyRevision)) reject("AVAILABILITY_CHAOS_REVISION_REJECTED", "Availability policy revision is invalid");
  for (const field of ["topologyDigest", "exerciseDigest", "evidenceDigest"]) {
    if (typeof input[field] !== "string" || !/^[0-9a-f]{64}$/u.test(input[field])) reject("AVAILABILITY_CHAOS_DIGEST_REJECTED", "Availability digest is invalid");
  }
  assertExactFields(input.controls, CONTROL_FIELDS, "Availability controls");
  for (const control of REQUIRED_AVAILABILITY_CONTROLS) {
    if (typeof input.controls[control] !== "boolean") reject("AVAILABILITY_CHAOS_CONTROL_REJECTED", "Availability control value is invalid");
  }
  assertExactFields(input.findings, FINDING_FIELDS, "Availability findings");
  for (const field of FINDING_FIELDS) {
    if (!Number.isSafeInteger(input.findings[field]) || input.findings[field] < 0 || input.findings[field] > 100000) reject("AVAILABILITY_CHAOS_FINDING_REJECTED", "Availability finding count is invalid");
  }
  return structuredClone(input);
}

export function evaluateAvailabilityReadiness(input) {
  const assessment = validateAvailabilityAssessment(input);
  const reasonCodes = REQUIRED_AVAILABILITY_CONTROLS.filter((control) => !assessment.controls[control]).map((control) => CONTROL_REASON_CODES[control]);
  for (const field of FINDING_FIELDS) if (assessment.findings[field] > 0) reasonCodes.push(FINDING_REASON_CODES[field]);
  const digest = createHash("sha256").update(canonicalJson(assessment)).digest("hex");
  return {
    schema: AVAILABILITY_CHAOS_DECISION_SCHEMA,
    decisionId: `availabilitydec_${digest.slice(0, 32)}`,
    assessmentId: assessment.assessmentId,
    readiness: reasonCodes.length === 0 ? "ELIGIBLE_FOR_INDEPENDENT_AVAILABILITY_REVIEW" : "NOT_READY",
    reasonCodes: reasonCodes.sort(),
    evidenceDigest: assessment.evidenceDigest,
    humanAuthorizationRequired: true,
    trafficGenerationAuthorized: false,
    chaosExecutionAuthorized: false,
    failoverAuthorized: false,
    remediationExecutionAuthorized: false,
    dataMutationAuthorized: false,
    tradingAuthorized: false,
    deploymentAuthorized: false,
    signingAuthorized: false,
    assetMovementAuthorized: false
  };
}
