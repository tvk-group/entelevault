import { createHash } from "node:crypto";
import { VaultLabError } from "./errors.mjs";

export const CLIENT_INTEGRITY_SCHEMA = "enteleclos.client-integrity-readiness.v1";
export const CLIENT_INTEGRITY_DECISION_SCHEMA = "enteleclos.client-integrity-decision.v1";

export const REQUIRED_CLIENT_INTEGRITY_CONTROLS = Object.freeze([
  "officialDistributionVerified",
  "appSignatureVerified",
  "reproducibleBuildMatched",
  "binaryIntegrityVerified",
  "runtimeAttestationVerified",
  "hardwareBackedStorageVerified",
  "debuggingDisabled",
  "rootJailbreakDetectionVerified",
  "hookingInstrumentationDetectionVerified",
  "antiTamperVerified",
  "secureUpdateVerified",
  "rollbackProtectionVerified",
  "telemetryRedactionVerified",
  "independentReviewComplete"
]);

const ROOT_FIELDS = new Set([
  "schema", "assessmentId", "assessedAt", "environment", "clientClass", "platformClass",
  "buildRevision", "binaryDigest", "attestationPolicyDigest", "controls", "findings", "evidenceDigest"
]);
const CONTROL_FIELDS = new Set(REQUIRED_CLIENT_INTEGRITY_CONTROLS);
const FINDING_FIELDS = new Set(["criticalOpen", "highOpen", "attestationFailures", "integrityMismatches", "unsignedBuilds"]);
const ENVIRONMENTS = new Set(["staging", "production-observation"]);
const CLIENT_CLASSES = new Set(["wallet-mobile", "wallet-extension", "exchange-mobile", "exchange-web"]);
const PLATFORM_CLASSES = new Set(["android", "ios", "browser-extension", "web"]);
const ALLOWED_PLATFORMS = Object.freeze({
  "wallet-mobile": new Set(["android", "ios"]),
  "wallet-extension": new Set(["browser-extension"]),
  "exchange-mobile": new Set(["android", "ios"]),
  "exchange-web": new Set(["web"])
});
const CONTROL_REASON_CODES = Object.freeze({
  officialDistributionVerified: "OFFICIAL_DISTRIBUTION_UNVERIFIED",
  appSignatureVerified: "APP_SIGNATURE_UNVERIFIED",
  reproducibleBuildMatched: "REPRODUCIBLE_BUILD_MISMATCH",
  binaryIntegrityVerified: "BINARY_INTEGRITY_UNVERIFIED",
  runtimeAttestationVerified: "RUNTIME_ATTESTATION_UNVERIFIED",
  hardwareBackedStorageVerified: "HARDWARE_BACKED_STORAGE_UNVERIFIED",
  debuggingDisabled: "DEBUGGING_NOT_DISABLED",
  rootJailbreakDetectionVerified: "ROOT_JAILBREAK_DETECTION_UNVERIFIED",
  hookingInstrumentationDetectionVerified: "HOOKING_INSTRUMENTATION_DETECTION_UNVERIFIED",
  antiTamperVerified: "ANTI_TAMPER_UNVERIFIED",
  secureUpdateVerified: "SECURE_UPDATE_UNVERIFIED",
  rollbackProtectionVerified: "ROLLBACK_PROTECTION_UNVERIFIED",
  telemetryRedactionVerified: "TELEMETRY_REDACTION_UNVERIFIED",
  independentReviewComplete: "INDEPENDENT_REVIEW_INCOMPLETE"
});
const FINDING_REASON_CODES = Object.freeze({
  criticalOpen: "CRITICAL_FINDINGS_OPEN",
  highOpen: "HIGH_FINDINGS_OPEN",
  attestationFailures: "ATTESTATION_FAILURES_DETECTED",
  integrityMismatches: "INTEGRITY_MISMATCHES_DETECTED",
  unsignedBuilds: "UNSIGNED_BUILDS_DETECTED"
});
const PROHIBITED_FIELD = /(?:address|attestationToken|binaryContent|candidate|command|credential|deviceId|email|executable|key|mnemonic|packageContent|password|payload|private|raw(?:Body|Data|Message|Payload|Request|Value)|secret|seed|signatureValue|target|token|transaction|user|walletData|walletFile)/iu;

function isRecord(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
function reject(code, message) { throw new VaultLabError(code, message); }

function assertExactFields(value, allowed, label) {
  if (!isRecord(value)) reject("CLIENT_INTEGRITY_INVALID", `${label} must be an object`);
  for (const key of Object.keys(value)) {
    if (PROHIBITED_FIELD.test(key)) reject("CLIENT_INTEGRITY_PROHIBITED_FIELD", `${label} contains a prohibited field`);
    if (!allowed.has(key)) reject("CLIENT_INTEGRITY_UNKNOWN_FIELD", `${label} has an unknown field`);
  }
  if (Object.keys(value).length !== allowed.size) reject("CLIENT_INTEGRITY_UNKNOWN_FIELD", `${label} field set is incomplete or unknown`);
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (isRecord(value)) return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}

export function validateClientIntegrityAssessment(input) {
  assertExactFields(input, ROOT_FIELDS, "Client-integrity assessment");
  if (input.schema !== CLIENT_INTEGRITY_SCHEMA) reject("CLIENT_INTEGRITY_SCHEMA_REJECTED", "Client-integrity schema is unsupported");
  if (typeof input.assessmentId !== "string" || !/^client_[0-9a-f]{32}$/u.test(input.assessmentId)) reject("CLIENT_INTEGRITY_ID_REJECTED", "Client-integrity identifier is invalid");
  if (typeof input.assessedAt !== "string" || Number.isNaN(Date.parse(input.assessedAt))) reject("CLIENT_INTEGRITY_TIME_REJECTED", "Client-integrity time is invalid");
  if (!ENVIRONMENTS.has(input.environment)) reject("CLIENT_INTEGRITY_ENVIRONMENT_REJECTED", "Client-integrity environment is unsupported");
  if (!CLIENT_CLASSES.has(input.clientClass) || !PLATFORM_CLASSES.has(input.platformClass) || !ALLOWED_PLATFORMS[input.clientClass].has(input.platformClass)) {
    reject("CLIENT_INTEGRITY_PLATFORM_REJECTED", "Client and platform classes are incompatible");
  }
  if (typeof input.buildRevision !== "string" || !/^[0-9a-f]{40}$/u.test(input.buildRevision)) reject("CLIENT_INTEGRITY_REVISION_REJECTED", "Client build revision is invalid");
  for (const field of ["binaryDigest", "attestationPolicyDigest", "evidenceDigest"]) {
    if (typeof input[field] !== "string" || !/^[0-9a-f]{64}$/u.test(input[field])) reject("CLIENT_INTEGRITY_DIGEST_REJECTED", "Client-integrity digest is invalid");
  }
  assertExactFields(input.controls, CONTROL_FIELDS, "Client-integrity controls");
  for (const control of REQUIRED_CLIENT_INTEGRITY_CONTROLS) {
    if (typeof input.controls[control] !== "boolean") reject("CLIENT_INTEGRITY_CONTROL_REJECTED", "Client-integrity control value is invalid");
  }
  assertExactFields(input.findings, FINDING_FIELDS, "Client-integrity findings");
  for (const field of FINDING_FIELDS) {
    if (!Number.isSafeInteger(input.findings[field]) || input.findings[field] < 0 || input.findings[field] > 100000) reject("CLIENT_INTEGRITY_FINDING_REJECTED", "Client-integrity finding count is invalid");
  }
  return structuredClone(input);
}

export function evaluateClientIntegrity(input) {
  const assessment = validateClientIntegrityAssessment(input);
  const reasonCodes = REQUIRED_CLIENT_INTEGRITY_CONTROLS.filter((control) => !assessment.controls[control]).map((control) => CONTROL_REASON_CODES[control]);
  for (const field of FINDING_FIELDS) if (assessment.findings[field] > 0) reasonCodes.push(FINDING_REASON_CODES[field]);
  const digest = createHash("sha256").update(canonicalJson(assessment)).digest("hex");
  return {
    schema: CLIENT_INTEGRITY_DECISION_SCHEMA,
    decisionId: `clientdec_${digest.slice(0, 32)}`,
    assessmentId: assessment.assessmentId,
    readiness: reasonCodes.length === 0 ? "ELIGIBLE_FOR_INDEPENDENT_CLIENT_REVIEW" : "NOT_READY",
    reasonCodes: reasonCodes.sort(),
    evidenceDigest: assessment.evidenceDigest,
    humanAuthorizationRequired: true,
    clientActivationAuthorized: false,
    distributionAuthorized: false,
    updateExecutionAuthorized: false,
    deviceAccessAuthorized: false,
    keyStorageAuthorized: false,
    deploymentAuthorized: false,
    signingAuthorized: false,
    assetMovementAuthorized: false
  };
}
