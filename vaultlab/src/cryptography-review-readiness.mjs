import { createHash } from "node:crypto";
import { VaultLabError } from "./errors.mjs";

export const CRYPTOGRAPHY_REVIEW_SCHEMA = "enteleclos.cryptography-review-readiness.v1";
export const CRYPTOGRAPHY_REVIEW_DECISION_SCHEMA = "enteleclos.cryptography-review-decision.v1";

export const REQUIRED_CRYPTOGRAPHY_REVIEW_CONTROLS = Object.freeze([
  "algorithmInventoryComplete", "approvedPrimitivesVerified", "protocolSpecificationReviewed",
  "parameterPolicyVerified", "kdfPolicyVerified", "randomnessSourceVerified", "nonceManagementVerified",
  "cryptographicMaterialLifecycleReviewed", "cryptoAgilityPlanVerified", "libraryProvenanceVerified",
  "sideChannelReviewComplete", "interoperabilityVectorsVerified", "migrationRollbackPlanVerified",
  "independentCryptographyReviewComplete"
]);

const ROOT_FIELDS = new Set(["schema", "assessmentId", "assessedAt", "environment", "componentClass", "designRevision", "specificationDigest", "threatModelDigest", "controls", "findings", "evidenceDigest"]);
const CONTROL_FIELDS = new Set(REQUIRED_CRYPTOGRAPHY_REVIEW_CONTROLS);
const FINDING_FIELDS = new Set(["criticalOpen", "highOpen", "parameterExceptions", "vectorFailures", "deprecatedPrimitives"]);
const ENVIRONMENTS = new Set(["staging", "production-observation"]);
const COMPONENT_CLASSES = new Set(["wallet-vault", "exchange-custody", "authentication-service", "evidence-service"]);
const CONTROL_REASONS = Object.freeze({
  algorithmInventoryComplete: "ALGORITHM_INVENTORY_INCOMPLETE", approvedPrimitivesVerified: "APPROVED_PRIMITIVES_UNVERIFIED",
  protocolSpecificationReviewed: "PROTOCOL_SPECIFICATION_UNREVIEWED", parameterPolicyVerified: "PARAMETER_POLICY_UNVERIFIED",
  kdfPolicyVerified: "KDF_POLICY_UNVERIFIED", randomnessSourceVerified: "RANDOMNESS_SOURCE_UNVERIFIED",
  nonceManagementVerified: "NONCE_MANAGEMENT_UNVERIFIED", cryptographicMaterialLifecycleReviewed: "CRYPTOGRAPHIC_MATERIAL_LIFECYCLE_UNREVIEWED",
  cryptoAgilityPlanVerified: "CRYPTO_AGILITY_PLAN_UNVERIFIED", libraryProvenanceVerified: "LIBRARY_PROVENANCE_UNVERIFIED",
  sideChannelReviewComplete: "SIDE_CHANNEL_REVIEW_INCOMPLETE", interoperabilityVectorsVerified: "INTEROPERABILITY_VECTORS_UNVERIFIED",
  migrationRollbackPlanVerified: "MIGRATION_ROLLBACK_PLAN_UNVERIFIED", independentCryptographyReviewComplete: "INDEPENDENT_CRYPTOGRAPHY_REVIEW_INCOMPLETE"
});
const FINDING_REASONS = Object.freeze({
  criticalOpen: "CRITICAL_CRYPTOGRAPHY_FINDINGS_OPEN", highOpen: "HIGH_CRYPTOGRAPHY_FINDINGS_OPEN",
  parameterExceptions: "PARAMETER_EXCEPTIONS_DETECTED", vectorFailures: "INTEROPERABILITY_VECTOR_FAILURES_DETECTED",
  deprecatedPrimitives: "DEPRECATED_PRIMITIVES_DETECTED"
});
const PROHIBITED_FIELD = /(?:address|candidate|ciphertext|command|credential|entropyValue|key|mnemonic|nonceValue|password|payload|plaintext|private|raw(?:Body|Data|Material|Message|Payload|Request|Value)|secret|seed|signatureValue|target|token|transaction|user|walletData|walletFile)/iu;

function isRecord(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
function reject(code, message) { throw new VaultLabError(code, message); }
function assertExactFields(value, allowed, label) {
  if (!isRecord(value)) reject("CRYPTOGRAPHY_REVIEW_INVALID", `${label} must be an object`);
  for (const key of Object.keys(value)) {
    if (PROHIBITED_FIELD.test(key)) reject("CRYPTOGRAPHY_REVIEW_PROHIBITED_FIELD", `${label} contains a prohibited field`);
    if (!allowed.has(key)) reject("CRYPTOGRAPHY_REVIEW_UNKNOWN_FIELD", `${label} has an unknown field`);
  }
  if (Object.keys(value).length !== allowed.size) reject("CRYPTOGRAPHY_REVIEW_UNKNOWN_FIELD", `${label} field set is incomplete or unknown`);
}
function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (isRecord(value)) return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}

export function validateCryptographyReview(input) {
  assertExactFields(input, ROOT_FIELDS, "Cryptography-review assessment");
  if (input.schema !== CRYPTOGRAPHY_REVIEW_SCHEMA) reject("CRYPTOGRAPHY_REVIEW_SCHEMA_REJECTED", "Cryptography-review schema is unsupported");
  if (typeof input.assessmentId !== "string" || !/^crypto_[0-9a-f]{32}$/u.test(input.assessmentId)) reject("CRYPTOGRAPHY_REVIEW_ID_REJECTED", "Cryptography-review identifier is invalid");
  if (typeof input.assessedAt !== "string" || Number.isNaN(Date.parse(input.assessedAt))) reject("CRYPTOGRAPHY_REVIEW_TIME_REJECTED", "Cryptography-review time is invalid");
  if (!ENVIRONMENTS.has(input.environment)) reject("CRYPTOGRAPHY_REVIEW_ENVIRONMENT_REJECTED", "Cryptography-review environment is unsupported");
  if (!COMPONENT_CLASSES.has(input.componentClass)) reject("CRYPTOGRAPHY_REVIEW_COMPONENT_REJECTED", "Cryptography-review component class is unsupported");
  if (typeof input.designRevision !== "string" || !/^[0-9a-f]{40}$/u.test(input.designRevision)) reject("CRYPTOGRAPHY_REVIEW_REVISION_REJECTED", "Cryptography-review design revision is invalid");
  for (const field of ["specificationDigest", "threatModelDigest", "evidenceDigest"]) if (typeof input[field] !== "string" || !/^[0-9a-f]{64}$/u.test(input[field])) reject("CRYPTOGRAPHY_REVIEW_DIGEST_REJECTED", "Cryptography-review digest is invalid");
  assertExactFields(input.controls, CONTROL_FIELDS, "Cryptography-review controls");
  for (const control of REQUIRED_CRYPTOGRAPHY_REVIEW_CONTROLS) if (typeof input.controls[control] !== "boolean") reject("CRYPTOGRAPHY_REVIEW_CONTROL_REJECTED", "Cryptography-review control value is invalid");
  assertExactFields(input.findings, FINDING_FIELDS, "Cryptography-review findings");
  for (const field of FINDING_FIELDS) if (!Number.isSafeInteger(input.findings[field]) || input.findings[field] < 0 || input.findings[field] > 100000) reject("CRYPTOGRAPHY_REVIEW_FINDING_REJECTED", "Cryptography-review finding count is invalid");
  return structuredClone(input);
}

export function evaluateCryptographyReview(input) {
  const assessment = validateCryptographyReview(input);
  const reasonCodes = REQUIRED_CRYPTOGRAPHY_REVIEW_CONTROLS.filter((control) => !assessment.controls[control]).map((control) => CONTROL_REASONS[control]);
  for (const field of FINDING_FIELDS) if (assessment.findings[field] > 0) reasonCodes.push(FINDING_REASONS[field]);
  const digest = createHash("sha256").update(canonicalJson(assessment)).digest("hex");
  return {
    schema: CRYPTOGRAPHY_REVIEW_DECISION_SCHEMA, decisionId: `cryptodec_${digest.slice(0, 32)}`, assessmentId: assessment.assessmentId,
    readiness: reasonCodes.length === 0 ? "ELIGIBLE_FOR_INDEPENDENT_CRYPTOGRAPHY_APPROVAL" : "NOT_READY",
    reasonCodes: reasonCodes.sort(), evidenceDigest: assessment.evidenceDigest, humanAuthorizationRequired: true,
    cryptographicOperationAuthorized: false, keyGenerationAuthorized: false, keyExportAuthorized: false,
    cryptoMigrationAuthorized: false, remediationExecutionAuthorized: false, deploymentAuthorized: false,
    signingAuthorized: false, assetMovementAuthorized: false
  };
}
