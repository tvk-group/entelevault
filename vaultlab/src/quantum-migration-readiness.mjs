import { createHash } from "node:crypto";
import { VaultLabError } from "./errors.mjs";

export const QUANTUM_MIGRATION_SCHEMA = "enteleclos.quantum-migration-readiness.v1";
export const QUANTUM_MIGRATION_DECISION_SCHEMA = "enteleclos.quantum-migration-decision.v1";

export const REQUIRED_QUANTUM_MIGRATION_CONTROLS = Object.freeze([
  "classicalAlgorithmInventoryComplete",
  "longLivedDataExposureAssessed",
  "asymmetricDependencyMapComplete",
  "standardsProfileApproved",
  "librarySupportRoadmapReviewed",
  "protocolNegotiationVersioned",
  "cryptoAgilityInterfacesVerified",
  "hybridMigrationPlanReviewed",
  "rollbackAndInteroperabilityPlanVerified",
  "materialLifecyclePlanReviewed",
  "dataFormatMigrationPlanReviewed",
  "supplyChainCompatibilityReviewed",
  "independentCryptographyReviewComplete",
  "customCryptographyProhibited"
]);

const ROOT_FIELDS = new Set([
  "schema",
  "assessmentId",
  "assessedAt",
  "environment",
  "systemClass",
  "architectureRevision",
  "inventoryDigest",
  "migrationPlanDigest",
  "controls",
  "findings",
  "evidenceDigest"
]);
const CONTROL_FIELDS = new Set(REQUIRED_QUANTUM_MIGRATION_CONTROLS);
const FINDING_FIELDS = new Set([
  "criticalOpen",
  "highOpen",
  "inventoryGaps",
  "unreviewedDependencies",
  "interoperabilityFailures"
]);
const ENVIRONMENTS = new Set(["staging", "production-observation"]);
const SYSTEM_CLASSES = new Set([
  "wallet-client",
  "exchange-frontend",
  "vault-service",
  "cloud-control-plane",
  "custody-interface"
]);
const CONTROL_REASONS = Object.freeze({
  classicalAlgorithmInventoryComplete: "CLASSICAL_ALGORITHM_INVENTORY_INCOMPLETE",
  longLivedDataExposureAssessed: "LONG_LIVED_DATA_EXPOSURE_UNASSESSED",
  asymmetricDependencyMapComplete: "ASYMMETRIC_DEPENDENCY_MAP_INCOMPLETE",
  standardsProfileApproved: "STANDARDS_PROFILE_UNAPPROVED",
  librarySupportRoadmapReviewed: "LIBRARY_SUPPORT_ROADMAP_UNREVIEWED",
  protocolNegotiationVersioned: "PROTOCOL_NEGOTIATION_UNVERSIONED",
  cryptoAgilityInterfacesVerified: "CRYPTO_AGILITY_INTERFACES_UNVERIFIED",
  hybridMigrationPlanReviewed: "HYBRID_MIGRATION_PLAN_UNREVIEWED",
  rollbackAndInteroperabilityPlanVerified: "ROLLBACK_INTEROPERABILITY_PLAN_UNVERIFIED",
  materialLifecyclePlanReviewed: "MATERIAL_LIFECYCLE_PLAN_UNREVIEWED",
  dataFormatMigrationPlanReviewed: "DATA_FORMAT_MIGRATION_PLAN_UNREVIEWED",
  supplyChainCompatibilityReviewed: "SUPPLY_CHAIN_COMPATIBILITY_UNREVIEWED",
  independentCryptographyReviewComplete: "INDEPENDENT_CRYPTOGRAPHY_REVIEW_INCOMPLETE",
  customCryptographyProhibited: "CUSTOM_CRYPTOGRAPHY_NOT_PROHIBITED"
});
const FINDING_REASONS = Object.freeze({
  criticalOpen: "CRITICAL_QUANTUM_MIGRATION_FINDINGS_OPEN",
  highOpen: "HIGH_QUANTUM_MIGRATION_FINDINGS_OPEN",
  inventoryGaps: "QUANTUM_MIGRATION_INVENTORY_GAPS",
  unreviewedDependencies: "QUANTUM_MIGRATION_DEPENDENCIES_UNREVIEWED",
  interoperabilityFailures: "QUANTUM_MIGRATION_INTEROPERABILITY_FAILURES"
});
const PROHIBITED_FIELD = /(?:address|candidate|ciphertext|command|credential|entropyValue|key|mnemonic|nonceValue|password|payload|plaintext|private|raw(?:Body|Data|Material|Message|Payload|Request|Value)|secret|seed|signatureValue|target|token|transaction|user|walletData|walletFile)/iu;

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function reject(code, message) {
  throw new VaultLabError(code, message);
}

function assertExactFields(value, allowed, label) {
  if (!isRecord(value)) reject("QUANTUM_MIGRATION_INVALID", `${label} must be an object`);
  for (const field of Object.keys(value)) {
    if (PROHIBITED_FIELD.test(field)) {
      reject("QUANTUM_MIGRATION_PROHIBITED_FIELD", `${label} contains a prohibited field`);
    }
    if (!allowed.has(field)) {
      reject("QUANTUM_MIGRATION_UNKNOWN_FIELD", `${label} has an unknown field`);
    }
  }
  if (Object.keys(value).length !== allowed.size) {
    reject("QUANTUM_MIGRATION_UNKNOWN_FIELD", `${label} field set is incomplete or unknown`);
  }
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value)
      .sort()
      .map((field) => `${JSON.stringify(field)}:${canonicalJson(value[field])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

export function validateQuantumMigrationReadiness(input) {
  assertExactFields(input, ROOT_FIELDS, "Quantum-migration assessment");
  if (input.schema !== QUANTUM_MIGRATION_SCHEMA) {
    reject("QUANTUM_MIGRATION_SCHEMA_REJECTED", "Quantum-migration schema is unsupported");
  }
  if (typeof input.assessmentId !== "string" || !/^quantum_[0-9a-f]{32}$/u.test(input.assessmentId)) {
    reject("QUANTUM_MIGRATION_ID_REJECTED", "Quantum-migration identifier is invalid");
  }
  if (typeof input.assessedAt !== "string" || Number.isNaN(Date.parse(input.assessedAt))) {
    reject("QUANTUM_MIGRATION_TIME_REJECTED", "Quantum-migration time is invalid");
  }
  if (!ENVIRONMENTS.has(input.environment)) {
    reject("QUANTUM_MIGRATION_ENVIRONMENT_REJECTED", "Quantum-migration environment is unsupported");
  }
  if (!SYSTEM_CLASSES.has(input.systemClass)) {
    reject("QUANTUM_MIGRATION_SYSTEM_REJECTED", "Quantum-migration system class is unsupported");
  }
  if (typeof input.architectureRevision !== "string" || !/^[0-9a-f]{40}$/u.test(input.architectureRevision)) {
    reject("QUANTUM_MIGRATION_REVISION_REJECTED", "Quantum-migration architecture revision is invalid");
  }
  for (const field of ["inventoryDigest", "migrationPlanDigest", "evidenceDigest"]) {
    if (typeof input[field] !== "string" || !/^[0-9a-f]{64}$/u.test(input[field])) {
      reject("QUANTUM_MIGRATION_DIGEST_REJECTED", "Quantum-migration digest is invalid");
    }
  }
  assertExactFields(input.controls, CONTROL_FIELDS, "Quantum-migration controls");
  for (const control of REQUIRED_QUANTUM_MIGRATION_CONTROLS) {
    if (typeof input.controls[control] !== "boolean") {
      reject("QUANTUM_MIGRATION_CONTROL_REJECTED", "Quantum-migration control value is invalid");
    }
  }
  assertExactFields(input.findings, FINDING_FIELDS, "Quantum-migration findings");
  for (const field of FINDING_FIELDS) {
    if (!Number.isSafeInteger(input.findings[field]) || input.findings[field] < 0 || input.findings[field] > 100000) {
      reject("QUANTUM_MIGRATION_FINDING_REJECTED", "Quantum-migration finding count is invalid");
    }
  }
  return structuredClone(input);
}

export function evaluateQuantumMigrationReadiness(input) {
  const assessment = validateQuantumMigrationReadiness(input);
  const reasonCodes = REQUIRED_QUANTUM_MIGRATION_CONTROLS
    .filter((control) => !assessment.controls[control])
    .map((control) => CONTROL_REASONS[control]);
  for (const field of FINDING_FIELDS) {
    if (assessment.findings[field] > 0) reasonCodes.push(FINDING_REASONS[field]);
  }
  const digest = createHash("sha256").update(canonicalJson(assessment)).digest("hex");
  return {
    schema: QUANTUM_MIGRATION_DECISION_SCHEMA,
    decisionId: `quantumdec_${digest.slice(0, 32)}`,
    assessmentId: assessment.assessmentId,
    readiness: reasonCodes.length === 0 ? "ELIGIBLE_FOR_INDEPENDENT_QUANTUM_MIGRATION_REVIEW" : "NOT_READY",
    reasonCodes: reasonCodes.sort(),
    evidenceDigest: assessment.evidenceDigest,
    humanAuthorizationRequired: true,
    quantumSafetyClaimed: false,
    algorithmMigrationAuthorized: false,
    cryptographicOperationAuthorized: false,
    custodyActivationAuthorized: false,
    deploymentAuthorized: false,
    signingAuthorized: false,
    assetMovementAuthorized: false
  };
}
