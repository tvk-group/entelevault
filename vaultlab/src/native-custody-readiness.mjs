import { createHash } from "node:crypto";
import { VaultLabError } from "./errors.mjs";

export const CUSTODY_READINESS_SCHEMA = "entelevault.custody-readiness.v1";
export const CUSTODY_DECISION_SCHEMA = "entelevault.custody-readiness-decision.v1";

export const REQUIRED_CUSTODY_CONTROLS = Object.freeze([
  "cryptographyReviewApproved",
  "hardwareBoundaryReviewed",
  "mobilePlatformStorageTested",
  "signingIntentGuardEnabled",
  "recoveryQuorumTested",
  "keyCeremonyRehearsed",
  "incidentExercisePassed",
  "dependencyProvenanceVerified",
  "reproducibleBuildVerified",
  "externalPenetrationTestPassed",
  "privacyReviewApproved",
  "monitoringAndRevocationTested"
]);

const ROOT_FIELDS = new Set([
  "schema",
  "assessmentId",
  "assessedAt",
  "sourceRevision",
  "environment",
  "architecture",
  "controls",
  "findings",
  "evidenceDigest"
]);
const ARCHITECTURE_FIELDS = new Set([
  "custodyModel",
  "keyGeneration",
  "exportPolicy",
  "recoveryModel"
]);
const CONTROL_FIELDS = new Set(REQUIRED_CUSTODY_CONTROLS);
const FINDING_FIELDS = new Set(["criticalOpen", "highOpen"]);
const MODELS = new Set([
  "institutional-hsm-quorum",
  "mpc-quorum",
  "non-custodial-device-bound"
]);
const KEY_GENERATION = new Set(["certified-hsm", "mpc-ceremony", "platform-hardware"]);
const EXPECTED_KEY_GENERATION = Object.freeze({
  "institutional-hsm-quorum": "certified-hsm",
  "mpc-quorum": "mpc-ceremony",
  "non-custodial-device-bound": "platform-hardware"
});
const CONTROL_REASON_CODES = Object.freeze({
  cryptographyReviewApproved: "CRYPTOGRAPHY_REVIEW_MISSING",
  hardwareBoundaryReviewed: "HARDWARE_BOUNDARY_REVIEW_MISSING",
  mobilePlatformStorageTested: "MOBILE_STORAGE_TEST_MISSING",
  signingIntentGuardEnabled: "SIGNING_INTENT_GUARD_MISSING",
  recoveryQuorumTested: "RECOVERY_QUORUM_TEST_MISSING",
  keyCeremonyRehearsed: "KEY_CEREMONY_REHEARSAL_MISSING",
  incidentExercisePassed: "INCIDENT_EXERCISE_MISSING",
  dependencyProvenanceVerified: "DEPENDENCY_PROVENANCE_MISSING",
  reproducibleBuildVerified: "REPRODUCIBLE_BUILD_MISSING",
  externalPenetrationTestPassed: "EXTERNAL_PENETRATION_TEST_MISSING",
  privacyReviewApproved: "PRIVACY_REVIEW_MISSING",
  monitoringAndRevocationTested: "MONITORING_REVOCATION_TEST_MISSING"
});
const PROHIBITED_FIELD = /(?:address|candidate|credential|keyMaterial|mnemonic|password|private|raw|seed|signature|target|transaction|walletFile)/iu;

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function reject(code, message) {
  throw new VaultLabError(code, message);
}

function assertExactFields(value, allowed, label) {
  if (!isRecord(value)) reject("CUSTODY_READINESS_INVALID", `${label} must be an object`);
  for (const key of Object.keys(value)) {
    if (PROHIBITED_FIELD.test(key)) {
      reject("CUSTODY_READINESS_PROHIBITED_FIELD", `${label} contains a prohibited field`);
    }
    if (!allowed.has(key)) reject("CUSTODY_READINESS_UNKNOWN_FIELD", `${label} has an unknown field`);
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

export function validateCustodyReadiness(input) {
  assertExactFields(input, ROOT_FIELDS, "Custody readiness assessment");
  if (input.schema !== CUSTODY_READINESS_SCHEMA) {
    reject("CUSTODY_READINESS_SCHEMA_REJECTED", "Custody readiness schema is unsupported");
  }
  if (typeof input.assessmentId !== "string" || !/^assess_[0-9a-f]{32}$/u.test(input.assessmentId)) {
    reject("CUSTODY_READINESS_ID_REJECTED", "Custody assessment identifier is invalid");
  }
  if (typeof input.assessedAt !== "string" || Number.isNaN(Date.parse(input.assessedAt))) {
    reject("CUSTODY_READINESS_TIME_REJECTED", "Custody assessment time is invalid");
  }
  if (typeof input.sourceRevision !== "string" || !/^[0-9a-f]{40}$/u.test(input.sourceRevision)) {
    reject("CUSTODY_READINESS_REVISION_REJECTED", "Custody source revision is invalid");
  }
  if (input.environment !== "staging") {
    reject("CUSTODY_READINESS_ENVIRONMENT_REJECTED", "Custody activation assessment is staging-only");
  }

  assertExactFields(input.architecture, ARCHITECTURE_FIELDS, "Custody architecture");
  if (!MODELS.has(input.architecture.custodyModel)) {
    reject("CUSTODY_ARCHITECTURE_REJECTED", "Custody model is unsupported");
  }
  if (!KEY_GENERATION.has(input.architecture.keyGeneration)) {
    reject("CUSTODY_ARCHITECTURE_REJECTED", "Custody key-generation model is unsupported");
  }
  if (input.architecture.keyGeneration !== EXPECTED_KEY_GENERATION[input.architecture.custodyModel]) {
    reject("CUSTODY_ARCHITECTURE_REJECTED", "Custody model and key generation are inconsistent");
  }
  if (
    input.architecture.exportPolicy !== "prohibited" ||
    input.architecture.recoveryModel !== "quorum-governed"
  ) {
    reject("CUSTODY_ARCHITECTURE_REJECTED", "Custody export or recovery policy is unsupported");
  }

  assertExactFields(input.controls, CONTROL_FIELDS, "Custody controls");
  if (Object.keys(input.controls).length !== REQUIRED_CUSTODY_CONTROLS.length) {
    reject("CUSTODY_CONTROL_REJECTED", "Custody control set is incomplete");
  }
  for (const control of REQUIRED_CUSTODY_CONTROLS) {
    if (typeof input.controls[control] !== "boolean") {
      reject("CUSTODY_CONTROL_REJECTED", "Custody control value is invalid");
    }
  }

  assertExactFields(input.findings, FINDING_FIELDS, "Custody findings");
  for (const field of FINDING_FIELDS) {
    if (
      !Number.isSafeInteger(input.findings[field]) ||
      input.findings[field] < 0 ||
      input.findings[field] > 100
    ) {
      reject("CUSTODY_FINDING_REJECTED", "Custody finding count is invalid");
    }
  }
  if (typeof input.evidenceDigest !== "string" || !/^[0-9a-f]{64}$/u.test(input.evidenceDigest)) {
    reject("CUSTODY_EVIDENCE_REJECTED", "Custody evidence digest is invalid");
  }
  return structuredClone(input);
}

export function evaluateCustodyReadiness(input) {
  const assessment = validateCustodyReadiness(input);
  const reasonCodes = REQUIRED_CUSTODY_CONTROLS
    .filter((control) => !assessment.controls[control])
    .map((control) => CONTROL_REASON_CODES[control]);
  if (assessment.findings.criticalOpen > 0) reasonCodes.push("CRITICAL_FINDINGS_OPEN");
  if (assessment.findings.highOpen > 0) reasonCodes.push("HIGH_FINDINGS_OPEN");

  const digest = createHash("sha256").update(canonicalJson(assessment)).digest("hex");
  return {
    schema: CUSTODY_DECISION_SCHEMA,
    decisionId: `custdec_${digest.slice(0, 32)}`,
    assessmentId: assessment.assessmentId,
    readiness:
      reasonCodes.length === 0 ? "ELIGIBLE_FOR_INDEPENDENT_ACTIVATION_REVIEW" : "NOT_READY",
    reasonCodes: reasonCodes.sort(),
    evidenceDigest: assessment.evidenceDigest,
    humanAuthorizationRequired: true,
    deploymentAuthorized: false,
    custodyActivationAuthorized: false,
    signingAuthorized: false,
    assetMovementAuthorized: false
  };
}
