import { createHash } from "node:crypto";
import { VaultLabError } from "./errors.mjs";

export const EXTERNAL_ASSESSMENT_SCHEMA = "enteleclos.external-assessment-readiness.v1";
export const EXTERNAL_ASSESSMENT_DECISION_SCHEMA = "enteleclos.external-assessment-decision.v1";

export const REQUIRED_EXTERNAL_ASSESSMENT_CONTROLS = Object.freeze([
  "writtenAuthorizationVerified",
  "scopeBoundariesVerified",
  "rulesOfEngagementVerified",
  "safeHarborVerified",
  "independentAssessorVerified",
  "assessorCompetenceVerified",
  "conflictCheckComplete",
  "testWindowApproved",
  "productionSafetyPlanVerified",
  "dataHandlingPlanVerified",
  "emergencyContactsVerified",
  "findingSeverityMethodVerified",
  "evidenceRetentionVerified",
  "independentClosureReviewPlanned"
]);

const ROOT_FIELDS = new Set([
  "schema", "assessmentId", "assessedAt", "environment", "scopeClass", "engagementRevision",
  "scopeDigest", "rulesOfEngagementDigest", "controls", "findings", "evidenceDigest"
]);
const CONTROL_FIELDS = new Set(REQUIRED_EXTERNAL_ASSESSMENT_CONTROLS);
const FINDING_FIELDS = new Set(["authorizationGaps", "scopeAmbiguities", "safetyGaps", "dataHandlingGaps", "unresolvedConflicts"]);
const ENVIRONMENTS = new Set(["staging", "production-observation"]);
const SCOPE_CLASSES = new Set(["wallet-client", "exchange-service", "vault-service", "cloud-perimeter"]);
const CONTROL_REASON_CODES = Object.freeze({
  writtenAuthorizationVerified: "WRITTEN_AUTHORIZATION_UNVERIFIED",
  scopeBoundariesVerified: "SCOPE_BOUNDARIES_UNVERIFIED",
  rulesOfEngagementVerified: "RULES_OF_ENGAGEMENT_UNVERIFIED",
  safeHarborVerified: "SAFE_HARBOR_UNVERIFIED",
  independentAssessorVerified: "INDEPENDENT_ASSESSOR_UNVERIFIED",
  assessorCompetenceVerified: "ASSESSOR_COMPETENCE_UNVERIFIED",
  conflictCheckComplete: "CONFLICT_CHECK_INCOMPLETE",
  testWindowApproved: "TEST_WINDOW_UNAPPROVED",
  productionSafetyPlanVerified: "PRODUCTION_SAFETY_PLAN_UNVERIFIED",
  dataHandlingPlanVerified: "DATA_HANDLING_PLAN_UNVERIFIED",
  emergencyContactsVerified: "EMERGENCY_CONTACTS_UNVERIFIED",
  findingSeverityMethodVerified: "FINDING_SEVERITY_METHOD_UNVERIFIED",
  evidenceRetentionVerified: "EVIDENCE_RETENTION_UNVERIFIED",
  independentClosureReviewPlanned: "INDEPENDENT_CLOSURE_REVIEW_UNPLANNED"
});
const FINDING_REASON_CODES = Object.freeze({
  authorizationGaps: "AUTHORIZATION_GAPS_DETECTED",
  scopeAmbiguities: "SCOPE_AMBIGUITIES_DETECTED",
  safetyGaps: "SAFETY_GAPS_DETECTED",
  dataHandlingGaps: "DATA_HANDLING_GAPS_DETECTED",
  unresolvedConflicts: "ASSESSOR_CONFLICTS_UNRESOLVED"
});
const PROHIBITED_FIELD = /(?:address|attack|binary|candidate|command|credential|endpoint|exploit|host|key|mnemonic|password|payload|private|raw(?:Body|Data|Finding|Message|Payload|Request|Value)|requestBody|secret|seed|signatureValue|target|token|transaction|url|user|walletData|walletFile)/iu;

function isRecord(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
function reject(code, message) { throw new VaultLabError(code, message); }
function assertExactFields(value, allowed, label) {
  if (!isRecord(value)) reject("EXTERNAL_ASSESSMENT_INVALID", `${label} must be an object`);
  for (const key of Object.keys(value)) {
    if (PROHIBITED_FIELD.test(key)) reject("EXTERNAL_ASSESSMENT_PROHIBITED_FIELD", `${label} contains a prohibited field`);
    if (!allowed.has(key)) reject("EXTERNAL_ASSESSMENT_UNKNOWN_FIELD", `${label} has an unknown field`);
  }
  if (Object.keys(value).length !== allowed.size) reject("EXTERNAL_ASSESSMENT_UNKNOWN_FIELD", `${label} field set is incomplete or unknown`);
}
function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (isRecord(value)) return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
}

export function validateExternalAssessment(input) {
  assertExactFields(input, ROOT_FIELDS, "External-assessment readiness record");
  if (input.schema !== EXTERNAL_ASSESSMENT_SCHEMA) reject("EXTERNAL_ASSESSMENT_SCHEMA_REJECTED", "External-assessment schema is unsupported");
  if (typeof input.assessmentId !== "string" || !/^external_[0-9a-f]{32}$/u.test(input.assessmentId)) reject("EXTERNAL_ASSESSMENT_ID_REJECTED", "External-assessment identifier is invalid");
  if (typeof input.assessedAt !== "string" || Number.isNaN(Date.parse(input.assessedAt))) reject("EXTERNAL_ASSESSMENT_TIME_REJECTED", "External-assessment time is invalid");
  if (!ENVIRONMENTS.has(input.environment)) reject("EXTERNAL_ASSESSMENT_ENVIRONMENT_REJECTED", "External-assessment environment is unsupported");
  if (!SCOPE_CLASSES.has(input.scopeClass)) reject("EXTERNAL_ASSESSMENT_SCOPE_REJECTED", "External-assessment scope class is unsupported");
  if (typeof input.engagementRevision !== "string" || !/^[0-9a-f]{40}$/u.test(input.engagementRevision)) reject("EXTERNAL_ASSESSMENT_REVISION_REJECTED", "External-assessment engagement revision is invalid");
  for (const field of ["scopeDigest", "rulesOfEngagementDigest", "evidenceDigest"]) {
    if (typeof input[field] !== "string" || !/^[0-9a-f]{64}$/u.test(input[field])) reject("EXTERNAL_ASSESSMENT_DIGEST_REJECTED", "External-assessment digest is invalid");
  }
  assertExactFields(input.controls, CONTROL_FIELDS, "External-assessment controls");
  for (const control of REQUIRED_EXTERNAL_ASSESSMENT_CONTROLS) {
    if (typeof input.controls[control] !== "boolean") reject("EXTERNAL_ASSESSMENT_CONTROL_REJECTED", "External-assessment control value is invalid");
  }
  assertExactFields(input.findings, FINDING_FIELDS, "External-assessment findings");
  for (const field of FINDING_FIELDS) {
    if (!Number.isSafeInteger(input.findings[field]) || input.findings[field] < 0 || input.findings[field] > 100000) reject("EXTERNAL_ASSESSMENT_FINDING_REJECTED", "External-assessment finding count is invalid");
  }
  return structuredClone(input);
}

export function evaluateExternalAssessmentReadiness(input) {
  const assessment = validateExternalAssessment(input);
  const reasonCodes = REQUIRED_EXTERNAL_ASSESSMENT_CONTROLS.filter((control) => !assessment.controls[control]).map((control) => CONTROL_REASON_CODES[control]);
  for (const field of FINDING_FIELDS) if (assessment.findings[field] > 0) reasonCodes.push(FINDING_REASON_CODES[field]);
  const digest = createHash("sha256").update(canonicalJson(assessment)).digest("hex");
  return {
    schema: EXTERNAL_ASSESSMENT_DECISION_SCHEMA,
    decisionId: `externaldec_${digest.slice(0, 32)}`,
    assessmentId: assessment.assessmentId,
    readiness: reasonCodes.length === 0 ? "ELIGIBLE_FOR_SEPARATE_EXTERNAL_ASSESSMENT_AUTHORIZATION" : "NOT_READY",
    reasonCodes: reasonCodes.sort(),
    evidenceDigest: assessment.evidenceDigest,
    humanAuthorizationRequired: true,
    vulnerabilityScanningAuthorized: false,
    exploitationAuthorized: false,
    trafficGenerationAuthorized: false,
    deviceAccessAuthorized: false,
    accessGrantAuthorized: false,
    remediationExecutionAuthorized: false,
    deploymentAuthorized: false,
    signingAuthorized: false,
    assetMovementAuthorized: false
  };
}
