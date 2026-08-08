import { createHash } from "node:crypto";
import { VaultLabError } from "./errors.mjs";

export const THIRD_PARTY_RISK_SCHEMA = "enteleclos.third-party-risk-readiness.v1";
export const THIRD_PARTY_RISK_DECISION_SCHEMA = "enteleclos.third-party-risk-decision.v1";
export const REQUIRED_THIRD_PARTY_RISK_CONTROLS = Object.freeze([
  "vendorInventoryComplete", "criticalityClassified", "securityDueDiligenceComplete", "privacyDueDiligenceComplete",
  "dataFlowReviewed", "accessScopeMinimized", "contractControlsVerified", "subprocessorVisibilityVerified",
  "incidentNotificationVerified", "continuityPlanVerified", "concentrationRiskReviewed", "exitPlanVerified",
  "ongoingMonitoringVerified", "independentRiskReviewComplete"
]);
const ROOT_FIELDS = new Set(["schema", "assessmentId", "assessedAt", "environment", "vendorClass", "systemClass", "policyRevision", "dueDiligenceDigest", "dependencyMapDigest", "controls", "findings", "evidenceDigest"]);
const CONTROL_FIELDS = new Set(REQUIRED_THIRD_PARTY_RISK_CONTROLS);
const FINDING_FIELDS = new Set(["criticalOpen", "highOpen", "overdueReviews", "concentrationExceptions", "exitPlanGaps"]);
const ENVIRONMENTS = new Set(["staging", "production-observation"]);
const VENDOR_CLASSES = new Set(["cloud-infrastructure", "market-data", "custody-technology", "software-supply-chain"]);
const SYSTEM_CLASSES = new Set(["wallet", "exchange", "vault", "security-platform"]);
const CONTROL_REASONS = Object.freeze({
  vendorInventoryComplete: "VENDOR_INVENTORY_INCOMPLETE", criticalityClassified: "CRITICALITY_UNCLASSIFIED",
  securityDueDiligenceComplete: "SECURITY_DUE_DILIGENCE_INCOMPLETE", privacyDueDiligenceComplete: "PRIVACY_DUE_DILIGENCE_INCOMPLETE",
  dataFlowReviewed: "DATA_FLOW_UNREVIEWED", accessScopeMinimized: "ACCESS_SCOPE_NOT_MINIMIZED",
  contractControlsVerified: "CONTRACT_CONTROLS_UNVERIFIED", subprocessorVisibilityVerified: "SUBPROCESSOR_VISIBILITY_UNVERIFIED",
  incidentNotificationVerified: "INCIDENT_NOTIFICATION_UNVERIFIED", continuityPlanVerified: "CONTINUITY_PLAN_UNVERIFIED",
  concentrationRiskReviewed: "CONCENTRATION_RISK_UNREVIEWED", exitPlanVerified: "EXIT_PLAN_UNVERIFIED",
  ongoingMonitoringVerified: "ONGOING_MONITORING_UNVERIFIED", independentRiskReviewComplete: "INDEPENDENT_RISK_REVIEW_INCOMPLETE"
});
const FINDING_REASONS = Object.freeze({criticalOpen: "CRITICAL_THIRD_PARTY_FINDINGS_OPEN", highOpen: "HIGH_THIRD_PARTY_FINDINGS_OPEN", overdueReviews: "THIRD_PARTY_REVIEWS_OVERDUE", concentrationExceptions: "CONCENTRATION_EXCEPTIONS_DETECTED", exitPlanGaps: "EXIT_PLAN_GAPS_DETECTED"});
const PROHIBITED_FIELD = /(?:account|address|candidate|command|contractContent|credential|endpoint|host|key|mnemonic|password|payload|personalData|private|raw(?:Body|Data|Document|Message|Payload|Request|Value)|secret|seed|signatureValue|target|token|transaction|url|user|vendorName|walletData|walletFile)/iu;
function isRecord(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
function reject(code, message) { throw new VaultLabError(code, message); }
function assertExactFields(value, allowed, label) {
  if (!isRecord(value)) reject("THIRD_PARTY_RISK_INVALID", `${label} must be an object`);
  for (const key of Object.keys(value)) {
    if (PROHIBITED_FIELD.test(key)) reject("THIRD_PARTY_RISK_PROHIBITED_FIELD", `${label} contains a prohibited field`);
    if (!allowed.has(key)) reject("THIRD_PARTY_RISK_UNKNOWN_FIELD", `${label} has an unknown field`);
  }
  if (Object.keys(value).length !== allowed.size) reject("THIRD_PARTY_RISK_UNKNOWN_FIELD", `${label} field set is incomplete or unknown`);
}
function canonicalJson(value) { if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`; if (isRecord(value)) return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`; return JSON.stringify(value); }
export function validateThirdPartyRisk(input) {
  assertExactFields(input, ROOT_FIELDS, "Third-party-risk assessment");
  if (input.schema !== THIRD_PARTY_RISK_SCHEMA) reject("THIRD_PARTY_RISK_SCHEMA_REJECTED", "Third-party-risk schema is unsupported");
  if (typeof input.assessmentId !== "string" || !/^thirdparty_[0-9a-f]{32}$/u.test(input.assessmentId)) reject("THIRD_PARTY_RISK_ID_REJECTED", "Third-party-risk identifier is invalid");
  if (typeof input.assessedAt !== "string" || Number.isNaN(Date.parse(input.assessedAt))) reject("THIRD_PARTY_RISK_TIME_REJECTED", "Third-party-risk time is invalid");
  if (!ENVIRONMENTS.has(input.environment)) reject("THIRD_PARTY_RISK_ENVIRONMENT_REJECTED", "Third-party-risk environment is unsupported");
  if (!VENDOR_CLASSES.has(input.vendorClass) || !SYSTEM_CLASSES.has(input.systemClass)) reject("THIRD_PARTY_RISK_CLASS_REJECTED", "Third-party-risk vendor or system class is unsupported");
  if (typeof input.policyRevision !== "string" || !/^[0-9a-f]{40}$/u.test(input.policyRevision)) reject("THIRD_PARTY_RISK_REVISION_REJECTED", "Third-party-risk policy revision is invalid");
  for (const field of ["dueDiligenceDigest", "dependencyMapDigest", "evidenceDigest"]) if (typeof input[field] !== "string" || !/^[0-9a-f]{64}$/u.test(input[field])) reject("THIRD_PARTY_RISK_DIGEST_REJECTED", "Third-party-risk digest is invalid");
  assertExactFields(input.controls, CONTROL_FIELDS, "Third-party-risk controls");
  for (const control of REQUIRED_THIRD_PARTY_RISK_CONTROLS) if (typeof input.controls[control] !== "boolean") reject("THIRD_PARTY_RISK_CONTROL_REJECTED", "Third-party-risk control value is invalid");
  assertExactFields(input.findings, FINDING_FIELDS, "Third-party-risk findings");
  for (const field of FINDING_FIELDS) if (!Number.isSafeInteger(input.findings[field]) || input.findings[field] < 0 || input.findings[field] > 100000) reject("THIRD_PARTY_RISK_FINDING_REJECTED", "Third-party-risk finding count is invalid");
  return structuredClone(input);
}
export function evaluateThirdPartyRisk(input) {
  const assessment = validateThirdPartyRisk(input);
  const reasonCodes = REQUIRED_THIRD_PARTY_RISK_CONTROLS.filter((control) => !assessment.controls[control]).map((control) => CONTROL_REASONS[control]);
  for (const field of FINDING_FIELDS) if (assessment.findings[field] > 0) reasonCodes.push(FINDING_REASONS[field]);
  const digest = createHash("sha256").update(canonicalJson(assessment)).digest("hex");
  return {
    schema: THIRD_PARTY_RISK_DECISION_SCHEMA, decisionId: `thirdpartydec_${digest.slice(0, 32)}`, assessmentId: assessment.assessmentId,
    readiness: reasonCodes.length === 0 ? "ELIGIBLE_FOR_INDEPENDENT_THIRD_PARTY_REVIEW" : "NOT_READY", reasonCodes: reasonCodes.sort(),
    evidenceDigest: assessment.evidenceDigest, humanAuthorizationRequired: true, vendorOnboardingAuthorized: false,
    contractExecutionAuthorized: false, credentialIssuanceAuthorized: false, dataSharingAuthorized: false,
    accessGrantAuthorized: false, procurementAuthorized: false, paymentAuthorized: false,
    deploymentAuthorized: false, signingAuthorized: false, assetMovementAuthorized: false
  };
}
