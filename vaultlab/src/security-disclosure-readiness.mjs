import { createHash } from "node:crypto";
import { VaultLabError } from "./errors.mjs";

export const SECURITY_DISCLOSURE_SCHEMA = "enteleclos.security-disclosure-readiness.v1";
export const SECURITY_DISCLOSURE_DECISION_SCHEMA = "enteleclos.security-disclosure-decision.v1";
export const REQUIRED_SECURITY_DISCLOSURE_CONTROLS = Object.freeze([
  "publishedPolicyVerified", "scopeRegistryVerified", "safeHarborVerified", "authorizedChannelsVerified",
  "researcherPrivacyVerified", "triageSlaVerified", "severityMethodVerified", "duplicateHandlingVerified",
  "rewardPolicyVerified", "legalEscalationPathVerified", "emergencyContactVerified", "evidenceHandlingVerified",
  "remediationTrackingVerified", "publicDisclosureApprovalVerified"
]);
const ROOT_FIELDS = new Set(["schema", "assessmentId", "assessedAt", "environment", "programClass", "systemClass", "programRevision", "policyDigest", "scopeDigest", "controls", "findings", "evidenceDigest"]);
const CONTROL_FIELDS = new Set(REQUIRED_SECURITY_DISCLOSURE_CONTROLS);
const FINDING_FIELDS = new Set(["policyGaps", "scopeAmbiguities", "overdueTriage", "privacyBreaches", "unresolvedDisputes"]);
const ENVIRONMENTS = new Set(["staging", "production-observation"]);
const PROGRAM_CLASSES = new Set(["private-disclosure", "public-bounty", "vendor-coordinated"]);
const SYSTEM_CLASSES = new Set(["wallet", "exchange", "vault", "security-platform"]);
const CONTROL_REASONS = Object.freeze({
  publishedPolicyVerified: "PUBLISHED_POLICY_UNVERIFIED", scopeRegistryVerified: "SCOPE_REGISTRY_UNVERIFIED",
  safeHarborVerified: "SAFE_HARBOR_UNVERIFIED", authorizedChannelsVerified: "AUTHORIZED_CHANNELS_UNVERIFIED",
  researcherPrivacyVerified: "RESEARCHER_PRIVACY_UNVERIFIED", triageSlaVerified: "TRIAGE_SLA_UNVERIFIED",
  severityMethodVerified: "SEVERITY_METHOD_UNVERIFIED", duplicateHandlingVerified: "DUPLICATE_HANDLING_UNVERIFIED",
  rewardPolicyVerified: "REWARD_POLICY_UNVERIFIED", legalEscalationPathVerified: "LEGAL_ESCALATION_PATH_UNVERIFIED",
  emergencyContactVerified: "EMERGENCY_CONTACT_UNVERIFIED", evidenceHandlingVerified: "EVIDENCE_HANDLING_UNVERIFIED",
  remediationTrackingVerified: "REMEDIATION_TRACKING_UNVERIFIED", publicDisclosureApprovalVerified: "PUBLIC_DISCLOSURE_APPROVAL_UNVERIFIED"
});
const FINDING_REASONS = Object.freeze({policyGaps: "POLICY_GAPS_DETECTED", scopeAmbiguities: "SCOPE_AMBIGUITIES_DETECTED", overdueTriage: "TRIAGE_OVERDUE", privacyBreaches: "RESEARCHER_PRIVACY_BREACHES_DETECTED", unresolvedDisputes: "DISCLOSURE_DISPUTES_UNRESOLVED"});
const PROHIBITED_FIELD = /(?:address|attack|candidate|command|credential|endpoint|exploit|findingDetail|host|key|mnemonic|password|payload|private|proofOfConcept|raw(?:Body|Data|Finding|Message|Payload|Report|Request|Value)|researcherIdentity|secret|seed|signatureValue|target|token|transaction|url|user|walletData|walletFile)/iu;
function isRecord(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
function reject(code, message) { throw new VaultLabError(code, message); }
function assertExactFields(value, allowed, label) {
  if (!isRecord(value)) reject("SECURITY_DISCLOSURE_INVALID", `${label} must be an object`);
  for (const key of Object.keys(value)) {
    if (PROHIBITED_FIELD.test(key)) reject("SECURITY_DISCLOSURE_PROHIBITED_FIELD", `${label} contains a prohibited field`);
    if (!allowed.has(key)) reject("SECURITY_DISCLOSURE_UNKNOWN_FIELD", `${label} has an unknown field`);
  }
  if (Object.keys(value).length !== allowed.size) reject("SECURITY_DISCLOSURE_UNKNOWN_FIELD", `${label} field set is incomplete or unknown`);
}
function canonicalJson(value) { if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`; if (isRecord(value)) return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`; return JSON.stringify(value); }
export function validateSecurityDisclosure(input) {
  assertExactFields(input, ROOT_FIELDS, "Security-disclosure assessment");
  if (input.schema !== SECURITY_DISCLOSURE_SCHEMA) reject("SECURITY_DISCLOSURE_SCHEMA_REJECTED", "Security-disclosure schema is unsupported");
  if (typeof input.assessmentId !== "string" || !/^disclosure_[0-9a-f]{32}$/u.test(input.assessmentId)) reject("SECURITY_DISCLOSURE_ID_REJECTED", "Security-disclosure identifier is invalid");
  if (typeof input.assessedAt !== "string" || Number.isNaN(Date.parse(input.assessedAt))) reject("SECURITY_DISCLOSURE_TIME_REJECTED", "Security-disclosure time is invalid");
  if (!ENVIRONMENTS.has(input.environment)) reject("SECURITY_DISCLOSURE_ENVIRONMENT_REJECTED", "Security-disclosure environment is unsupported");
  if (!PROGRAM_CLASSES.has(input.programClass) || !SYSTEM_CLASSES.has(input.systemClass)) reject("SECURITY_DISCLOSURE_CLASS_REJECTED", "Security-disclosure program or system class is unsupported");
  if (typeof input.programRevision !== "string" || !/^[0-9a-f]{40}$/u.test(input.programRevision)) reject("SECURITY_DISCLOSURE_REVISION_REJECTED", "Security-disclosure program revision is invalid");
  for (const field of ["policyDigest", "scopeDigest", "evidenceDigest"]) if (typeof input[field] !== "string" || !/^[0-9a-f]{64}$/u.test(input[field])) reject("SECURITY_DISCLOSURE_DIGEST_REJECTED", "Security-disclosure digest is invalid");
  assertExactFields(input.controls, CONTROL_FIELDS, "Security-disclosure controls");
  for (const control of REQUIRED_SECURITY_DISCLOSURE_CONTROLS) if (typeof input.controls[control] !== "boolean") reject("SECURITY_DISCLOSURE_CONTROL_REJECTED", "Security-disclosure control value is invalid");
  assertExactFields(input.findings, FINDING_FIELDS, "Security-disclosure findings");
  for (const field of FINDING_FIELDS) if (!Number.isSafeInteger(input.findings[field]) || input.findings[field] < 0 || input.findings[field] > 100000) reject("SECURITY_DISCLOSURE_FINDING_REJECTED", "Security-disclosure finding count is invalid");
  return structuredClone(input);
}
export function evaluateSecurityDisclosure(input) {
  const assessment = validateSecurityDisclosure(input);
  const reasonCodes = REQUIRED_SECURITY_DISCLOSURE_CONTROLS.filter((control) => !assessment.controls[control]).map((control) => CONTROL_REASONS[control]);
  for (const field of FINDING_FIELDS) if (assessment.findings[field] > 0) reasonCodes.push(FINDING_REASONS[field]);
  const digest = createHash("sha256").update(canonicalJson(assessment)).digest("hex");
  return {
    schema: SECURITY_DISCLOSURE_DECISION_SCHEMA, decisionId: `disclosuredec_${digest.slice(0, 32)}`, assessmentId: assessment.assessmentId,
    readiness: reasonCodes.length === 0 ? "ELIGIBLE_FOR_SEPARATE_DISCLOSURE_PROGRAM_APPROVAL" : "NOT_READY", reasonCodes: reasonCodes.sort(),
    evidenceDigest: assessment.evidenceDigest, humanAuthorizationRequired: true, programActivationAuthorized: false,
    vulnerabilityScanningAuthorized: false, exploitationAuthorized: false, publicDisclosureAuthorized: false,
    rewardPaymentAuthorized: false, remediationExecutionAuthorized: false, deploymentAuthorized: false,
    signingAuthorized: false, assetMovementAuthorized: false
  };
}
