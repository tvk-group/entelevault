import { createHash } from "node:crypto";
import { VaultLabError } from "./errors.mjs";

export const SIGNER_CEREMONY_SCHEMA = "entelevault.signer-ceremony-governance.v1";
export const SIGNER_CEREMONY_DECISION_SCHEMA = "entelevault.signer-ceremony-decision.v1";

export const SIGNER_CEREMONY_CONTROL_FIELDS = Object.freeze([
  "ceremonyPlanApproved",
  "participantIndependenceVerified",
  "participantIdentityAttested",
  "separationOfDutiesVerified",
  "environmentIsolationVerified",
  "deviceAttestationVerified",
  "entropySourceReviewCompleted",
  "backupPolicyReviewed",
  "quorumFailureTested",
  "abortProcedureTested",
  "tamperEvidenceVerified",
  "transcriptDigestSealed",
  "independentReviewApproved"
]);

const ROOT_FIELDS = new Set([
  "schema",
  "ceremonyId",
  "phase",
  "openedAt",
  "lastTransitionAt",
  "environment",
  "architecture",
  "controls",
  "approvals",
  "findings",
  "evidenceDigest"
]);
const ARCHITECTURE_FIELDS = new Set([
  "signerModel",
  "thresholdClass",
  "exportPolicy",
  "networkClass"
]);
const CONTROL_FIELDS = new Set(SIGNER_CEREMONY_CONTROL_FIELDS);
const APPROVAL_FIELDS = new Set(["role", "approverId", "approvedAt", "attestationDigest"]);
const FINDING_FIELDS = new Set(["criticalOpen", "highOpen", "mediumOpen"]);
const PHASES = Object.freeze([
  "planned",
  "participants-verified",
  "environment-attested",
  "quorum-rehearsed",
  "evidence-sealed",
  "independently-reviewed",
  "closed"
]);
const PHASE_INDEX = Object.freeze(Object.fromEntries(PHASES.map((phase, index) => [phase, index])));
const TRANSITIONS = Object.freeze({
  planned: new Set(["participants-verified"]),
  "participants-verified": new Set(["environment-attested"]),
  "environment-attested": new Set(["quorum-rehearsed"]),
  "quorum-rehearsed": new Set(["evidence-sealed"]),
  "evidence-sealed": new Set(["independently-reviewed"]),
  "independently-reviewed": new Set(["closed"]),
  closed: new Set()
});
const REQUIRED_CONTROLS_BY_PHASE = Object.freeze({
  planned: ["ceremonyPlanApproved"],
  "participants-verified": SIGNER_CEREMONY_CONTROL_FIELDS.slice(0, 4),
  "environment-attested": SIGNER_CEREMONY_CONTROL_FIELDS.slice(0, 7),
  "quorum-rehearsed": SIGNER_CEREMONY_CONTROL_FIELDS.slice(0, 10),
  "evidence-sealed": SIGNER_CEREMONY_CONTROL_FIELDS.slice(0, 12),
  "independently-reviewed": SIGNER_CEREMONY_CONTROL_FIELDS,
  closed: SIGNER_CEREMONY_CONTROL_FIELDS
});
const CONTROL_REASON_CODES = Object.freeze({
  ceremonyPlanApproved: "CEREMONY_PLAN_UNAPPROVED",
  participantIndependenceVerified: "PARTICIPANT_INDEPENDENCE_UNVERIFIED",
  participantIdentityAttested: "PARTICIPANT_IDENTITY_UNATTESTED",
  separationOfDutiesVerified: "SEPARATION_OF_DUTIES_UNVERIFIED",
  environmentIsolationVerified: "ENVIRONMENT_ISOLATION_UNVERIFIED",
  deviceAttestationVerified: "DEVICE_ATTESTATION_UNVERIFIED",
  entropySourceReviewCompleted: "ENTROPY_SOURCE_REVIEW_INCOMPLETE",
  backupPolicyReviewed: "BACKUP_POLICY_UNREVIEWED",
  quorumFailureTested: "QUORUM_FAILURE_UNTESTED",
  abortProcedureTested: "ABORT_PROCEDURE_UNTESTED",
  tamperEvidenceVerified: "TAMPER_EVIDENCE_UNVERIFIED",
  transcriptDigestSealed: "TRANSCRIPT_DIGEST_UNSEALED",
  independentReviewApproved: "INDEPENDENT_REVIEW_UNAPPROVED"
});
const NEXT_PHASE_REASON = Object.freeze({
  planned: "PARTICIPANT_VERIFICATION_REQUIRED",
  "participants-verified": "ENVIRONMENT_ATTESTATION_REQUIRED",
  "environment-attested": "QUORUM_REHEARSAL_REQUIRED",
  "quorum-rehearsed": "EVIDENCE_SEALING_REQUIRED",
  "evidence-sealed": "INDEPENDENT_REVIEW_REQUIRED"
});
const SIGNER_MODELS = new Set(["certified-hsm-quorum", "mpc-quorum", "device-bound-quorum"]);
const THRESHOLD_CLASSES = new Set(["two-of-three", "three-of-five", "policy-defined"]);
const NETWORK_CLASSES = new Set(["isolated", "restricted"]);
const APPROVAL_ROLES = new Set(["security", "custody", "operations", "compliance", "independent-review"]);
const QUORUM_ROLES = Object.freeze(["security", "custody", "operations"]);
const PROHIBITED_FIELD = /(?:address|candidate|command|credential|email|entropyValue|executable|keyShare|mnemonic|participantName|password|payload|privateKey|rawEntropy|secret|seed|signatureValue|target|token|transaction|transcriptContent|user|wallet)/iu;

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function reject(code, message) {
  throw new VaultLabError(code, message);
}

function assertExactFields(value, allowed, label) {
  if (!isRecord(value)) reject("SIGNER_CEREMONY_INVALID", `${label} must be an object`);
  for (const key of Object.keys(value)) {
    if (PROHIBITED_FIELD.test(key)) {
      reject("SIGNER_CEREMONY_PROHIBITED_FIELD", `${label} contains a prohibited field`);
    }
    if (!allowed.has(key)) reject("SIGNER_CEREMONY_UNKNOWN_FIELD", `${label} has an unknown field`);
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

export function validateSignerCeremony(input) {
  assertExactFields(input, ROOT_FIELDS, "Signer ceremony");
  if (input.schema !== SIGNER_CEREMONY_SCHEMA) {
    reject("SIGNER_CEREMONY_SCHEMA_REJECTED", "Signer-ceremony schema is unsupported");
  }
  if (typeof input.ceremonyId !== "string" || !/^ceremony_[0-9a-f]{32}$/u.test(input.ceremonyId)) {
    reject("SIGNER_CEREMONY_ID_REJECTED", "Signer-ceremony identifier is invalid");
  }
  if (!PHASES.includes(input.phase)) reject("SIGNER_CEREMONY_PHASE_REJECTED", "Signer-ceremony phase is unsupported");
  if (
    typeof input.openedAt !== "string" ||
    Number.isNaN(Date.parse(input.openedAt)) ||
    typeof input.lastTransitionAt !== "string" ||
    Number.isNaN(Date.parse(input.lastTransitionAt)) ||
    Date.parse(input.lastTransitionAt) < Date.parse(input.openedAt)
  ) {
    reject("SIGNER_CEREMONY_TIME_REJECTED", "Signer-ceremony timestamps are invalid");
  }
  if (input.environment !== "staging") {
    reject("SIGNER_CEREMONY_ENVIRONMENT_REJECTED", "Signer-ceremony assurance is staging-only");
  }

  assertExactFields(input.architecture, ARCHITECTURE_FIELDS, "Signer architecture");
  if (!SIGNER_MODELS.has(input.architecture.signerModel)) reject("SIGNER_ARCHITECTURE_REJECTED", "Signer model is unsupported");
  if (!THRESHOLD_CLASSES.has(input.architecture.thresholdClass)) reject("SIGNER_ARCHITECTURE_REJECTED", "Signer threshold class is unsupported");
  if (input.architecture.exportPolicy !== "prohibited") reject("SIGNER_ARCHITECTURE_REJECTED", "Signer export policy must be prohibited");
  if (!NETWORK_CLASSES.has(input.architecture.networkClass)) reject("SIGNER_ARCHITECTURE_REJECTED", "Signer network class is unsupported");

  assertExactFields(input.controls, CONTROL_FIELDS, "Signer-ceremony controls");
  if (Object.keys(input.controls).length !== SIGNER_CEREMONY_CONTROL_FIELDS.length) {
    reject("SIGNER_CEREMONY_CONTROL_REJECTED", "Signer-ceremony control set is incomplete");
  }
  for (const control of SIGNER_CEREMONY_CONTROL_FIELDS) {
    if (typeof input.controls[control] !== "boolean") reject("SIGNER_CEREMONY_CONTROL_REJECTED", "Signer-ceremony control value is invalid");
  }
  const allowed = new Set(REQUIRED_CONTROLS_BY_PHASE[input.phase]);
  if (SIGNER_CEREMONY_CONTROL_FIELDS.some((control) => input.controls[control] && !allowed.has(control))) {
    reject("SIGNER_CEREMONY_CONTROL_REJECTED", "Signer-ceremony controls cannot be completed before their phase");
  }

  if (!Array.isArray(input.approvals) || input.approvals.length > 5) {
    reject("SIGNER_CEREMONY_APPROVAL_REJECTED", "Signer-ceremony approvals are outside policy");
  }
  for (const approval of input.approvals) {
    assertExactFields(approval, APPROVAL_FIELDS, "Signer-ceremony approval");
    if (!APPROVAL_ROLES.has(approval.role)) reject("SIGNER_CEREMONY_APPROVAL_REJECTED", "Signer-ceremony approval role is unsupported");
    if (typeof approval.approverId !== "string" || !/^approver_[0-9a-f]{16}$/u.test(approval.approverId)) {
      reject("SIGNER_CEREMONY_APPROVAL_REJECTED", "Signer-ceremony approver identifier is invalid");
    }
    if (
      typeof approval.approvedAt !== "string" ||
      Number.isNaN(Date.parse(approval.approvedAt)) ||
      Date.parse(approval.approvedAt) < Date.parse(input.openedAt) ||
      Date.parse(approval.approvedAt) > Date.parse(input.lastTransitionAt)
    ) {
      reject("SIGNER_CEREMONY_APPROVAL_REJECTED", "Signer-ceremony approval time is invalid");
    }
    if (typeof approval.attestationDigest !== "string" || !/^[0-9a-f]{64}$/u.test(approval.attestationDigest)) {
      reject("SIGNER_CEREMONY_APPROVAL_REJECTED", "Signer-ceremony attestation digest is invalid");
    }
  }
  if (new Set(input.approvals.map((approval) => approval.role)).size !== input.approvals.length) {
    reject("SIGNER_CEREMONY_APPROVAL_REJECTED", "Signer-ceremony approval roles must be unique");
  }
  if (new Set(input.approvals.map((approval) => approval.approverId)).size !== input.approvals.length) {
    reject("SIGNER_CEREMONY_APPROVAL_REJECTED", "Signer-ceremony approvers must be independent");
  }
  if (PHASE_INDEX[input.phase] < PHASE_INDEX["quorum-rehearsed"] && input.approvals.length > 0) {
    reject("SIGNER_CEREMONY_APPROVAL_REJECTED", "Signer-ceremony approvals cannot precede quorum rehearsal");
  }
  if (
    PHASE_INDEX[input.phase] < PHASE_INDEX["independently-reviewed"] &&
    input.approvals.some((approval) => approval.role === "independent-review")
  ) {
    reject("SIGNER_CEREMONY_APPROVAL_REJECTED", "Independent approval cannot precede independent review");
  }

  assertExactFields(input.findings, FINDING_FIELDS, "Signer-ceremony findings");
  for (const field of FINDING_FIELDS) {
    if (!Number.isSafeInteger(input.findings[field]) || input.findings[field] < 0 || input.findings[field] > 1000) {
      reject("SIGNER_CEREMONY_FINDING_REJECTED", "Signer-ceremony finding count is invalid");
    }
  }
  if (typeof input.evidenceDigest !== "string" || !/^[0-9a-f]{64}$/u.test(input.evidenceDigest)) {
    reject("SIGNER_CEREMONY_EVIDENCE_REJECTED", "Signer-ceremony evidence digest is invalid");
  }
  return structuredClone(input);
}

function phaseReasonCodes(ceremony) {
  const reasonCodes = REQUIRED_CONTROLS_BY_PHASE[ceremony.phase]
    .filter((control) => !ceremony.controls[control])
    .map((control) => CONTROL_REASON_CODES[control]);
  if (PHASE_INDEX[ceremony.phase] >= PHASE_INDEX["quorum-rehearsed"]) {
    const roles = new Set(ceremony.approvals.map((approval) => approval.role));
    if (QUORUM_ROLES.some((role) => !roles.has(role))) reasonCodes.push("CEREMONY_QUORUM_INCOMPLETE");
  }
  if (PHASE_INDEX[ceremony.phase] >= PHASE_INDEX["independently-reviewed"]) {
    const roles = new Set(ceremony.approvals.map((approval) => approval.role));
    if (!roles.has("independent-review")) reasonCodes.push("INDEPENDENT_REVIEW_MISSING");
    if (ceremony.findings.criticalOpen > 0) reasonCodes.push("CRITICAL_FINDINGS_OPEN");
    if (ceremony.findings.highOpen > 0) reasonCodes.push("HIGH_FINDINGS_OPEN");
    if (ceremony.findings.mediumOpen > 0) reasonCodes.push("MEDIUM_FINDINGS_OPEN");
  }
  return reasonCodes;
}

export function evaluateSignerCeremony(input) {
  const ceremony = validateSignerCeremony(input);
  const reasonCodes = phaseReasonCodes(ceremony);
  if (NEXT_PHASE_REASON[ceremony.phase]) reasonCodes.push(NEXT_PHASE_REASON[ceremony.phase]);
  const recommendation =
    ceremony.phase === "closed"
      ? reasonCodes.length === 0
        ? "CLOSED"
        : "INVALID_CLOSURE_RECORD"
      : ceremony.phase === "independently-reviewed" && reasonCodes.length === 0
        ? "READY_FOR_SEPARATE_CEREMONY_AUTHORIZATION"
        : "ACTIVE_CEREMONY_GOVERNANCE_REQUIRED";
  const digest = createHash("sha256").update(canonicalJson(ceremony)).digest("hex");
  return {
    schema: SIGNER_CEREMONY_DECISION_SCHEMA,
    decisionId: `ceremonydec_${digest.slice(0, 32)}`,
    ceremonyId: ceremony.ceremonyId,
    recommendation,
    reasonCodes: reasonCodes.sort(),
    evidenceDigest: ceremony.evidenceDigest,
    humanAuthorizationRequired: true,
    ceremonyExecutionAuthorized: false,
    signerActivationAuthorized: false,
    keyGenerationAuthorized: false,
    keyExportAuthorized: false,
    signingAuthorized: false,
    deploymentAuthorized: false,
    assetMovementAuthorized: false
  };
}

export function validateSignerCeremonyTransition(currentInput, nextInput) {
  const current = validateSignerCeremony(currentInput);
  const next = validateSignerCeremony(nextInput);
  if (
    current.ceremonyId !== next.ceremonyId ||
    current.openedAt !== next.openedAt ||
    current.environment !== next.environment ||
    canonicalJson(current.architecture) !== canonicalJson(next.architecture)
  ) {
    reject("SIGNER_CEREMONY_TRANSITION_IDENTITY_REJECTED", "Signer-ceremony identity and architecture cannot change");
  }
  if (!TRANSITIONS[current.phase].has(next.phase)) {
    reject("SIGNER_CEREMONY_TRANSITION_REJECTED", "Signer-ceremony phase transition is not permitted");
  }
  if (Date.parse(next.lastTransitionAt) <= Date.parse(current.lastTransitionAt)) {
    reject("SIGNER_CEREMONY_TRANSITION_TIME_REJECTED", "Signer-ceremony time must move forward");
  }
  for (const control of SIGNER_CEREMONY_CONTROL_FIELDS) {
    if (current.controls[control] && !next.controls[control]) {
      reject("SIGNER_CEREMONY_TRANSITION_CONTROL_REJECTED", "Signer-ceremony controls cannot be weakened");
    }
  }
  for (const currentApproval of current.approvals) {
    const nextApproval = next.approvals.find((approval) => approval.role === currentApproval.role);
    if (!nextApproval || canonicalJson(nextApproval) !== canonicalJson(currentApproval)) {
      reject("SIGNER_CEREMONY_TRANSITION_CONTROL_REJECTED", "Signer-ceremony approvals are append-only");
    }
  }
  if (phaseReasonCodes(next).length > 0) {
    reject("SIGNER_CEREMONY_TRANSITION_CONTROL_REJECTED", "Required signer-ceremony evidence is incomplete");
  }
  return {
    accepted: true,
    from: current.phase,
    to: next.phase,
    humanAuthorizationRequired: true,
    ceremonyExecutionAuthorized: false,
    signerActivationAuthorized: false,
    keyGenerationAuthorized: false,
    keyExportAuthorized: false,
    signingAuthorized: false,
    deploymentAuthorized: false,
    assetMovementAuthorized: false
  };
}
