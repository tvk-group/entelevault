import { createHash } from "node:crypto";
import { VaultLabError } from "./errors.mjs";

export const LEDGER_INTEGRITY_SCHEMA = "enteleexchange.ledger-integrity.v1";
export const LEDGER_INTEGRITY_DECISION_SCHEMA = "enteleexchange.ledger-integrity-decision.v1";

export const REQUIRED_LEDGER_CONTROLS = Object.freeze([
  "doubleEntryInvariantVerified",
  "customerAssetSegregationVerified",
  "hotWalletExposureWithinPolicy",
  "liabilitySnapshotComplete",
  "assetSnapshotComplete",
  "reconciliationMatched",
  "withdrawalQueueReconciled",
  "depositFinalityReconciled",
  "feeAccountingReconciled",
  "suspenseAccountsCleared",
  "reserveMethodReviewed",
  "independentAttestationCurrent",
  "monitoringAlertsTested",
  "replayProtectionVerified"
]);

const ROOT_FIELDS = new Set([
  "schema",
  "assessmentId",
  "assessedAt",
  "environment",
  "snapshot",
  "controls",
  "findings",
  "evidenceDigest"
]);
const SNAPSHOT_FIELDS = new Set([
  "ledgerSnapshotDigest",
  "assetSnapshotDigest",
  "liabilitySnapshotDigest",
  "reconciliationDigest",
  "reserveMethodDigest",
  "sequenceClass",
  "coverageClass"
]);
const CONTROL_FIELDS = new Set(REQUIRED_LEDGER_CONTROLS);
const FINDING_FIELDS = new Set(["criticalOpen", "highOpen", "mediumOpen", "unreconciledItems"]);
const ENVIRONMENTS = new Set(["staging", "production-observation"]);
const SEQUENCE_CLASSES = new Set(["current", "lagging", "unknown"]);
const COVERAGE_CLASSES = new Set(["complete", "partial", "unknown"]);
const CONTROL_REASON_CODES = Object.freeze({
  doubleEntryInvariantVerified: "DOUBLE_ENTRY_INVARIANT_UNVERIFIED",
  customerAssetSegregationVerified: "CUSTOMER_ASSET_SEGREGATION_UNVERIFIED",
  hotWalletExposureWithinPolicy: "HOT_WALLET_EXPOSURE_OUTSIDE_POLICY",
  liabilitySnapshotComplete: "LIABILITY_SNAPSHOT_INCOMPLETE",
  assetSnapshotComplete: "ASSET_SNAPSHOT_INCOMPLETE",
  reconciliationMatched: "RECONCILIATION_MISMATCH",
  withdrawalQueueReconciled: "WITHDRAWAL_QUEUE_UNRECONCILED",
  depositFinalityReconciled: "DEPOSIT_FINALITY_UNRECONCILED",
  feeAccountingReconciled: "FEE_ACCOUNTING_UNRECONCILED",
  suspenseAccountsCleared: "SUSPENSE_ACCOUNTS_NOT_CLEARED",
  reserveMethodReviewed: "RESERVE_METHOD_UNREVIEWED",
  independentAttestationCurrent: "INDEPENDENT_ATTESTATION_NOT_CURRENT",
  monitoringAlertsTested: "MONITORING_ALERTS_UNTESTED",
  replayProtectionVerified: "REPLAY_PROTECTION_UNVERIFIED"
});
const PROHIBITED_FIELD = /(?:address|(?:^account$|accountId|accountNumber)|balance|candidate|command|credential|customerId|email|key|mnemonic|password|payload|private|(?:^raw$|raw(?:Balance|Body|Data|Ledger|Payload|Record|Snapshot|Transaction|Value))|secret|seed|signature|target|token|transaction|user|walletFile)/iu;

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function reject(code, message) {
  throw new VaultLabError(code, message);
}

function assertExactFields(value, allowed, label) {
  if (!isRecord(value)) reject("LEDGER_INTEGRITY_INVALID", `${label} must be an object`);
  for (const key of Object.keys(value)) {
    if (PROHIBITED_FIELD.test(key)) {
      reject("LEDGER_INTEGRITY_PROHIBITED_FIELD", `${label} contains a prohibited field`);
    }
    if (!allowed.has(key)) reject("LEDGER_INTEGRITY_UNKNOWN_FIELD", `${label} has an unknown field`);
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

export function validateLedgerIntegrityAssessment(input) {
  assertExactFields(input, ROOT_FIELDS, "Ledger-integrity assessment");
  if (input.schema !== LEDGER_INTEGRITY_SCHEMA) {
    reject("LEDGER_INTEGRITY_SCHEMA_REJECTED", "Ledger-integrity schema is unsupported");
  }
  if (typeof input.assessmentId !== "string" || !/^ledger_[0-9a-f]{32}$/u.test(input.assessmentId)) {
    reject("LEDGER_INTEGRITY_ID_REJECTED", "Ledger-integrity assessment identifier is invalid");
  }
  if (typeof input.assessedAt !== "string" || Number.isNaN(Date.parse(input.assessedAt))) {
    reject("LEDGER_INTEGRITY_TIME_REJECTED", "Ledger-integrity assessment time is invalid");
  }
  if (!ENVIRONMENTS.has(input.environment)) {
    reject("LEDGER_INTEGRITY_ENVIRONMENT_REJECTED", "Ledger-integrity environment is unsupported");
  }

  assertExactFields(input.snapshot, SNAPSHOT_FIELDS, "Ledger snapshot evidence");
  for (const field of [
    "ledgerSnapshotDigest",
    "assetSnapshotDigest",
    "liabilitySnapshotDigest",
    "reconciliationDigest",
    "reserveMethodDigest"
  ]) {
    if (typeof input.snapshot[field] !== "string" || !/^[0-9a-f]{64}$/u.test(input.snapshot[field])) {
      reject("LEDGER_INTEGRITY_SNAPSHOT_REJECTED", "Ledger snapshot digest is invalid");
    }
  }
  if (!SEQUENCE_CLASSES.has(input.snapshot.sequenceClass)) {
    reject("LEDGER_INTEGRITY_SNAPSHOT_REJECTED", "Ledger sequence class is unsupported");
  }
  if (!COVERAGE_CLASSES.has(input.snapshot.coverageClass)) {
    reject("LEDGER_INTEGRITY_SNAPSHOT_REJECTED", "Ledger coverage class is unsupported");
  }

  assertExactFields(input.controls, CONTROL_FIELDS, "Ledger-integrity controls");
  if (Object.keys(input.controls).length !== REQUIRED_LEDGER_CONTROLS.length) {
    reject("LEDGER_INTEGRITY_CONTROL_REJECTED", "Ledger-integrity control set is incomplete");
  }
  for (const field of REQUIRED_LEDGER_CONTROLS) {
    if (typeof input.controls[field] !== "boolean") {
      reject("LEDGER_INTEGRITY_CONTROL_REJECTED", "Ledger-integrity control value is invalid");
    }
  }

  assertExactFields(input.findings, FINDING_FIELDS, "Ledger-integrity findings");
  for (const field of FINDING_FIELDS) {
    if (
      !Number.isSafeInteger(input.findings[field]) ||
      input.findings[field] < 0 ||
      input.findings[field] > 1_000_000
    ) {
      reject("LEDGER_INTEGRITY_FINDING_REJECTED", "Ledger-integrity finding count is invalid");
    }
  }
  if (typeof input.evidenceDigest !== "string" || !/^[0-9a-f]{64}$/u.test(input.evidenceDigest)) {
    reject("LEDGER_INTEGRITY_EVIDENCE_REJECTED", "Ledger-integrity evidence digest is invalid");
  }
  return structuredClone(input);
}

export function evaluateLedgerIntegrity(input) {
  const assessment = validateLedgerIntegrityAssessment(input);
  const reasonCodes = REQUIRED_LEDGER_CONTROLS
    .filter((control) => !assessment.controls[control])
    .map((control) => CONTROL_REASON_CODES[control]);
  if (assessment.snapshot.sequenceClass !== "current") reasonCodes.push("LEDGER_SEQUENCE_NOT_CURRENT");
  if (assessment.snapshot.coverageClass !== "complete") reasonCodes.push("LEDGER_COVERAGE_INCOMPLETE");
  if (assessment.findings.criticalOpen > 0) reasonCodes.push("CRITICAL_FINDINGS_OPEN");
  if (assessment.findings.highOpen > 0) reasonCodes.push("HIGH_FINDINGS_OPEN");
  if (assessment.findings.mediumOpen > 0) reasonCodes.push("MEDIUM_FINDINGS_OPEN");
  if (assessment.findings.unreconciledItems > 0) reasonCodes.push("UNRECONCILED_ITEMS_OPEN");
  const readiness =
    reasonCodes.length === 0
      ? "ELIGIBLE_FOR_INDEPENDENT_FINANCIAL_CONTROL_REVIEW"
      : "NOT_READY";
  const digest = createHash("sha256").update(canonicalJson(assessment)).digest("hex");
  return {
    schema: LEDGER_INTEGRITY_DECISION_SCHEMA,
    decisionId: `ledgerdec_${digest.slice(0, 32)}`,
    assessmentId: assessment.assessmentId,
    readiness,
    reasonCodes: reasonCodes.sort(),
    evidenceDigest: assessment.evidenceDigest,
    humanAuthorizationRequired: true,
    proofOfSolvencyEstablished: false,
    financialClaimAuthorized: false,
    balanceMutationAuthorized: false,
    tradingAuthorized: false,
    withdrawalAuthorized: false,
    signingAuthorized: false,
    assetMovementAuthorized: false
  };
}
