import assert from "node:assert/strict";
import test from "node:test";
import {
  evaluatePrivacyDataMinimization,
  PRIVACY_DATA_MINIMIZATION_SCHEMA,
  REQUIRED_PRIVACY_DATA_MINIMIZATION_CONTROLS,
  validatePrivacyDataMinimization
} from "../src/privacy-data-minimization-readiness.mjs";

function controls(enabled = REQUIRED_PRIVACY_DATA_MINIMIZATION_CONTROLS) {
  return Object.fromEntries(REQUIRED_PRIVACY_DATA_MINIMIZATION_CONTROLS.map((control) => [control, enabled.includes(control)]));
}
function assessment(overrides = {}) {
  const base = {
    schema: PRIVACY_DATA_MINIMIZATION_SCHEMA,
    assessmentId: "privacy_0123456789abcdef0123456789abcdef",
    assessedAt: "2026-08-09T00:00:00.000Z",
    environment: "staging",
    systemClass: "exchange",
    dataClass: "customer-identity",
    policyRevision: "a".repeat(40),
    dataFlowDigest: "b".repeat(64),
    retentionPolicyDigest: "c".repeat(64),
    controls: controls(),
    findings: { criticalOpen: 0, highOpen: 0, excessFields: 0, retentionBreaches: 0, deletionVerificationFailures: 0 },
    evidenceDigest: "d".repeat(64)
  };
  return { ...base, ...overrides, controls: { ...base.controls, ...(overrides.controls ?? {}) }, findings: { ...base.findings, ...(overrides.findings ?? {}) } };
}

test("complete minimized evidence is only eligible for independent privacy review", () => {
  const decision = evaluatePrivacyDataMinimization(assessment());
  assert.equal(decision.readiness, "ELIGIBLE_FOR_INDEPENDENT_PRIVACY_REVIEW");
  assert.equal(decision.reasonCodes.length, 0);
  for (const field of ["rawDataAccessAuthorized", "dataDeletionAuthorized", "retentionMutationAuthorized", "accessGrantAuthorized", "remediationExecutionAuthorized", "dataMutationAuthorized", "deploymentAuthorized", "signingAuthorized", "assetMovementAuthorized"]) assert.equal(decision[field], false);
});

test("all 16,384 privacy-control combinations permit only the fully satisfied set", () => {
  const total = 1 << REQUIRED_PRIVACY_DATA_MINIMIZATION_CONTROLS.length;
  let eligible = 0;
  for (let mask = 0; mask < total; mask += 1) {
    const enabled = REQUIRED_PRIVACY_DATA_MINIMIZATION_CONTROLS.filter((_, index) => Boolean(mask & (1 << index)));
    const decision = evaluatePrivacyDataMinimization(assessment({ controls: controls(enabled) }));
    if (decision.readiness === "ELIGIBLE_FOR_INDEPENDENT_PRIVACY_REVIEW") eligible += 1;
    assert.equal(decision.rawDataAccessAuthorized, false);
  }
  assert.equal(eligible, 1);
});

test("privacy findings, overcollection, retention, and deletion failures fail closed", () => {
  const cases = [["criticalOpen", "CRITICAL_PRIVACY_FINDINGS_OPEN"], ["highOpen", "HIGH_PRIVACY_FINDINGS_OPEN"], ["excessFields", "EXCESS_FIELDS_DETECTED"], ["retentionBreaches", "RETENTION_BREACHES_DETECTED"], ["deletionVerificationFailures", "DELETION_VERIFICATION_FAILURES_DETECTED"]];
  for (const [field, reason] of cases) {
    const decision = evaluatePrivacyDataMinimization(assessment({ findings: { [field]: 1 } }));
    assert.equal(decision.readiness, "NOT_READY");
    assert.equal(decision.reasonCodes.includes(reason), true);
  }
});

test("unsupported environments, systems, and data classes fail closed", () => {
  assert.throws(() => validatePrivacyDataMinimization(assessment({ environment: "production" })), (error) => error.code === "PRIVACY_MINIMIZATION_ENVIRONMENT_REJECTED");
  assert.throws(() => validatePrivacyDataMinimization(assessment({ systemClass: "unknown" })), (error) => error.code === "PRIVACY_MINIMIZATION_CLASS_REJECTED");
  assert.throws(() => validatePrivacyDataMinimization(assessment({ dataClass: "raw-customer-records" })), (error) => error.code === "PRIVACY_MINIMIZATION_CLASS_REJECTED");
});

test("personal data, identifiers, credentials, raw records, and wallet material are rejected", () => {
  for (const prohibited of [{ personalData: "value" }, { emailAddress: "value" }, { phoneNumber: "value" }, { credential: "value" }, { rawRecord: "value" }, { privateKey: "value" }, { walletFile: "value" }]) {
    assert.throws(() => validatePrivacyDataMinimization(assessment(prohibited)), (error) => error.code === "PRIVACY_MINIMIZATION_PROHIBITED_FIELD");
  }
});

test("privacy decisions are deterministic and omit system, data flow, controls, and findings", () => {
  const first = evaluatePrivacyDataMinimization(assessment());
  assert.deepEqual(first, evaluatePrivacyDataMinimization(assessment()));
  for (const field of ["systemClass", "dataClass", "policyRevision", "dataFlowDigest", "retentionPolicyDigest", "controls", "findings"]) assert.equal(field in first, false);
});
