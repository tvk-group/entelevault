import assert from "node:assert/strict";
import test from "node:test";
import {
  REQUIRED_RESILIENCE_CONTROLS,
  RESILIENCE_READINESS_SCHEMA,
  evaluateResilienceReadiness,
  validateResilienceAssessment
} from "../src/resilience-readiness.mjs";

function assessment(overrides = {}) {
  const base = {
    schema: RESILIENCE_READINESS_SCHEMA,
    assessmentId: "resilience_0123456789abcdef0123456789abcdef",
    assessedAt: "2026-08-07T00:00:00.000Z",
    environment: "staging",
    scope: {
      systemClass: "exchange",
      recoveryTier: "tier-0",
      exerciseClass: "failover-rehearsal",
      dataClass: "ledger-state"
    },
    evidence: {
      planDigest: "1".repeat(64),
      backupPolicyDigest: "2".repeat(64),
      restoreEvidenceDigest: "3".repeat(64),
      dependencyMapDigest: "4".repeat(64),
      reconciliationDigest: "5".repeat(64),
      exerciseRevision: "6".repeat(40),
      recoveryPointClass: "within-objective",
      recoveryTimeClass: "within-objective"
    },
    controls: Object.fromEntries(REQUIRED_RESILIENCE_CONTROLS.map((control) => [control, true])),
    findings: { criticalOpen: 0, highOpen: 0, mediumOpen: 0, unreconciledItems: 0 },
    evidenceDigest: "a".repeat(64)
  };
  return {
    ...base,
    ...overrides,
    scope: { ...base.scope, ...(overrides.scope ?? {}) },
    evidence: { ...base.evidence, ...(overrides.evidence ?? {}) },
    controls: { ...base.controls, ...(overrides.controls ?? {}) },
    findings: { ...base.findings, ...(overrides.findings ?? {}) }
  };
}

test("all fourteen resilience controls are necessary and sufficient for review eligibility", () => {
  const total = 1 << REQUIRED_RESILIENCE_CONTROLS.length;
  const allEnabled = total - 1;
  let eligible = 0;
  for (let mask = 0; mask < total; mask += 1) {
    const controls = Object.fromEntries(
      REQUIRED_RESILIENCE_CONTROLS.map((control, index) => [control, Boolean(mask & (1 << index))])
    );
    const decision = evaluateResilienceReadiness(assessment({ controls }));
    const expected = mask === allEnabled;
    assert.equal(decision.readiness === "ELIGIBLE_FOR_INDEPENDENT_RESILIENCE_REVIEW", expected);
    if (expected) eligible += 1;
    assert.equal(decision.restorationAuthorized, false);
    assert.equal(decision.failoverAuthorized, false);
    assert.equal(decision.dataMutationAuthorized, false);
  }
  assert.equal(total, 16_384);
  assert.equal(eligible, 1);
});

test("recovery objectives and every open finding fail closed", () => {
  const cases = [
    [assessment({ evidence: { recoveryPointClass: "outside-objective" } }), "RECOVERY_POINT_OBJECTIVE_NOT_MET"],
    [assessment({ evidence: { recoveryTimeClass: "unknown" } }), "RECOVERY_TIME_OBJECTIVE_NOT_MET"],
    [assessment({ findings: { criticalOpen: 1 } }), "CRITICAL_FINDINGS_OPEN"],
    [assessment({ findings: { highOpen: 1 } }), "HIGH_FINDINGS_OPEN"],
    [assessment({ findings: { mediumOpen: 1 } }), "MEDIUM_FINDINGS_OPEN"],
    [assessment({ findings: { unreconciledItems: 1 } }), "UNRECONCILED_ITEMS_OPEN"]
  ];
  for (const [snapshot, reason] of cases) {
    const decision = evaluateResilienceReadiness(snapshot);
    assert.equal(decision.readiness, "NOT_READY");
    assert.equal(decision.reasonCodes.includes(reason), true);
  }
});

test("resilience eligibility never authorizes restoration, failover, deployment, signing, or mutation", () => {
  const decision = evaluateResilienceReadiness(assessment());
  assert.equal(decision.readiness, "ELIGIBLE_FOR_INDEPENDENT_RESILIENCE_REVIEW");
  assert.equal(decision.humanAuthorizationRequired, true);
  for (const field of [
    "restorationAuthorized",
    "failoverAuthorized",
    "dataMutationAuthorized",
    "balanceMutationAuthorized",
    "deploymentAuthorized",
    "signingAuthorized",
    "assetMovementAuthorized"
  ]) assert.equal(decision[field], false);
});

test("backup payloads, database dumps, records, secrets, credentials, and transactions are rejected", () => {
  for (const prohibited of [
    { backupData: "value" },
    { backupPayload: "value" },
    { databaseDump: "value" },
    { rawRecords: [] },
    { privateKey: "value" },
    { credential: "value" },
    { accessToken: "value" },
    { transaction: "value" }
  ]) {
    assert.throws(
      () => validateResilienceAssessment(assessment(prohibited)),
      (error) => error.code === "RESILIENCE_PROHIBITED_FIELD"
    );
  }
});

test("resilience assessments require the complete exact control set and digest-only evidence", () => {
  const incomplete = assessment();
  delete incomplete.controls.independentReviewApproved;
  assert.throws(
    () => validateResilienceAssessment(incomplete),
    (error) => error.code === "RESILIENCE_CONTROL_REJECTED"
  );
  assert.throws(
    () => validateResilienceAssessment(assessment({ evidence: { planDigest: "not-a-digest" } })),
    (error) => error.code === "RESILIENCE_EVIDENCE_REJECTED"
  );
  assert.throws(
    () => validateResilienceAssessment(assessment({ environment: "production-observation" })),
    (error) => error.code === "RESILIENCE_ENVIRONMENT_REJECTED"
  );
});

test("resilience decisions are deterministic and omit scope, evidence, controls, and findings", () => {
  const first = evaluateResilienceReadiness(assessment());
  const second = evaluateResilienceReadiness(assessment());
  assert.deepEqual(first, second);
  assert.equal("scope" in first, false);
  assert.equal("evidence" in first, false);
  assert.equal("controls" in first, false);
  assert.equal("findings" in first, false);
});
