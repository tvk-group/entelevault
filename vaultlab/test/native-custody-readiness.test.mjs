import assert from "node:assert/strict";
import test from "node:test";
import {
  CUSTODY_READINESS_SCHEMA,
  evaluateCustodyReadiness,
  REQUIRED_CUSTODY_CONTROLS,
  validateCustodyReadiness
} from "../src/native-custody-readiness.mjs";

function assessment(overrides = {}) {
  const base = {
    schema: CUSTODY_READINESS_SCHEMA,
    assessmentId: "assess_0123456789abcdef0123456789abcdef",
    assessedAt: "2026-08-07T00:00:00.000Z",
    sourceRevision: "a".repeat(40),
    environment: "staging",
    architecture: {
      custodyModel: "non-custodial-device-bound",
      keyGeneration: "platform-hardware",
      exportPolicy: "prohibited",
      recoveryModel: "quorum-governed"
    },
    controls: Object.fromEntries(REQUIRED_CUSTODY_CONTROLS.map((control) => [control, true])),
    findings: { criticalOpen: 0, highOpen: 0 },
    evidenceDigest: "b".repeat(64)
  };
  return {
    ...base,
    ...overrides,
    architecture: { ...base.architecture, ...(overrides.architecture ?? {}) },
    controls: { ...base.controls, ...(overrides.controls ?? {}) },
    findings: { ...base.findings, ...(overrides.findings ?? {}) }
  };
}

test("a complete assessment is only eligible for independent activation review", () => {
  const decision = evaluateCustodyReadiness(assessment());
  assert.equal(decision.readiness, "ELIGIBLE_FOR_INDEPENDENT_ACTIVATION_REVIEW");
  assert.deepEqual(decision.reasonCodes, []);
  assert.equal(decision.humanAuthorizationRequired, true);
  assert.equal(decision.deploymentAuthorized, false);
  assert.equal(decision.custodyActivationAuthorized, false);
  assert.equal(decision.signingAuthorized, false);
  assert.equal(decision.assetMovementAuthorized, false);
});

test("all 4,096 control combinations permit only the fully satisfied set", () => {
  const totalCombinations = 1 << REQUIRED_CUSTODY_CONTROLS.length;
  const allEnabledMask = totalCombinations - 1;
  for (let mask = 0; mask < totalCombinations; mask += 1) {
    const controls = Object.fromEntries(
      REQUIRED_CUSTODY_CONTROLS.map((control, index) => [control, Boolean(mask & (1 << index))])
    );
    const decision = evaluateCustodyReadiness(assessment({ controls }));
    assert.equal(
      decision.readiness === "ELIGIBLE_FOR_INDEPENDENT_ACTIVATION_REVIEW",
      mask === allEnabledMask
    );
    assert.equal(decision.custodyActivationAuthorized, false);
  }
});

test("open critical or high findings block readiness", () => {
  assert.equal(
    evaluateCustodyReadiness(assessment({ findings: { criticalOpen: 1 } })).readiness,
    "NOT_READY"
  );
  assert.equal(
    evaluateCustodyReadiness(assessment({ findings: { highOpen: 1 } })).readiness,
    "NOT_READY"
  );
});

test("custody model and key-generation boundary must agree", () => {
  assert.throws(
    () =>
      validateCustodyReadiness(
        assessment({
          architecture: {
            custodyModel: "institutional-hsm-quorum",
            keyGeneration: "platform-hardware"
          }
        })
      ),
    (error) => error.code === "CUSTODY_ARCHITECTURE_REJECTED"
  );
});

test("production activation requests and secret-bearing fields are rejected", () => {
  assert.throws(
    () => validateCustodyReadiness(assessment({ environment: "production" })),
    (error) => error.code === "CUSTODY_READINESS_ENVIRONMENT_REJECTED"
  );
  for (const prohibited of [{ walletFile: "value" }, { privateKeyMaterial: "value" }]) {
    assert.throws(
      () => validateCustodyReadiness(assessment(prohibited)),
      (error) => error.code === "CUSTODY_READINESS_PROHIBITED_FIELD"
    );
  }
});
