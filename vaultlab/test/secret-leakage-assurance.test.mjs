import assert from "node:assert/strict";
import test from "node:test";
import {
  evaluateSecretLeakage,
  REQUIRED_SECRET_LEAKAGE_CONTROLS,
  SECRET_LEAKAGE_SCHEMA,
  validateSecretLeakageAssessment
} from "../src/secret-leakage-assurance.mjs";

function controls(enabled = REQUIRED_SECRET_LEAKAGE_CONTROLS) {
  return Object.fromEntries(REQUIRED_SECRET_LEAKAGE_CONTROLS.map((control) => [control, enabled.includes(control)]));
}

function assessment(overrides = {}) {
  const base = {
    schema: SECRET_LEAKAGE_SCHEMA,
    assessmentId: "leak_0123456789abcdef0123456789abcdef",
    assessedAt: "2026-08-07T00:00:00.000Z",
    environment: "staging",
    component: "entelevault-service",
    scanClass: "runtime-telemetry",
    policyRevision: "a".repeat(40),
    rulesetDigest: "b".repeat(64),
    controls: controls(),
    findings: {
      credentialClassHits: 0,
      tokenClassHits: 0,
      keyMaterialClassHits: 0,
      walletMaterialClassHits: 0,
      unclassifiedEntropyHits: 0
    },
    evidenceDigest: "c".repeat(64)
  };
  return {
    ...base,
    ...overrides,
    controls: { ...base.controls, ...(overrides.controls ?? {}) },
    findings: { ...base.findings, ...(overrides.findings ?? {}) }
  };
}

test("complete sanitized leakage evidence is only eligible for independent review", () => {
  const decision = evaluateSecretLeakage(assessment());
  assert.equal(decision.readiness, "ELIGIBLE_FOR_INDEPENDENT_LEAKAGE_REVIEW");
  assert.equal(decision.reasonCodes.length, 0);
  assert.equal(decision.humanAuthorizationRequired, true);
  assert.equal(decision.remediationExecutionAuthorized, false);
  assert.equal(decision.credentialRevocationAuthorized, false);
  assert.equal(decision.artifactDeletionAuthorized, false);
  assert.equal(decision.accessGrantAuthorized, false);
  assert.equal(decision.deploymentAuthorized, false);
  assert.equal(decision.signingAuthorized, false);
  assert.equal(decision.assetMovementAuthorized, false);
});

test("all 4,096 leakage-control combinations permit only the fully satisfied set", () => {
  const total = 1 << REQUIRED_SECRET_LEAKAGE_CONTROLS.length;
  let eligible = 0;
  for (let mask = 0; mask < total; mask += 1) {
    const enabled = REQUIRED_SECRET_LEAKAGE_CONTROLS.filter((_, index) => Boolean(mask & (1 << index)));
    const decision = evaluateSecretLeakage(assessment({ controls: controls(enabled) }));
    if (decision.readiness === "ELIGIBLE_FOR_INDEPENDENT_LEAKAGE_REVIEW") eligible += 1;
    assert.equal(decision.remediationExecutionAuthorized, false);
  }
  assert.equal(eligible, 1);
});

test("every secret-class or entropy finding blocks and escalates", () => {
  const cases = [
    ["credentialClassHits", "CREDENTIAL_CLASS_FINDINGS"],
    ["tokenClassHits", "TOKEN_CLASS_FINDINGS"],
    ["keyMaterialClassHits", "KEY_MATERIAL_CLASS_FINDINGS"],
    ["walletMaterialClassHits", "WALLET_MATERIAL_CLASS_FINDINGS"],
    ["unclassifiedEntropyHits", "UNCLASSIFIED_ENTROPY_FINDINGS"]
  ];
  for (const [field, reason] of cases) {
    const decision = evaluateSecretLeakage(assessment({ findings: { [field]: 1 } }));
    assert.equal(decision.readiness, "BLOCK_AND_ESCALATE");
    assert.equal(decision.reasonCodes.includes(reason), true);
  }
});

test("raw logs, traces, reports, credentials, tokens, keys, and wallet material are rejected", () => {
  for (const prohibited of [
    { rawLog: "value" },
    { traceContent: "value" },
    { crashContent: "value" },
    { credentialValue: "value" },
    { tokenValue: "value" },
    { privateKey: "value" },
    { walletFile: "value" }
  ]) {
    assert.throws(
      () => validateSecretLeakageAssessment(assessment(prohibited)),
      (error) => error.code === "SECRET_LEAKAGE_PROHIBITED_FIELD"
    );
  }
});

test("leakage assessments require an exact complete control and finding set", () => {
  const missingControl = assessment();
  delete missingControl.controls.traceScanPassed;
  assert.throws(
    () => validateSecretLeakageAssessment(missingControl),
    (error) => error.code === "SECRET_LEAKAGE_UNKNOWN_FIELD"
  );
  assert.throws(
    () => validateSecretLeakageAssessment(assessment({ findings: { credentialClassHits: -1 } })),
    (error) => error.code === "SECRET_LEAKAGE_FINDING_REJECTED"
  );
});

test("leakage decisions are deterministic and omit scan classifications and controls", () => {
  const first = evaluateSecretLeakage(assessment());
  const second = evaluateSecretLeakage(assessment());
  assert.deepEqual(first, second);
  assert.equal("component" in first, false);
  assert.equal("scanClass" in first, false);
  assert.equal("controls" in first, false);
  assert.equal("findings" in first, false);
});
