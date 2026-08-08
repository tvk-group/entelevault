import assert from "node:assert/strict";
import test from "node:test";
import {
  evaluateExternalAssessmentReadiness,
  EXTERNAL_ASSESSMENT_SCHEMA,
  REQUIRED_EXTERNAL_ASSESSMENT_CONTROLS,
  validateExternalAssessment
} from "../src/external-assessment-readiness.mjs";

function controls(enabled = REQUIRED_EXTERNAL_ASSESSMENT_CONTROLS) {
  return Object.fromEntries(REQUIRED_EXTERNAL_ASSESSMENT_CONTROLS.map((control) => [control, enabled.includes(control)]));
}
function assessment(overrides = {}) {
  const base = {
    schema: EXTERNAL_ASSESSMENT_SCHEMA,
    assessmentId: "external_0123456789abcdef0123456789abcdef",
    assessedAt: "2026-08-09T00:00:00.000Z",
    environment: "staging",
    scopeClass: "exchange-service",
    engagementRevision: "a".repeat(40),
    scopeDigest: "b".repeat(64),
    rulesOfEngagementDigest: "c".repeat(64),
    controls: controls(),
    findings: { authorizationGaps: 0, scopeAmbiguities: 0, safetyGaps: 0, dataHandlingGaps: 0, unresolvedConflicts: 0 },
    evidenceDigest: "d".repeat(64)
  };
  return { ...base, ...overrides, controls: { ...base.controls, ...(overrides.controls ?? {}) }, findings: { ...base.findings, ...(overrides.findings ?? {}) } };
}

test("complete engagement evidence is only eligible for separate human authorization", () => {
  const decision = evaluateExternalAssessmentReadiness(assessment());
  assert.equal(decision.readiness, "ELIGIBLE_FOR_SEPARATE_EXTERNAL_ASSESSMENT_AUTHORIZATION");
  assert.equal(decision.reasonCodes.length, 0);
  for (const field of ["vulnerabilityScanningAuthorized", "exploitationAuthorized", "trafficGenerationAuthorized", "deviceAccessAuthorized", "accessGrantAuthorized", "remediationExecutionAuthorized", "deploymentAuthorized", "signingAuthorized", "assetMovementAuthorized"]) assert.equal(decision[field], false);
});

test("all 16,384 assessment-control combinations permit only the fully satisfied set", () => {
  const total = 1 << REQUIRED_EXTERNAL_ASSESSMENT_CONTROLS.length;
  let eligible = 0;
  for (let mask = 0; mask < total; mask += 1) {
    const enabled = REQUIRED_EXTERNAL_ASSESSMENT_CONTROLS.filter((_, index) => Boolean(mask & (1 << index)));
    const decision = evaluateExternalAssessmentReadiness(assessment({ controls: controls(enabled) }));
    if (decision.readiness === "ELIGIBLE_FOR_SEPARATE_EXTERNAL_ASSESSMENT_AUTHORIZATION") eligible += 1;
    assert.equal(decision.exploitationAuthorized, false);
  }
  assert.equal(eligible, 1);
});

test("authorization, scope, safety, data, and conflict gaps fail closed", () => {
  const cases = [["authorizationGaps", "AUTHORIZATION_GAPS_DETECTED"], ["scopeAmbiguities", "SCOPE_AMBIGUITIES_DETECTED"], ["safetyGaps", "SAFETY_GAPS_DETECTED"], ["dataHandlingGaps", "DATA_HANDLING_GAPS_DETECTED"], ["unresolvedConflicts", "ASSESSOR_CONFLICTS_UNRESOLVED"]];
  for (const [field, reason] of cases) {
    const decision = evaluateExternalAssessmentReadiness(assessment({ findings: { [field]: 1 } }));
    assert.equal(decision.readiness, "NOT_READY");
    assert.equal(decision.reasonCodes.includes(reason), true);
  }
});

test("unsupported environments and scopes fail closed", () => {
  assert.throws(() => validateExternalAssessment(assessment({ environment: "production" })), (error) => error.code === "EXTERNAL_ASSESSMENT_ENVIRONMENT_REJECTED");
  assert.throws(() => validateExternalAssessment(assessment({ scopeClass: "arbitrary-target" })), (error) => error.code === "EXTERNAL_ASSESSMENT_SCOPE_REJECTED");
});

test("attacks, exploits, targets, credentials, payloads, and wallet material are rejected", () => {
  for (const prohibited of [{ attackPlan: "value" }, { exploitCode: "value" }, { targetHost: "value" }, { credential: "value" }, { rawPayload: "value" }, { walletData: "value" }]) {
    assert.throws(() => validateExternalAssessment(assessment(prohibited)), (error) => error.code === "EXTERNAL_ASSESSMENT_PROHIBITED_FIELD");
  }
});

test("external-assessment decisions are deterministic and omit scope, controls, and findings", () => {
  const first = evaluateExternalAssessmentReadiness(assessment());
  assert.deepEqual(first, evaluateExternalAssessmentReadiness(assessment()));
  for (const field of ["scopeClass", "engagementRevision", "scopeDigest", "rulesOfEngagementDigest", "controls", "findings"]) assert.equal(field in first, false);
});
