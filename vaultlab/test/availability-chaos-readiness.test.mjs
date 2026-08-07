import assert from "node:assert/strict";
import test from "node:test";
import {
  AVAILABILITY_CHAOS_SCHEMA,
  evaluateAvailabilityReadiness,
  REQUIRED_AVAILABILITY_CONTROLS,
  validateAvailabilityAssessment
} from "../src/availability-chaos-readiness.mjs";

function controls(enabled = REQUIRED_AVAILABILITY_CONTROLS) {
  return Object.fromEntries(REQUIRED_AVAILABILITY_CONTROLS.map((control) => [control, enabled.includes(control)]));
}
function assessment(overrides = {}) {
  const base = {
    schema: AVAILABILITY_CHAOS_SCHEMA,
    assessmentId: "availability_0123456789abcdef0123456789abcdef",
    assessedAt: "2026-08-08T00:00:00.000Z",
    environment: "isolated-test",
    systemClass: "exchange",
    scenarioClass: "queue-exhaustion",
    policyRevision: "a".repeat(40),
    topologyDigest: "b".repeat(64),
    exerciseDigest: "c".repeat(64),
    controls: controls(),
    findings: { criticalOpen: 0, highOpen: 0, availabilityBreaches: 0, unrecoveredDependencies: 0, dataIntegrityMismatches: 0 },
    evidenceDigest: "d".repeat(64)
  };
  return { ...base, ...overrides, controls: { ...base.controls, ...(overrides.controls ?? {}) }, findings: { ...base.findings, ...(overrides.findings ?? {}) } };
}

test("complete isolated availability evidence is only eligible for independent review", () => {
  const decision = evaluateAvailabilityReadiness(assessment());
  assert.equal(decision.readiness, "ELIGIBLE_FOR_INDEPENDENT_AVAILABILITY_REVIEW");
  assert.equal(decision.reasonCodes.length, 0);
  for (const field of ["trafficGenerationAuthorized", "chaosExecutionAuthorized", "failoverAuthorized", "remediationExecutionAuthorized", "dataMutationAuthorized", "tradingAuthorized", "deploymentAuthorized", "signingAuthorized", "assetMovementAuthorized"]) assert.equal(decision[field], false);
});

test("all 16,384 availability-control combinations permit only the fully satisfied set", () => {
  const total = 1 << REQUIRED_AVAILABILITY_CONTROLS.length;
  let eligible = 0;
  for (let mask = 0; mask < total; mask += 1) {
    const enabled = REQUIRED_AVAILABILITY_CONTROLS.filter((_, index) => Boolean(mask & (1 << index)));
    const decision = evaluateAvailabilityReadiness(assessment({ controls: controls(enabled) }));
    if (decision.readiness === "ELIGIBLE_FOR_INDEPENDENT_AVAILABILITY_REVIEW") eligible += 1;
    assert.equal(decision.chaosExecutionAuthorized, false);
  }
  assert.equal(eligible, 1);
});

test("availability, dependency, integrity, critical, and high findings fail closed", () => {
  const cases = [["criticalOpen", "CRITICAL_FINDINGS_OPEN"], ["highOpen", "HIGH_FINDINGS_OPEN"], ["availabilityBreaches", "AVAILABILITY_BREACHES_DETECTED"], ["unrecoveredDependencies", "UNRECOVERED_DEPENDENCIES_DETECTED"], ["dataIntegrityMismatches", "DATA_INTEGRITY_MISMATCHES_DETECTED"]];
  for (const [field, reason] of cases) {
    const decision = evaluateAvailabilityReadiness(assessment({ findings: { [field]: 1 } }));
    assert.equal(decision.readiness, "NOT_READY");
    assert.equal(decision.reasonCodes.includes(reason), true);
  }
});

test("production and production-observation chaos exercises are rejected", () => {
  for (const environment of ["production", "production-observation"]) assert.throws(() => validateAvailabilityAssessment(assessment({ environment })), (error) => error.code === "AVAILABILITY_CHAOS_ENVIRONMENT_REJECTED");
});

test("commands, targets, hosts, URLs, traffic, credentials, tokens, and payloads are rejected", () => {
  for (const prohibited of [{ command: "value" }, { target: "value" }, { host: "value" }, { targetUrl: "value" }, { rawTraffic: "value" }, { credential: "value" }, { accessToken: "value" }, { rawPayload: "value" }]) {
    assert.throws(() => validateAvailabilityAssessment(assessment(prohibited)), (error) => error.code === "AVAILABILITY_CHAOS_PROHIBITED_FIELD");
  }
});

test("availability decisions are deterministic and omit topology, scenario, controls, and findings", () => {
  const first = evaluateAvailabilityReadiness(assessment());
  assert.deepEqual(first, evaluateAvailabilityReadiness(assessment()));
  for (const field of ["systemClass", "scenarioClass", "topologyDigest", "controls", "findings"]) assert.equal(field in first, false);
});
