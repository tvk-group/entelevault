import assert from "node:assert/strict";
import test from "node:test";
import {
  evaluateReleaseProvenance,
  RELEASE_PROVENANCE_SCHEMA,
  REQUIRED_RELEASE_CONTROLS,
  validateReleaseProvenance
} from "../src/release-provenance.mjs";

function assessment(overrides = {}) {
  const base = {
    schema: RELEASE_PROVENANCE_SCHEMA,
    assessmentId: "release_0123456789abcdef0123456789abcdef",
    assessedAt: "2026-08-07T00:00:00.000Z",
    environment: "ci",
    component: "entelewallet-client",
    sourceRevision: "a".repeat(40),
    artifactDigest: "b".repeat(64),
    builderIdentityDigest: "c".repeat(64),
    workflowDigest: "d".repeat(64),
    sbomDigest: "e".repeat(64),
    dependencyLockDigest: "f".repeat(64),
    controls: Object.fromEntries(REQUIRED_RELEASE_CONTROLS.map((control) => [control, true])),
    findings: { criticalOpen: 0, highOpen: 0, mediumOpen: 0 },
    evidenceDigest: "0".repeat(64)
  };
  return {
    ...base,
    ...overrides,
    controls: { ...base.controls, ...(overrides.controls ?? {}) },
    findings: { ...base.findings, ...(overrides.findings ?? {}) }
  };
}

test("complete provenance permits only an independent promotion review", () => {
  const decision = evaluateReleaseProvenance(assessment());
  assert.equal(decision.readiness, "ELIGIBLE_FOR_INDEPENDENT_PROMOTION_REVIEW");
  assert.deepEqual(decision.reasonCodes, []);
  assert.equal(decision.humanAuthorizationRequired, true);
  assert.equal(decision.deploymentAuthorized, false);
  assert.equal(decision.signingAuthorized, false);
  assert.equal(decision.custodyActivationAuthorized, false);
  assert.equal(decision.assetMovementAuthorized, false);
});

test("all 16,384 release-control combinations allow only the all-true set", () => {
  const totalCombinations = 1 << REQUIRED_RELEASE_CONTROLS.length;
  const allEnabledMask = totalCombinations - 1;
  for (let mask = 0; mask < totalCombinations; mask += 1) {
    const controls = Object.fromEntries(
      REQUIRED_RELEASE_CONTROLS.map((control, index) => [control, Boolean(mask & (1 << index))])
    );
    const decision = evaluateReleaseProvenance(assessment({ controls }));
    assert.equal(
      decision.readiness === "ELIGIBLE_FOR_INDEPENDENT_PROMOTION_REVIEW",
      mask === allEnabledMask
    );
    assert.equal(decision.deploymentAuthorized, false);
  }
});

test("every open security finding blocks promotion readiness", () => {
  for (const findings of [
    { criticalOpen: 1 },
    { highOpen: 1 },
    { mediumOpen: 1 }
  ]) {
    const decision = evaluateReleaseProvenance(assessment({ findings }));
    assert.equal(decision.readiness, "NOT_READY");
  }
});

test("production requests and unsupported components fail closed", () => {
  assert.throws(
    () => validateReleaseProvenance(assessment({ environment: "production" })),
    (error) => error.code === "RELEASE_PROVENANCE_ENVIRONMENT_REJECTED"
  );
  assert.throws(
    () => validateReleaseProvenance(assessment({ component: "unknown-component" })),
    (error) => error.code === "RELEASE_PROVENANCE_COMPONENT_REJECTED"
  );
});

test("release inputs cannot contain payloads, credentials, commands, or deployment tokens", () => {
  for (const prohibited of [
    { artifactContent: "value" },
    { deploymentToken: "value" },
    { signingKey: "value" },
    { rawPayload: "value" },
    { command: "value" }
  ]) {
    assert.throws(
      () => validateReleaseProvenance(assessment(prohibited)),
      (error) => error.code === "RELEASE_PROVENANCE_PROHIBITED_FIELD"
    );
  }
});

test("release decisions are deterministic and contain no build input metadata", () => {
  const first = evaluateReleaseProvenance(assessment());
  const second = evaluateReleaseProvenance(assessment());
  assert.deepEqual(first, second);
  assert.equal("sourceRevision" in first, false);
  assert.equal("artifactDigest" in first, false);
  assert.equal("controls" in first, false);
});
