import assert from "node:assert/strict";
import test from "node:test";
import {
  CLIENT_INTEGRITY_SCHEMA,
  evaluateClientIntegrity,
  REQUIRED_CLIENT_INTEGRITY_CONTROLS,
  validateClientIntegrityAssessment
} from "../src/client-integrity-readiness.mjs";

function controls(enabled = REQUIRED_CLIENT_INTEGRITY_CONTROLS) {
  return Object.fromEntries(REQUIRED_CLIENT_INTEGRITY_CONTROLS.map((control) => [control, enabled.includes(control)]));
}
function assessment(overrides = {}) {
  const base = {
    schema: CLIENT_INTEGRITY_SCHEMA,
    assessmentId: "client_0123456789abcdef0123456789abcdef",
    assessedAt: "2026-08-08T00:00:00.000Z",
    environment: "staging",
    clientClass: "wallet-mobile",
    platformClass: "android",
    buildRevision: "a".repeat(40),
    binaryDigest: "b".repeat(64),
    attestationPolicyDigest: "c".repeat(64),
    controls: controls(),
    findings: { criticalOpen: 0, highOpen: 0, attestationFailures: 0, integrityMismatches: 0, unsignedBuilds: 0 },
    evidenceDigest: "d".repeat(64)
  };
  return { ...base, ...overrides, controls: { ...base.controls, ...(overrides.controls ?? {}) }, findings: { ...base.findings, ...(overrides.findings ?? {}) } };
}

test("complete client evidence is only eligible for independent review", () => {
  const decision = evaluateClientIntegrity(assessment());
  assert.equal(decision.readiness, "ELIGIBLE_FOR_INDEPENDENT_CLIENT_REVIEW");
  assert.equal(decision.reasonCodes.length, 0);
  for (const field of ["clientActivationAuthorized", "distributionAuthorized", "updateExecutionAuthorized", "deviceAccessAuthorized", "keyStorageAuthorized", "deploymentAuthorized", "signingAuthorized", "assetMovementAuthorized"]) assert.equal(decision[field], false);
});

test("all 16,384 client-control combinations permit only the fully satisfied set", () => {
  const total = 1 << REQUIRED_CLIENT_INTEGRITY_CONTROLS.length;
  let eligible = 0;
  for (let mask = 0; mask < total; mask += 1) {
    const enabled = REQUIRED_CLIENT_INTEGRITY_CONTROLS.filter((_, index) => Boolean(mask & (1 << index)));
    const decision = evaluateClientIntegrity(assessment({ controls: controls(enabled) }));
    if (decision.readiness === "ELIGIBLE_FOR_INDEPENDENT_CLIENT_REVIEW") eligible += 1;
    assert.equal(decision.clientActivationAuthorized, false);
  }
  assert.equal(eligible, 1);
});

test("findings and attestation or integrity failures fail closed", () => {
  const cases = [["criticalOpen", "CRITICAL_FINDINGS_OPEN"], ["highOpen", "HIGH_FINDINGS_OPEN"], ["attestationFailures", "ATTESTATION_FAILURES_DETECTED"], ["integrityMismatches", "INTEGRITY_MISMATCHES_DETECTED"], ["unsignedBuilds", "UNSIGNED_BUILDS_DETECTED"]];
  for (const [field, reason] of cases) {
    const decision = evaluateClientIntegrity(assessment({ findings: { [field]: 1 } }));
    assert.equal(decision.readiness, "NOT_READY");
    assert.equal(decision.reasonCodes.includes(reason), true);
  }
});

test("client and platform classes must remain compatible", () => {
  assert.throws(() => validateClientIntegrityAssessment(assessment({ platformClass: "browser-extension" })), (error) => error.code === "CLIENT_INTEGRITY_PLATFORM_REJECTED");
  assert.equal(validateClientIntegrityAssessment(assessment({ clientClass: "wallet-extension", platformClass: "browser-extension" })).platformClass, "browser-extension");
});

test("attestation tokens, device identifiers, binaries, credentials, keys, and wallet material are rejected", () => {
  for (const prohibited of [{ attestationToken: "value" }, { deviceId: "value" }, { binaryContent: "value" }, { credential: "value" }, { privateKey: "value" }, { rawPayload: "value" }, { walletFile: "value" }]) {
    assert.throws(() => validateClientIntegrityAssessment(assessment(prohibited)), (error) => error.code === "CLIENT_INTEGRITY_PROHIBITED_FIELD");
  }
});

test("client decisions are deterministic and omit platform, build, controls, and findings", () => {
  const first = evaluateClientIntegrity(assessment());
  assert.deepEqual(first, evaluateClientIntegrity(assessment()));
  for (const field of ["clientClass", "platformClass", "buildRevision", "controls", "findings"]) assert.equal(field in first, false);
});
