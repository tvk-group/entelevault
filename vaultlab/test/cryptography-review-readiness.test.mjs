import assert from "node:assert/strict";
import test from "node:test";
import { CRYPTOGRAPHY_REVIEW_SCHEMA, evaluateCryptographyReview, REQUIRED_CRYPTOGRAPHY_REVIEW_CONTROLS, validateCryptographyReview } from "../src/cryptography-review-readiness.mjs";
function controls(enabled = REQUIRED_CRYPTOGRAPHY_REVIEW_CONTROLS) { return Object.fromEntries(REQUIRED_CRYPTOGRAPHY_REVIEW_CONTROLS.map((control) => [control, enabled.includes(control)])); }
function assessment(overrides = {}) {
  const base = { schema: CRYPTOGRAPHY_REVIEW_SCHEMA, assessmentId: "crypto_0123456789abcdef0123456789abcdef", assessedAt: "2026-08-10T00:00:00.000Z", environment: "staging", componentClass: "wallet-vault", designRevision: "a".repeat(40), specificationDigest: "b".repeat(64), threatModelDigest: "c".repeat(64), controls: controls(), findings: { criticalOpen: 0, highOpen: 0, parameterExceptions: 0, vectorFailures: 0, deprecatedPrimitives: 0 }, evidenceDigest: "d".repeat(64) };
  return { ...base, ...overrides, controls: { ...base.controls, ...(overrides.controls ?? {}) }, findings: { ...base.findings, ...(overrides.findings ?? {}) } };
}
test("complete cryptography evidence is only eligible for independent approval", () => {
  const decision = evaluateCryptographyReview(assessment());
  assert.equal(decision.readiness, "ELIGIBLE_FOR_INDEPENDENT_CRYPTOGRAPHY_APPROVAL");
  for (const field of ["cryptographicOperationAuthorized", "keyGenerationAuthorized", "keyExportAuthorized", "cryptoMigrationAuthorized", "remediationExecutionAuthorized", "deploymentAuthorized", "signingAuthorized", "assetMovementAuthorized"]) assert.equal(decision[field], false);
});
test("all 16,384 cryptography-control combinations permit only the fully satisfied set", () => {
  let eligible = 0; const total = 1 << REQUIRED_CRYPTOGRAPHY_REVIEW_CONTROLS.length;
  for (let mask = 0; mask < total; mask += 1) { const enabled = REQUIRED_CRYPTOGRAPHY_REVIEW_CONTROLS.filter((_, index) => Boolean(mask & (1 << index))); const decision = evaluateCryptographyReview(assessment({ controls: controls(enabled) })); if (decision.readiness === "ELIGIBLE_FOR_INDEPENDENT_CRYPTOGRAPHY_APPROVAL") eligible += 1; assert.equal(decision.cryptographicOperationAuthorized, false); }
  assert.equal(eligible, 1);
});
test("open findings, parameter exceptions, vector failures, and deprecated primitives fail closed", () => {
  const cases = [["criticalOpen", "CRITICAL_CRYPTOGRAPHY_FINDINGS_OPEN"], ["highOpen", "HIGH_CRYPTOGRAPHY_FINDINGS_OPEN"], ["parameterExceptions", "PARAMETER_EXCEPTIONS_DETECTED"], ["vectorFailures", "INTEROPERABILITY_VECTOR_FAILURES_DETECTED"], ["deprecatedPrimitives", "DEPRECATED_PRIMITIVES_DETECTED"]];
  for (const [field, reason] of cases) { const decision = evaluateCryptographyReview(assessment({ findings: { [field]: 1 } })); assert.equal(decision.readiness, "NOT_READY"); assert.equal(decision.reasonCodes.includes(reason), true); }
});
test("unsupported environments and component classes fail closed", () => {
  assert.throws(() => validateCryptographyReview(assessment({ environment: "production" })), (error) => error.code === "CRYPTOGRAPHY_REVIEW_ENVIRONMENT_REJECTED");
  assert.throws(() => validateCryptographyReview(assessment({ componentClass: "unknown" })), (error) => error.code === "CRYPTOGRAPHY_REVIEW_COMPONENT_REJECTED");
});
test("keys, entropy, plaintext, ciphertext, credentials, and wallet material are rejected", () => {
  for (const prohibited of [{ privateKey: "value" }, { entropyValue: "value" }, { plaintext: "value" }, { ciphertext: "value" }, { credential: "value" }, { walletFile: "value" }]) assert.throws(() => validateCryptographyReview(assessment(prohibited)), (error) => error.code === "CRYPTOGRAPHY_REVIEW_PROHIBITED_FIELD");
});
test("cryptography decisions are deterministic and omit design, controls, and findings", () => {
  const first = evaluateCryptographyReview(assessment()); assert.deepEqual(first, evaluateCryptographyReview(assessment()));
  for (const field of ["componentClass", "designRevision", "specificationDigest", "threatModelDigest", "controls", "findings"]) assert.equal(field in first, false);
});
