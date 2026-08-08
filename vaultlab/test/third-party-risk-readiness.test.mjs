import assert from "node:assert/strict";
import test from "node:test";
import { evaluateThirdPartyRisk, REQUIRED_THIRD_PARTY_RISK_CONTROLS, THIRD_PARTY_RISK_SCHEMA, validateThirdPartyRisk } from "../src/third-party-risk-readiness.mjs";
function controls(enabled = REQUIRED_THIRD_PARTY_RISK_CONTROLS) { return Object.fromEntries(REQUIRED_THIRD_PARTY_RISK_CONTROLS.map((control) => [control, enabled.includes(control)])); }
function assessment(overrides = {}) {
  const base = { schema: THIRD_PARTY_RISK_SCHEMA, assessmentId: "thirdparty_0123456789abcdef0123456789abcdef", assessedAt: "2026-08-10T00:00:00.000Z", environment: "staging", vendorClass: "cloud-infrastructure", systemClass: "exchange", policyRevision: "a".repeat(40), dueDiligenceDigest: "b".repeat(64), dependencyMapDigest: "c".repeat(64), controls: controls(), findings: { criticalOpen: 0, highOpen: 0, overdueReviews: 0, concentrationExceptions: 0, exitPlanGaps: 0 }, evidenceDigest: "d".repeat(64) };
  return { ...base, ...overrides, controls: { ...base.controls, ...(overrides.controls ?? {}) }, findings: { ...base.findings, ...(overrides.findings ?? {}) } };
}
test("complete third-party evidence is only eligible for independent review", () => {
  const decision = evaluateThirdPartyRisk(assessment()); assert.equal(decision.readiness, "ELIGIBLE_FOR_INDEPENDENT_THIRD_PARTY_REVIEW");
  for (const field of ["vendorOnboardingAuthorized", "contractExecutionAuthorized", "credentialIssuanceAuthorized", "dataSharingAuthorized", "accessGrantAuthorized", "procurementAuthorized", "paymentAuthorized", "deploymentAuthorized", "signingAuthorized", "assetMovementAuthorized"]) assert.equal(decision[field], false);
});
test("all 16,384 third-party-control combinations permit only the fully satisfied set", () => {
  let eligible = 0; const total = 1 << REQUIRED_THIRD_PARTY_RISK_CONTROLS.length;
  for (let mask = 0; mask < total; mask += 1) { const enabled = REQUIRED_THIRD_PARTY_RISK_CONTROLS.filter((_, index) => Boolean(mask & (1 << index))); const decision = evaluateThirdPartyRisk(assessment({ controls: controls(enabled) })); if (decision.readiness === "ELIGIBLE_FOR_INDEPENDENT_THIRD_PARTY_REVIEW") eligible += 1; assert.equal(decision.vendorOnboardingAuthorized, false); }
  assert.equal(eligible, 1);
});
test("open findings, overdue reviews, concentration exceptions, and exit gaps fail closed", () => {
  const cases = [["criticalOpen", "CRITICAL_THIRD_PARTY_FINDINGS_OPEN"], ["highOpen", "HIGH_THIRD_PARTY_FINDINGS_OPEN"], ["overdueReviews", "THIRD_PARTY_REVIEWS_OVERDUE"], ["concentrationExceptions", "CONCENTRATION_EXCEPTIONS_DETECTED"], ["exitPlanGaps", "EXIT_PLAN_GAPS_DETECTED"]];
  for (const [field, reason] of cases) { const decision = evaluateThirdPartyRisk(assessment({ findings: { [field]: 1 } })); assert.equal(decision.readiness, "NOT_READY"); assert.equal(decision.reasonCodes.includes(reason), true); }
});
test("unsupported environments, vendor classes, and systems fail closed", () => {
  assert.throws(() => validateThirdPartyRisk(assessment({ environment: "production" })), (error) => error.code === "THIRD_PARTY_RISK_ENVIRONMENT_REJECTED");
  assert.throws(() => validateThirdPartyRisk(assessment({ vendorClass: "unknown" })), (error) => error.code === "THIRD_PARTY_RISK_CLASS_REJECTED");
  assert.throws(() => validateThirdPartyRisk(assessment({ systemClass: "unknown" })), (error) => error.code === "THIRD_PARTY_RISK_CLASS_REJECTED");
});
test("vendor identities, contracts, credentials, endpoints, personal data, and wallet material are rejected", () => {
  for (const prohibited of [{ vendorName: "value" }, { contractContent: "value" }, { credential: "value" }, { endpointUrl: "value" }, { personalData: "value" }, { walletFile: "value" }]) assert.throws(() => validateThirdPartyRisk(assessment(prohibited)), (error) => error.code === "THIRD_PARTY_RISK_PROHIBITED_FIELD");
});
test("third-party decisions are deterministic and omit vendor, dependency, controls, and findings", () => {
  const first = evaluateThirdPartyRisk(assessment()); assert.deepEqual(first, evaluateThirdPartyRisk(assessment()));
  for (const field of ["vendorClass", "systemClass", "policyRevision", "dueDiligenceDigest", "dependencyMapDigest", "controls", "findings"]) assert.equal(field in first, false);
});
