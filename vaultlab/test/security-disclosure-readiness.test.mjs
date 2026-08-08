import assert from "node:assert/strict";
import test from "node:test";
import { evaluateSecurityDisclosure, REQUIRED_SECURITY_DISCLOSURE_CONTROLS, SECURITY_DISCLOSURE_SCHEMA, validateSecurityDisclosure } from "../src/security-disclosure-readiness.mjs";
function controls(enabled = REQUIRED_SECURITY_DISCLOSURE_CONTROLS) { return Object.fromEntries(REQUIRED_SECURITY_DISCLOSURE_CONTROLS.map((control) => [control, enabled.includes(control)])); }
function assessment(overrides = {}) {
  const base = { schema: SECURITY_DISCLOSURE_SCHEMA, assessmentId: "disclosure_0123456789abcdef0123456789abcdef", assessedAt: "2026-08-10T00:00:00.000Z", environment: "staging", programClass: "private-disclosure", systemClass: "security-platform", programRevision: "a".repeat(40), policyDigest: "b".repeat(64), scopeDigest: "c".repeat(64), controls: controls(), findings: { policyGaps: 0, scopeAmbiguities: 0, overdueTriage: 0, privacyBreaches: 0, unresolvedDisputes: 0 }, evidenceDigest: "d".repeat(64) };
  return { ...base, ...overrides, controls: { ...base.controls, ...(overrides.controls ?? {}) }, findings: { ...base.findings, ...(overrides.findings ?? {}) } };
}
test("complete disclosure evidence is only eligible for separate program approval", () => {
  const decision = evaluateSecurityDisclosure(assessment()); assert.equal(decision.readiness, "ELIGIBLE_FOR_SEPARATE_DISCLOSURE_PROGRAM_APPROVAL");
  for (const field of ["programActivationAuthorized", "vulnerabilityScanningAuthorized", "exploitationAuthorized", "publicDisclosureAuthorized", "rewardPaymentAuthorized", "remediationExecutionAuthorized", "deploymentAuthorized", "signingAuthorized", "assetMovementAuthorized"]) assert.equal(decision[field], false);
});
test("all 16,384 disclosure-control combinations permit only the fully satisfied set", () => {
  let eligible = 0; const total = 1 << REQUIRED_SECURITY_DISCLOSURE_CONTROLS.length;
  for (let mask = 0; mask < total; mask += 1) { const enabled = REQUIRED_SECURITY_DISCLOSURE_CONTROLS.filter((_, index) => Boolean(mask & (1 << index))); const decision = evaluateSecurityDisclosure(assessment({ controls: controls(enabled) })); if (decision.readiness === "ELIGIBLE_FOR_SEPARATE_DISCLOSURE_PROGRAM_APPROVAL") eligible += 1; assert.equal(decision.exploitationAuthorized, false); }
  assert.equal(eligible, 1);
});
test("policy, scope, triage, privacy, and dispute findings fail closed", () => {
  const cases = [["policyGaps", "POLICY_GAPS_DETECTED"], ["scopeAmbiguities", "SCOPE_AMBIGUITIES_DETECTED"], ["overdueTriage", "TRIAGE_OVERDUE"], ["privacyBreaches", "RESEARCHER_PRIVACY_BREACHES_DETECTED"], ["unresolvedDisputes", "DISCLOSURE_DISPUTES_UNRESOLVED"]];
  for (const [field, reason] of cases) { const decision = evaluateSecurityDisclosure(assessment({ findings: { [field]: 1 } })); assert.equal(decision.readiness, "NOT_READY"); assert.equal(decision.reasonCodes.includes(reason), true); }
});
test("unsupported environments, programs, and system classes fail closed", () => {
  assert.throws(() => validateSecurityDisclosure(assessment({ environment: "production" })), (error) => error.code === "SECURITY_DISCLOSURE_ENVIRONMENT_REJECTED");
  assert.throws(() => validateSecurityDisclosure(assessment({ programClass: "unbounded-testing" })), (error) => error.code === "SECURITY_DISCLOSURE_CLASS_REJECTED");
  assert.throws(() => validateSecurityDisclosure(assessment({ systemClass: "unknown" })), (error) => error.code === "SECURITY_DISCLOSURE_CLASS_REJECTED");
});
test("reports, exploit material, researcher identities, targets, and wallet material are rejected", () => {
  for (const prohibited of [{ rawReport: "value" }, { exploitCode: "value" }, { proofOfConcept: "value" }, { researcherIdentity: "value" }, { targetHost: "value" }, { walletData: "value" }]) assert.throws(() => validateSecurityDisclosure(assessment(prohibited)), (error) => error.code === "SECURITY_DISCLOSURE_PROHIBITED_FIELD");
});
test("disclosure decisions are deterministic and omit program, scope, controls, and findings", () => {
  const first = evaluateSecurityDisclosure(assessment()); assert.deepEqual(first, evaluateSecurityDisclosure(assessment()));
  for (const field of ["programClass", "systemClass", "programRevision", "policyDigest", "scopeDigest", "controls", "findings"]) assert.equal(field in first, false);
});
