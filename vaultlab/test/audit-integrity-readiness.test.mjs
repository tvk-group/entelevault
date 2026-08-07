import assert from "node:assert/strict";
import test from "node:test";
import {
  AUDIT_INTEGRITY_SCHEMA,
  evaluateAuditIntegrity,
  REQUIRED_AUDIT_INTEGRITY_CONTROLS,
  validateAuditIntegrityAssessment
} from "../src/audit-integrity-readiness.mjs";

function controls(enabled = REQUIRED_AUDIT_INTEGRITY_CONTROLS) {
  return Object.fromEntries(REQUIRED_AUDIT_INTEGRITY_CONTROLS.map((control) => [control, enabled.includes(control)]));
}

function assessment(overrides = {}) {
  const base = {
    schema: AUDIT_INTEGRITY_SCHEMA,
    assessmentId: "audit_0123456789abcdef0123456789abcdef",
    assessedAt: "2026-08-07T00:00:00.000Z",
    environment: "staging",
    systemClass: "exchange",
    streamClass: "ledger-events",
    policyRevision: "a".repeat(40),
    streamDigest: "b".repeat(64),
    anchorDigest: "c".repeat(64),
    controls: controls(),
    findings: {
      criticalOpen: 0,
      highOpen: 0,
      sequenceGaps: 0,
      duplicateEvents: 0,
      integrityMismatches: 0
    },
    evidenceDigest: "d".repeat(64)
  };
  return {
    ...base,
    ...overrides,
    controls: { ...base.controls, ...(overrides.controls ?? {}) },
    findings: { ...base.findings, ...(overrides.findings ?? {}) }
  };
}

test("complete audit evidence is only eligible for independent review", () => {
  const decision = evaluateAuditIntegrity(assessment());
  assert.equal(decision.readiness, "ELIGIBLE_FOR_INDEPENDENT_AUDIT_REVIEW");
  assert.equal(decision.reasonCodes.length, 0);
  assert.equal(decision.humanAuthorizationRequired, true);
  assert.equal(decision.auditWriteAuthorized, false);
  assert.equal(decision.auditDeleteAuthorized, false);
  assert.equal(decision.logAccessAuthorized, false);
  assert.equal(decision.remediationExecutionAuthorized, false);
  assert.equal(decision.dataMutationAuthorized, false);
  assert.equal(decision.deploymentAuthorized, false);
  assert.equal(decision.signingAuthorized, false);
  assert.equal(decision.assetMovementAuthorized, false);
});

test("all 16,384 audit-control combinations permit only the fully satisfied set", () => {
  const total = 1 << REQUIRED_AUDIT_INTEGRITY_CONTROLS.length;
  let eligible = 0;
  for (let mask = 0; mask < total; mask += 1) {
    const enabled = REQUIRED_AUDIT_INTEGRITY_CONTROLS.filter((_, index) => Boolean(mask & (1 << index)));
    const decision = evaluateAuditIntegrity(assessment({ controls: controls(enabled) }));
    if (decision.readiness === "ELIGIBLE_FOR_INDEPENDENT_AUDIT_REVIEW") eligible += 1;
    assert.equal(decision.auditWriteAuthorized, false);
  }
  assert.equal(eligible, 1);
});

test("open findings, sequence gaps, duplicates, and integrity mismatches fail closed", () => {
  const cases = [
    ["criticalOpen", "CRITICAL_FINDINGS_OPEN"],
    ["highOpen", "HIGH_FINDINGS_OPEN"],
    ["sequenceGaps", "SEQUENCE_GAPS_DETECTED"],
    ["duplicateEvents", "DUPLICATE_EVENTS_DETECTED"],
    ["integrityMismatches", "INTEGRITY_MISMATCHES_DETECTED"]
  ];
  for (const [field, reason] of cases) {
    const decision = evaluateAuditIntegrity(assessment({ findings: { [field]: 1 } }));
    assert.equal(decision.readiness, "NOT_READY");
    assert.equal(decision.reasonCodes.includes(reason), true);
  }
});

test("raw events, logs, payloads, credentials, tokens, keys, and wallet material are rejected", () => {
  for (const prohibited of [
    { rawEvent: "value" },
    { logContent: "value" },
    { eventPayload: "value" },
    { credential: "value" },
    { accessToken: "value" },
    { privateKey: "value" },
    { walletData: "value" }
  ]) {
    assert.throws(
      () => validateAuditIntegrityAssessment(assessment(prohibited)),
      (error) => error.code === "AUDIT_INTEGRITY_PROHIBITED_FIELD"
    );
  }
});

test("audit assessments require exact controls, digests, and bounded counts", () => {
  const missingControl = assessment();
  delete missingControl.controls.hashChainVerified;
  assert.throws(
    () => validateAuditIntegrityAssessment(missingControl),
    (error) => error.code === "AUDIT_INTEGRITY_UNKNOWN_FIELD"
  );
  assert.throws(
    () => validateAuditIntegrityAssessment(assessment({ anchorDigest: "short" })),
    (error) => error.code === "AUDIT_INTEGRITY_DIGEST_REJECTED"
  );
  assert.throws(
    () => validateAuditIntegrityAssessment(assessment({ findings: { sequenceGaps: -1 } })),
    (error) => error.code === "AUDIT_INTEGRITY_FINDING_REJECTED"
  );
});

test("audit decisions are deterministic and omit stream metadata, controls, and findings", () => {
  const first = evaluateAuditIntegrity(assessment());
  const second = evaluateAuditIntegrity(assessment());
  assert.deepEqual(first, second);
  assert.equal("systemClass" in first, false);
  assert.equal("streamClass" in first, false);
  assert.equal("controls" in first, false);
  assert.equal("findings" in first, false);
});
