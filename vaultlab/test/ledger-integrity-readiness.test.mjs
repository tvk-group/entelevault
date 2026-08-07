import assert from "node:assert/strict";
import test from "node:test";
import {
  evaluateLedgerIntegrity,
  LEDGER_INTEGRITY_SCHEMA,
  REQUIRED_LEDGER_CONTROLS,
  validateLedgerIntegrityAssessment
} from "../src/ledger-integrity-readiness.mjs";

function assessment(overrides = {}) {
  const base = {
    schema: LEDGER_INTEGRITY_SCHEMA,
    assessmentId: "ledger_0123456789abcdef0123456789abcdef",
    assessedAt: "2026-08-07T00:00:00.000Z",
    environment: "production-observation",
    snapshot: {
      ledgerSnapshotDigest: "1".repeat(64),
      assetSnapshotDigest: "2".repeat(64),
      liabilitySnapshotDigest: "3".repeat(64),
      reconciliationDigest: "4".repeat(64),
      reserveMethodDigest: "5".repeat(64),
      sequenceClass: "current",
      coverageClass: "complete"
    },
    controls: Object.fromEntries(REQUIRED_LEDGER_CONTROLS.map((control) => [control, true])),
    findings: { criticalOpen: 0, highOpen: 0, mediumOpen: 0, unreconciledItems: 0 },
    evidenceDigest: "a".repeat(64)
  };
  return {
    ...base,
    ...overrides,
    snapshot: { ...base.snapshot, ...(overrides.snapshot ?? {}) },
    controls: { ...base.controls, ...(overrides.controls ?? {}) },
    findings: { ...base.findings, ...(overrides.findings ?? {}) }
  };
}

test("all fourteen ledger controls are necessary and sufficient for review eligibility", () => {
  const total = 1 << REQUIRED_LEDGER_CONTROLS.length;
  const allEnabled = total - 1;
  let eligible = 0;
  for (let mask = 0; mask < total; mask += 1) {
    const controls = Object.fromEntries(
      REQUIRED_LEDGER_CONTROLS.map((control, index) => [control, Boolean(mask & (1 << index))])
    );
    const decision = evaluateLedgerIntegrity(assessment({ controls }));
    const expected = mask === allEnabled;
    assert.equal(decision.readiness === "ELIGIBLE_FOR_INDEPENDENT_FINANCIAL_CONTROL_REVIEW", expected);
    if (expected) eligible += 1;
    assert.equal(decision.balanceMutationAuthorized, false);
    assert.equal(decision.tradingAuthorized, false);
    assert.equal(decision.assetMovementAuthorized, false);
  }
  assert.equal(total, 16_384);
  assert.equal(eligible, 1);
});

test("ledger classifications and findings fail closed", () => {
  const cases = [
    [assessment({ snapshot: { sequenceClass: "lagging" } }), "LEDGER_SEQUENCE_NOT_CURRENT"],
    [assessment({ snapshot: { coverageClass: "partial" } }), "LEDGER_COVERAGE_INCOMPLETE"],
    [assessment({ findings: { criticalOpen: 1 } }), "CRITICAL_FINDINGS_OPEN"],
    [assessment({ findings: { highOpen: 1 } }), "HIGH_FINDINGS_OPEN"],
    [assessment({ findings: { mediumOpen: 1 } }), "MEDIUM_FINDINGS_OPEN"],
    [assessment({ findings: { unreconciledItems: 1 } }), "UNRECONCILED_ITEMS_OPEN"]
  ];
  for (const [snapshot, reason] of cases) {
    const decision = evaluateLedgerIntegrity(snapshot);
    assert.equal(decision.readiness, "NOT_READY");
    assert.equal(decision.reasonCodes.includes(reason), true);
  }
});

test("ledger readiness is not a solvency claim or operational authorization", () => {
  const decision = evaluateLedgerIntegrity(assessment());
  assert.equal(decision.readiness, "ELIGIBLE_FOR_INDEPENDENT_FINANCIAL_CONTROL_REVIEW");
  assert.equal(decision.humanAuthorizationRequired, true);
  assert.equal(decision.proofOfSolvencyEstablished, false);
  assert.equal(decision.financialClaimAuthorized, false);
  assert.equal(decision.balanceMutationAuthorized, false);
  assert.equal(decision.tradingAuthorized, false);
  assert.equal(decision.withdrawalAuthorized, false);
  assert.equal(decision.signingAuthorized, false);
  assert.equal(decision.assetMovementAuthorized, false);
});

test("raw balances, accounts, addresses, transactions, and wallet data are rejected", () => {
  for (const prohibited of [
    { rawBalances: [] },
    { accountId: "value" },
    { customerAddress: "value" },
    { transactions: [] },
    { walletFile: "value" },
    { credential: "value" }
  ]) {
    assert.throws(
      () => validateLedgerIntegrityAssessment(assessment(prohibited)),
      (error) => error.code === "LEDGER_INTEGRITY_PROHIBITED_FIELD"
    );
  }
});

test("ledger assessments require the complete exact control set and digest-only snapshots", () => {
  const incomplete = assessment();
  delete incomplete.controls.replayProtectionVerified;
  assert.throws(
    () => validateLedgerIntegrityAssessment(incomplete),
    (error) => error.code === "LEDGER_INTEGRITY_CONTROL_REJECTED"
  );
  assert.throws(
    () => validateLedgerIntegrityAssessment(assessment({ snapshot: { ledgerSnapshotDigest: "not-a-digest" } })),
    (error) => error.code === "LEDGER_INTEGRITY_SNAPSHOT_REJECTED"
  );
});

test("ledger decisions are deterministic and omit snapshot/control detail", () => {
  const first = evaluateLedgerIntegrity(assessment());
  const second = evaluateLedgerIntegrity(assessment());
  assert.deepEqual(first, second);
  assert.equal("snapshot" in first, false);
  assert.equal("controls" in first, false);
  assert.equal("findings" in first, false);
});
