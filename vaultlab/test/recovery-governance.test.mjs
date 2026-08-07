import assert from "node:assert/strict";
import test from "node:test";
import {
  evaluateRecoveryCase,
  RECOVERY_CASE_SCHEMA,
  validateRecoveryCase,
  validateRecoveryTransition
} from "../src/recovery-governance.mjs";

function approval(role, suffix) {
  return {
    role,
    approverId: `approver_${suffix}`,
    approvedAt: "2026-08-09T00:00:00.000Z",
    attestationDigest: suffix[0].repeat(64)
  };
}

function recoveryCase(overrides = {}) {
  const base = {
    schema: RECOVERY_CASE_SCHEMA,
    caseId: "case_0123456789abcdef0123456789abcdef",
    phase: "quorum-approved",
    openedAt: "2026-08-07T00:00:00.000Z",
    lastTransitionAt: "2026-08-09T00:00:00.000Z",
    environment: "staging",
    authority: {
      verified: true,
      subjectMatch: true,
      scopeApproved: true,
      counselReviewed: true
    },
    approvals: [
      approval("legal", "1111111111111111"),
      approval("security", "2222222222222222"),
      approval("custody", "3333333333333333")
    ],
    waitingPeriod: { requiredHours: 48, elapsedHours: 48, emergencyOverride: false },
    notifications: {
      requesterNotified: true,
      securityNotified: true,
      custodyNotified: true
    },
    findings: { criticalOpen: 0, highOpen: 0 },
    evidenceDigest: "a".repeat(64)
  };
  return {
    ...base,
    ...overrides,
    authority: { ...base.authority, ...(overrides.authority ?? {}) },
    waitingPeriod: { ...base.waitingPeriod, ...(overrides.waitingPeriod ?? {}) },
    notifications: { ...base.notifications, ...(overrides.notifications ?? {}) },
    findings: { ...base.findings, ...(overrides.findings ?? {}) }
  };
}

test("complete governance can only recommend separate custody review", () => {
  const decision = evaluateRecoveryCase(recoveryCase());
  assert.equal(decision.recommendation, "READY_FOR_SEPARATE_CUSTODY_REVIEW");
  assert.deepEqual(decision.reasonCodes, []);
  assert.equal(decision.humanAuthorizationRequired, true);
  assert.equal(decision.executionAuthorized, false);
  assert.equal(decision.signingAuthorized, false);
  assert.equal(decision.assetMovementAuthorized, false);
});

test("authority, quorum, cooling, notification, and finding failures block", () => {
  const cases = [
    [recoveryCase({ authority: { counselReviewed: false } }), "AUTHORITY_INCOMPLETE"],
    [recoveryCase({ approvals: recoveryCase().approvals.slice(0, 2) }), "QUORUM_INCOMPLETE"],
    [recoveryCase({ waitingPeriod: { elapsedHours: 47 } }), "COOLING_PERIOD_ACTIVE"],
    [recoveryCase({ waitingPeriod: { emergencyOverride: true } }), "EMERGENCY_OVERRIDE_REJECTED"],
    [recoveryCase({ notifications: { requesterNotified: false } }), "NOTIFICATIONS_INCOMPLETE"],
    [recoveryCase({ findings: { criticalOpen: 1 } }), "CRITICAL_FINDINGS_OPEN"],
    [recoveryCase({ findings: { highOpen: 1 } }), "HIGH_FINDINGS_OPEN"]
  ];
  for (const [snapshot, reason] of cases) {
    const decision = evaluateRecoveryCase(snapshot);
    assert.equal(decision.recommendation, "BLOCK");
    assert.equal(decision.reasonCodes.includes(reason), true);
  }
});

test("one person cannot satisfy multiple approval roles", () => {
  const approvals = recoveryCase().approvals;
  approvals[1].approverId = approvals[0].approverId;
  assert.throws(
    () => validateRecoveryCase(recoveryCase({ approvals })),
    (error) => error.code === "RECOVERY_APPROVAL_REJECTED"
  );
});

test("fast-forward and backward-time transitions are rejected", () => {
  const intake = recoveryCase({
    phase: "intake",
    approvals: [],
    lastTransitionAt: "2026-08-07T00:00:00.000Z",
    waitingPeriod: { elapsedHours: 0 }
  });
  assert.throws(
    () => validateRecoveryTransition(intake, recoveryCase({ phase: "quorum-approved" })),
    (error) => error.code === "RECOVERY_TRANSITION_REJECTED"
  );
  const authority = recoveryCase({ phase: "authority-verified", approvals: [] });
  assert.throws(
    () =>
      validateRecoveryTransition(
        intake,
        { ...authority, lastTransitionAt: "2026-08-06T00:00:00.000Z" }
      ),
    (error) =>
      error.code === "RECOVERY_CASE_TIME_REJECTED" ||
      error.code === "RECOVERY_TRANSITION_TIME_REJECTED"
  );
});

test("the sequential authority transition is accepted without execution authority", () => {
  const intake = recoveryCase({
    phase: "intake",
    approvals: [],
    lastTransitionAt: "2026-08-07T00:00:00.000Z",
    waitingPeriod: { elapsedHours: 0 }
  });
  const authority = recoveryCase({
    phase: "authority-verified",
    approvals: [],
    lastTransitionAt: "2026-08-07T01:00:00.000Z",
    waitingPeriod: { elapsedHours: 1 }
  });
  const result = validateRecoveryTransition(intake, authority);
  assert.equal(result.accepted, true);
  assert.equal(result.executionAuthorized, false);
  assert.equal(result.assetMovementAuthorized, false);
});

test("approval times must be contained by the observed case timeline", () => {
  const cases = [
    recoveryCase({
      approvals: [
        { ...approval("legal", "1111111111111111"), approvedAt: "2026-08-06T23:59:59.000Z" }
      ]
    }),
    recoveryCase({
      approvals: [
        { ...approval("legal", "1111111111111111"), approvedAt: "2026-08-09T00:00:01.000Z" }
      ]
    }),
    recoveryCase({ waitingPeriod: { elapsedHours: 49 } })
  ];
  for (const snapshot of cases) {
    assert.throws(
      () => validateRecoveryCase(snapshot),
      (error) =>
        error.code === "RECOVERY_APPROVAL_REJECTED" || error.code === "RECOVERY_WAIT_REJECTED"
    );
  }
});

test("progression cannot weaken policy, authority, approvals, or readiness controls", () => {
  const quorum = recoveryCase();
  const cases = [
    recoveryCase({
      phase: "migration-prepared",
      waitingPeriod: { requiredHours: 24 }
    }),
    recoveryCase({ phase: "migration-prepared", authority: { verified: false } }),
    recoveryCase({ phase: "migration-prepared", approvals: quorum.approvals.slice(1) }),
    recoveryCase({ phase: "migration-prepared", findings: { highOpen: 1 } })
  ];
  for (const next of cases) {
    assert.throws(
      () => validateRecoveryTransition(quorum, next),
      (error) => error.code === "RECOVERY_TRANSITION_CONTROL_REJECTED"
    );
  }
});

test("completion preserves controls and still grants no execution authority", () => {
  const prepared = recoveryCase({ phase: "migration-prepared" });
  const completed = recoveryCase({
    phase: "completed",
    lastTransitionAt: "2026-08-09T01:00:00.000Z",
    waitingPeriod: { elapsedHours: 49 }
  });
  const result = validateRecoveryTransition(prepared, completed);
  assert.equal(result.accepted, true);
  assert.equal(result.executionAuthorized, false);
  assert.equal(result.assetMovementAuthorized, false);
});

test("wallet material and target data are rejected", () => {
  for (const prohibited of [{ walletAddress: "value" }, { privateKey: "value" }, { target: "value" }]) {
    assert.throws(
      () => validateRecoveryCase(recoveryCase(prohibited)),
      (error) => error.code === "RECOVERY_CASE_PROHIBITED_FIELD"
    );
  }
});
