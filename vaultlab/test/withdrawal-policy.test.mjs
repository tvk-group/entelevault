import assert from "node:assert/strict";
import test from "node:test";
import {
  evaluateWithdrawalRequest,
  validateWithdrawalRequest,
  WITHDRAWAL_REQUEST_SCHEMA
} from "../src/withdrawal-policy.mjs";

function request(overrides = {}) {
  const base = {
    schema: WITHDRAWAL_REQUEST_SCHEMA,
    requestId: "wdreq_0123456789abcdef0123456789abcdef",
    observedAt: "2026-08-07T00:00:00.000Z",
    environment: "production-observation",
    subject: {
      accountAgeClass: "established",
      sessionAssurance: "phishing-resistant",
      deviceTrust: "trusted",
      recentCredentialChange: false,
      accountTakeoverSuspected: false
    },
    withdrawal: {
      assetClass: "stable",
      amountClass: "standard",
      destinationTrust: "allowlisted",
      velocityClass: "normal",
      crossBorderRisk: "low",
      complianceStatus: "clear",
      networkRisk: "low"
    },
    controls: {
      phishingResistantMfaSatisfied: true,
      freshReauthenticationSatisfied: true,
      cooldownRequiredHours: 24,
      cooldownElapsedHours: 24,
      dualApprovalRequired: true,
      dualApprovalSatisfied: true,
      travelRuleRequired: true,
      travelRuleSatisfied: true
    },
    evidenceDigest: "a".repeat(64)
  };
  return {
    ...base,
    ...overrides,
    subject: { ...base.subject, ...(overrides.subject ?? {}) },
    withdrawal: { ...base.withdrawal, ...(overrides.withdrawal ?? {}) },
    controls: { ...base.controls, ...(overrides.controls ?? {}) }
  };
}

test("low-risk withdrawal proceeds only to a separate authorization system", () => {
  const decision = evaluateWithdrawalRequest(request());
  assert.equal(decision.recommendation, "PROCEED_TO_SEPARATE_AUTHORIZATION");
  assert.deepEqual(decision.reasonCodes, []);
  assert.equal(decision.humanAuthorizationRequired, true);
  assert.equal(decision.holdExecutionAuthorized, false);
  assert.equal(decision.withdrawalAuthorized, false);
  assert.equal(decision.signingAuthorized, false);
  assert.equal(decision.assetMovementAuthorized, false);
});

test("every material withdrawal failure holds and escalates", () => {
  const cases = [
    [request({ subject: { accountTakeoverSuspected: true } }), "ACCOUNT_TAKEOVER_SUSPECTED"],
    [request({ subject: { deviceTrust: "blocked" } }), "DEVICE_BLOCKED"],
    [request({ subject: { sessionAssurance: "degraded" } }), "SESSION_ASSURANCE_DEGRADED"],
    [request({ withdrawal: { destinationTrust: "blocked" } }), "DESTINATION_BLOCKED"],
    [request({ withdrawal: { amountClass: "limit-exceeding" } }), "AMOUNT_LIMIT_EXCEEDED"],
    [request({ withdrawal: { velocityClass: "limit-exceeding" } }), "VELOCITY_LIMIT_EXCEEDED"],
    [request({ withdrawal: { complianceStatus: "blocked" } }), "COMPLIANCE_BLOCKED"],
    [request({ withdrawal: { complianceStatus: "unavailable" } }), "COMPLIANCE_UNAVAILABLE"],
    [request({ withdrawal: { crossBorderRisk: "high" } }), "CROSS_BORDER_RISK_HIGH"],
    [request({ withdrawal: { networkRisk: "high" } }), "NETWORK_RISK_HIGH"],
    [request({ controls: { phishingResistantMfaSatisfied: false } }), "PHISHING_RESISTANT_MFA_REQUIRED"],
    [request({ controls: { freshReauthenticationSatisfied: false } }), "FRESH_REAUTHENTICATION_REQUIRED"],
    [
      request({ subject: { recentCredentialChange: true }, controls: { cooldownElapsedHours: 23 } }),
      "CREDENTIAL_CHANGE_COOLDOWN_ACTIVE"
    ],
    [request({ controls: { dualApprovalSatisfied: false } }), "DUAL_APPROVAL_REQUIRED"],
    [request({ controls: { travelRuleSatisfied: false } }), "TRAVEL_RULE_INCOMPLETE"],
    [
      request({ withdrawal: { amountClass: "elevated" }, controls: { dualApprovalRequired: false } }),
      "DUAL_APPROVAL_POLICY_MISSING"
    ],
    [
      request({ withdrawal: { destinationTrust: "new" }, controls: { dualApprovalRequired: false } }),
      "DUAL_APPROVAL_POLICY_MISSING"
    ],
    [
      request({ withdrawal: { crossBorderRisk: "medium" }, controls: { travelRuleRequired: false } }),
      "TRAVEL_RULE_POLICY_MISSING"
    ]
  ];
  for (const [snapshot, reason] of cases) {
    const decision = evaluateWithdrawalRequest(snapshot);
    assert.equal(decision.recommendation, "HOLD_AND_ESCALATE");
    assert.equal(decision.reasonCodes.includes(reason), true);
    assert.equal(decision.withdrawalAuthorized, false);
  }
});

test("uncertain or elevated classifications require human risk review", () => {
  const cases = [
    request({ subject: { accountAgeClass: "new" } }),
    request({ subject: { sessionAssurance: "standard" } }),
    request({ subject: { deviceTrust: "new" } }),
    request({ withdrawal: { assetClass: "unknown" } }),
    request({ withdrawal: { amountClass: "elevated" } }),
    request({ withdrawal: { destinationTrust: "known" } }),
    request({ withdrawal: { velocityClass: "elevated" } }),
    request({ withdrawal: { crossBorderRisk: "medium" } }),
    request({ withdrawal: { networkRisk: "unknown" } }),
    request({ withdrawal: { complianceStatus: "review" } })
  ];
  for (const snapshot of cases) {
    assert.equal(
      evaluateWithdrawalRequest(snapshot).recommendation,
      "REQUIRE_HUMAN_RISK_REVIEW"
    );
  }
});

test("recent credential changes cannot weaken the minimum cooldown", () => {
  assert.throws(
    () =>
      validateWithdrawalRequest(
        request({ subject: { recentCredentialChange: true }, controls: { cooldownRequiredHours: 23 } })
      ),
    (error) => error.code === "WITHDRAWAL_CONTROL_REJECTED"
  );
});

test("raw values, identities, targets, transactions, and credentials are rejected", () => {
  for (const prohibited of [
    { recipientAddress: "value" },
    { amountValue: "value" },
    { userEmail: "value" },
    { rawTransaction: "value" },
    { credentialValue: "value" },
    { target: "value" }
  ]) {
    assert.throws(
      () => validateWithdrawalRequest(request(prohibited)),
      (error) => error.code === "WITHDRAWAL_PROHIBITED_FIELD"
    );
  }
});

test("withdrawal decisions are deterministic and contain no request classifications", () => {
  const first = evaluateWithdrawalRequest(request());
  const second = evaluateWithdrawalRequest(request());
  assert.deepEqual(first, second);
  assert.equal("subject" in first, false);
  assert.equal("withdrawal" in first, false);
  assert.equal("controls" in first, false);
});
