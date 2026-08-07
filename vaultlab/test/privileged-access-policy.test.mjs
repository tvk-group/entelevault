import assert from "node:assert/strict";
import test from "node:test";
import {
  evaluatePrivilegedAccessRequest,
  PRIVILEGED_ACCESS_SCHEMA,
  validatePrivilegedAccessRequest
} from "../src/privileged-access-policy.mjs";

function request(overrides = {}) {
  const base = {
    schema: PRIVILEGED_ACCESS_SCHEMA,
    requestId: "pareq_0123456789abcdef0123456789abcdef",
    observedAt: "2026-08-07T00:00:00.000Z",
    environment: "production-observation",
    principal: {
      roleClass: "security",
      employmentStatus: "active",
      privilegeTier: "standard",
      separationOfDutiesConflict: false,
      recentRoleChange: false
    },
    session: {
      assurance: "phishing-resistant",
      deviceTrust: "managed",
      sessionAgeMinutes: 5,
      networkTrust: "corporate",
      anomalyClass: "none"
    },
    action: {
      resourceClass: "configuration",
      riskClass: "low",
      changeWindow: "approved",
      scopeClass: "read-only"
    },
    controls: {
      phishingResistantMfaSatisfied: true,
      freshReauthenticationSatisfied: true,
      ticketBound: true,
      justInTimeGrant: true,
      maxSessionAgeMinutes: 30,
      grantExpiresMinutes: 15,
      dualApprovalRequired: false,
      dualApprovalSatisfied: false,
      breakGlassDeclared: false,
      postActionReviewRequired: false
    },
    evidenceDigest: "a".repeat(64)
  };
  return {
    ...base,
    ...overrides,
    principal: { ...base.principal, ...(overrides.principal ?? {}) },
    session: { ...base.session, ...(overrides.session ?? {}) },
    action: { ...base.action, ...(overrides.action ?? {}) },
    controls: { ...base.controls, ...(overrides.controls ?? {}) }
  };
}

test("low-risk privileged metadata proceeds only to separate authorization", () => {
  const decision = evaluatePrivilegedAccessRequest(request());
  assert.equal(decision.recommendation, "PROCEED_TO_SEPARATE_ACCESS_AUTHORIZATION");
  assert.deepEqual(decision.reasonCodes, []);
  assert.equal(decision.humanAuthorizationRequired, true);
  assert.equal(decision.accessGrantAuthorized, false);
  assert.equal(decision.privilegedActionAuthorized, false);
  assert.equal(decision.deploymentAuthorized, false);
  assert.equal(decision.signingAuthorized, false);
  assert.equal(decision.assetMovementAuthorized, false);
});

test("material privileged-access failures block and escalate", () => {
  const cases = [
    [request({ principal: { employmentStatus: "terminated" } }), "PRINCIPAL_STATUS_NOT_ACTIVE"],
    [request({ principal: { separationOfDutiesConflict: true } }), "SEPARATION_OF_DUTIES_CONFLICT"],
    [request({ session: { assurance: "degraded" } }), "SESSION_ASSURANCE_DEGRADED"],
    [request({ session: { deviceTrust: "blocked" } }), "DEVICE_BLOCKED"],
    [request({ session: { networkTrust: "untrusted" } }), "NETWORK_UNTRUSTED"],
    [request({ session: { anomalyClass: "critical" } }), "CRITICAL_SESSION_ANOMALY"],
    [request({ session: { sessionAgeMinutes: 31 } }), "SESSION_MAX_AGE_EXCEEDED"],
    [request({ controls: { phishingResistantMfaSatisfied: false } }), "PHISHING_RESISTANT_MFA_REQUIRED"],
    [request({ controls: { freshReauthenticationSatisfied: false } }), "FRESH_REAUTHENTICATION_REQUIRED"],
    [request({ controls: { ticketBound: false } }), "TICKET_BINDING_REQUIRED"],
    [request({ controls: { justInTimeGrant: false } }), "JUST_IN_TIME_GRANT_REQUIRED"],
    [
      request({ controls: { dualApprovalRequired: true, dualApprovalSatisfied: false } }),
      "DUAL_APPROVAL_INCOMPLETE"
    ],
    [request({ action: { riskClass: "high" } }), "DUAL_APPROVAL_POLICY_MISSING"],
    [request({ action: { scopeClass: "broad-write" } }), "BROAD_WRITE_DUAL_APPROVAL_MISSING"],
    [request({ principal: { privilegeTier: "break-glass" } }), "BREAK_GLASS_DECLARATION_REQUIRED"],
    [request({ controls: { breakGlassDeclared: true } }), "BREAK_GLASS_REVIEW_REQUIRED"],
    [request({ action: { changeWindow: "outside" } }), "CHANGE_WINDOW_NOT_APPROVED"],
    [request({ action: { scopeClass: "unknown" } }), "ACTION_SCOPE_UNKNOWN"]
  ];
  for (const [snapshot, reason] of cases) {
    const decision = evaluatePrivilegedAccessRequest(snapshot);
    assert.equal(decision.recommendation, "BLOCK_AND_ESCALATE");
    assert.equal(decision.reasonCodes.includes(reason), true);
    assert.equal(decision.accessGrantAuthorized, false);
  }
});

test("uncertain, elevated, changed, or emergency classifications require human review", () => {
  const cases = [
    request({ principal: { recentRoleChange: true } }),
    request({ principal: { privilegeTier: "elevated" } }),
    request({ session: { assurance: "standard" } }),
    request({ session: { deviceTrust: "new" } }),
    request({ session: { networkTrust: "approved-remote" } }),
    request({ session: { anomalyClass: "elevated" } }),
    request({ action: { riskClass: "medium" } }),
    request({ action: { scopeClass: "bounded-write" } }),
    request({ action: { changeWindow: "emergency" } })
  ];
  for (const snapshot of cases) {
    assert.equal(
      evaluatePrivilegedAccessRequest(snapshot).recommendation,
      "REQUIRE_HUMAN_PRIVILEGE_REVIEW"
    );
  }
});

test("high-risk and break-glass metadata can only reach human review with all controls", () => {
  const decision = evaluatePrivilegedAccessRequest(
    request({
      principal: { privilegeTier: "break-glass" },
      action: { riskClass: "critical", changeWindow: "emergency", scopeClass: "bounded-write" },
      controls: {
        dualApprovalRequired: true,
        dualApprovalSatisfied: true,
        breakGlassDeclared: true,
        postActionReviewRequired: true
      }
    })
  );
  assert.equal(decision.recommendation, "REQUIRE_HUMAN_PRIVILEGE_REVIEW");
  assert.equal(decision.accessGrantAuthorized, false);
  assert.equal(decision.privilegedActionAuthorized, false);
});

test("session limits and raw identity, token, command, or credential fields are rejected", () => {
  assert.throws(
    () => validatePrivilegedAccessRequest(request({ controls: { grantExpiresMinutes: 31, maxSessionAgeMinutes: 30 } })),
    (error) => error.code === "PRIVILEGED_ACCESS_CONTROL_REJECTED"
  );
  for (const prohibited of [
    { username: "value" },
    { email: "value" },
    { accessToken: "value" },
    { commandPayload: "value" },
    { credential: "value" },
    { walletAddress: "value" }
  ]) {
    assert.throws(
      () => validatePrivilegedAccessRequest(request(prohibited)),
      (error) => error.code === "PRIVILEGED_ACCESS_PROHIBITED_FIELD"
    );
  }
});

test("privileged-access decisions are deterministic and omit request classifications", () => {
  const first = evaluatePrivilegedAccessRequest(request());
  const second = evaluatePrivilegedAccessRequest(request());
  assert.deepEqual(first, second);
  assert.equal("principal" in first, false);
  assert.equal("session" in first, false);
  assert.equal("action" in first, false);
  assert.equal("controls" in first, false);
});
