import assert from "node:assert/strict";
import test from "node:test";
import {
  API_SESSION_SCHEMA,
  evaluateApiSessionRequest,
  validateApiSessionRequest
} from "../src/api-session-security.mjs";

function request(overrides = {}) {
  const base = {
    schema: API_SESSION_SCHEMA,
    requestId: "apireq_0123456789abcdef0123456789abcdef",
    observedAt: "2026-08-07T00:00:00.000Z",
    environment: "production-observation",
    client: {
      clientClass: "first-party-service",
      registrationStatus: "approved",
      authMaterialAgeClass: "current",
      scopeClass: "read-only",
      ownerStatus: "active"
    },
    session: {
      assurance: "mutual-tls",
      deviceTrust: "attested",
      networkTrust: "private",
      ageMinutes: 5,
      anomalyClass: "none"
    },
    request: {
      operationClass: "read",
      riskClass: "low",
      replayStatus: "fresh",
      originStatus: "allowlisted",
      rateClass: "normal"
    },
    controls: {
      clientRegistrationVerified: true,
      leastPrivilegeVerified: true,
      mutualTlsRequired: true,
      mutualTlsSatisfied: true,
      requestSignatureRequired: false,
      requestSignatureVerified: false,
      nonceVerified: true,
      timestampWindowVerified: true,
      rateLimitApplied: true,
      schemaValidated: true,
      idempotencyVerified: true,
      sessionRevocationChecked: true,
      maxSessionAgeMinutes: 30,
      dualApprovalRequired: false,
      dualApprovalSatisfied: false
    },
    evidenceDigest: "a".repeat(64)
  };
  return {
    ...base,
    ...overrides,
    client: { ...base.client, ...(overrides.client ?? {}) },
    session: { ...base.session, ...(overrides.session ?? {}) },
    request: { ...base.request, ...(overrides.request ?? {}) },
    controls: { ...base.controls, ...(overrides.controls ?? {}) }
  };
}

test("low-risk API metadata proceeds only to a separate authorization system", () => {
  const decision = evaluateApiSessionRequest(request());
  assert.equal(decision.recommendation, "PROCEED_TO_SEPARATE_API_AUTHORIZATION");
  assert.deepEqual(decision.reasonCodes, []);
  assert.equal(decision.humanAuthorizationRequired, true);
  for (const field of [
    "requestExecutionAuthorized",
    "accessGrantAuthorized",
    "sessionStartAuthorized",
    "tradingAuthorized",
    "withdrawalAuthorized",
    "balanceMutationAuthorized",
    "signingAuthorized",
    "assetMovementAuthorized"
  ]) assert.equal(decision[field], false);
});

test("every material API/session failure blocks and escalates", () => {
  const cases = [
    [request({ client: { registrationStatus: "revoked" } }), "CLIENT_REGISTRATION_UNVERIFIED"],
    [request({ client: { ownerStatus: "suspended" } }), "CLIENT_OWNER_NOT_ACTIVE"],
    [request({ client: { authMaterialAgeClass: "expired" } }), "AUTH_MATERIAL_NOT_CURRENT"],
    [request({ client: { scopeClass: "unknown" } }), "CLIENT_SCOPE_UNKNOWN"],
    [request({ request: { operationClass: "order-submit" } }), "WRITE_SCOPE_INSUFFICIENT"],
    [request({ controls: { leastPrivilegeVerified: false } }), "LEAST_PRIVILEGE_UNVERIFIED"],
    [request({ session: { assurance: "degraded" } }), "SESSION_ASSURANCE_INSUFFICIENT"],
    [request({ session: { deviceTrust: "blocked" } }), "DEVICE_TRUST_INSUFFICIENT"],
    [request({ session: { networkTrust: "untrusted" } }), "NETWORK_TRUST_INSUFFICIENT"],
    [request({ session: { anomalyClass: "critical" } }), "SESSION_ANOMALY_UNRESOLVED"],
    [request({ session: { ageMinutes: 31 } }), "SESSION_MAX_AGE_EXCEEDED"],
    [request({ request: { replayStatus: "replayed" } }), "REPLAY_PROTECTION_INCOMPLETE"],
    [request({ request: { originStatus: "blocked" } }), "REQUEST_ORIGIN_UNTRUSTED"],
    [request({ request: { rateClass: "limit-exceeded" } }), "RATE_POLICY_VIOLATION"],
    [request({ controls: { rateLimitApplied: false } }), "RATE_LIMIT_NOT_APPLIED"],
    [request({ controls: { schemaValidated: false } }), "REQUEST_SCHEMA_UNVALIDATED"],
    [request({ controls: { idempotencyVerified: false } }), "IDEMPOTENCY_UNVERIFIED"],
    [request({ controls: { sessionRevocationChecked: false } }), "SESSION_REVOCATION_UNCHECKED"],
    [request({ controls: { mutualTlsSatisfied: false } }), "MUTUAL_TLS_INCOMPLETE"],
    [request({ client: { clientClass: "partner-service" }, controls: { mutualTlsRequired: false } }), "MUTUAL_TLS_POLICY_MISSING"],
    [request({ client: { scopeClass: "bounded-write" }, request: { operationClass: "order-submit" } }), "REQUEST_SIGNATURE_POLICY_MISSING"],
    [request({ controls: { requestSignatureRequired: true } }), "REQUEST_SIGNATURE_UNVERIFIED"],
    [request({ controls: { dualApprovalRequired: true } }), "DUAL_APPROVAL_INCOMPLETE"],
    [request({ request: { riskClass: "high" } }), "DUAL_APPROVAL_POLICY_MISSING"]
  ];
  for (const [snapshot, reason] of cases) {
    const decision = evaluateApiSessionRequest(snapshot);
    assert.equal(decision.recommendation, "BLOCK_AND_ESCALATE");
    assert.equal(decision.reasonCodes.includes(reason), true);
    assert.equal(decision.requestExecutionAuthorized, false);
  }
});

test("elevated but controlled classifications require human API risk review", () => {
  const signedWriteControls = {
    requestSignatureRequired: true,
    requestSignatureVerified: true,
    dualApprovalRequired: true,
    dualApprovalSatisfied: true
  };
  const cases = [
    request({ client: { authMaterialAgeClass: "rotation-due" } }),
    request({ client: { clientClass: "user-device" } }),
    request({ session: { assurance: "standard" } }),
    request({ session: { deviceTrust: "new" } }),
    request({ session: { networkTrust: "approved-public" } }),
    request({ session: { anomalyClass: "elevated" } }),
    request({ request: { originStatus: "new" } }),
    request({ request: { rateClass: "elevated" } }),
    request({ request: { riskClass: "medium" } }),
    request({ client: { scopeClass: "bounded-write" } }),
    request({
      client: { scopeClass: "bounded-write" },
      request: { operationClass: "order-submit" },
      controls: signedWriteControls
    })
  ];
  for (const snapshot of cases) {
    assert.equal(evaluateApiSessionRequest(snapshot).recommendation, "REQUIRE_HUMAN_API_RISK_REVIEW");
  }
});

test("controlled privileged API requests still grant no execution or trading authority", () => {
  const decision = evaluateApiSessionRequest(
    request({
      client: { scopeClass: "privileged" },
      request: { operationClass: "admin-config", riskClass: "critical" },
      controls: {
        requestSignatureRequired: true,
        requestSignatureVerified: true,
        dualApprovalRequired: true,
        dualApprovalSatisfied: true
      }
    })
  );
  assert.equal(decision.recommendation, "REQUIRE_HUMAN_API_RISK_REVIEW");
  assert.equal(decision.requestExecutionAuthorized, false);
  assert.equal(decision.tradingAuthorized, false);
  assert.equal(decision.balanceMutationAuthorized, false);
});

test("raw secrets, tokens, keys, payloads, identities, addresses, and transactions are rejected", () => {
  for (const prohibited of [
    { apiKey: "value" },
    { accessToken: "value" },
    { credential: "value" },
    { rawPayload: "value" },
    { userId: "value" },
    { walletAddress: "value" },
    { transaction: "value" },
    { signatureValue: "value" }
  ]) {
    assert.throws(
      () => validateApiSessionRequest(request(prohibited)),
      (error) => error.code === "API_SESSION_PROHIBITED_FIELD"
    );
  }
});

test("API/session decisions are deterministic and omit request classifications", () => {
  const first = evaluateApiSessionRequest(request());
  const second = evaluateApiSessionRequest(request());
  assert.deepEqual(first, second);
  assert.equal("client" in first, false);
  assert.equal("session" in first, false);
  assert.equal("request" in first, false);
  assert.equal("controls" in first, false);
});
