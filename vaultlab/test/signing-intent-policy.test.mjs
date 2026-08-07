import assert from "node:assert/strict";
import test from "node:test";
import {
  evaluateSigningIntent,
  SIGNING_INTENT_SCHEMA,
  validateSigningIntent
} from "../src/signing-intent-policy.mjs";

function request(overrides = {}) {
  const base = {
    schema: SIGNING_INTENT_SCHEMA,
    requestId: "req_0123456789abcdef0123456789abcdef",
    observedAt: "2026-08-07T00:00:00.000Z",
    environment: "production-observation",
    network: { family: "evm", chainReference: "eip155:1" },
    intent: {
      operation: "transfer",
      assetClass: "native",
      amountClass: "bounded",
      destinationTrust: "allowlisted",
      decoded: true,
      simulation: "match",
      unlimitedApproval: false,
      valueDirection: "debit",
      riskScore: 10
    },
    policy: {
      requireDecoded: true,
      requireSimulation: true,
      maxRiskScore: 60,
      allowUnlimitedApproval: false,
      allowNewDestination: false
    },
    evidenceDigest: "a".repeat(64)
  };
  return {
    ...base,
    ...overrides,
    network: { ...base.network, ...(overrides.network ?? {}) },
    intent: { ...base.intent, ...(overrides.intent ?? {}) },
    policy: { ...base.policy, ...(overrides.policy ?? {}) }
  };
}

test("low-risk intents proceed only to human confirmation", () => {
  const decision = evaluateSigningIntent(request());
  assert.equal(decision.recommendation, "PROCEED_TO_HUMAN_CONFIRMATION");
  assert.deepEqual(decision.reasonCodes, []);
  assert.equal(decision.humanConfirmationRequired, true);
  assert.equal(decision.executionAuthorized, false);
  assert.equal(decision.signingAuthorized, false);
  assert.equal(decision.assetMovementAuthorized, false);
});

test("each material risk condition blocks the signing path", () => {
  const cases = [
    [{ intent: { destinationTrust: "blocked" } }, "BLOCKED_DESTINATION"],
    [{ intent: { riskScore: 61 } }, "RISK_SCORE_EXCEEDED"],
    [{ intent: { decoded: false } }, "INTENT_NOT_DECODED"],
    [{ intent: { simulation: "mismatch" } }, "SIMULATION_MISMATCH"],
    [{ intent: { simulation: "unavailable" } }, "SIMULATION_REQUIRED"],
    [{ intent: { unlimitedApproval: true } }, "UNLIMITED_APPROVAL"],
    [{ intent: { destinationTrust: "new" } }, "NEW_DESTINATION"]
  ];
  for (const [change, reason] of cases) {
    const decision = evaluateSigningIntent(request(change));
    assert.equal(decision.recommendation, "BLOCK");
    assert.equal(decision.reasonCodes.includes(reason), true);
    assert.equal(decision.signingAuthorized, false);
  }
});

test("unknown asset or high-near-limit risk requires human review", () => {
  assert.equal(
    evaluateSigningIntent(request({ intent: { assetClass: "unknown" } })).recommendation,
    "REQUIRE_HUMAN_REVIEW"
  );
  assert.equal(
    evaluateSigningIntent(request({ intent: { riskScore: 48 } })).recommendation,
    "REQUIRE_HUMAN_REVIEW"
  );
});

test("raw transactions, addresses, signatures, and credentials are rejected", () => {
  for (const prohibited of [
    { rawTransaction: "0x00" },
    { recipientAddress: "0x00" },
    { signature: "value" },
    { credential: "value" }
  ]) {
    assert.throws(
      () => validateSigningIntent(request(prohibited)),
      (error) => error.code === "SIGNING_INTENT_PROHIBITED_FIELD"
    );
  }
});

test("decisions are deterministic and contain no intent details", () => {
  const first = evaluateSigningIntent(request());
  const second = evaluateSigningIntent(request());
  assert.deepEqual(first, second);
  assert.equal("intent" in first, false);
  assert.equal("network" in first, false);
});
