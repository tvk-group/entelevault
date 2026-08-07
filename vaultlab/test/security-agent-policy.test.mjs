import assert from "node:assert/strict";
import test from "node:test";
import {
  evaluateSecurityEvent,
  SECURITY_EVENT_SCHEMA,
  SUPPORTED_EVENT_TYPES,
  validateSecurityEvent
} from "../src/security-agent-policy.mjs";

function event(overrides = {}) {
  return {
    schema: SECURITY_EVENT_SCHEMA,
    eventId: "evt_0123456789abcdef0123456789abcdef",
    occurredAt: "2026-08-07T00:00:00.000Z",
    type: "signing.intent-mismatch",
    severity: "critical",
    resource: {
      kind: "signing-request",
      id: "res_0123456789abcdef",
      environment: "production-observation"
    },
    evidenceDigest: "a".repeat(64),
    signals: [
      { code: "SIMULATION_MISMATCH", value: true },
      { code: "RISK_SCORE", value: 98 }
    ],
    ...overrides
  };
}

test("all supported event classes produce recommendation-only decisions", () => {
  for (const type of SUPPORTED_EVENT_TYPES) {
    const decision = evaluateSecurityEvent(event({ type }));
    assert.equal(decision.recommendation, "BLOCK_AND_ESCALATE");
    assert.equal(decision.humanAuthorizationRequired, true);
    assert.equal(decision.executionAuthorized, false);
    assert.equal(decision.signingAuthorized, false);
    assert.equal(decision.assetMovementAuthorized, false);
  }
});

test("severity changes recommendation but never grants execution authority", () => {
  const expected = {
    low: "REVIEW",
    medium: "REQUIRE_HUMAN_REVIEW",
    high: "QUARANTINE_AND_REVIEW",
    critical: "BLOCK_AND_ESCALATE"
  };
  for (const [severity, recommendation] of Object.entries(expected)) {
    const decision = evaluateSecurityEvent(event({ severity }));
    assert.equal(decision.recommendation, recommendation);
    assert.equal(decision.executionAuthorized, false);
  }
});

test("commands, transactions, target data, credentials, and string signals are rejected", () => {
  for (const prohibited of [
    { command: "run" },
    { transaction: "0x00" },
    { target: "person" },
    { credential: "secret" }
  ]) {
    assert.throws(
      () => validateSecurityEvent(event(prohibited)),
      (error) => error.code === "SECURITY_EVENT_PROHIBITED_FIELD"
    );
  }
  assert.throws(
    () => validateSecurityEvent(event({ signals: [{ code: "RAW_CONTEXT", value: "free text" }] })),
    (error) => error.code === "SECURITY_EVENT_SIGNAL_REJECTED"
  );
});

test("decisions are deterministic and expose no raw signal values", () => {
  const first = evaluateSecurityEvent(event());
  const second = evaluateSecurityEvent(event());
  assert.deepEqual(first, second);
  assert.equal("signals" in first, false);
  assert.equal(JSON.stringify(first).includes("RISK_SCORE"), false);
});
