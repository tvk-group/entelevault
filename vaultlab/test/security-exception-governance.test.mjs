import assert from "node:assert/strict";
import test from "node:test";
import {
  evaluateSecurityException,
  SECURITY_EXCEPTION_CONTROL_FIELDS,
  SECURITY_EXCEPTION_SCHEMA,
  validateSecurityExceptionCase,
  validateSecurityExceptionTransition
} from "../src/security-exception-governance.mjs";

function approval(role, marker, approvedAt = "2026-08-08T00:00:00.000Z") {
  return {
    role,
    approverId: `approver_${marker.repeat(16)}`,
    approvedAt,
    attestationDigest: marker.repeat(64)
  };
}

const quorum = [approval("security", "1"), approval("risk", "2"), approval("control-owner", "3")];
const triageControls = [
  "scopeBound",
  "ownerAssigned",
  "customerImpactAssessed",
  "regulatoryImpactAssessed"
];
const riskControls = [
  ...triageControls,
  "remediationPlanApproved",
  "compensatingControlsVerified",
  "monitoringPlanVerified",
  "expiryEnforced",
  "rollbackPlanVerified"
];

function controls(enabled = []) {
  return {
    ...Object.fromEntries(SECURITY_EXCEPTION_CONTROL_FIELDS.map((control) => [control, enabled.includes(control)])),
    maxDurationHours: 720
  };
}

function exceptionCase(overrides = {}) {
  const base = {
    schema: SECURITY_EXCEPTION_SCHEMA,
    exceptionId: "exception_0123456789abcdef0123456789abcdef",
    phase: "risk-review-approved",
    requestedAt: "2026-08-07T00:00:00.000Z",
    lastTransitionAt: "2026-08-08T00:00:00.000Z",
    expiresAt: "2026-09-06T00:00:00.000Z",
    environment: "staging",
    scope: {
      component: "entelevault-service",
      controlFamily: "monitoring",
      riskClass: "moderate",
      exceptionClass: "temporary-operational"
    },
    controls: controls(riskControls),
    approvals: quorum,
    findings: { criticalOpen: 0, highOpen: 0, mediumOpen: 0 },
    evidenceDigest: "a".repeat(64)
  };
  return {
    ...base,
    ...overrides,
    scope: { ...base.scope, ...(overrides.scope ?? {}) },
    controls: { ...base.controls, ...(overrides.controls ?? {}) },
    findings: { ...base.findings, ...(overrides.findings ?? {}) }
  };
}

function requestedCase(overrides = {}) {
  return exceptionCase({
    phase: "requested",
    lastTransitionAt: "2026-08-07T00:00:00.000Z",
    controls: controls([]),
    approvals: [],
    ...overrides
  });
}

test("a security-exception request is evidence only and grants no policy bypass", () => {
  const decision = evaluateSecurityException(requestedCase());
  assert.equal(decision.recommendation, "ACTIVE_EXCEPTION_GOVERNANCE_REQUIRED");
  assert.equal(decision.reasonCodes.includes("TRIAGE_REQUIRED"), true);
  assert.equal(decision.humanAuthorizationRequired, true);
  assert.equal(decision.exceptionGrantAuthorized, false);
  assert.equal(decision.policyBypassAuthorized, false);
  assert.equal(decision.accessGrantAuthorized, false);
  assert.equal(decision.remediationExecutionAuthorized, false);
  assert.equal(decision.deploymentAuthorized, false);
  assert.equal(decision.signingAuthorized, false);
  assert.equal(decision.assetMovementAuthorized, false);
});

test("future controls and premature approvals are rejected", () => {
  assert.throws(
    () => validateSecurityExceptionCase(requestedCase({ controls: { remediationVerified: true } })),
    (error) => error.code === "SECURITY_EXCEPTION_CONTROL_REJECTED"
  );
  assert.throws(
    () => validateSecurityExceptionCase(requestedCase({ approvals: [approval("security", "1")] })),
    (error) => error.code === "SECURITY_EXCEPTION_APPROVAL_REJECTED"
  );
  assert.throws(
    () => validateSecurityExceptionCase(exceptionCase({ approvals: [...quorum, approval("independent-review", "4")] })),
    (error) => error.code === "SECURITY_EXCEPTION_APPROVAL_REJECTED"
  );
});

test("the complete forward-only exception lifecycle validates without granting authority", () => {
  const requested = requestedCase();
  const triaged = exceptionCase({
    phase: "triaged",
    lastTransitionAt: "2026-08-07T01:00:00.000Z",
    controls: controls(triageControls),
    approvals: []
  });
  const compensated = exceptionCase({
    phase: "compensating-controls-verified",
    lastTransitionAt: "2026-08-07T02:00:00.000Z",
    controls: controls(riskControls),
    approvals: []
  });
  const reviewed = exceptionCase();
  const monitored = exceptionCase({ phase: "monitoring-active", lastTransitionAt: "2026-08-09T00:00:00.000Z" });
  const remediated = exceptionCase({
    phase: "remediated",
    lastTransitionAt: "2026-08-10T00:00:00.000Z",
    controls: controls([...riskControls, "remediationVerified"])
  });
  const closed = exceptionCase({
    phase: "independently-closed",
    lastTransitionAt: "2026-08-11T00:00:00.000Z",
    controls: controls(SECURITY_EXCEPTION_CONTROL_FIELDS),
    approvals: [...quorum, approval("independent-review", "4", "2026-08-11T00:00:00.000Z")]
  });
  const pairs = [
    [requested, triaged],
    [triaged, compensated],
    [compensated, reviewed],
    [reviewed, monitored],
    [monitored, remediated],
    [remediated, closed]
  ];
  for (const [current, next] of pairs) {
    const result = validateSecurityExceptionTransition(current, next);
    assert.equal(result.accepted, true);
    assert.equal(result.exceptionGrantAuthorized, false);
    assert.equal(result.policyBypassAuthorized, false);
  }
  assert.equal(evaluateSecurityException(reviewed).recommendation, "READY_FOR_SEPARATE_EXCEPTION_AUTHORIZATION");
  assert.equal(evaluateSecurityException(monitored).recommendation, "ACTIVE_MONITORING_REQUIRED");
  assert.equal(evaluateSecurityException(remediated).recommendation, "READY_FOR_SEPARATE_CLOSURE_REVIEW");
  assert.equal(evaluateSecurityException(closed).recommendation, "CLOSED");
});

test("fast-forward, same-time, risk downgrade, duration change, and approval removal fail closed", () => {
  assert.throws(
    () => validateSecurityExceptionTransition(requestedCase(), exceptionCase()),
    (error) => error.code === "SECURITY_EXCEPTION_TRANSITION_REJECTED"
  );
  const reviewed = exceptionCase({ scope: { riskClass: "high" } });
  const invalid = [
    exceptionCase({ phase: "monitoring-active", scope: { riskClass: "high" } }),
    exceptionCase({ phase: "monitoring-active", lastTransitionAt: "2026-08-09T00:00:00.000Z", scope: { riskClass: "moderate" } }),
    exceptionCase({ phase: "monitoring-active", lastTransitionAt: "2026-08-09T00:00:00.000Z", controls: { maxDurationHours: 700 }, scope: { riskClass: "high" } }),
    exceptionCase({ phase: "monitoring-active", lastTransitionAt: "2026-08-09T00:00:00.000Z", approvals: quorum.slice(1), scope: { riskClass: "high" } })
  ];
  const expected = [
    "SECURITY_EXCEPTION_TRANSITION_TIME_REJECTED",
    "SECURITY_EXCEPTION_TRANSITION_CONTROL_REJECTED",
    "SECURITY_EXCEPTION_DURATION_REJECTED",
    "SECURITY_EXCEPTION_TRANSITION_CONTROL_REJECTED"
  ];
  for (let index = 0; index < invalid.length; index += 1) {
    assert.throws(
      () => validateSecurityExceptionTransition(reviewed, invalid[index]),
      (error) => error.code === expected[index]
    );
  }
});

test("critical-risk exceptions, expired approvals, and open high findings cannot proceed", () => {
  const critical = evaluateSecurityException(requestedCase({ scope: { riskClass: "critical" } }));
  assert.equal(critical.reasonCodes.includes("CRITICAL_RISK_EXCEPTION_PROHIBITED"), true);
  assert.throws(
    () => validateSecurityExceptionTransition(
      requestedCase({ scope: { riskClass: "critical" } }),
      exceptionCase({
        phase: "triaged",
        lastTransitionAt: "2026-08-07T01:00:00.000Z",
        scope: { riskClass: "critical" },
        controls: controls(triageControls),
        approvals: []
      })
    ),
    (error) => error.code === "SECURITY_EXCEPTION_TRANSITION_CONTROL_REJECTED"
  );
  const expired = evaluateSecurityException(exceptionCase({ lastTransitionAt: "2026-09-06T00:00:00.000Z" }));
  assert.equal(expired.reasonCodes.includes("EXCEPTION_EXPIRED"), true);
  const findings = evaluateSecurityException(exceptionCase({ findings: { highOpen: 1 } }));
  assert.equal(findings.reasonCodes.includes("HIGH_FINDINGS_OPEN"), true);
  assert.equal(findings.recommendation, "ACTIVE_EXCEPTION_GOVERNANCE_REQUIRED");
});

test("expiry and maximum duration are immutable and capped at thirty days", () => {
  assert.throws(
    () => validateSecurityExceptionCase(requestedCase({ expiresAt: "2026-09-07T00:00:00.000Z" })),
    (error) => error.code === "SECURITY_EXCEPTION_DURATION_REJECTED"
  );
  assert.throws(
    () => validateSecurityExceptionTransition(
      exceptionCase(),
      exceptionCase({ phase: "monitoring-active", lastTransitionAt: "2026-08-09T00:00:00.000Z", expiresAt: "2026-09-05T00:00:00.000Z" })
    ),
    (error) => error.code === "SECURITY_EXCEPTION_TRANSITION_IDENTITY_REJECTED"
  );
});

test("commands, credentials, identities, payloads, keys, tokens, and wallet data are rejected", () => {
  for (const prohibited of [
    { command: "value" },
    { credential: "value" },
    { identityValue: "value" },
    { rawPayload: "value" },
    { privateKey: "value" },
    { accessToken: "value" },
    { walletData: "value" }
  ]) {
    assert.throws(
      () => validateSecurityExceptionCase(exceptionCase(prohibited)),
      (error) => error.code === "SECURITY_EXCEPTION_PROHIBITED_FIELD"
    );
  }
});

test("exception decisions are deterministic and omit scope, controls, approvals, and findings", () => {
  const first = evaluateSecurityException(exceptionCase());
  const second = evaluateSecurityException(exceptionCase());
  assert.deepEqual(first, second);
  assert.equal("scope" in first, false);
  assert.equal("controls" in first, false);
  assert.equal("approvals" in first, false);
  assert.equal("findings" in first, false);
});
