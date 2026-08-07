import assert from "node:assert/strict";
import test from "node:test";
import {
  BREAK_GLASS_CASE_SCHEMA,
  BREAK_GLASS_CONTROL_FIELDS,
  evaluateBreakGlassCase,
  validateBreakGlassCase,
  validateBreakGlassTransition
} from "../src/break-glass-governance.mjs";

function approval(role, marker, approvedAt = "2026-08-08T00:00:00.000Z") {
  return {
    role,
    approverId: `approver_${marker.repeat(16)}`,
    approvedAt,
    attestationDigest: marker.repeat(64)
  };
}

const quorum = [approval("security", "1"), approval("operations", "2"), approval("custody", "3")];

function controls(enabled = []) {
  return {
    ...Object.fromEntries(BREAK_GLASS_CONTROL_FIELDS.map((control) => [control, enabled.includes(control)])),
    timeLimitMinutes: 30
  };
}

const preRequest = ["normalAccessUnavailable", "emergencyJustificationReviewed"];
const preAccess = [
  ...preRequest,
  "phishingResistantMfaVerified",
  "hardwareBoundIdentityVerified",
  "sessionRecordingPlanned",
  "realTimeMonitoringPlanned",
  "automaticRevocationPlanned",
  "postEventReviewPlanned"
];

function breakGlassCase(overrides = {}) {
  const base = {
    schema: BREAK_GLASS_CASE_SCHEMA,
    caseId: "bgcase_0123456789abcdef0123456789abcdef",
    phase: "quorum-approved",
    openedAt: "2026-08-07T00:00:00.000Z",
    lastTransitionAt: "2026-08-08T00:00:00.000Z",
    environment: "production-observation",
    scope: { systemClass: "vault", riskClass: "critical", accessClass: "bounded-admin" },
    authority: {
      incidentLinked: true,
      legalBasisReviewed: true,
      ownerVerified: true,
      leastPrivilegeReviewed: true
    },
    controls: controls(preAccess),
    approvals: quorum,
    findings: { criticalOpen: 0, highOpen: 0, mediumOpen: 0 },
    evidenceDigest: "a".repeat(64)
  };
  return {
    ...base,
    ...overrides,
    scope: { ...base.scope, ...(overrides.scope ?? {}) },
    authority: { ...base.authority, ...(overrides.authority ?? {}) },
    controls: { ...base.controls, ...(overrides.controls ?? {}) },
    findings: { ...base.findings, ...(overrides.findings ?? {}) }
  };
}

function requestedCase(overrides = {}) {
  return breakGlassCase({
    phase: "requested",
    lastTransitionAt: "2026-08-07T00:00:00.000Z",
    authority: {
      incidentLinked: false,
      legalBasisReviewed: false,
      ownerVerified: false,
      leastPrivilegeReviewed: false
    },
    controls: controls([]),
    approvals: [],
    ...overrides
  });
}

test("a break-glass request is evidence only and grants no access or session authority", () => {
  const decision = evaluateBreakGlassCase(requestedCase());
  assert.equal(decision.recommendation, "ACTIVE_GOVERNANCE_REQUIRED");
  assert.equal(decision.reasonCodes.includes("AUTHORITY_VERIFICATION_REQUIRED"), true);
  assert.equal(decision.humanAuthorizationRequired, true);
  assert.equal(decision.accessGrantAuthorized, false);
  assert.equal(decision.sessionStartAuthorized, false);
  assert.equal(decision.revocationExecutionAuthorized, false);
  assert.equal(decision.deploymentAuthorized, false);
  assert.equal(decision.signingAuthorized, false);
  assert.equal(decision.assetMovementAuthorized, false);
});

test("quorum-approved and active-window records still do not grant access", () => {
  const approved = evaluateBreakGlassCase(breakGlassCase());
  const active = evaluateBreakGlassCase(
    breakGlassCase({ phase: "active-window", lastTransitionAt: "2026-08-08T01:00:00.000Z" })
  );
  assert.equal(approved.reasonCodes.includes("SEPARATE_ACCESS_AUTHORIZATION_REQUIRED"), true);
  assert.equal(active.reasonCodes.includes("REVOCATION_EVIDENCE_REQUIRED"), true);
  for (const decision of [approved, active]) {
    assert.equal(decision.recommendation, "ACTIVE_GOVERNANCE_REQUIRED");
    assert.equal(decision.accessGrantAuthorized, false);
    assert.equal(decision.sessionStartAuthorized, false);
  }
});

test("future-phase evidence and premature approvals are rejected", () => {
  assert.throws(
    () => validateBreakGlassCase(requestedCase({ controls: { revocationVerified: true } })),
    (error) => error.code === "BREAK_GLASS_CONTROL_REJECTED"
  );
  assert.throws(
    () => validateBreakGlassCase(requestedCase({ authority: { incidentLinked: true } })),
    (error) => error.code === "BREAK_GLASS_AUTHORITY_REJECTED"
  );
  assert.throws(
    () => validateBreakGlassCase(requestedCase({ approvals: [approval("security", "1")] })),
    (error) => error.code === "BREAK_GLASS_APPROVAL_REJECTED"
  );
  assert.throws(
    () =>
      validateBreakGlassCase(
        breakGlassCase({ approvals: [...quorum, approval("independent-review", "4")] })
      ),
    (error) => error.code === "BREAK_GLASS_APPROVAL_REJECTED"
  );
});

test("each forward transition requires completed governance evidence", () => {
  const requested = requestedCase();
  const authorityVerified = breakGlassCase({
    phase: "authority-verified",
    lastTransitionAt: "2026-08-07T01:00:00.000Z",
    controls: controls(preRequest),
    approvals: []
  });
  assert.equal(validateBreakGlassTransition(requested, authorityVerified).accepted, true);
  assert.equal(validateBreakGlassTransition(authorityVerified, breakGlassCase()).accepted, true);

  const incomplete = breakGlassCase({
    controls: { phishingResistantMfaVerified: false }
  });
  assert.throws(
    () => validateBreakGlassTransition(authorityVerified, incomplete),
    (error) => error.code === "BREAK_GLASS_TRANSITION_CONTROL_REJECTED"
  );
});

test("fast-forward, same-time, weaker risk, changed limits, and removed approvals are rejected", () => {
  const requested = requestedCase();
  assert.throws(
    () =>
      validateBreakGlassTransition(
        requested,
        breakGlassCase({ phase: "quorum-approved", lastTransitionAt: "2026-08-08T00:00:00.000Z" })
      ),
    (error) => error.code === "BREAK_GLASS_TRANSITION_REJECTED"
  );
  const active = breakGlassCase({ phase: "active-window", lastTransitionAt: "2026-08-08T01:00:00.000Z" });
  const invalid = [
    breakGlassCase({
      phase: "revoked",
      lastTransitionAt: "2026-08-08T01:00:00.000Z",
      controls: { ...controls([...preAccess, "revocationVerified"]) }
    }),
    breakGlassCase({
      phase: "revoked",
      lastTransitionAt: "2026-08-08T02:00:00.000Z",
      scope: { riskClass: "high" },
      controls: controls([...preAccess, "revocationVerified"])
    }),
    breakGlassCase({
      phase: "revoked",
      lastTransitionAt: "2026-08-08T02:00:00.000Z",
      controls: { ...controls([...preAccess, "revocationVerified"]), timeLimitMinutes: 15 }
    }),
    breakGlassCase({
      phase: "revoked",
      lastTransitionAt: "2026-08-08T02:00:00.000Z",
      controls: controls([...preAccess, "revocationVerified"]),
      approvals: quorum.slice(1)
    })
  ];
  const expected = [
    "BREAK_GLASS_TRANSITION_TIME_REJECTED",
    "BREAK_GLASS_TRANSITION_CONTROL_REJECTED",
    "BREAK_GLASS_TRANSITION_CONTROL_REJECTED",
    "BREAK_GLASS_TRANSITION_CONTROL_REJECTED"
  ];
  for (let index = 0; index < invalid.length; index += 1) {
    assert.throws(
      () => validateBreakGlassTransition(active, invalid[index]),
      (error) => error.code === expected[index]
    );
  }
});

test("review and closure require sealed evidence, independent approval, and zero findings", () => {
  const reviewed = breakGlassCase({
    phase: "reviewed",
    lastTransitionAt: "2026-08-09T00:00:00.000Z",
    controls: controls(BREAK_GLASS_CONTROL_FIELDS),
    approvals: [...quorum, approval("independent-review", "4", "2026-08-09T00:00:00.000Z")]
  });
  const ready = evaluateBreakGlassCase(reviewed);
  assert.equal(ready.recommendation, "READY_FOR_SEPARATE_CLOSURE_REVIEW");
  const closed = breakGlassCase({ ...reviewed, phase: "closed", lastTransitionAt: "2026-08-09T01:00:00.000Z" });
  assert.equal(validateBreakGlassTransition(reviewed, closed).accepted, true);
  assert.equal(evaluateBreakGlassCase(closed).recommendation, "CLOSED");

  const invalid = evaluateBreakGlassCase(
    breakGlassCase({ ...closed, findings: { highOpen: 1 } })
  );
  assert.equal(invalid.recommendation, "INVALID_CLOSURE_RECORD");
  assert.equal(invalid.reasonCodes.includes("HIGH_FINDINGS_OPEN"), true);
});

test("commands, credentials, tokens, targets, raw payloads, keys, and wallet files are rejected", () => {
  for (const prohibited of [
    { command: "value" },
    { credential: "value" },
    { accessToken: "value" },
    { target: "value" },
    { rawPayload: "value" },
    { privateKey: "value" },
    { walletFile: "value" }
  ]) {
    assert.throws(
      () => validateBreakGlassCase(breakGlassCase(prohibited)),
      (error) => error.code === "BREAK_GLASS_PROHIBITED_FIELD"
    );
  }
});
