import assert from "node:assert/strict";
import test from "node:test";
import {
  evaluateIncidentCase,
  INCIDENT_CASE_SCHEMA,
  INCIDENT_CONTROL_FIELDS,
  validateIncidentCase,
  validateIncidentTransition
} from "../src/incident-governance.mjs";

function approval(role, marker) {
  return {
    role,
    approverId: `approver_${marker.repeat(16)}`,
    approvedAt: "2026-08-08T00:00:00.000Z",
    attestationDigest: marker.repeat(64)
  };
}

function incidentCase(overrides = {}) {
  const base = {
    schema: INCIDENT_CASE_SCHEMA,
    incidentId: "inc_0123456789abcdef0123456789abcdef",
    phase: "recovery-reviewed",
    openedAt: "2026-08-07T00:00:00.000Z",
    lastTransitionAt: "2026-08-08T00:00:00.000Z",
    environment: "production-observation",
    classification: {
      severity: "high",
      domain: "exchange",
      customerImpact: "suspected",
      assetImpact: "none"
    },
    controls: Object.fromEntries(INCIDENT_CONTROL_FIELDS.map((control) => [control, true])),
    approvals: [
      approval("security", "1"),
      approval("operations", "2"),
      approval("independent-review", "3")
    ],
    findings: { criticalOpen: 0, highOpen: 0, mediumOpen: 0 },
    evidenceDigest: "a".repeat(64)
  };
  return {
    ...base,
    ...overrides,
    classification: { ...base.classification, ...(overrides.classification ?? {}) },
    controls: { ...base.controls, ...(overrides.controls ?? {}) },
    findings: { ...base.findings, ...(overrides.findings ?? {}) }
  };
}

function detectedCase(overrides = {}) {
  const emptyControls = Object.fromEntries(
    INCIDENT_CONTROL_FIELDS.map((control) => [control, false])
  );
  return incidentCase({
    phase: "detected",
    lastTransitionAt: "2026-08-07T00:00:00.000Z",
    ...overrides,
    controls: { ...emptyControls, ...(overrides.controls ?? {}) },
    approvals: overrides.approvals ?? []
  });
}

test("a detected incident requires response but grants no operational authority", () => {
  const decision = evaluateIncidentCase(detectedCase());
  assert.equal(decision.recommendation, "ACTIVE_RESPONSE_REQUIRED");
  assert.equal(decision.reasonCodes.includes("TRIAGE_REQUIRED"), true);
  assert.equal(decision.humanAuthorizationRequired, true);
  assert.equal(decision.containmentAuthorized, false);
  assert.equal(decision.accessRevocationAuthorized, false);
  assert.equal(decision.deploymentAuthorized, false);
  assert.equal(decision.signingAuthorized, false);
  assert.equal(decision.assetMovementAuthorized, false);
});

test("recovery-reviewed incidents require all controls, independent quorum, and zero findings", () => {
  assert.equal(
    evaluateIncidentCase(incidentCase()).recommendation,
    "READY_FOR_SEPARATE_CLOSURE_REVIEW"
  );
  const cases = [
    [incidentCase({ controls: { reconciliationVerified: false } }), "RECONCILIATION_UNVERIFIED"],
    [incidentCase({ approvals: incidentCase().approvals.slice(0, 2) }), "CLOSURE_QUORUM_INCOMPLETE"],
    [incidentCase({ findings: { criticalOpen: 1 } }), "CRITICAL_FINDINGS_OPEN"],
    [incidentCase({ findings: { highOpen: 1 } }), "HIGH_FINDINGS_OPEN"],
    [incidentCase({ findings: { mediumOpen: 1 } }), "MEDIUM_FINDINGS_OPEN"]
  ];
  for (const [snapshot, reason] of cases) {
    const decision = evaluateIncidentCase(snapshot);
    assert.equal(decision.recommendation, "ACTIVE_RESPONSE_REQUIRED");
    assert.equal(decision.reasonCodes.includes(reason), true);
  }
});

test("fast-forward, same-time, and backward transitions are rejected", () => {
  const detected = detectedCase();
  assert.throws(
    () =>
      validateIncidentTransition(
        detected,
        detectedCase({
          phase: "contained",
          lastTransitionAt: "2026-08-07T02:00:00.000Z",
          controls: {
            incidentCommanderAssigned: true,
            evidencePreserved: true,
            securityNotified: true,
            legalNotified: true,
            custodyNotified: true,
            containmentVerified: true
          }
        })
      ),
    (error) => error.code === "INCIDENT_TRANSITION_REJECTED"
  );
  const triaged = detectedCase({
    phase: "triaged",
    lastTransitionAt: "2026-08-07T00:00:00.000Z",
    controls: {
      incidentCommanderAssigned: true,
      evidencePreserved: true,
      securityNotified: true,
      legalNotified: true,
      custodyNotified: true
    }
  });
  assert.throws(
    () => validateIncidentTransition(detected, triaged),
    (error) => error.code === "INCIDENT_TRANSITION_TIME_REJECTED"
  );
});

test("future-phase controls and closure approvals cannot be pre-recorded", () => {
  assert.throws(
    () => validateIncidentCase(detectedCase({ controls: { containmentVerified: true } })),
    (error) => error.code === "INCIDENT_CONTROL_REJECTED"
  );
  assert.throws(
    () => validateIncidentCase(detectedCase({ approvals: [approval("security", "1")] })),
    (error) => error.code === "INCIDENT_APPROVAL_REJECTED"
  );
});

test("triage transition requires evidence, commander, and notifications", () => {
  const detected = detectedCase();
  const triageControls = {
    incidentCommanderAssigned: true,
    evidencePreserved: true,
    securityNotified: true,
    legalNotified: true,
    custodyNotified: true
  };
  const triaged = detectedCase({
    phase: "triaged",
    lastTransitionAt: "2026-08-07T01:00:00.000Z",
    controls: triageControls
  });
  const accepted = validateIncidentTransition(detected, triaged);
  assert.equal(accepted.accepted, true);
  assert.equal(accepted.containmentAuthorized, false);
  assert.equal(accepted.accessRevocationAuthorized, false);

  assert.throws(
    () =>
      validateIncidentTransition(
        detected,
        detectedCase({
          phase: "triaged",
          lastTransitionAt: "2026-08-07T01:00:00.000Z",
          controls: { ...triageControls, evidencePreserved: false }
        })
      ),
    (error) => error.code === "INCIDENT_TRANSITION_CONTROL_REJECTED"
  );
});

test("severity, completed controls, and prior approvals cannot be weakened", () => {
  const current = incidentCase();
  const changes = [
    incidentCase({
      phase: "closed",
      lastTransitionAt: "2026-08-08T01:00:00.000Z",
      classification: { severity: "medium" }
    }),
    incidentCase({
      phase: "closed",
      lastTransitionAt: "2026-08-08T01:00:00.000Z",
      controls: { evidencePreserved: false }
    }),
    incidentCase({
      phase: "closed",
      lastTransitionAt: "2026-08-08T01:00:00.000Z",
      approvals: current.approvals.slice(1)
    })
  ];
  for (const next of changes) {
    assert.throws(
      () => validateIncidentTransition(current, next),
      (error) => error.code === "INCIDENT_TRANSITION_CONTROL_REJECTED"
    );
  }
});

test("valid closure records still grant no containment, revocation, or execution authority", () => {
  const current = incidentCase();
  const closed = incidentCase({
    phase: "closed",
    lastTransitionAt: "2026-08-08T01:00:00.000Z"
  });
  const transition = validateIncidentTransition(current, closed);
  assert.equal(transition.accepted, true);
  assert.equal(transition.containmentAuthorized, false);
  assert.equal(transition.accessRevocationAuthorized, false);
  assert.equal(transition.deploymentAuthorized, false);
  assert.equal(transition.signingAuthorized, false);
  assert.equal(transition.assetMovementAuthorized, false);
  assert.equal(evaluateIncidentCase(closed).recommendation, "CLOSED");
});

test("closed records with incomplete evidence fail closed", () => {
  const decision = evaluateIncidentCase(
    incidentCase({ phase: "closed", controls: { independentClosureApproved: false } })
  );
  assert.equal(decision.recommendation, "INVALID_CLOSURE_RECORD");
  assert.equal(decision.reasonCodes.includes("INDEPENDENT_CLOSURE_UNAPPROVED"), true);
});

test("incident inputs reject commands, credentials, payloads, targets, and wallet data", () => {
  for (const prohibited of [
    { responseCommand: "value" },
    { credential: "value" },
    { rawPayload: "value" },
    { target: "value" },
    { walletAddress: "value" }
  ]) {
    assert.throws(
      () => validateIncidentCase(incidentCase(prohibited)),
      (error) => error.code === "INCIDENT_CASE_PROHIBITED_FIELD"
    );
  }
});
