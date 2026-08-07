import assert from "node:assert/strict";
import test from "node:test";
import {
  SIGNER_CEREMONY_CONTROL_FIELDS,
  SIGNER_CEREMONY_SCHEMA,
  evaluateSignerCeremony,
  validateSignerCeremony,
  validateSignerCeremonyTransition
} from "../src/signer-ceremony-governance.mjs";

function approval(role, marker, approvedAt = "2026-08-08T00:00:00.000Z") {
  return {
    role,
    approverId: `approver_${marker.repeat(16)}`,
    approvedAt,
    attestationDigest: marker.repeat(64)
  };
}

const quorum = [approval("security", "1"), approval("custody", "2"), approval("operations", "3")];

function controls(enabled) {
  return Object.fromEntries(SIGNER_CEREMONY_CONTROL_FIELDS.map((control) => [control, enabled.includes(control)]));
}

const participantControls = SIGNER_CEREMONY_CONTROL_FIELDS.slice(0, 4);
const environmentControls = SIGNER_CEREMONY_CONTROL_FIELDS.slice(0, 7);
const rehearsalControls = SIGNER_CEREMONY_CONTROL_FIELDS.slice(0, 10);
const sealedControls = SIGNER_CEREMONY_CONTROL_FIELDS.slice(0, 12);

function ceremony(overrides = {}) {
  const base = {
    schema: SIGNER_CEREMONY_SCHEMA,
    ceremonyId: "ceremony_0123456789abcdef0123456789abcdef",
    phase: "quorum-rehearsed",
    openedAt: "2026-08-07T00:00:00.000Z",
    lastTransitionAt: "2026-08-08T00:00:00.000Z",
    environment: "staging",
    architecture: {
      signerModel: "mpc-quorum",
      thresholdClass: "three-of-five",
      exportPolicy: "prohibited",
      networkClass: "isolated"
    },
    controls: controls(rehearsalControls),
    approvals: quorum,
    findings: { criticalOpen: 0, highOpen: 0, mediumOpen: 0 },
    evidenceDigest: "a".repeat(64)
  };
  return {
    ...base,
    ...overrides,
    architecture: { ...base.architecture, ...(overrides.architecture ?? {}) },
    controls: { ...base.controls, ...(overrides.controls ?? {}) },
    findings: { ...base.findings, ...(overrides.findings ?? {}) }
  };
}

function planned(overrides = {}) {
  return ceremony({
    phase: "planned",
    lastTransitionAt: "2026-08-07T00:00:00.000Z",
    controls: controls(["ceremonyPlanApproved"]),
    approvals: [],
    ...overrides
  });
}

test("a planned ceremony is evidence only and grants no signer authority", () => {
  const decision = evaluateSignerCeremony(planned());
  assert.equal(decision.recommendation, "ACTIVE_CEREMONY_GOVERNANCE_REQUIRED");
  assert.equal(decision.reasonCodes.includes("PARTICIPANT_VERIFICATION_REQUIRED"), true);
  for (const field of [
    "ceremonyExecutionAuthorized",
    "signerActivationAuthorized",
    "keyGenerationAuthorized",
    "keyExportAuthorized",
    "signingAuthorized",
    "deploymentAuthorized",
    "assetMovementAuthorized"
  ]) assert.equal(decision[field], false);
});

test("future-phase controls and premature approvals are rejected", () => {
  assert.throws(
    () => validateSignerCeremony(planned({ controls: { quorumFailureTested: true } })),
    (error) => error.code === "SIGNER_CEREMONY_CONTROL_REJECTED"
  );
  assert.throws(
    () => validateSignerCeremony(planned({ approvals: [approval("security", "1")] })),
    (error) => error.code === "SIGNER_CEREMONY_APPROVAL_REJECTED"
  );
  assert.throws(
    () => validateSignerCeremony(ceremony({ approvals: [...quorum, approval("independent-review", "4")] })),
    (error) => error.code === "SIGNER_CEREMONY_APPROVAL_REJECTED"
  );
});

test("the complete forward-only ceremony lifecycle validates", () => {
  const participant = ceremony({
    phase: "participants-verified",
    lastTransitionAt: "2026-08-07T01:00:00.000Z",
    controls: controls(participantControls),
    approvals: []
  });
  const environment = ceremony({
    phase: "environment-attested",
    lastTransitionAt: "2026-08-07T02:00:00.000Z",
    controls: controls(environmentControls),
    approvals: []
  });
  const rehearsal = ceremony();
  const sealed = ceremony({
    phase: "evidence-sealed",
    lastTransitionAt: "2026-08-08T01:00:00.000Z",
    controls: controls(sealedControls)
  });
  const reviewed = ceremony({
    phase: "independently-reviewed",
    lastTransitionAt: "2026-08-09T00:00:00.000Z",
    controls: controls(SIGNER_CEREMONY_CONTROL_FIELDS),
    approvals: [...quorum, approval("independent-review", "4", "2026-08-09T00:00:00.000Z")]
  });
  const closed = ceremony({
    ...reviewed,
    phase: "closed",
    lastTransitionAt: "2026-08-09T01:00:00.000Z"
  });
  const path = [planned(), participant, environment, rehearsal, sealed, reviewed, closed];
  for (let index = 0; index < path.length - 1; index += 1) {
    const transition = validateSignerCeremonyTransition(path[index], path[index + 1]);
    assert.equal(transition.accepted, true);
    assert.equal(transition.signerActivationAuthorized, false);
  }
  assert.equal(evaluateSignerCeremony(reviewed).recommendation, "READY_FOR_SEPARATE_CEREMONY_AUTHORIZATION");
  assert.equal(evaluateSignerCeremony(closed).recommendation, "CLOSED");
});

test("fast-forward, same-time, architecture changes, weakened controls, and removed approvals fail closed", () => {
  assert.throws(
    () => validateSignerCeremonyTransition(planned(), ceremony()),
    (error) => error.code === "SIGNER_CEREMONY_TRANSITION_REJECTED"
  );
  const current = ceremony();
  const invalid = [
    ceremony({ phase: "evidence-sealed", controls: controls(sealedControls) }),
    ceremony({
      phase: "evidence-sealed",
      lastTransitionAt: "2026-08-08T01:00:00.000Z",
      architecture: { networkClass: "restricted" },
      controls: controls(sealedControls)
    }),
    ceremony({
      phase: "evidence-sealed",
      lastTransitionAt: "2026-08-08T01:00:00.000Z",
      controls: { ...controls(sealedControls), abortProcedureTested: false }
    }),
    ceremony({
      phase: "evidence-sealed",
      lastTransitionAt: "2026-08-08T01:00:00.000Z",
      controls: controls(sealedControls),
      approvals: quorum.slice(1)
    })
  ];
  const expected = [
    "SIGNER_CEREMONY_TRANSITION_TIME_REJECTED",
    "SIGNER_CEREMONY_TRANSITION_IDENTITY_REJECTED",
    "SIGNER_CEREMONY_TRANSITION_CONTROL_REJECTED",
    "SIGNER_CEREMONY_TRANSITION_CONTROL_REJECTED"
  ];
  for (let index = 0; index < invalid.length; index += 1) {
    assert.throws(
      () => validateSignerCeremonyTransition(current, invalid[index]),
      (error) => error.code === expected[index]
    );
  }
});

test("independent review requires full controls, quorum, and zero findings", () => {
  const reviewed = ceremony({
    phase: "independently-reviewed",
    lastTransitionAt: "2026-08-09T00:00:00.000Z",
    controls: controls(SIGNER_CEREMONY_CONTROL_FIELDS),
    approvals: [...quorum, approval("independent-review", "4", "2026-08-09T00:00:00.000Z")]
  });
  assert.equal(evaluateSignerCeremony(reviewed).recommendation, "READY_FOR_SEPARATE_CEREMONY_AUTHORIZATION");
  const cases = [
    [ceremony({ ...reviewed, controls: { independentReviewApproved: false } }), "INDEPENDENT_REVIEW_UNAPPROVED"],
    [ceremony({ ...reviewed, approvals: reviewed.approvals.slice(1) }), "CEREMONY_QUORUM_INCOMPLETE"],
    [ceremony({ ...reviewed, findings: { highOpen: 1 } }), "HIGH_FINDINGS_OPEN"]
  ];
  for (const [snapshot, reason] of cases) {
    const decision = evaluateSignerCeremony(snapshot);
    assert.equal(decision.recommendation, "ACTIVE_CEREMONY_GOVERNANCE_REQUIRED");
    assert.equal(decision.reasonCodes.includes(reason), true);
  }
});

test("closed ceremonies with incomplete evidence are invalid", () => {
  const decision = evaluateSignerCeremony(
    ceremony({
      phase: "closed",
      lastTransitionAt: "2026-08-09T01:00:00.000Z",
      controls: controls(SIGNER_CEREMONY_CONTROL_FIELDS),
      approvals: [...quorum, approval("independent-review", "4", "2026-08-09T00:00:00.000Z")],
      findings: { mediumOpen: 1 }
    })
  );
  assert.equal(decision.recommendation, "INVALID_CLOSURE_RECORD");
  assert.equal(decision.reasonCodes.includes("MEDIUM_FINDINGS_OPEN"), true);
});

test("key shares, secrets, entropy, transcripts, credentials, signatures, and commands are rejected", () => {
  for (const prohibited of [
    { keyShare: "value" },
    { privateKey: "value" },
    { seed: "value" },
    { rawEntropy: "value" },
    { transcriptContent: "value" },
    { credential: "value" },
    { signatureValue: "value" },
    { command: "value" }
  ]) {
    assert.throws(
      () => validateSignerCeremony(ceremony(prohibited)),
      (error) => error.code === "SIGNER_CEREMONY_PROHIBITED_FIELD"
    );
  }
});

test("signer-ceremony decisions are deterministic and omit architecture/control detail", () => {
  const first = evaluateSignerCeremony(ceremony());
  const second = evaluateSignerCeremony(ceremony());
  assert.deepEqual(first, second);
  assert.equal("architecture" in first, false);
  assert.equal("controls" in first, false);
  assert.equal("approvals" in first, false);
});
