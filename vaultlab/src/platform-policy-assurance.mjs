import {
  evaluateSigningIntent,
  SIGNING_INTENT_SCHEMA,
  validateSigningIntent
} from "./signing-intent-policy.mjs";
import {
  evaluateRecoveryCase,
  RECOVERY_CASE_SCHEMA,
  validateRecoveryTransition
} from "./recovery-governance.mjs";
import {
  CUSTODY_READINESS_SCHEMA,
  evaluateCustodyReadiness,
  REQUIRED_CUSTODY_CONTROLS
} from "./native-custody-readiness.mjs";

const AUTHORITY_FIELDS = Object.freeze([
  "executionAuthorized",
  "signingAuthorized",
  "assetMovementAuthorized",
  "deploymentAuthorized",
  "custodyActivationAuthorized"
]);

function grantsAuthority(decision) {
  return AUTHORITY_FIELDS.some((field) => decision[field] === true);
}

function signingRequest(overrides = {}) {
  const base = {
    schema: SIGNING_INTENT_SCHEMA,
    requestId: "req_0123456789abcdef0123456789abcdef",
    observedAt: "2026-08-07T00:00:00.000Z",
    environment: "ci",
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

function approval(role, marker) {
  return {
    role,
    approverId: `approver_${marker.repeat(16)}`,
    approvedAt: "2026-08-09T00:00:00.000Z",
    attestationDigest: marker.repeat(64)
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
    approvals: [approval("legal", "1"), approval("security", "2"), approval("custody", "3")],
    waitingPeriod: { requiredHours: 48, elapsedHours: 48, emergencyOverride: false },
    notifications: {
      requesterNotified: true,
      securityNotified: true,
      custodyNotified: true
    },
    findings: { criticalOpen: 0, highOpen: 0 },
    evidenceDigest: "b".repeat(64)
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

function custodyAssessment(controls) {
  return {
    schema: CUSTODY_READINESS_SCHEMA,
    assessmentId: "assess_0123456789abcdef0123456789abcdef",
    assessedAt: "2026-08-07T00:00:00.000Z",
    sourceRevision: "c".repeat(40),
    environment: "staging",
    architecture: {
      custodyModel: "non-custodial-device-bound",
      keyGeneration: "platform-hardware",
      exportPolicy: "prohibited",
      recoveryModel: "quorum-governed"
    },
    controls,
    findings: { criticalOpen: 0, highOpen: 0 },
    evidenceDigest: "d".repeat(64)
  };
}

function result(id, evaluatedCases, passed) {
  return { id, status: passed ? "PASS" : "FAIL", evaluatedCases };
}

function assureSigningPolicy() {
  const decisions = [
    evaluateSigningIntent(signingRequest()),
    evaluateSigningIntent(signingRequest({ intent: { destinationTrust: "blocked" } })),
    evaluateSigningIntent(signingRequest({ intent: { simulation: "mismatch" } })),
    evaluateSigningIntent(signingRequest({ intent: { unlimitedApproval: true } }))
  ];
  let prohibitedRejected = false;
  try {
    validateSigningIntent(signingRequest({ rawTransaction: "synthetic-prohibited-value" }));
  } catch (error) {
    prohibitedRejected = error?.code === "SIGNING_INTENT_PROHIBITED_FIELD";
  }
  const passed =
    decisions[0].recommendation === "PROCEED_TO_HUMAN_CONFIRMATION" &&
    decisions.slice(1).every((decision) => decision.recommendation === "BLOCK") &&
    decisions.every((decision) => !grantsAuthority(decision)) &&
    prohibitedRejected;
  return result("VL-PLATFORM-SIGNING", decisions.length + 1, passed);
}

function assureRecoveryGovernance() {
  const ready = evaluateRecoveryCase(recoveryCase());
  const blocked = evaluateRecoveryCase(recoveryCase({ findings: { highOpen: 1 } }));
  const prepared = recoveryCase({ phase: "migration-prepared" });
  const completed = recoveryCase({
    phase: "completed",
    lastTransitionAt: "2026-08-09T01:00:00.000Z",
    waitingPeriod: { elapsedHours: 49 }
  });
  const transition = validateRecoveryTransition(prepared, completed);
  let tamperRejected = false;
  try {
    validateRecoveryTransition(
      recoveryCase(),
      recoveryCase({ phase: "migration-prepared", waitingPeriod: { requiredHours: 24 } })
    );
  } catch (error) {
    tamperRejected = error?.code === "RECOVERY_TRANSITION_CONTROL_REJECTED";
  }
  const passed =
    ready.recommendation === "READY_FOR_SEPARATE_CUSTODY_REVIEW" &&
    blocked.recommendation === "BLOCK" &&
    transition.accepted &&
    !grantsAuthority(ready) &&
    !grantsAuthority(blocked) &&
    !grantsAuthority(transition) &&
    tamperRejected;
  return result("VL-PLATFORM-RECOVERY", 4, passed);
}

function assureCustodyReadiness() {
  const total = 1 << REQUIRED_CUSTODY_CONTROLS.length;
  const allEnabled = total - 1;
  let eligible = 0;
  let authorityGranted = false;
  for (let mask = 0; mask < total; mask += 1) {
    const controls = Object.fromEntries(
      REQUIRED_CUSTODY_CONTROLS.map((control, index) => [control, Boolean(mask & (1 << index))])
    );
    const decision = evaluateCustodyReadiness(custodyAssessment(controls));
    if (decision.readiness === "ELIGIBLE_FOR_INDEPENDENT_ACTIVATION_REVIEW") eligible += 1;
    if (grantsAuthority(decision)) authorityGranted = true;
    if ((mask === allEnabled) !== (decision.readiness === "ELIGIBLE_FOR_INDEPENDENT_ACTIVATION_REVIEW")) {
      return result("VL-PLATFORM-CUSTODY", total, false);
    }
  }
  return result("VL-PLATFORM-CUSTODY", total, eligible === 1 && !authorityGranted);
}

export function runPlatformPolicyAssurance({ generatedAt = new Date().toISOString() } = {}) {
  if (typeof generatedAt !== "string" || Number.isNaN(Date.parse(generatedAt))) {
    throw new TypeError("generatedAt must be an ISO-compatible date-time");
  }
  const checks = [assureSigningPolicy(), assureRecoveryGovernance(), assureCustodyReadiness()];
  const passed = checks.filter((check) => check.status === "PASS").length;
  return {
    schema: "enteleclos.platform-policy-assurance.v1",
    generatedAt,
    scope: "sanitized-metadata-only",
    result: passed === checks.length ? "PASS" : "FAIL",
    authorityGranted: false,
    summary: { passed, failed: checks.length - passed, total: checks.length },
    checks
  };
}
