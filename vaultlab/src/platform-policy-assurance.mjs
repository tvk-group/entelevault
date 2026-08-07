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
import {
  evaluateWithdrawalRequest,
  validateWithdrawalRequest,
  WITHDRAWAL_REQUEST_SCHEMA
} from "./withdrawal-policy.mjs";
import {
  evaluateReleaseProvenance,
  RELEASE_PROVENANCE_SCHEMA,
  REQUIRED_RELEASE_CONTROLS
} from "./release-provenance.mjs";
import {
  evaluateIncidentCase,
  INCIDENT_CASE_SCHEMA,
  INCIDENT_CONTROL_FIELDS,
  validateIncidentTransition
} from "./incident-governance.mjs";
import {
  evaluatePrivilegedAccessRequest,
  PRIVILEGED_ACCESS_SCHEMA,
  validatePrivilegedAccessRequest
} from "./privileged-access-policy.mjs";
import {
  evaluateLedgerIntegrity,
  LEDGER_INTEGRITY_SCHEMA,
  REQUIRED_LEDGER_CONTROLS
} from "./ledger-integrity-readiness.mjs";
import {
  BREAK_GLASS_CASE_SCHEMA,
  BREAK_GLASS_CONTROL_FIELDS,
  evaluateBreakGlassCase,
  validateBreakGlassTransition
} from "./break-glass-governance.mjs";
import {
  API_SESSION_SCHEMA,
  evaluateApiSessionRequest,
  validateApiSessionRequest
} from "./api-session-security.mjs";
import {
  evaluateSignerCeremony,
  SIGNER_CEREMONY_CONTROL_FIELDS,
  SIGNER_CEREMONY_SCHEMA,
  validateSignerCeremonyTransition
} from "./signer-ceremony-governance.mjs";
import {
  evaluateResilienceReadiness,
  REQUIRED_RESILIENCE_CONTROLS,
  RESILIENCE_READINESS_SCHEMA
} from "./resilience-readiness.mjs";

const AUTHORITY_FIELDS = Object.freeze([
  "executionAuthorized",
  "signingAuthorized",
  "assetMovementAuthorized",
  "deploymentAuthorized",
  "custodyActivationAuthorized",
  "withdrawalAuthorized",
  "holdExecutionAuthorized",
  "containmentAuthorized",
  "accessRevocationAuthorized",
  "accessGrantAuthorized",
  "privilegedActionAuthorized",
  "financialClaimAuthorized",
  "balanceMutationAuthorized",
  "tradingAuthorized",
  "sessionStartAuthorized",
  "revocationExecutionAuthorized",
  "requestExecutionAuthorized",
  "ceremonyExecutionAuthorized",
  "signerActivationAuthorized",
  "keyGenerationAuthorized",
  "keyExportAuthorized",
  "restorationAuthorized",
  "failoverAuthorized",
  "dataMutationAuthorized"
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

function withdrawalRequest(overrides = {}) {
  const base = {
    schema: WITHDRAWAL_REQUEST_SCHEMA,
    requestId: "wdreq_0123456789abcdef0123456789abcdef",
    observedAt: "2026-08-07T00:00:00.000Z",
    environment: "ci",
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
    evidenceDigest: "e".repeat(64)
  };
  return {
    ...base,
    ...overrides,
    subject: { ...base.subject, ...(overrides.subject ?? {}) },
    withdrawal: { ...base.withdrawal, ...(overrides.withdrawal ?? {}) },
    controls: { ...base.controls, ...(overrides.controls ?? {}) }
  };
}

function releaseAssessment(controls) {
  return {
    schema: RELEASE_PROVENANCE_SCHEMA,
    assessmentId: "release_0123456789abcdef0123456789abcdef",
    assessedAt: "2026-08-07T00:00:00.000Z",
    environment: "ci",
    component: "entelevault-service",
    sourceRevision: "f".repeat(40),
    artifactDigest: "0".repeat(64),
    builderIdentityDigest: "1".repeat(64),
    workflowDigest: "2".repeat(64),
    sbomDigest: "3".repeat(64),
    dependencyLockDigest: "4".repeat(64),
    controls,
    findings: { criticalOpen: 0, highOpen: 0, mediumOpen: 0 },
    evidenceDigest: "5".repeat(64)
  };
}

function incidentApproval(role, marker) {
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
    environment: "staging",
    classification: {
      severity: "high",
      domain: "exchange",
      customerImpact: "suspected",
      assetImpact: "none"
    },
    controls: Object.fromEntries(INCIDENT_CONTROL_FIELDS.map((control) => [control, true])),
    approvals: [
      incidentApproval("security", "6"),
      incidentApproval("operations", "7"),
      incidentApproval("independent-review", "8")
    ],
    findings: { criticalOpen: 0, highOpen: 0, mediumOpen: 0 },
    evidenceDigest: "9".repeat(64)
  };
  return {
    ...base,
    ...overrides,
    classification: { ...base.classification, ...(overrides.classification ?? {}) },
    controls: { ...base.controls, ...(overrides.controls ?? {}) },
    findings: { ...base.findings, ...(overrides.findings ?? {}) }
  };
}

function privilegedAccessRequest(overrides = {}) {
  const base = {
    schema: PRIVILEGED_ACCESS_SCHEMA,
    requestId: "pareq_0123456789abcdef0123456789abcdef",
    observedAt: "2026-08-07T00:00:00.000Z",
    environment: "ci",
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

function ledgerAssessment(controls) {
  return {
    schema: LEDGER_INTEGRITY_SCHEMA,
    assessmentId: "ledger_0123456789abcdef0123456789abcdef",
    assessedAt: "2026-08-07T00:00:00.000Z",
    environment: "staging",
    snapshot: {
      ledgerSnapshotDigest: "a".repeat(64),
      assetSnapshotDigest: "b".repeat(64),
      liabilitySnapshotDigest: "c".repeat(64),
      reconciliationDigest: "d".repeat(64),
      reserveMethodDigest: "e".repeat(64),
      sequenceClass: "current",
      coverageClass: "complete"
    },
    controls,
    findings: { criticalOpen: 0, highOpen: 0, mediumOpen: 0, unreconciledItems: 0 },
    evidenceDigest: "f".repeat(64)
  };
}

function breakGlassApproval(role, marker) {
  return {
    role,
    approverId: `approver_${marker.repeat(16)}`,
    approvedAt: "2026-08-09T00:00:00.000Z",
    attestationDigest: marker.repeat(64)
  };
}

function breakGlassCase(overrides = {}) {
  const base = {
    schema: BREAK_GLASS_CASE_SCHEMA,
    caseId: "bgcase_0123456789abcdef0123456789abcdef",
    phase: "reviewed",
    openedAt: "2026-08-07T00:00:00.000Z",
    lastTransitionAt: "2026-08-09T00:00:00.000Z",
    environment: "staging",
    scope: { systemClass: "vault", riskClass: "critical", accessClass: "bounded-admin" },
    authority: {
      incidentLinked: true,
      legalBasisReviewed: true,
      ownerVerified: true,
      leastPrivilegeReviewed: true
    },
    controls: {
      ...Object.fromEntries(BREAK_GLASS_CONTROL_FIELDS.map((control) => [control, true])),
      timeLimitMinutes: 30
    },
    approvals: [
      breakGlassApproval("security", "1"),
      breakGlassApproval("operations", "2"),
      breakGlassApproval("custody", "3"),
      breakGlassApproval("independent-review", "4")
    ],
    findings: { criticalOpen: 0, highOpen: 0, mediumOpen: 0 },
    evidenceDigest: "5".repeat(64)
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

function apiSessionRequest(overrides = {}) {
  const base = {
    schema: API_SESSION_SCHEMA,
    requestId: "apireq_0123456789abcdef0123456789abcdef",
    observedAt: "2026-08-07T00:00:00.000Z",
    environment: "ci",
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
    evidenceDigest: "6".repeat(64)
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

function signerCeremonyApproval(role, marker) {
  return {
    role,
    approverId: `approver_${marker.repeat(16)}`,
    approvedAt: "2026-08-10T00:00:00.000Z",
    attestationDigest: marker.repeat(64)
  };
}

function signerCeremony(overrides = {}) {
  const base = {
    schema: SIGNER_CEREMONY_SCHEMA,
    ceremonyId: "ceremony_0123456789abcdef0123456789abcdef",
    phase: "independently-reviewed",
    openedAt: "2026-08-07T00:00:00.000Z",
    lastTransitionAt: "2026-08-10T00:00:00.000Z",
    environment: "staging",
    architecture: {
      signerModel: "mpc-quorum",
      thresholdClass: "three-of-five",
      exportPolicy: "prohibited",
      networkClass: "isolated"
    },
    controls: Object.fromEntries(SIGNER_CEREMONY_CONTROL_FIELDS.map((control) => [control, true])),
    approvals: [
      signerCeremonyApproval("security", "1"),
      signerCeremonyApproval("custody", "2"),
      signerCeremonyApproval("operations", "3"),
      signerCeremonyApproval("independent-review", "4")
    ],
    findings: { criticalOpen: 0, highOpen: 0, mediumOpen: 0 },
    evidenceDigest: "7".repeat(64)
  };
  return {
    ...base,
    ...overrides,
    architecture: { ...base.architecture, ...(overrides.architecture ?? {}) },
    controls: { ...base.controls, ...(overrides.controls ?? {}) },
    findings: { ...base.findings, ...(overrides.findings ?? {}) }
  };
}

function resilienceAssessment(controls) {
  return {
    schema: RESILIENCE_READINESS_SCHEMA,
    assessmentId: "resilience_0123456789abcdef0123456789abcdef",
    assessedAt: "2026-08-07T00:00:00.000Z",
    environment: "staging",
    scope: {
      systemClass: "exchange",
      recoveryTier: "tier-0",
      exerciseClass: "failover-rehearsal",
      dataClass: "ledger-state"
    },
    evidence: {
      planDigest: "1".repeat(64),
      backupPolicyDigest: "2".repeat(64),
      restoreEvidenceDigest: "3".repeat(64),
      dependencyMapDigest: "4".repeat(64),
      reconciliationDigest: "5".repeat(64),
      exerciseRevision: "6".repeat(40),
      recoveryPointClass: "within-objective",
      recoveryTimeClass: "within-objective"
    },
    controls,
    findings: { criticalOpen: 0, highOpen: 0, mediumOpen: 0, unreconciledItems: 0 },
    evidenceDigest: "8".repeat(64)
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

function assureWithdrawalPolicy() {
  const decisions = [
    evaluateWithdrawalRequest(withdrawalRequest()),
    evaluateWithdrawalRequest(withdrawalRequest({ subject: { accountTakeoverSuspected: true } })),
    evaluateWithdrawalRequest(withdrawalRequest({ withdrawal: { complianceStatus: "unavailable" } })),
    evaluateWithdrawalRequest(withdrawalRequest({ withdrawal: { destinationTrust: "new" } }))
  ];
  let prohibitedRejected = false;
  try {
    validateWithdrawalRequest(withdrawalRequest({ rawTransaction: "synthetic-prohibited-value" }));
  } catch (error) {
    prohibitedRejected = error?.code === "WITHDRAWAL_PROHIBITED_FIELD";
  }
  const passed =
    decisions[0].recommendation === "PROCEED_TO_SEPARATE_AUTHORIZATION" &&
    decisions[1].recommendation === "HOLD_AND_ESCALATE" &&
    decisions[2].recommendation === "HOLD_AND_ESCALATE" &&
    decisions[3].recommendation === "REQUIRE_HUMAN_RISK_REVIEW" &&
    decisions.every((decision) => !grantsAuthority(decision)) &&
    prohibitedRejected;
  return result("VL-PLATFORM-WITHDRAWAL", decisions.length + 1, passed);
}

function assureReleaseProvenance() {
  const total = 1 << REQUIRED_RELEASE_CONTROLS.length;
  const allEnabled = total - 1;
  let eligible = 0;
  let authorityGranted = false;
  for (let mask = 0; mask < total; mask += 1) {
    const controls = Object.fromEntries(
      REQUIRED_RELEASE_CONTROLS.map((control, index) => [control, Boolean(mask & (1 << index))])
    );
    const decision = evaluateReleaseProvenance(releaseAssessment(controls));
    if (decision.readiness === "ELIGIBLE_FOR_INDEPENDENT_PROMOTION_REVIEW") eligible += 1;
    if (grantsAuthority(decision)) authorityGranted = true;
    if ((mask === allEnabled) !== (decision.readiness === "ELIGIBLE_FOR_INDEPENDENT_PROMOTION_REVIEW")) {
      return result("VL-PLATFORM-PROVENANCE", total, false);
    }
  }
  return result("VL-PLATFORM-PROVENANCE", total, eligible === 1 && !authorityGranted);
}

function assureIncidentGovernance() {
  const ready = evaluateIncidentCase(incidentCase());
  const blocked = evaluateIncidentCase(incidentCase({ findings: { mediumOpen: 1 } }));
  const closed = incidentCase({
    phase: "closed",
    lastTransitionAt: "2026-08-08T01:00:00.000Z"
  });
  const transition = validateIncidentTransition(incidentCase(), closed);
  let downgradeRejected = false;
  try {
    validateIncidentTransition(
      incidentCase(),
      incidentCase({
        phase: "closed",
        lastTransitionAt: "2026-08-08T01:00:00.000Z",
        classification: { severity: "medium" }
      })
    );
  } catch (error) {
    downgradeRejected = error?.code === "INCIDENT_TRANSITION_CONTROL_REJECTED";
  }
  const passed =
    ready.recommendation === "READY_FOR_SEPARATE_CLOSURE_REVIEW" &&
    blocked.recommendation === "ACTIVE_RESPONSE_REQUIRED" &&
    transition.accepted &&
    !grantsAuthority(ready) &&
    !grantsAuthority(blocked) &&
    !grantsAuthority(transition) &&
    downgradeRejected;
  return result("VL-PLATFORM-INCIDENT", 4, passed);
}

function assurePrivilegedAccess() {
  const decisions = [
    evaluatePrivilegedAccessRequest(privilegedAccessRequest()),
    evaluatePrivilegedAccessRequest(
      privilegedAccessRequest({ principal: { separationOfDutiesConflict: true } })
    ),
    evaluatePrivilegedAccessRequest(
      privilegedAccessRequest({ action: { riskClass: "medium" } })
    ),
    evaluatePrivilegedAccessRequest(
      privilegedAccessRequest({ session: { deviceTrust: "blocked" } })
    )
  ];
  let prohibitedRejected = false;
  try {
    validatePrivilegedAccessRequest(privilegedAccessRequest({ accessToken: "prohibited" }));
  } catch (error) {
    prohibitedRejected = error?.code === "PRIVILEGED_ACCESS_PROHIBITED_FIELD";
  }
  const passed =
    decisions[0].recommendation === "PROCEED_TO_SEPARATE_ACCESS_AUTHORIZATION" &&
    decisions[1].recommendation === "BLOCK_AND_ESCALATE" &&
    decisions[2].recommendation === "REQUIRE_HUMAN_PRIVILEGE_REVIEW" &&
    decisions[3].recommendation === "BLOCK_AND_ESCALATE" &&
    decisions.every((decision) => !grantsAuthority(decision)) &&
    prohibitedRejected;
  return result("VL-PLATFORM-PRIVILEGED", decisions.length + 1, passed);
}

function assureLedgerIntegrity() {
  const total = 1 << REQUIRED_LEDGER_CONTROLS.length;
  const allEnabled = total - 1;
  let eligible = 0;
  let authorityGranted = false;
  for (let mask = 0; mask < total; mask += 1) {
    const controls = Object.fromEntries(
      REQUIRED_LEDGER_CONTROLS.map((control, index) => [control, Boolean(mask & (1 << index))])
    );
    const decision = evaluateLedgerIntegrity(ledgerAssessment(controls));
    if (decision.readiness === "ELIGIBLE_FOR_INDEPENDENT_FINANCIAL_CONTROL_REVIEW") eligible += 1;
    if (grantsAuthority(decision)) authorityGranted = true;
    if ((mask === allEnabled) !== (decision.readiness === "ELIGIBLE_FOR_INDEPENDENT_FINANCIAL_CONTROL_REVIEW")) {
      return result("VL-PLATFORM-LEDGER", total, false);
    }
  }
  return result("VL-PLATFORM-LEDGER", total, eligible === 1 && !authorityGranted);
}

function assureBreakGlassGovernance() {
  const reviewed = evaluateBreakGlassCase(breakGlassCase());
  const blocked = evaluateBreakGlassCase(breakGlassCase({ findings: { mediumOpen: 1 } }));
  const closed = breakGlassCase({
    phase: "closed",
    lastTransitionAt: "2026-08-09T01:00:00.000Z"
  });
  const transition = validateBreakGlassTransition(breakGlassCase(), closed);
  let downgradeRejected = false;
  try {
    validateBreakGlassTransition(
      breakGlassCase(),
      breakGlassCase({
        phase: "closed",
        lastTransitionAt: "2026-08-09T01:00:00.000Z",
        scope: { riskClass: "high" }
      })
    );
  } catch (error) {
    downgradeRejected = error?.code === "BREAK_GLASS_TRANSITION_CONTROL_REJECTED";
  }
  const passed =
    reviewed.recommendation === "READY_FOR_SEPARATE_CLOSURE_REVIEW" &&
    blocked.recommendation === "ACTIVE_GOVERNANCE_REQUIRED" &&
    transition.accepted &&
    !grantsAuthority(reviewed) &&
    !grantsAuthority(blocked) &&
    !grantsAuthority(transition) &&
    downgradeRejected;
  return result("VL-PLATFORM-BREAK-GLASS", 4, passed);
}

function assureApiSessionSecurity() {
  const decisions = [
    evaluateApiSessionRequest(apiSessionRequest()),
    evaluateApiSessionRequest(apiSessionRequest({ client: { registrationStatus: "revoked" } })),
    evaluateApiSessionRequest(apiSessionRequest({ session: { anomalyClass: "elevated" } })),
    evaluateApiSessionRequest(apiSessionRequest({ request: { replayStatus: "replayed" } }))
  ];
  let prohibitedRejected = false;
  try {
    validateApiSessionRequest(apiSessionRequest({ accessToken: "prohibited" }));
  } catch (error) {
    prohibitedRejected = error?.code === "API_SESSION_PROHIBITED_FIELD";
  }
  const passed =
    decisions[0].recommendation === "PROCEED_TO_SEPARATE_API_AUTHORIZATION" &&
    decisions[1].recommendation === "BLOCK_AND_ESCALATE" &&
    decisions[2].recommendation === "REQUIRE_HUMAN_API_RISK_REVIEW" &&
    decisions[3].recommendation === "BLOCK_AND_ESCALATE" &&
    decisions.every((decision) => !grantsAuthority(decision)) &&
    prohibitedRejected;
  return result("VL-PLATFORM-API-SESSION", decisions.length + 1, passed);
}

function assureSignerCeremonyGovernance() {
  const reviewed = evaluateSignerCeremony(signerCeremony());
  const blocked = evaluateSignerCeremony(signerCeremony({ findings: { mediumOpen: 1 } }));
  const closed = signerCeremony({
    phase: "closed",
    lastTransitionAt: "2026-08-10T01:00:00.000Z"
  });
  const transition = validateSignerCeremonyTransition(signerCeremony(), closed);
  let architectureChangeRejected = false;
  try {
    validateSignerCeremonyTransition(
      signerCeremony(),
      signerCeremony({
        phase: "closed",
        lastTransitionAt: "2026-08-10T01:00:00.000Z",
        architecture: { thresholdClass: "two-of-three" }
      })
    );
  } catch (error) {
    architectureChangeRejected = error?.code === "SIGNER_CEREMONY_TRANSITION_IDENTITY_REJECTED";
  }
  const passed =
    reviewed.recommendation === "READY_FOR_SEPARATE_CEREMONY_AUTHORIZATION" &&
    blocked.recommendation === "ACTIVE_CEREMONY_GOVERNANCE_REQUIRED" &&
    transition.accepted &&
    !grantsAuthority(reviewed) &&
    !grantsAuthority(blocked) &&
    !grantsAuthority(transition) &&
    architectureChangeRejected;
  return result("VL-PLATFORM-SIGNER-CEREMONY", 4, passed);
}

function assureResilienceReadiness() {
  const total = 1 << REQUIRED_RESILIENCE_CONTROLS.length;
  const allEnabled = total - 1;
  let eligible = 0;
  let authorityGranted = false;
  for (let mask = 0; mask < total; mask += 1) {
    const controls = Object.fromEntries(
      REQUIRED_RESILIENCE_CONTROLS.map((control, index) => [control, Boolean(mask & (1 << index))])
    );
    const decision = evaluateResilienceReadiness(resilienceAssessment(controls));
    if (decision.readiness === "ELIGIBLE_FOR_INDEPENDENT_RESILIENCE_REVIEW") eligible += 1;
    if (grantsAuthority(decision)) authorityGranted = true;
    if ((mask === allEnabled) !== (decision.readiness === "ELIGIBLE_FOR_INDEPENDENT_RESILIENCE_REVIEW")) {
      return result("VL-PLATFORM-RESILIENCE", total, false);
    }
  }
  return result("VL-PLATFORM-RESILIENCE", total, eligible === 1 && !authorityGranted);
}

export function runPlatformPolicyAssurance({ generatedAt = new Date().toISOString() } = {}) {
  if (typeof generatedAt !== "string" || Number.isNaN(Date.parse(generatedAt))) {
    throw new TypeError("generatedAt must be an ISO-compatible date-time");
  }
  const checks = [
    assureSigningPolicy(),
    assureRecoveryGovernance(),
    assureCustodyReadiness(),
    assureWithdrawalPolicy(),
    assureReleaseProvenance(),
    assureIncidentGovernance(),
    assurePrivilegedAccess(),
    assureLedgerIntegrity(),
    assureBreakGlassGovernance(),
    assureApiSessionSecurity(),
    assureSignerCeremonyGovernance(),
    assureResilienceReadiness()
  ];
  const passed = checks.filter((check) => check.status === "PASS").length;
  return {
    schema: "enteleclos.platform-policy-assurance.v4",
    generatedAt,
    scope: "sanitized-metadata-only",
    result: passed === checks.length ? "PASS" : "FAIL",
    authorityGranted: false,
    summary: { passed, failed: checks.length - passed, total: checks.length },
    checks
  };
}
