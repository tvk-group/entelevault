import assert from "node:assert/strict";
import test from "node:test";
import {
  evaluateConsumerReleaseGate,
  validateConsumerReleaseManifest
} from "../src/consumer-release-gate.mjs";
import { runPlatformPolicyAssurance } from "../src/platform-policy-assurance.mjs";
import { PLATFORM_POLICY_EXPECTED_CASES } from "../src/platform-policy-report.mjs";

const PASSING_REPORT = runPlatformPolicyAssurance({ generatedAt: "2026-08-11T00:00:00.000Z" });

function manifest(overrides = {}) {
  const base = {
    schema: "enteleclos.consumer-release-manifest.v1",
    applicationId: "entelewallet",
    repository: "tvk-group/entelewallet-app",
    componentClass: "wallet-client",
    releaseEnvironment: "production-review",
    policyRevision: "e".repeat(40),
    maxReportAgeSeconds: 900,
    policy: {
      failClosed: true,
      humanAuthorizationRequired: true,
      independentReviewRequired: true,
      authorityGranted: false,
      criticalFindingsAllowed: 0,
      highFindingsAllowed: 0
    },
    custodyBoundary: {
      mode: "external-non-custodial",
      receivesSecretMaterial: false,
      signingAuthority: false,
      assetMovementAuthority: false,
      custodyActivationAuthority: false
    },
    cryptographyMigration: {
      inventoryStatus: "complete",
      longLivedDataAssessment: "required",
      migrationArchitecture: "independent-review-required",
      customCryptography: "prohibited",
      productionMigration: "separately-authorized",
      classicalControls: "required"
    },
    requiredChecks: Object.keys(PLATFORM_POLICY_EXPECTED_CASES)
  };
  return {
    ...base,
    ...overrides,
    policy: { ...base.policy, ...(overrides.policy ?? {}) },
    custodyBoundary: { ...base.custodyBoundary, ...(overrides.custodyBoundary ?? {}) },
    cryptographyMigration: { ...base.cryptographyMigration, ...(overrides.cryptographyMigration ?? {}) }
  };
}

function evaluate(manifestOverride = {}, contextOverride = {}, reportOverride = {}) {
  return evaluateConsumerReleaseGate(
    { manifest: manifest(manifestOverride), report: { ...structuredClone(PASSING_REPORT), ...reportOverride } },
    {
      repository: "tvk-group/entelewallet-app",
      sourceRevision: "a".repeat(40),
      policyRevision: "e".repeat(40),
      observedAt: "2026-08-11T00:01:00.000Z",
      ...contextOverride
    }
  );
}

test("passing evidence is revision-bound and grants no authority", () => {
  const attestation = evaluate();
  assert.equal(attestation.status, "PASS");
  assert.equal(attestation.releaseDisposition, "ELIGIBLE_FOR_HUMAN_RELEASE_REVIEW");
  assert.equal(attestation.sourceRevision, "a".repeat(40));
  assert.equal(attestation.platformChecks, 26);
  assert.equal(attestation.cryptographyMigrationStatus, "GOVERNANCE_PRESENT_NO_QUANTUM_SAFETY_CLAIM");
  for (const field of [
    "authorityGranted",
    "deploymentAuthorized",
    "custodyActivationAuthorized",
    "signingAuthorized",
    "assetMovementAuthorized"
  ]) assert.equal(attestation[field], false);
});

test("repository, source revision, and policy revision fail closed on mismatch", () => {
  assert.throws(() => evaluate({}, { repository: "tvk-group/other" }), (error) => error.code === "CONSUMER_GATE_REPOSITORY_MISMATCH");
  assert.throws(() => evaluate({}, { sourceRevision: "invalid" }), (error) => error.code === "CONSUMER_GATE_SOURCE_REVISION_REJECTED");
  assert.throws(() => evaluate({}, { policyRevision: "f".repeat(40) }), (error) => error.code === "CONSUMER_GATE_POLICY_REVISION_MISMATCH");
});

test("stale and future reports fail closed", () => {
  assert.throws(
    () => evaluate({}, { observedAt: "2026-08-11T01:00:00.000Z" }),
    (error) => error.code === "CONSUMER_GATE_REPORT_STALE"
  );
  assert.throws(
    () => evaluate({}, { observedAt: "2026-08-10T23:58:00.000Z" }),
    (error) => error.code === "CONSUMER_GATE_REPORT_STALE"
  );
});

test("missing or altered required checks fail closed", () => {
  const missing = Object.keys(PLATFORM_POLICY_EXPECTED_CASES).slice(1);
  assert.throws(
    () => validateConsumerReleaseManifest(manifest({ requiredChecks: missing })),
    (error) => error.code === "CONSUMER_GATE_CHECKS_REJECTED"
  );
  const altered = Object.keys(PLATFORM_POLICY_EXPECTED_CASES);
  altered[0] = "VL-PLATFORM-UNKNOWN";
  assert.throws(
    () => validateConsumerReleaseManifest(manifest({ requiredChecks: altered })),
    (error) => error.code === "CONSUMER_GATE_CHECKS_REJECTED"
  );
});

test("authority, findings, custody, and migration-policy weakening fail closed", () => {
  const cases = [
    manifest({ policy: { authorityGranted: true } }),
    manifest({ policy: { criticalFindingsAllowed: 1 } }),
    manifest({ custodyBoundary: { receivesSecretMaterial: true } }),
    manifest({ custodyBoundary: { signingAuthority: true } }),
    manifest({ cryptographyMigration: { customCryptography: "allowed" } }),
    manifest({ cryptographyMigration: { productionMigration: "automatic" } })
  ];
  for (const candidate of cases) assert.throws(() => validateConsumerReleaseManifest(candidate));
});

test("component-specific custody modes are enforced", () => {
  assert.throws(
    () => validateConsumerReleaseManifest(manifest({ componentClass: "exchange-frontend" })),
    (error) => error.code === "CONSUMER_GATE_CUSTODY_REJECTED"
  );
  const exchange = validateConsumerReleaseManifest(manifest({
    applicationId: "enteleexchange",
    repository: "tvk-group/enteleexchange",
    componentClass: "exchange-frontend",
    custodyBoundary: { mode: "disabled" }
  }));
  assert.equal(exchange.custodyBoundary.mode, "disabled");
});

test("attestation digests are deterministic for identical evidence", () => {
  const first = evaluate();
  const second = evaluate();
  assert.equal(first.platformReportDigest, second.platformReportDigest);
  assert.equal(first.manifestDigest, second.manifestDigest);
});
