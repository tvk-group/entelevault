import assert from "node:assert/strict";
import test from "node:test";
import {
  evaluateQuantumMigrationReadiness,
  QUANTUM_MIGRATION_SCHEMA,
  REQUIRED_QUANTUM_MIGRATION_CONTROLS,
  validateQuantumMigrationReadiness
} from "../src/quantum-migration-readiness.mjs";

function controls(enabled = REQUIRED_QUANTUM_MIGRATION_CONTROLS) {
  return Object.fromEntries(
    REQUIRED_QUANTUM_MIGRATION_CONTROLS.map((control) => [control, enabled.includes(control)])
  );
}

function assessment(overrides = {}) {
  const base = {
    schema: QUANTUM_MIGRATION_SCHEMA,
    assessmentId: "quantum_0123456789abcdef0123456789abcdef",
    assessedAt: "2026-08-11T00:00:00.000Z",
    environment: "staging",
    systemClass: "wallet-client",
    architectureRevision: "a".repeat(40),
    inventoryDigest: "b".repeat(64),
    migrationPlanDigest: "c".repeat(64),
    controls: controls(),
    findings: {
      criticalOpen: 0,
      highOpen: 0,
      inventoryGaps: 0,
      unreviewedDependencies: 0,
      interoperabilityFailures: 0
    },
    evidenceDigest: "d".repeat(64)
  };
  return {
    ...base,
    ...overrides,
    controls: { ...base.controls, ...(overrides.controls ?? {}) },
    findings: { ...base.findings, ...(overrides.findings ?? {}) }
  };
}

test("complete migration governance is eligible only for independent review", () => {
  const decision = evaluateQuantumMigrationReadiness(assessment());
  assert.equal(decision.readiness, "ELIGIBLE_FOR_INDEPENDENT_QUANTUM_MIGRATION_REVIEW");
  assert.equal(decision.quantumSafetyClaimed, false);
  for (const field of [
    "algorithmMigrationAuthorized",
    "cryptographicOperationAuthorized",
    "custodyActivationAuthorized",
    "deploymentAuthorized",
    "signingAuthorized",
    "assetMovementAuthorized"
  ]) assert.equal(decision[field], false);
});

test("all 16,384 migration-control combinations permit only the fully satisfied set", () => {
  let eligible = 0;
  const total = 1 << REQUIRED_QUANTUM_MIGRATION_CONTROLS.length;
  for (let mask = 0; mask < total; mask += 1) {
    const enabled = REQUIRED_QUANTUM_MIGRATION_CONTROLS.filter((_, index) => Boolean(mask & (1 << index)));
    const decision = evaluateQuantumMigrationReadiness(assessment({ controls: controls(enabled) }));
    if (decision.readiness === "ELIGIBLE_FOR_INDEPENDENT_QUANTUM_MIGRATION_REVIEW") eligible += 1;
    assert.equal(decision.quantumSafetyClaimed, false);
    assert.equal(decision.algorithmMigrationAuthorized, false);
  }
  assert.equal(eligible, 1);
});

test("findings and migration gaps fail closed", () => {
  const cases = [
    ["criticalOpen", "CRITICAL_QUANTUM_MIGRATION_FINDINGS_OPEN"],
    ["highOpen", "HIGH_QUANTUM_MIGRATION_FINDINGS_OPEN"],
    ["inventoryGaps", "QUANTUM_MIGRATION_INVENTORY_GAPS"],
    ["unreviewedDependencies", "QUANTUM_MIGRATION_DEPENDENCIES_UNREVIEWED"],
    ["interoperabilityFailures", "QUANTUM_MIGRATION_INTEROPERABILITY_FAILURES"]
  ];
  for (const [field, reason] of cases) {
    const decision = evaluateQuantumMigrationReadiness(assessment({ findings: { [field]: 1 } }));
    assert.equal(decision.readiness, "NOT_READY");
    assert.equal(decision.reasonCodes.includes(reason), true);
  }
});

test("unsupported environments and system classes fail closed", () => {
  assert.throws(
    () => validateQuantumMigrationReadiness(assessment({ environment: "production" })),
    (error) => error.code === "QUANTUM_MIGRATION_ENVIRONMENT_REJECTED"
  );
  assert.throws(
    () => validateQuantumMigrationReadiness(assessment({ systemClass: "unknown" })),
    (error) => error.code === "QUANTUM_MIGRATION_SYSTEM_REJECTED"
  );
});

test("operational and secret-like fields are rejected", () => {
  for (const prohibited of [
    { privateKey: "value" },
    { ciphertext: "value" },
    { credential: "value" },
    { target: "value" },
    { transaction: "value" }
  ]) {
    assert.throws(
      () => validateQuantumMigrationReadiness(assessment(prohibited)),
      (error) => error.code === "QUANTUM_MIGRATION_PROHIBITED_FIELD"
    );
  }
});

test("migration decisions are deterministic and omit architecture and control details", () => {
  const first = evaluateQuantumMigrationReadiness(assessment());
  assert.deepEqual(first, evaluateQuantumMigrationReadiness(assessment()));
  for (const field of [
    "systemClass",
    "architectureRevision",
    "inventoryDigest",
    "migrationPlanDigest",
    "controls",
    "findings"
  ]) assert.equal(field in first, false);
});
