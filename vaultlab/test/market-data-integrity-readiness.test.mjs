import assert from "node:assert/strict";
import test from "node:test";
import {
  evaluateMarketDataIntegrity,
  MARKET_DATA_INTEGRITY_SCHEMA,
  REQUIRED_MARKET_DATA_CONTROLS,
  validateMarketDataAssessment
} from "../src/market-data-integrity-readiness.mjs";

function controls(enabled = REQUIRED_MARKET_DATA_CONTROLS) {
  return Object.fromEntries(REQUIRED_MARKET_DATA_CONTROLS.map((control) => [control, enabled.includes(control)]));
}
function assessment(overrides = {}) {
  const base = {
    schema: MARKET_DATA_INTEGRITY_SCHEMA,
    assessmentId: "market_0123456789abcdef0123456789abcdef",
    assessedAt: "2026-08-08T00:00:00.000Z",
    environment: "staging",
    marketClass: "spot",
    feedClass: "consolidated",
    policyRevision: "a".repeat(40),
    observationDigest: "b".repeat(64),
    quorumDigest: "c".repeat(64),
    controls: controls(),
    findings: { criticalOpen: 0, highOpen: 0, staleObservations: 0, divergentObservations: 0, sequenceGaps: 0 },
    evidenceDigest: "d".repeat(64)
  };
  return { ...base, ...overrides, controls: { ...base.controls, ...(overrides.controls ?? {}) }, findings: { ...base.findings, ...(overrides.findings ?? {}) } };
}

test("complete market-data evidence is only eligible for independent review", () => {
  const decision = evaluateMarketDataIntegrity(assessment());
  assert.equal(decision.readiness, "ELIGIBLE_FOR_INDEPENDENT_MARKET_DATA_REVIEW");
  assert.equal(decision.reasonCodes.length, 0);
  for (const field of ["pricePublicationAuthorized", "tradingAuthorized", "orderExecutionAuthorized", "riskLimitMutationAuthorized", "financialClaimAuthorized", "deploymentAuthorized", "signingAuthorized", "assetMovementAuthorized"]) assert.equal(decision[field], false);
});

test("all 16,384 market-data control combinations permit only the fully satisfied set", () => {
  const total = 1 << REQUIRED_MARKET_DATA_CONTROLS.length;
  let eligible = 0;
  for (let mask = 0; mask < total; mask += 1) {
    const enabled = REQUIRED_MARKET_DATA_CONTROLS.filter((_, index) => Boolean(mask & (1 << index)));
    const decision = evaluateMarketDataIntegrity(assessment({ controls: controls(enabled) }));
    if (decision.readiness === "ELIGIBLE_FOR_INDEPENDENT_MARKET_DATA_REVIEW") eligible += 1;
    assert.equal(decision.tradingAuthorized, false);
  }
  assert.equal(eligible, 1);
});

test("open, stale, divergent, and sequence findings fail closed", () => {
  const cases = [["criticalOpen", "CRITICAL_FINDINGS_OPEN"], ["highOpen", "HIGH_FINDINGS_OPEN"], ["staleObservations", "STALE_OBSERVATIONS_DETECTED"], ["divergentObservations", "DIVERGENT_OBSERVATIONS_DETECTED"], ["sequenceGaps", "SEQUENCE_GAPS_DETECTED"]];
  for (const [field, reason] of cases) {
    const decision = evaluateMarketDataIntegrity(assessment({ findings: { [field]: 1 } }));
    assert.equal(decision.readiness, "NOT_READY");
    assert.equal(decision.reasonCodes.includes(reason), true);
  }
});

test("raw feeds, prices, symbols, credentials, orders, trades, and transactions are rejected", () => {
  for (const prohibited of [{ rawFeed: "value" }, { feedContent: "value" }, { priceValue: "value" }, { symbolValue: "value" }, { credential: "value" }, { order: "value" }, { trade: "value" }, { transaction: "value" }]) {
    assert.throws(() => validateMarketDataAssessment(assessment(prohibited)), (error) => error.code === "MARKET_DATA_PROHIBITED_FIELD");
  }
});

test("market-data assessments require exact controls, digests, and bounded counts", () => {
  const incomplete = assessment();
  delete incomplete.controls.crossSourceQuorumVerified;
  assert.throws(() => validateMarketDataAssessment(incomplete), (error) => error.code === "MARKET_DATA_UNKNOWN_FIELD");
  assert.throws(() => validateMarketDataAssessment(assessment({ quorumDigest: "short" })), (error) => error.code === "MARKET_DATA_DIGEST_REJECTED");
});

test("market-data decisions are deterministic and omit market, feed, controls, and findings", () => {
  const first = evaluateMarketDataIntegrity(assessment());
  assert.deepEqual(first, evaluateMarketDataIntegrity(assessment()));
  for (const field of ["marketClass", "feedClass", "controls", "findings"]) assert.equal(field in first, false);
});
