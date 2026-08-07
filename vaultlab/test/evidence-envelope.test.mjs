import assert from "node:assert/strict";
import test from "node:test";
import { createEvidenceEnvelope } from "../src/evidence-envelope.mjs";
import { runAssuranceSuite } from "../src/assurance-runner.mjs";

const REVISION = "a".repeat(40);
const RECORDED_AT = "2026-08-07T00:00:00.000Z";

test("evidence envelopes expose only publishable assurance metadata", async () => {
  const credential = "VaultLab-Evidence-Test-Credential-2026";
  const report = await runAssuranceSuite({ credential });
  const envelope = createEvidenceEnvelope(report, {
    sourceRevision: REVISION,
    runnerIdentity: "local-vaultlab",
    recordedAt: RECORDED_AT
  });
  assert.equal(envelope.result, "PASS");
  assert.equal(envelope.controlsFailed, 0);
  assert.equal(envelope.containsFixture, false);
  assert.equal(envelope.containsCredential, false);
  assert.equal(envelope.containsWalletMaterial, false);
  assert.equal(JSON.stringify(envelope).includes(credential), false);
  assert.equal(JSON.stringify(envelope).includes(report.fixtureId), false);
});

test("report digests are deterministic and bind the complete report", async () => {
  const report = await runAssuranceSuite({ credential: "VaultLab-Digest-Test-Credential-2026" });
  const options = {
    sourceRevision: REVISION,
    runnerIdentity: "local-vaultlab",
    recordedAt: RECORDED_AT
  };
  const first = createEvidenceEnvelope(report, options);
  const second = createEvidenceEnvelope(structuredClone(report), options);
  assert.equal(first.reportDigest, second.reportDigest);

  const changed = structuredClone(report);
  changed.durationMs += 0.01;
  assert.notEqual(createEvidenceEnvelope(changed, options).reportDigest, first.reportDigest);
});

test("failed reports, short revisions, and unknown runners are rejected", async () => {
  const report = await runAssuranceSuite({ credential: "VaultLab-Reject-Test-Credential-2026" });
  assert.throws(
    () => createEvidenceEnvelope({ ...report, result: "FAIL" }, {
      sourceRevision: REVISION,
      runnerIdentity: "local-vaultlab"
    }),
    (error) => error.code === "EVIDENCE_REPORT_REJECTED"
  );
  assert.throws(
    () => createEvidenceEnvelope(report, { sourceRevision: "abc", runnerIdentity: "local-vaultlab" }),
    (error) => error.code === "EVIDENCE_REVISION_REJECTED"
  );
  assert.throws(
    () => createEvidenceEnvelope(report, { sourceRevision: REVISION, runnerIdentity: "unknown" }),
    (error) => error.code === "EVIDENCE_RUNNER_REJECTED"
  );

  const inconsistent = structuredClone(report);
  inconsistent.checks[0].status = "FAIL";
  assert.throws(
    () => createEvidenceEnvelope(inconsistent, {
      sourceRevision: REVISION,
      runnerIdentity: "local-vaultlab"
    }),
    (error) => error.code === "EVIDENCE_REPORT_REJECTED"
  );
});
