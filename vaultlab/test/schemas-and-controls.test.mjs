import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const schemaFiles = [
  "api-session-security.schema.json",
  "assurance-report.schema.json",
  "audit-integrity-readiness.schema.json",
  "availability-chaos-readiness.schema.json",
  "break-glass-governance.schema.json",
  "custody-readiness.schema.json",
  "cryptography-review-readiness.schema.json",
  "client-integrity-readiness.schema.json",
  "evidence-envelope.schema.json",
  "external-assessment-readiness.schema.json",
  "incident-governance.schema.json",
  "ledger-integrity.schema.json",
  "market-data-integrity-readiness.schema.json",
  "platform-policy-assurance.schema.json",
  "privacy-data-minimization-readiness.schema.json",
  "privileged-access.schema.json",
  "recovery-governance.schema.json",
  "resilience-readiness.schema.json",
  "release-provenance.schema.json",
  "security-event.schema.json",
  "security-disclosure-readiness.schema.json",
  "security-exception-governance.schema.json",
  "secret-leakage-assurance.schema.json",
  "signing-intent.schema.json",
  "signer-ceremony-governance.schema.json",
  "synthetic-artifact.schema.json",
  "third-party-risk-readiness.schema.json",
  "vulnerability-remediation-readiness.schema.json",
  "withdrawal-risk.schema.json"
];

test("machine-readable schemas parse and prohibit unknown root fields", async () => {
  const ids = new Set();
  function assertHardenedObjects(value) {
    if (value === null || typeof value !== "object") return;
    if (value.type === "object") {
      assert.equal(value.additionalProperties, false);
      assert.equal(Array.isArray(value.required), true);
      assert.equal(value.required.every((field) => field in value.properties), true);
    }
    for (const child of Object.values(value)) assertHardenedObjects(child);
  }
  for (const file of schemaFiles) {
    const schema = JSON.parse(
      await readFile(new URL(`../schemas/${file}`, import.meta.url), "utf8")
    );
    assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
    assert.equal(schema.type, "object");
    assert.equal(schema.additionalProperties, false);
    assert.equal(Array.isArray(schema.required), true);
    assert.equal(ids.has(schema.$id), false);
    ids.add(schema.$id);
    assertHardenedObjects(schema);
  }
});

test("control catalog identifiers are unique and every control blocks release", async () => {
  const catalog = JSON.parse(
    await readFile(new URL("../controls/vaultlab-controls.json", import.meta.url), "utf8")
  );
  const ids = catalog.controls.map((control) => control.id);
  assert.equal(catalog.catalogId, "ENTELE-VAULTLAB-10");
  assert.equal(catalog.controls.length, 58);
  assert.equal(new Set(ids).size, ids.length);
  assert.equal(catalog.controls.every((control) => control.releaseImpact === "blocking"), true);
  assert.deepEqual(catalog.baselineMappings, [
    "NIST-SSDF",
    "OWASP-ASVS",
    "OWASP-MASVS",
    "CCSS"
  ]);
});
