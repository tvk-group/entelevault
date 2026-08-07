import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const schemaFiles = [
  "assurance-report.schema.json",
  "custody-readiness.schema.json",
  "evidence-envelope.schema.json",
  "platform-policy-assurance.schema.json",
  "recovery-governance.schema.json",
  "security-event.schema.json",
  "signing-intent.schema.json",
  "synthetic-artifact.schema.json"
];

test("machine-readable schemas parse and prohibit unknown root fields", async () => {
  for (const file of schemaFiles) {
    const schema = JSON.parse(
      await readFile(new URL(`../schemas/${file}`, import.meta.url), "utf8")
    );
    assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
    assert.equal(schema.type, "object");
    assert.equal(schema.additionalProperties, false);
    assert.equal(Array.isArray(schema.required), true);
  }
});

test("control catalog identifiers are unique and every control blocks release", async () => {
  const catalog = JSON.parse(
    await readFile(new URL("../controls/vaultlab-controls.json", import.meta.url), "utf8")
  );
  const ids = catalog.controls.map((control) => control.id);
  assert.equal(catalog.catalogId, "ENTELE-VAULTLAB-3");
  assert.equal(catalog.controls.length, 16);
  assert.equal(new Set(ids).size, ids.length);
  assert.equal(catalog.controls.every((control) => control.releaseImpact === "blocking"), true);
  assert.deepEqual(catalog.baselineMappings, [
    "NIST-SSDF",
    "OWASP-ASVS",
    "OWASP-MASVS",
    "CCSS"
  ]);
});
