import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { verifyProductionBoundary } from "../src/production-boundary.mjs";

async function withRepositoryFixture(operation) {
  const root = await mkdtemp(join(tmpdir(), "entelevault-boundary-"));
  try {
    await mkdir(join(root, "src"));
    await mkdir(join(root, "vaultlab"));
    await writeFile(join(root, "src", "app.mjs"), "export const ready = true;\n", "utf8");
    await writeFile(
      join(root, "vaultlab", "fixture.mjs"),
      "export const marker = 'SYNTHETIC-NONVALUE';\n",
      "utf8"
    );
    await operation(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test("test-only VaultLab files are excluded from production scanning", async () => {
  await withRepositoryFixture(async (root) => {
    const report = await verifyProductionBoundary(root);
    assert.equal(report.status, "PASS");
    assert.equal(report.scannedFiles, 1);
    assert.deepEqual(report.violations, []);
  });
});

test("production references to VaultLab fail the boundary", async () => {
  await withRepositoryFixture(async (root) => {
    await writeFile(
      join(root, "src", "app.mjs"),
      "import { runAssuranceSuite } from '@enteleclos/vaultlab';\n",
      "utf8"
    );
    const report = await verifyProductionBoundary(root);
    assert.equal(report.status, "FAIL");
    assert.deepEqual(report.violations, [{ path: "src/app.mjs", rule: "VL-PROD-IMPORT" }]);
  });
});

test("production fixture and credential markers fail without leaking content", async () => {
  await withRepositoryFixture(async (root) => {
    await writeFile(
      join(root, "src", "config.json"),
      JSON.stringify({ mode: "SYNTHETIC-NONVALUE", token: "VaultLab-Forbidden-Test-Value" }),
      "utf8"
    );
    const report = await verifyProductionBoundary(root);
    assert.equal(report.status, "FAIL");
    assert.equal(report.violations.length, 2);
    assert.equal(JSON.stringify(report).includes("Forbidden-Test-Value"), false);
  });
});
