#!/usr/bin/env node
import { readFile } from "node:fs/promises";

const path = process.argv[2];
if (!path) {
  console.error("Usage: node ./bin/validate-report.mjs <vaultlab-report.json>");
  process.exitCode = 2;
} else {
  const raw = await readFile(path, "utf8");
  if (Buffer.byteLength(raw, "utf8") > 256 * 1024) {
    throw new Error("Assurance report exceeds the size policy");
  }

  const report = JSON.parse(raw);
  const allowedRootFields = new Set([
    "schema",
    "controlSet",
    "generatedAt",
    "scope",
    "fixtureId",
    "result",
    "summary",
    "durationMs",
    "checks"
  ]);
  const prohibitedKey = /(?:private.?key|mnemonic|seed.?phrase|password.?list|candidates?|credential|target|address)/iu;
  const addressLike = /\b0x[0-9a-f]{40}\b/iu;
  const mnemonicLike = /\b(?:[a-z]{3,12}\s+){11,23}[a-z]{3,12}\b/iu;

  for (const key of Object.keys(report)) {
    if (!allowedRootFields.has(key)) throw new Error("Assurance report has an unknown root field");
  }

  function inspect(value, depth = 0) {
    if (depth > 6) throw new Error("Assurance report nesting limit exceeded");
    if (Array.isArray(value)) {
      if (value.length > 64) throw new Error("Assurance report array limit exceeded");
      value.forEach((entry) => inspect(entry, depth + 1));
      return;
    }
    if (value && typeof value === "object") {
      for (const [key, entry] of Object.entries(value)) {
        if (prohibitedKey.test(key)) throw new Error("Assurance report contains a prohibited field");
        inspect(entry, depth + 1);
      }
      return;
    }
    if (typeof value === "string" && (addressLike.test(value) || mnemonicLike.test(value))) {
      throw new Error("Assurance report contains prohibited wallet-shaped material");
    }
  }

  inspect(report);
  if (
    report.schema !== "entelevault.vaultlab.assurance-report.v1" ||
    report.scope !== "synthetic-only" ||
    report.result !== "PASS" ||
    report.summary?.failed !== 0 ||
    !Array.isArray(report.checks) ||
    report.checks.length === 0
  ) {
    throw new Error("Assurance report does not satisfy the release policy");
  }

  console.log(`VaultLab report policy PASS (${report.summary.passed}/${report.summary.total})`);
}
