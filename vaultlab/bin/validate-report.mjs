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
  const summaryFields = new Set(["passed", "failed", "total"]);
  const checkFields = new Set(["id", "status", "statement", "reason", "rejectionCode"]);
  const exactFields = (value, allowed) =>
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).every((key) => allowed.has(key));
  if (
    report.schema !== "entelevault.vaultlab.assurance-report.v1" ||
    report.controlSet !== "ENTELE-VAULTLAB-1" ||
    typeof report.generatedAt !== "string" ||
    Number.isNaN(Date.parse(report.generatedAt)) ||
    report.scope !== "synthetic-only" ||
    typeof report.fixtureId !== "string" ||
    !/^vlab_[0-9a-f]{32}$/u.test(report.fixtureId) ||
    report.result !== "PASS" ||
    !exactFields(report.summary, summaryFields) ||
    !Number.isSafeInteger(report.summary?.passed) ||
    !Number.isSafeInteger(report.summary?.failed) ||
    !Number.isSafeInteger(report.summary?.total) ||
    report.summary?.failed !== 0 ||
    report.summary?.passed !== report.summary?.total ||
    !Array.isArray(report.checks) ||
    report.checks.length !== report.summary?.total ||
    report.checks.some(
      (check) =>
        !exactFields(check, checkFields) ||
        typeof check.id !== "string" ||
        !/^VL-[A-Z0-9-]+$/u.test(check.id) ||
        check.status !== "PASS"
    ) ||
    new Set(report.checks.map((check) => check.id)).size !== report.checks.length
  ) {
    throw new Error("Assurance report does not satisfy the release policy");
  }

  console.log(`VaultLab report policy PASS (${report.summary.passed}/${report.summary.total})`);
}
