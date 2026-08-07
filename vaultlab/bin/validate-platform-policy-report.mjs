#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { validatePlatformPolicyReport } from "../src/platform-policy-report.mjs";

const reportPath = resolve(process.argv[2] ?? "vaultlab-platform-policy-report.json");
const report = JSON.parse(await readFile(reportPath, "utf8"));
const validated = validatePlatformPolicyReport(report);
console.log(
  JSON.stringify({
    schema: "enteleclos.platform-policy-validation.v1",
    status: "PASS",
    reportSchema: validated.schema,
    checks: validated.summary.total,
    authorityGranted: false
  })
);
