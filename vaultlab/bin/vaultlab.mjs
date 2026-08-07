#!/usr/bin/env node
import { randomBytes } from "node:crypto";
import { runAssuranceSuite } from "../src/assurance-runner.mjs";

const command = process.argv[2];
if (command !== "assess") {
  console.error("Usage: npm run assure");
  console.error("VaultLab does not accept wallet paths, targets, or password lists.");
  process.exitCode = 2;
} else {
  const credential = `VaultLab-${randomBytes(24).toString("base64url")}`;
  const report = await runAssuranceSuite({ credential });
  console.log(JSON.stringify(report, null, 2));
  if (report.result !== "PASS") process.exitCode = 1;
}
