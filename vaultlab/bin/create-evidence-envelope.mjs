#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { createEvidenceEnvelope } from "../src/evidence-envelope.mjs";

const reportPath = process.argv[2];
const sourceRevision = process.argv[3];
if (!reportPath || !sourceRevision) {
  console.error("Usage: npm run evidence -- <report.json> <40-character-git-sha>");
  process.exitCode = 2;
} else {
  const report = JSON.parse(await readFile(reportPath, "utf8"));
  const envelope = createEvidenceEnvelope(report, {
    sourceRevision,
    runnerIdentity: process.env.GITHUB_ACTIONS === "true" ? "github-actions" : "local-vaultlab"
  });
  console.log(JSON.stringify(envelope, null, 2));
}
