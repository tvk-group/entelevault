#!/usr/bin/env node
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { evaluateConsumerReleaseGate } from "../src/consumer-release-gate.mjs";

const allowedOptions = new Set([
  "manifest",
  "report",
  "repository",
  "source-revision",
  "policy-revision",
  "observed-at",
  "output"
]);

function parseOptions(args) {
  const options = new Map();
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (!argument.startsWith("--") || argument.includes("=")) {
      throw new TypeError("Consumer release gate options must use --name value form");
    }
    const name = argument.slice(2);
    if (!allowedOptions.has(name) || options.has(name)) {
      throw new TypeError("Consumer release gate option is unknown or duplicated");
    }
    const value = args[index + 1];
    if (typeof value !== "string" || value.startsWith("--")) {
      throw new TypeError("Consumer release gate option value is missing");
    }
    options.set(name, value);
    index += 1;
  }
  return options;
}

try {
  const options = parseOptions(process.argv.slice(2));
  const manifestPath = resolve(options.get("manifest") ?? ".enteleclos/production-assurance.json");
  const reportPath = resolve(options.get("report") ?? ".enteleclos/out/platform-policy-report.json");
  const outputPath = resolve(options.get("output") ?? ".enteleclos/out/release-attestation.json");
  const repository = options.get("repository") ?? process.env.GITHUB_REPOSITORY;
  const sourceRevision = options.get("source-revision") ?? process.env.GITHUB_SHA;
  const policyRevision = options.get("policy-revision") ?? process.env.ENTELECLOS_POLICY_REVISION;
  const observedAt = options.get("observed-at") ?? new Date().toISOString();
  const [manifest, report] = await Promise.all([
    readFile(manifestPath, "utf8").then(JSON.parse),
    readFile(reportPath, "utf8").then(JSON.parse)
  ]);
  const attestation = evaluateConsumerReleaseGate(
    { manifest, report },
    { repository, sourceRevision, policyRevision, observedAt }
  );
  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, `${JSON.stringify(attestation, null, 2)}\n`, { encoding: "utf8", flag: "wx" });
  process.stdout.write(`${JSON.stringify({
    schema: attestation.schema,
    status: attestation.status,
    releaseDisposition: attestation.releaseDisposition,
    repository: attestation.repository,
    sourceRevision: attestation.sourceRevision,
    policyRevision: attestation.policyRevision,
    authorityGranted: false
  })}\n`);
} catch (error) {
  const knownCode = typeof error?.code === "string" && /^(?:CONSUMER_GATE|PLATFORM_REPORT)_/u.test(error.code);
  process.stderr.write(`${JSON.stringify({
    schema: "enteleclos.consumer-release-gate-error.v1",
    status: "FAIL",
    code: knownCode ? error.code : "CONSUMER_GATE_FAILED",
    message: knownCode && typeof error?.message === "string" ? error.message : "Consumer release gate failed"
  })}\n`);
  process.exitCode = 1;
}
