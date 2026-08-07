import { createHash } from "node:crypto";
import { VaultLabError } from "./errors.mjs";

export const EVIDENCE_ENVELOPE_SCHEMA = "enteleclos.assurance-evidence.v1";

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function reject(code, message) {
  throw new VaultLabError(code, message);
}

function hasExactFields(value, allowed) {
  return isRecord(value) && Object.keys(value).every((key) => allowed.has(key));
}

export function createEvidenceEnvelope(report, { sourceRevision, runnerIdentity, recordedAt } = {}) {
  if (!isRecord(report)) reject("EVIDENCE_REPORT_REJECTED", "Assurance report must be an object");
  const rootFields = new Set([
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
  const summaryFields = new Set(["passed", "failed", "total"]);
  const checkFields = new Set(["id", "status", "statement", "reason", "rejectionCode"]);
  if (
    !hasExactFields(report, rootFields) ||
    report.schema !== "entelevault.vaultlab.assurance-report.v1" ||
    report.controlSet !== "ENTELE-VAULTLAB-1" ||
    typeof report.generatedAt !== "string" ||
    Number.isNaN(Date.parse(report.generatedAt)) ||
    report.scope !== "synthetic-only" ||
    typeof report.fixtureId !== "string" ||
    !/^vlab_[0-9a-f]{32}$/u.test(report.fixtureId) ||
    report.result !== "PASS" ||
    !isRecord(report.summary) ||
    !hasExactFields(report.summary, summaryFields) ||
    report.summary.failed !== 0 ||
    !Number.isSafeInteger(report.summary.passed) ||
    !Number.isSafeInteger(report.summary.total) ||
    report.summary.passed !== report.summary.total ||
    !Array.isArray(report.checks) ||
    report.checks.length !== report.summary.total ||
    report.checks.some(
      (check) =>
        !hasExactFields(check, checkFields) ||
        typeof check.id !== "string" ||
        !/^VL-[A-Z0-9-]+$/u.test(check.id) ||
        check.status !== "PASS"
    ) ||
    new Set(report.checks.map((check) => check.id)).size !== report.checks.length
  ) {
    reject("EVIDENCE_REPORT_REJECTED", "Assurance report does not satisfy evidence policy");
  }
  if (typeof sourceRevision !== "string" || !/^[0-9a-f]{40}$/u.test(sourceRevision)) {
    reject("EVIDENCE_REVISION_REJECTED", "Source revision must be a full Git commit SHA");
  }
  if (!new Set(["github-actions", "local-vaultlab"]).has(runnerIdentity)) {
    reject("EVIDENCE_RUNNER_REJECTED", "Evidence runner identity is unsupported");
  }
  const effectiveRecordedAt = recordedAt ?? new Date().toISOString();
  if (typeof effectiveRecordedAt !== "string" || Number.isNaN(Date.parse(effectiveRecordedAt))) {
    reject("EVIDENCE_TIME_REJECTED", "Evidence timestamp is invalid");
  }

  const reportDigest = createHash("sha256").update(canonicalJson(report)).digest("hex");
  return {
    schema: EVIDENCE_ENVELOPE_SCHEMA,
    recordedAt: effectiveRecordedAt,
    sourceRevision,
    runnerIdentity,
    reportDigest,
    reportSchema: report.schema,
    reportGeneratedAt: report.generatedAt,
    controlSet: report.controlSet,
    scope: report.scope,
    result: report.result,
    controlsPassed: report.summary.passed,
    controlsFailed: report.summary.failed,
    publishableFieldsOnly: true,
    containsFixture: false,
    containsCredential: false,
    containsWalletMaterial: false
  };
}
