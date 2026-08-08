import { createHash } from "node:crypto";
import { VaultLabError } from "./errors.mjs";

export const ASSURANCE_SIGNER_GATEWAY_SCHEMA =
  "entelevault.assurance-signer-gateway-case.v2";
export const ASSURANCE_SIGNER_GATEWAY_DECISION_SCHEMA =
  "entelevault.assurance-signer-gateway-decision.v2";

export const ASSURANCE_SIGNER_ALGORITHMS = Object.freeze(["Ed25519", "ML-DSA-65"]);

export const ASSURANCE_SIGNER_TRUSTED_CALLERS = Object.freeze({
  "entelewallet-app": Object.freeze({
    projectId: "prj_BzvQEtgeP5oTsWeYxmlhzGMUfwNI",
    receiptIssuer: "wallet",
    keyPurpose: "wallet-assurance-receipt"
  }),
  enteleexchange: Object.freeze({
    projectId: "prj_34FPbar6y63CISVsUg1HXnv81dF7",
    receiptIssuer: "exchange",
    keyPurpose: "exchange-assurance-receipt"
  }),
  entelevault: Object.freeze({
    projectId: "prj_lVL6JHyySLVzkLhG3AmML0y6deZc",
    receiptIssuer: "custody",
    keyPurpose: "custody-assurance-receipt"
  }),
  enteleclos: Object.freeze({
    projectId: "prj_V9rcuB81fJimWQRb46dNjeOpEfb7",
    receiptIssuer: "cloud",
    keyPurpose: "cloud-assurance-receipt"
  })
});

const TEAM_OWNER = "tvk-group";
const TEAM_OWNER_ID = "team_MOHi5TFHhsgsCUm8qfCYpnf6";
const VERCEL_ISSUER = "https://oidc.vercel.com/tvk-group";
const VERCEL_AUDIENCE = "https://vercel.com/tvk-group";
const MAX_TOKEN_LIFETIME_SECONDS = 65 * 60;
const MAX_RECEIPT_LIFETIME_MILLISECONDS = 5 * 60_000;
const CLOCK_SKEW_MILLISECONDS = 60_000;
const MAX_BODY_BYTES = 64 * 1024;
const CHALLENGE_BYTES = 32;
const RECEIPT_ID_BYTES = 18;

const ROOT_FIELDS = new Set([
  "schema",
  "caseId",
  "observedAt",
  "environment",
  "caller",
  "request",
  "receipt",
  "transport",
  "replay",
  "provider"
]);
const CALLER_FIELDS = new Set([
  "issuer",
  "audience",
  "subject",
  "owner",
  "ownerId",
  "project",
  "projectId",
  "deploymentEnvironment",
  "sourceRevision",
  "tokenLifetimeSeconds",
  "runtimeIdentityVerified"
]);
const REQUEST_FIELDS = new Set([
  "schema",
  "method",
  "purpose",
  "keyPurpose",
  "algorithms",
  "receiptDigest",
  "sourceRevision",
  "canonicalReceiptStatus",
  "commandPath",
  "requestBytes"
]);
const RECEIPT_FIELDS = new Set([
  "schema",
  "receiptId",
  "challenge",
  "purpose",
  "issuer",
  "audience",
  "subject",
  "environment",
  "sourceRevision",
  "issuedAt",
  "expiresAt",
  "policyVersion",
  "decision",
  "evidenceDigest",
  "commandPath",
  "controls"
]);
const RECEIPT_CONTROL_FIELDS = new Set([
  "humanQuorum",
  "hardwareBackedKeys",
  "transactionSimulation",
  "destinationPolicy",
  "rateLimits",
  "recoveryDrillCurrent",
  "workloadIdentity",
  "productionRevisionBound",
  "cryptoInventoryComplete"
]);
const TRANSPORT_FIELDS = new Set([
  "tlsVersion",
  "redirectPolicy",
  "contentType",
  "trustedSourceVerified",
  "maximumRequestBytes",
  "maximumResponseBytes"
]);
const REPLAY_FIELDS = new Set([
  "requestChallenge",
  "observedReceiptId",
  "challengeStatus",
  "receiptIdStatus",
  "idempotencyStatus",
  "rateLimitStatus"
]);
const PROVIDER_FIELDS = new Set([
  "keyProtection",
  "hardwareBacked",
  "keyExportPolicy",
  "purposeIsolation",
  "auditSinkAvailable",
  "independentAssessmentApproved",
  "classicalSignatureAvailable",
  "postQuantumSignatureAvailable"
]);
const PROHIBITED_FIELD =
  /(?:authorization|candidate|credential|entropy|executable|keyMaterial|keyShare|mnemonic|password|payload|privateKey|rawKey|secret|seed|signatureValue|target|token|transaction|walletFile)/iu;

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function reject(code, message) {
  throw new VaultLabError(code, message);
}

function assertExactFields(value, allowed, label) {
  if (!isRecord(value)) reject("ASSURANCE_SIGNER_GATEWAY_INVALID", `${label} must be an object`);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key) && PROHIBITED_FIELD.test(key)) {
      reject(
        "ASSURANCE_SIGNER_GATEWAY_PROHIBITED_FIELD",
        `${label} contains a prohibited field`
      );
    }
    if (!allowed.has(key)) {
      reject("ASSURANCE_SIGNER_GATEWAY_FIELDS_REJECTED", `${label} has an unknown field`);
    }
  }
  if (Object.keys(value).length !== allowed.size) {
    reject(
      "ASSURANCE_SIGNER_GATEWAY_FIELDS_REJECTED",
      `${label} field set is incomplete or unknown`
    );
  }
}

function assertIdentifier(value, code, label) {
  if (typeof value !== "string" || !/^[A-Za-z0-9._:/-]{1,160}$/u.test(value)) {
    reject(code, `${label} is invalid`);
  }
}

function assertTimestamp(value, code, label) {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value))) {
    reject(code, `${label} is invalid`);
  }
}

function isCanonicalBase64Url(value, expectedBytes) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/u.test(value)) return false;
  try {
    const decoded = Buffer.from(value, "base64url");
    return decoded.byteLength === expectedBytes && decoded.toString("base64url") === value;
  } catch {
    return false;
  }
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

export function digestAssuranceReceipt(receipt) {
  return createHash("sha256").update(canonicalJson(receipt)).digest("hex");
}

export function validateAssuranceSignerGatewayCase(input) {
  assertExactFields(input, ROOT_FIELDS, "Assurance signer gateway case");
  if (input.schema !== ASSURANCE_SIGNER_GATEWAY_SCHEMA) {
    reject(
      "ASSURANCE_SIGNER_GATEWAY_SCHEMA_REJECTED",
      "Assurance signer gateway schema is unsupported"
    );
  }
  if (typeof input.caseId !== "string" || !/^gateway_[0-9a-f]{32}$/u.test(input.caseId)) {
    reject("ASSURANCE_SIGNER_GATEWAY_ID_REJECTED", "Assurance signer gateway case ID is invalid");
  }
  assertTimestamp(
    input.observedAt,
    "ASSURANCE_SIGNER_GATEWAY_TIME_REJECTED",
    "Assurance signer gateway observation time"
  );
  if (input.environment !== "staging") {
    reject(
      "ASSURANCE_SIGNER_GATEWAY_ENVIRONMENT_REJECTED",
      "Assurance signer gateway conformance is staging-only"
    );
  }

  assertExactFields(input.caller, CALLER_FIELDS, "Assurance signer caller");
  for (const field of [
    "issuer",
    "audience",
    "subject",
    "owner",
    "ownerId",
    "project",
    "projectId",
    "deploymentEnvironment",
    "sourceRevision"
  ]) {
    assertIdentifier(
      input.caller[field],
      "ASSURANCE_SIGNER_GATEWAY_CALLER_REJECTED",
      `Assurance signer caller ${field}`
    );
  }
  if (!/^[0-9a-f]{40}$/u.test(input.caller.sourceRevision)) {
    reject(
      "ASSURANCE_SIGNER_GATEWAY_CALLER_REJECTED",
      "Assurance signer caller revision is invalid"
    );
  }
  if (
    !Number.isSafeInteger(input.caller.tokenLifetimeSeconds) ||
    input.caller.tokenLifetimeSeconds < 1 ||
    input.caller.tokenLifetimeSeconds > MAX_TOKEN_LIFETIME_SECONDS ||
    typeof input.caller.runtimeIdentityVerified !== "boolean"
  ) {
    reject(
      "ASSURANCE_SIGNER_GATEWAY_CALLER_REJECTED",
      "Assurance signer caller lifetime or identity evidence is invalid"
    );
  }

  assertExactFields(input.request, REQUEST_FIELDS, "Assurance signer request");
  for (const field of ["schema", "method", "purpose", "keyPurpose", "sourceRevision"]) {
    assertIdentifier(
      input.request[field],
      "ASSURANCE_SIGNER_GATEWAY_REQUEST_REJECTED",
      `Assurance signer request ${field}`
    );
  }
  if (
    !Array.isArray(input.request.algorithms) ||
    input.request.algorithms.length < 1 ||
    input.request.algorithms.length > ASSURANCE_SIGNER_ALGORITHMS.length ||
    input.request.algorithms.some(
      (algorithm) => !ASSURANCE_SIGNER_ALGORITHMS.includes(algorithm)
    ) ||
    new Set(input.request.algorithms).size !== input.request.algorithms.length ||
    typeof input.request.receiptDigest !== "string" ||
    !/^[0-9a-f]{64}$/u.test(input.request.receiptDigest) ||
    !/^[0-9a-f]{40}$/u.test(input.request.sourceRevision) ||
    typeof input.request.commandPath !== "boolean" ||
    !new Set(["exact", "mismatched", "unparseable", "unknown"]).has(
      input.request.canonicalReceiptStatus
    ) ||
    !Number.isSafeInteger(input.request.requestBytes) ||
    input.request.requestBytes < 1 ||
    input.request.requestBytes > MAX_BODY_BYTES
  ) {
    reject("ASSURANCE_SIGNER_GATEWAY_REQUEST_REJECTED", "Assurance signer request is invalid");
  }

  assertExactFields(input.receipt, RECEIPT_FIELDS, "Assurance receipt");
  for (const field of [
    "schema",
    "purpose",
    "issuer",
    "audience",
    "subject",
    "environment",
    "sourceRevision",
    "policyVersion",
    "decision"
  ]) {
    assertIdentifier(
      input.receipt[field],
      "ASSURANCE_SIGNER_GATEWAY_RECEIPT_REJECTED",
      `Assurance receipt ${field}`
    );
  }
  assertTimestamp(
    input.receipt.issuedAt,
    "ASSURANCE_SIGNER_GATEWAY_RECEIPT_REJECTED",
    "Assurance receipt issue time"
  );
  assertTimestamp(
    input.receipt.expiresAt,
    "ASSURANCE_SIGNER_GATEWAY_RECEIPT_REJECTED",
    "Assurance receipt expiry time"
  );
  if (
    !isCanonicalBase64Url(input.receipt.receiptId, RECEIPT_ID_BYTES) ||
    !isCanonicalBase64Url(input.receipt.challenge, CHALLENGE_BYTES) ||
    !/^[0-9a-f]{40}$/u.test(input.receipt.sourceRevision) ||
    !/^[0-9a-f]{64}$/u.test(input.receipt.evidenceDigest) ||
    typeof input.receipt.commandPath !== "boolean"
  ) {
    reject("ASSURANCE_SIGNER_GATEWAY_RECEIPT_REJECTED", "Assurance receipt is invalid");
  }
  assertExactFields(input.receipt.controls, RECEIPT_CONTROL_FIELDS, "Assurance receipt controls");
  if (
    [...RECEIPT_CONTROL_FIELDS].some(
      (control) => typeof input.receipt.controls[control] !== "boolean"
    )
  ) {
    reject(
      "ASSURANCE_SIGNER_GATEWAY_RECEIPT_REJECTED",
      "Assurance receipt control evidence is invalid"
    );
  }

  assertExactFields(input.transport, TRANSPORT_FIELDS, "Assurance signer transport");
  if (
    !new Set(["TLS1.2", "TLS1.3"]).has(input.transport.tlsVersion) ||
    !new Set(["error", "follow"]).has(input.transport.redirectPolicy) ||
    !new Set(["application/json", "application/octet-stream"]).has(
      input.transport.contentType
    ) ||
    typeof input.transport.trustedSourceVerified !== "boolean" ||
    !Number.isSafeInteger(input.transport.maximumRequestBytes) ||
    input.transport.maximumRequestBytes < 1 ||
    input.transport.maximumRequestBytes > MAX_BODY_BYTES ||
    !Number.isSafeInteger(input.transport.maximumResponseBytes) ||
    input.transport.maximumResponseBytes < 1 ||
    input.transport.maximumResponseBytes > MAX_BODY_BYTES
  ) {
    reject(
      "ASSURANCE_SIGNER_GATEWAY_TRANSPORT_REJECTED",
      "Assurance signer transport evidence is invalid"
    );
  }

  assertExactFields(input.replay, REPLAY_FIELDS, "Assurance signer replay controls");
  if (
    !isCanonicalBase64Url(input.replay.requestChallenge, CHALLENGE_BYTES) ||
    !isCanonicalBase64Url(input.replay.observedReceiptId, RECEIPT_ID_BYTES) ||
    !new Set(["fresh", "replayed", "mismatched", "malformed", "unknown"]).has(
      input.replay.challengeStatus
    ) ||
    !new Set(["unique", "duplicate", "malformed", "unknown"]).has(
      input.replay.receiptIdStatus
    ) ||
    !new Set(["new", "duplicate", "unknown"]).has(input.replay.idempotencyStatus) ||
    !new Set(["within-limit", "exceeded", "unknown"]).has(input.replay.rateLimitStatus)
  ) {
    reject(
      "ASSURANCE_SIGNER_GATEWAY_REPLAY_REJECTED",
      "Assurance signer replay evidence is invalid"
    );
  }

  assertExactFields(input.provider, PROVIDER_FIELDS, "Assurance signer provider");
  if (
    !new Set(["hsm", "cloud-hsm", "managed-kms", "mpc", "software"]).has(
      input.provider.keyProtection
    ) ||
    typeof input.provider.hardwareBacked !== "boolean" ||
    !new Set(["prohibited", "allowed", "unknown"]).has(input.provider.keyExportPolicy) ||
    typeof input.provider.purposeIsolation !== "boolean" ||
    typeof input.provider.auditSinkAvailable !== "boolean" ||
    typeof input.provider.independentAssessmentApproved !== "boolean" ||
    typeof input.provider.classicalSignatureAvailable !== "boolean" ||
    typeof input.provider.postQuantumSignatureAvailable !== "boolean"
  ) {
    reject(
      "ASSURANCE_SIGNER_GATEWAY_PROVIDER_REJECTED",
      "Assurance signer provider evidence is invalid"
    );
  }
  return structuredClone(input);
}

export function evaluateAssuranceSignerGatewayCase(input) {
  const gatewayCase = validateAssuranceSignerGatewayCase(input);
  const reasons = [];
  const expectedCaller = ASSURANCE_SIGNER_TRUSTED_CALLERS[gatewayCase.caller.project];
  const expectedSubject = `owner:${TEAM_OWNER}:project:${gatewayCase.caller.project}:environment:production`;

  if (
    !expectedCaller ||
    gatewayCase.caller.issuer !== VERCEL_ISSUER ||
    gatewayCase.caller.audience !== VERCEL_AUDIENCE ||
    gatewayCase.caller.subject !== expectedSubject ||
    gatewayCase.caller.owner !== TEAM_OWNER ||
    gatewayCase.caller.ownerId !== TEAM_OWNER_ID ||
    gatewayCase.caller.projectId !== expectedCaller?.projectId ||
    gatewayCase.caller.deploymentEnvironment !== "production"
  ) {
    reasons.push("CALLER_IDENTITY_MISMATCH");
  }
  if (!gatewayCase.caller.runtimeIdentityVerified) reasons.push("RUNTIME_IDENTITY_UNVERIFIED");
  if (
    gatewayCase.request.schema !== "osoix.assurance-signing-request.v2" ||
    gatewayCase.request.method !== "POST" ||
    gatewayCase.request.purpose !== "assurance-receipt-signing"
  ) {
    reasons.push("REQUEST_CONTRACT_MISMATCH");
  }
  if (gatewayCase.request.canonicalReceiptStatus !== "exact") {
    reasons.push("CANONICAL_RECEIPT_REJECTED");
  }
  if (
    gatewayCase.request.algorithms.length !== ASSURANCE_SIGNER_ALGORITHMS.length ||
    ASSURANCE_SIGNER_ALGORITHMS.some(
      (algorithm, index) => gatewayCase.request.algorithms[index] !== algorithm
    )
  ) {
    reasons.push("ALGORITHM_SET_MISMATCH");
  }
  if (
    gatewayCase.request.commandPath ||
    gatewayCase.receipt.commandPath ||
    gatewayCase.receipt.decision !== "deny"
  ) {
    reasons.push("AUTHORITY_BOUNDARY_REJECTED");
  }
  if (
    !expectedCaller ||
    gatewayCase.request.keyPurpose !== expectedCaller.keyPurpose ||
    gatewayCase.receipt.issuer !== expectedCaller.receiptIssuer
  ) {
    reasons.push("KEY_PURPOSE_MISMATCH");
  }
  if (
    gatewayCase.receipt.schema !== "osoix.assurance-receipt.v2" ||
    gatewayCase.receipt.purpose !== "read-only-assurance" ||
    gatewayCase.receipt.audience !== "OSOIX" ||
    gatewayCase.receipt.environment !== "production"
  ) {
    reasons.push("RECEIPT_CONTRACT_MISMATCH");
  }
  if (
    gatewayCase.replay.requestChallenge !== gatewayCase.receipt.challenge ||
    gatewayCase.replay.challengeStatus !== "fresh"
  ) {
    reasons.push("CHALLENGE_BINDING_REJECTED");
  }
  if (gatewayCase.replay.observedReceiptId !== gatewayCase.receipt.receiptId) {
    reasons.push("RECEIPT_ID_BINDING_REJECTED");
  }
  if (
    gatewayCase.request.sourceRevision !== gatewayCase.caller.sourceRevision ||
    gatewayCase.receipt.sourceRevision !== gatewayCase.caller.sourceRevision
  ) {
    reasons.push("SOURCE_REVISION_MISMATCH");
  }
  if (gatewayCase.request.receiptDigest !== digestAssuranceReceipt(gatewayCase.receipt)) {
    reasons.push("RECEIPT_DIGEST_MISMATCH");
  }

  const issuedAt = Date.parse(gatewayCase.receipt.issuedAt);
  const expiresAt = Date.parse(gatewayCase.receipt.expiresAt);
  const observedAt = Date.parse(gatewayCase.observedAt);
  if (
    expiresAt <= issuedAt ||
    expiresAt - issuedAt > MAX_RECEIPT_LIFETIME_MILLISECONDS ||
    observedAt < issuedAt - CLOCK_SKEW_MILLISECONDS ||
    observedAt > expiresAt + CLOCK_SKEW_MILLISECONDS
  ) {
    reasons.push("RECEIPT_FRESHNESS_REJECTED");
  }
  if (
    gatewayCase.transport.tlsVersion !== "TLS1.3" ||
    gatewayCase.transport.redirectPolicy !== "error" ||
    gatewayCase.transport.contentType !== "application/json" ||
    !gatewayCase.transport.trustedSourceVerified ||
    gatewayCase.request.requestBytes > gatewayCase.transport.maximumRequestBytes
  ) {
    reasons.push("TRANSPORT_POLICY_REJECTED");
  }
  if (
    gatewayCase.replay.receiptIdStatus !== "unique" ||
    gatewayCase.replay.idempotencyStatus !== "new" ||
    gatewayCase.replay.rateLimitStatus !== "within-limit"
  ) {
    reasons.push("REPLAY_OR_RATE_POLICY_REJECTED");
  }
  if (
    !new Set(["hsm", "cloud-hsm", "managed-kms", "mpc"]).has(
      gatewayCase.provider.keyProtection
    ) ||
    !gatewayCase.provider.hardwareBacked ||
    gatewayCase.provider.keyExportPolicy !== "prohibited" ||
    !gatewayCase.provider.purposeIsolation ||
    !gatewayCase.provider.auditSinkAvailable ||
    !gatewayCase.provider.independentAssessmentApproved ||
    !gatewayCase.provider.classicalSignatureAvailable ||
    !gatewayCase.provider.postQuantumSignatureAvailable
  ) {
    reasons.push("PROVIDER_POSTURE_REJECTED");
  }

  const digest = createHash("sha256").update(canonicalJson(gatewayCase)).digest("hex");
  return {
    schema: ASSURANCE_SIGNER_GATEWAY_DECISION_SCHEMA,
    decisionId: `gatewaydec_${digest.slice(0, 32)}`,
    caseId: gatewayCase.caseId,
    recommendation:
      reasons.length === 0
        ? "ELIGIBLE_FOR_SEPARATE_SIGNER_IMPLEMENTATION_REVIEW"
        : "BLOCK_SIGNER_GATEWAY_REQUEST",
    reasonCodes: reasons.sort(),
    humanAuthorizationRequired: true,
    independentReviewRequired: true,
    runtimeDeploymentAuthorized: false,
    requestExecutionAuthorized: false,
    signingAuthorized: false,
    cryptographicOperationAuthorized: false,
    keyGenerationAuthorized: false,
    keyExportAuthorized: false,
    assetMovementAuthorized: false
  };
}
