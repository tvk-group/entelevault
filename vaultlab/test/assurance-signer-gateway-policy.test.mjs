import assert from "node:assert/strict";
import test from "node:test";
import {
  ASSURANCE_SIGNER_ALGORITHMS,
  ASSURANCE_SIGNER_GATEWAY_SCHEMA,
  digestAssuranceReceipt,
  evaluateAssuranceSignerGatewayCase,
  validateAssuranceSignerGatewayCase
} from "../src/assurance-signer-gateway-policy.mjs";

const REVISION = "a".repeat(40);

function receipt(overrides = {}) {
  const base = {
    schema: "osoix.assurance-receipt.v1",
    issuer: "wallet",
    audience: "OSOIX",
    subject: "entelewallet-production-control-plane",
    environment: "production",
    sourceRevision: REVISION,
    issuedAt: "2026-08-08T09:00:00.000Z",
    expiresAt: "2026-08-08T09:05:00.000Z",
    policyVersion: "entelewallet-source-gates-2026.08.08.v2",
    decision: "deny",
    evidenceDigest: "b".repeat(64),
    commandPath: false,
    controls: {
      humanQuorum: false,
      hardwareBackedKeys: false,
      transactionSimulation: false,
      destinationPolicy: false,
      rateLimits: false,
      recoveryDrillCurrent: false,
      workloadIdentity: true,
      productionRevisionBound: true,
      cryptoInventoryComplete: false
    }
  };
  return {
    ...base,
    ...overrides,
    controls: { ...base.controls, ...(overrides.controls ?? {}) }
  };
}

function gatewayCase(overrides = {}) {
  const baseReceipt = receipt(overrides.receipt);
  const base = {
    schema: ASSURANCE_SIGNER_GATEWAY_SCHEMA,
    caseId: "gateway_0123456789abcdef0123456789abcdef",
    observedAt: "2026-08-08T09:00:30.000Z",
    environment: "staging",
    caller: {
      issuer: "https://oidc.vercel.com/tvk-group",
      audience: "https://vercel.com/tvk-group",
      subject: "owner:tvk-group:project:entelewallet-app:environment:production",
      owner: "tvk-group",
      ownerId: "team_MOHi5TFHhsgsCUm8qfCYpnf6",
      project: "entelewallet-app",
      projectId: "prj_BzvQEtgeP5oTsWeYxmlhzGMUfwNI",
      deploymentEnvironment: "production",
      sourceRevision: REVISION,
      tokenLifetimeSeconds: 3600,
      runtimeIdentityVerified: true
    },
    request: {
      schema: "osoix.assurance-signing-request.v1",
      method: "POST",
      purpose: "assurance-receipt-signing",
      keyPurpose: "wallet-assurance-receipt",
      algorithms: [...ASSURANCE_SIGNER_ALGORITHMS],
      receiptDigest: digestAssuranceReceipt(baseReceipt),
      sourceRevision: REVISION,
      commandPath: false,
      requestBytes: 8192
    },
    receipt: baseReceipt,
    transport: {
      tlsVersion: "TLS1.3",
      redirectPolicy: "error",
      contentType: "application/json",
      trustedSourceVerified: true,
      maximumRequestBytes: 65536,
      maximumResponseBytes: 65536
    },
    replay: {
      nonceStatus: "unique",
      idempotencyStatus: "new",
      rateLimitStatus: "within-limit"
    },
    provider: {
      keyProtection: "managed-kms",
      hardwareBacked: true,
      keyExportPolicy: "prohibited",
      purposeIsolation: true,
      auditSinkAvailable: true,
      independentAssessmentApproved: true,
      classicalSignatureAvailable: true,
      postQuantumSignatureAvailable: true
    }
  };
  const candidate = {
    ...base,
    ...overrides,
    caller: { ...base.caller, ...(overrides.caller ?? {}) },
    request: { ...base.request, ...(overrides.request ?? {}) },
    receipt: baseReceipt,
    transport: { ...base.transport, ...(overrides.transport ?? {}) },
    replay: { ...base.replay, ...(overrides.replay ?? {}) },
    provider: { ...base.provider, ...(overrides.provider ?? {}) }
  };
  if (overrides.receipt && !overrides.request?.receiptDigest) {
    candidate.request.receiptDigest = digestAssuranceReceipt(candidate.receipt);
  }
  return candidate;
}

test("a complete fixed-purpose case is review-eligible but grants no runtime authority", () => {
  const decision = evaluateAssuranceSignerGatewayCase(gatewayCase());
  assert.equal(decision.recommendation, "ELIGIBLE_FOR_SEPARATE_SIGNER_IMPLEMENTATION_REVIEW");
  assert.deepEqual(decision.reasonCodes, []);
  for (const field of [
    "runtimeDeploymentAuthorized",
    "requestExecutionAuthorized",
    "signingAuthorized",
    "cryptographicOperationAuthorized",
    "keyGenerationAuthorized",
    "keyExportAuthorized",
    "assetMovementAuthorized"
  ]) assert.equal(decision[field], false);
});

test("all four exact caller identities and key purposes are modeled", () => {
  const callers = [
    ["entelewallet-app", "prj_BzvQEtgeP5oTsWeYxmlhzGMUfwNI", "wallet", "wallet"],
    ["enteleexchange", "prj_34FPbar6y63CISVsUg1HXnv81dF7", "exchange", "exchange"],
    ["entelevault", "prj_lVL6JHyySLVzkLhG3AmML0y6deZc", "custody", "custody"],
    ["enteleclos", "prj_V9rcuB81fJimWQRb46dNjeOpEfb7", "cloud", "cloud"]
  ];
  for (const [project, projectId, issuer, keyPrefix] of callers) {
    const decision = evaluateAssuranceSignerGatewayCase(
      gatewayCase({
        caller: {
          project,
          projectId,
          subject: `owner:tvk-group:project:${project}:environment:production`
        },
        request: { keyPurpose: `${keyPrefix}-assurance-receipt` },
        receipt: { issuer }
      })
    );
    assert.equal(decision.recommendation, "ELIGIBLE_FOR_SEPARATE_SIGNER_IMPLEMENTATION_REVIEW");
  }
});

test("caller identity, runtime identity, and key-purpose confusion fail closed", () => {
  const cases = [
    [gatewayCase({ caller: { projectId: "prj_wrong" } }), "CALLER_IDENTITY_MISMATCH"],
    [gatewayCase({ caller: { runtimeIdentityVerified: false } }), "RUNTIME_IDENTITY_UNVERIFIED"],
    [gatewayCase({ request: { keyPurpose: "exchange-assurance-receipt" } }), "KEY_PURPOSE_MISMATCH"]
  ];
  for (const [candidate, reason] of cases) {
    const decision = evaluateAssuranceSignerGatewayCase(candidate);
    assert.equal(decision.recommendation, "BLOCK_SIGNER_GATEWAY_REQUEST");
    assert.equal(decision.reasonCodes.includes(reason), true);
  }
});

test("digest, revision, freshness, decision, and command boundaries fail closed", () => {
  const cases = [
    [gatewayCase({ request: { receiptDigest: "f".repeat(64) } }), "RECEIPT_DIGEST_MISMATCH"],
    [gatewayCase({ request: { sourceRevision: "c".repeat(40) } }), "SOURCE_REVISION_MISMATCH"],
    [gatewayCase({ receipt: { expiresAt: "2026-08-08T09:05:01.000Z" } }), "RECEIPT_FRESHNESS_REJECTED"],
    [gatewayCase({ receipt: { decision: "allow" } }), "AUTHORITY_BOUNDARY_REJECTED"],
    [gatewayCase({ request: { commandPath: true } }), "AUTHORITY_BOUNDARY_REJECTED"]
  ];
  for (const [candidate, reason] of cases) {
    const decision = evaluateAssuranceSignerGatewayCase(candidate);
    assert.equal(decision.recommendation, "BLOCK_SIGNER_GATEWAY_REQUEST");
    assert.equal(decision.reasonCodes.includes(reason), true);
  }
});

test("generic signing shapes and weakened transport are rejected", () => {
  const cases = [
    [gatewayCase({ request: { method: "GET" } }), "REQUEST_CONTRACT_MISMATCH"],
    [gatewayCase({ request: { purpose: "generic-signing" } }), "REQUEST_CONTRACT_MISMATCH"],
    [gatewayCase({ request: { algorithms: ["Ed25519"] } }), "ALGORITHM_SET_MISMATCH"],
    [gatewayCase({ transport: { redirectPolicy: "follow" } }), "TRANSPORT_POLICY_REJECTED"],
    [gatewayCase({ transport: { trustedSourceVerified: false } }), "TRANSPORT_POLICY_REJECTED"]
  ];
  for (const [candidate, reason] of cases) {
    const decision = evaluateAssuranceSignerGatewayCase(candidate);
    assert.equal(decision.recommendation, "BLOCK_SIGNER_GATEWAY_REQUEST");
    assert.equal(decision.reasonCodes.includes(reason), true);
  }
});

test("replay, idempotency, rate, provider, export, and audit failures block review", () => {
  const cases = [
    gatewayCase({ replay: { nonceStatus: "replayed" } }),
    gatewayCase({ replay: { idempotencyStatus: "duplicate" } }),
    gatewayCase({ replay: { rateLimitStatus: "exceeded" } }),
    gatewayCase({ provider: { keyProtection: "software" } }),
    gatewayCase({ provider: { hardwareBacked: false } }),
    gatewayCase({ provider: { keyExportPolicy: "allowed" } }),
    gatewayCase({ provider: { purposeIsolation: false } }),
    gatewayCase({ provider: { auditSinkAvailable: false } }),
    gatewayCase({ provider: { independentAssessmentApproved: false } }),
    gatewayCase({ provider: { postQuantumSignatureAvailable: false } })
  ];
  for (const candidate of cases) {
    const decision = evaluateAssuranceSignerGatewayCase(candidate);
    assert.equal(decision.recommendation, "BLOCK_SIGNER_GATEWAY_REQUEST");
  }
});

test("secret, wallet, arbitrary payload, signature, and credential fields are prohibited", () => {
  for (const prohibited of [
    { privateKey: "prohibited" },
    { keyShare: "prohibited" },
    { mnemonic: "prohibited" },
    { walletFile: "prohibited" },
    { payload: "prohibited" },
    { signatureValue: "prohibited" },
    { credential: "prohibited" }
  ]) {
    assert.throws(
      () => validateAssuranceSignerGatewayCase(gatewayCase(prohibited)),
      (error) => error.code === "ASSURANCE_SIGNER_GATEWAY_PROHIBITED_FIELD"
    );
  }
});

test("decisions are deterministic and expose no caller, receipt, provider, or transport detail", () => {
  const first = evaluateAssuranceSignerGatewayCase(gatewayCase());
  const second = evaluateAssuranceSignerGatewayCase(gatewayCase());
  assert.deepEqual(first, second);
  for (const field of ["caller", "request", "receipt", "transport", "replay", "provider"]) {
    assert.equal(field in first, false);
  }
});
