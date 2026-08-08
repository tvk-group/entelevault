const ISSUER = "custody";
const SUBJECT = "entelevault-vaultlab-production-boundary";
const DECISION = "deny";
const POLICY_VERSION = "entelevault-synthetic-only-2026.08.08";
const SOURCE_EVIDENCE = {
  "system": "EnteleVAULT",
  "runtime": "VaultLab-synthetic-assurance",
  "productionCustody": false,
  "realKeysAccepted": false,
  "signingAuthority": false,
  "assetMovementAuthority": false,
  "reason": "current-repository-is-assurance-lab-not-production-HSM-or-MPC-custody"
};
const CONTROLS = { humanQuorum: false, hardwareBackedKeys: false, transactionSimulation: false, destinationPolicy: false, rateLimits: false, recoveryDrillCurrent: false, workloadIdentity: Boolean(process.env.VERCEL_OIDC_TOKEN), cryptoInventoryComplete: false };

const MAX_TOKEN_BYTES = 16 * 1024;
const MAX_JWKS_BYTES = 128 * 1024;
const MAX_SIGNER_BYTES = 64 * 1024;

function base64UrlBytes(value) {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  return new Uint8Array(Buffer.from(normalized, "base64"));
}

function decodeJwtPart(value) {
  const bytes = base64UrlBytes(value);
  if (bytes.byteLength > MAX_TOKEN_BYTES) throw new Error("JWT part too large");
  return JSON.parse(Buffer.from(bytes).toString("utf8"));
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.entries(value)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`)
    .join(",")}}`;
}

async function sha256(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Buffer.from(digest).toString("hex");
}

function safeHttpsUrl(value) {
  if (!value) return null;
  try {
    const url = new URL(value);
    return url.protocol === "https:" && !url.username && !url.password ? url : null;
  } catch {
    return null;
  }
}

async function boundedJson(response, maximumBytes) {
  const length = Number(response.headers.get("content-length") || 0);
  if (length > maximumBytes) throw new Error("Response too large");
  const text = await response.text();
  if (Buffer.byteLength(text, "utf8") > maximumBytes) throw new Error("Response too large");
  return JSON.parse(text);
}

async function authenticateOsoix(req) {
  if (req.headers["x-osoix-purpose"] !== "read-only-assurance") return false;
  const authorization = req.headers.authorization || "";
  const token = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
  if (!token || Buffer.byteLength(token, "utf8") > MAX_TOKEN_BYTES) return false;

  const issuer = process.env.OSOIX_OIDC_ISSUER || "https://oidc.vercel.com/tvk-group";
  const audience = process.env.OSOIX_OIDC_AUDIENCE || "https://vercel.com/tvk-group";
  const subject = process.env.OSOIX_OIDC_SUBJECT ||
    "owner:tvk-group:project:osoix:environment:production";
  const issuerUrl = safeHttpsUrl(issuer);
  if (!issuerUrl) return false;

  try {
    const parts = token.split(".");
    if (parts.length !== 3) return false;
    const header = decodeJwtPart(parts[0]);
    const payload = decodeJwtPart(parts[1]);
    if (header.alg !== "RS256" || typeof header.kid !== "string") return false;

    const jwksUrl = new URL(`${issuerUrl.pathname.replace(/\/$/, "")}/.well-known/jwks`, issuerUrl.origin);
    const response = await fetch(jwksUrl, {
      cache: "no-store",
      redirect: "error",
      signal: AbortSignal.timeout(3_000),
    });
    if (!response.ok) return false;
    const jwks = await boundedJson(response, MAX_JWKS_BYTES);
    const jwk = Array.isArray(jwks.keys)
      ? jwks.keys.find((candidate) => candidate.kid === header.kid && candidate.kty === "RSA")
      : null;
    if (!jwk) return false;
    const key = await crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"],
    );
    const verified = await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      key,
      base64UrlBytes(parts[2]),
      new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
    );
    const now = Math.floor(Date.now() / 1000);
    const validAudience = payload.aud === audience ||
      (Array.isArray(payload.aud) && payload.aud.includes(audience));
    return verified && payload.iss === issuer && validAudience && payload.sub === subject &&
      Number.isFinite(payload.iat) && payload.iat <= now + 60 &&
      Number.isFinite(payload.exp) && payload.exp > now &&
      (!Number.isFinite(payload.nbf) || payload.nbf <= now + 60);
  } catch {
    return false;
  }
}

async function signReceipt(receipt) {
  const signerUrl = safeHttpsUrl(process.env.ASSURANCE_SIGNER_URL);
  const signerToken = process.env.VERCEL_OIDC_TOKEN || process.env.ASSURANCE_SIGNER_TOKEN;
  if (!signerUrl || !signerToken) throw new Error("Signer unavailable");
  const canonicalReceipt = canonicalJson(receipt);
  const receiptDigest = await sha256(canonicalReceipt);
  const response = await fetch(signerUrl, {
    method: "POST",
    cache: "no-store",
    redirect: "error",
    signal: AbortSignal.timeout(4_000),
    headers: {
      "Authorization": `Bearer ${signerToken}`,
      ...(process.env.VERCEL_OIDC_TOKEN
        ? { "x-vercel-trusted-oidc-idp-token": process.env.VERCEL_OIDC_TOKEN }
        : {}),
      "Content-Type": "application/json",
      "X-OSOIX-Purpose": "assurance-receipt-signing",
    },
    body: JSON.stringify({
      schema: "osoix.assurance-signing-request.v1",
      keyPurpose: `${ISSUER}-assurance-receipt`,
      algorithms: ["Ed25519", "ML-DSA-65"],
      receiptDigest,
      canonicalReceipt: Buffer.from(canonicalReceipt).toString("base64url"),
      commandPath: false,
    }),
  });
  if (!response.ok) throw new Error("Signer rejected request");
  const signed = await boundedJson(response, MAX_SIGNER_BYTES);
  if (signed.receiptDigest !== receiptDigest || signed.signatureAlgorithm !== "Ed25519" ||
      signed.postQuantumAlgorithm !== "ML-DSA-65" || signed.commandPath !== false ||
      typeof signed.signature !== "string" || typeof signed.postQuantumSignature !== "string") {
    throw new Error("Signer response invalid");
  }
  return {
    receipt,
    signature: signed.signature,
    signatureAlgorithm: "Ed25519",
    postQuantumSignature: signed.postQuantumSignature,
  };
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "private, no-store, max-age=0");
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({ status: "blocked", commandPath: false });
  }
  if (!(await authenticateOsoix(req))) {
    return res.status(401).json({ status: "blocked", commandPath: false });
  }

  const issuedAt = new Date();
  const receipt = {
    schema: "osoix.assurance-receipt.v1",
    issuer: ISSUER,
    audience: "OSOIX",
    subject: SUBJECT,
    environment: process.env.VERCEL_ENV || process.env.NODE_ENV || "unknown",
    issuedAt: issuedAt.toISOString(),
    expiresAt: new Date(issuedAt.getTime() + 5 * 60_000).toISOString(),
    policyVersion: POLICY_VERSION,
    decision: DECISION,
    evidenceDigest: await sha256(canonicalJson(SOURCE_EVIDENCE)),
    commandPath: false,
    controls: CONTROLS,
  };

  try {
    return res.status(200).json(await signReceipt(receipt));
  } catch {
    return res.status(503).json({ status: "blocked", reason: "signer_unavailable", commandPath: false });
  }
}
