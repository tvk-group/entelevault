const RECEIPT_CONFIG = Object.freeze({
  issuer: 'custody',
  subject: 'entelevault-vaultlab-production-boundary',
  policyVersion: 'entelevault-synthetic-only-2026.08.08.v2',
  repository: 'entelevault',
  sourceEvidence: Object.freeze({
    system: 'EnteleVAULT',
    runtime: 'synthetic-assurance-boundary',
    productionCustody: false,
    realKeysAccepted: false,
    signingAuthority: false,
    assetMovementAuthority: false,
    reason: 'current-repository-is-assurance-lab-not-production-HSM-or-MPC-custody',
  }),
});
const EXPECTED_REPOSITORY = Object.freeze({
  owner: 'tvk-group',
  name: RECEIPT_CONFIG.repository,
  ref: 'main',
});
const OSOIX_IDENTITY = Object.freeze({
  issuer: 'https://oidc.vercel.com/tvk-group',
  jwksUrl: 'https://oidc.vercel.com/tvk-group/.well-known/jwks',
  audience: 'https://vercel.com/tvk-group',
  subject: 'owner:tvk-group:project:osoix:environment:production',
  owner: 'tvk-group',
  ownerId: 'team_MOHi5TFHhsgsCUm8qfCYpnf6',
  project: 'osoix',
  projectId: 'prj_eZx5KHE6d8xPZnJI1TSGHQ711FWb',
  environment: 'production',
});

const MAX_TOKEN_BYTES = 16 * 1024;
const MAX_JWKS_BYTES = 128 * 1024;
const MAX_SIGNER_BYTES = 64 * 1024;
const MAX_OIDC_LIFETIME_SECONDS = 65 * 60;
const CLOCK_SKEW_SECONDS = 60;
const JWKS_CACHE_MILLISECONDS = 5 * 60_000;
const ED25519_SIGNATURE_BYTES = 64;
const ML_DSA_65_SIGNATURE_BYTES = 3309;
const CHALLENGE_BYTES = 32;
const RECEIPT_ID_BYTES = 18;

let jwksCache = null;

function headerValue(req, name) {
  const value = req.headers?.[name.toLowerCase()];
  if (Array.isArray(value)) return value.length === 1 ? value[0] : '';
  return typeof value === 'string' ? value : '';
}

function getRuntimeIdentity(req) {
  const workloadToken = headerValue(req, 'x-vercel-oidc-token');
  const environment = process.env.VERCEL_ENV || '';
  const sourceRevision = process.env.VERCEL_GIT_COMMIT_SHA || '';
  const repositoryOwner = process.env.VERCEL_GIT_REPO_OWNER || '';
  const repositoryName = process.env.VERCEL_GIT_REPO_SLUG || '';
  const sourceRef = process.env.VERCEL_GIT_COMMIT_REF || '';
  const valid = Boolean(
    workloadToken &&
    Buffer.byteLength(workloadToken, 'utf8') <= MAX_TOKEN_BYTES &&
    environment === 'production' &&
    /^[a-f0-9]{40}$/i.test(sourceRevision) &&
    repositoryOwner === EXPECTED_REPOSITORY.owner &&
    repositoryName === EXPECTED_REPOSITORY.name &&
    sourceRef === EXPECTED_REPOSITORY.ref,
  );

  return {
    valid,
    workloadToken,
    evidence: {
      environment: environment || 'unknown',
      sourceRevision: sourceRevision || 'unknown',
      repositoryOwner: repositoryOwner || 'unknown',
      repositoryName: repositoryName || 'unknown',
      sourceRef: sourceRef || 'unknown',
      deploymentHost: process.env.VERCEL_URL || 'unknown',
      workloadIdentityPresent: Boolean(workloadToken),
      productionRevisionBound: valid,
    },
  };
}

function getControls(runtimeIdentity) {
  return {
    humanQuorum: false,
    hardwareBackedKeys: false,
    transactionSimulation: false,
    destinationPolicy: false,
    rateLimits: false,
    recoveryDrillCurrent: false,
    workloadIdentity: runtimeIdentity.valid,
    productionRevisionBound: runtimeIdentity.valid,
    cryptoInventoryComplete: false,
  };
}

function getDecision(controls) {
  return Object.values(controls).every(Boolean) ? 'allow' : 'deny';
}

function base64UrlBytes(value) {
  const normalized = value.replaceAll('-', '+').replaceAll('_', '/');
  return new Uint8Array(Buffer.from(normalized, 'base64'));
}

function decodeJwtPart(value) {
  const bytes = base64UrlBytes(value);
  if (bytes.byteLength > MAX_TOKEN_BYTES) throw new Error('JWT part too large');
  return JSON.parse(Buffer.from(bytes).toString('utf8'));
}

function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.entries(value)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`)
    .join(',')}}`;
}

async function sha256(value) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return Buffer.from(digest).toString('hex');
}

function safeHttpsUrl(value) {
  if (!value) return null;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && !url.username && !url.password ? url : null;
  } catch {
    return null;
  }
}

function getSignerUrl() {
  const signerUrl = safeHttpsUrl(process.env.ASSURANCE_SIGNER_URL);
  const allowedOrigin = safeHttpsUrl(process.env.ASSURANCE_SIGNER_ALLOWED_ORIGIN);
  if (
    !signerUrl ||
    !allowedOrigin ||
    allowedOrigin.href !== `${allowedOrigin.origin}/` ||
    signerUrl.origin !== allowedOrigin.origin ||
    signerUrl.pathname === '/' ||
    signerUrl.search ||
    signerUrl.hash
  ) {
    return null;
  }
  return signerUrl;
}

async function readBoundedBody(response, maximumBytes) {
  const declaredLength = response.headers.get('content-length');
  if (declaredLength !== null) {
    if (!/^\d+$/.test(declaredLength) || Number(declaredLength) > maximumBytes) {
      throw new Error('Response too large');
    }
  }
  if (!response.body) return '';

  const reader = response.body.getReader();
  const chunks = [];
  let totalBytes = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    totalBytes += value.byteLength;
    if (totalBytes > maximumBytes) {
      await reader.cancel().catch(() => undefined);
      throw new Error('Response too large');
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks, totalBytes).toString('utf8');
}

async function boundedJson(response, maximumBytes) {
  const contentType = (response.headers.get('content-type') || '').split(';', 1)[0].trim();
  if (contentType !== 'application/json' && contentType !== 'application/jwk-set+json') {
    throw new Error('Unexpected response content type');
  }
  return JSON.parse(await readBoundedBody(response, maximumBytes));
}

function validOsoixClaims(payload, now) {
  const validAudience =
    payload.aud === OSOIX_IDENTITY.audience ||
    (Array.isArray(payload.aud) && payload.aud.includes(OSOIX_IDENTITY.audience));
  return Boolean(
    payload.iss === OSOIX_IDENTITY.issuer &&
    validAudience &&
    payload.sub === OSOIX_IDENTITY.subject &&
    payload.owner === OSOIX_IDENTITY.owner &&
    payload.owner_id === OSOIX_IDENTITY.ownerId &&
    payload.project === OSOIX_IDENTITY.project &&
    payload.project_id === OSOIX_IDENTITY.projectId &&
    payload.environment === OSOIX_IDENTITY.environment &&
    Number.isFinite(payload.iat) &&
    payload.iat >= now - MAX_OIDC_LIFETIME_SECONDS &&
    payload.iat <= now + CLOCK_SKEW_SECONDS &&
    Number.isFinite(payload.exp) &&
    payload.exp > now &&
    payload.exp - payload.iat <= MAX_OIDC_LIFETIME_SECONDS &&
    (!Number.isFinite(payload.nbf) || payload.nbf <= now + CLOCK_SKEW_SECONDS),
  );
}

async function loadJwks(forceRefresh = false) {
  if (!forceRefresh && jwksCache?.expiresAt > Date.now()) return jwksCache.value;
  const response = await fetch(OSOIX_IDENTITY.jwksUrl, {
    cache: 'no-store',
    redirect: 'error',
    signal: AbortSignal.timeout(3_000),
    headers: { Accept: 'application/jwk-set+json, application/json' },
  });
  if (!response.ok) throw new Error('JWKS unavailable');
  const jwks = await boundedJson(response, MAX_JWKS_BYTES);
  if (!Array.isArray(jwks.keys) || jwks.keys.length > 32) throw new Error('JWKS invalid');
  jwksCache = { value: jwks, expiresAt: Date.now() + JWKS_CACHE_MILLISECONDS };
  return jwks;
}

async function authenticateOsoix(req) {
  if (headerValue(req, 'x-osoix-purpose') !== 'read-only-assurance') return false;
  const authorization = headerValue(req, 'authorization');
  const token = authorization.startsWith('Bearer ') ? authorization.slice(7) : '';
  if (!token || Buffer.byteLength(token, 'utf8') > MAX_TOKEN_BYTES) return false;

  try {
    const parts = token.split('.');
    if (parts.length !== 3) return false;
    const header = decodeJwtPart(parts[0]);
    const payload = decodeJwtPart(parts[1]);
    const now = Math.floor(Date.now() / 1000);
    if (
      header.alg !== 'RS256' ||
      String(header.typ || '').toUpperCase() !== 'JWT' ||
      typeof header.kid !== 'string' ||
      !/^[A-Za-z0-9._-]{1,128}$/.test(header.kid) ||
      !validOsoixClaims(payload, now)
    ) {
      return false;
    }

    let jwks = await loadJwks();
    let jwk = jwks.keys.find(
      (candidate) =>
        candidate.kid === header.kid &&
        candidate.kty === 'RSA' &&
        (!candidate.use || candidate.use === 'sig') &&
        (!candidate.alg || candidate.alg === 'RS256'),
    );
    if (!jwk) {
      jwks = await loadJwks(true);
      jwk = jwks.keys.find(
        (candidate) =>
          candidate.kid === header.kid &&
          candidate.kty === 'RSA' &&
          (!candidate.use || candidate.use === 'sig') &&
          (!candidate.alg || candidate.alg === 'RS256'),
      );
    }
    if (!jwk) return false;

    const key = await crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify'],
    );
    return crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5',
      key,
      base64UrlBytes(parts[2]),
      new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
    );
  } catch {
    return false;
  }
}

function isCanonicalBase64Url(value, expectedBytes) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) return false;
  try {
    const decoded = Buffer.from(value, 'base64url');
    return decoded.byteLength === expectedBytes && decoded.toString('base64url') === value;
  } catch {
    return false;
  }
}

function validIdentifier(value) {
  return typeof value === 'string' && /^[A-Za-z0-9._:/-]{1,128}$/.test(value);
}

function randomIdentifier() {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(RECEIPT_ID_BYTES))).toString(
    'base64url',
  );
}

async function signReceipt(receipt, runtimeIdentity) {
  const signerUrl = getSignerUrl();
  if (!signerUrl || !runtimeIdentity.valid) throw new Error('Signer unavailable');
  const canonicalReceipt = canonicalJson(receipt);
  const receiptDigest = await sha256(canonicalReceipt);
  const response = await fetch(signerUrl, {
    method: 'POST',
    cache: 'no-store',
    redirect: 'error',
    signal: AbortSignal.timeout(4_000),
    headers: {
      Authorization: `Bearer ${runtimeIdentity.workloadToken}`,
      'x-vercel-trusted-oidc-idp-token': runtimeIdentity.workloadToken,
      'Content-Type': 'application/json',
      Accept: 'application/json',
      'X-OSOIX-Purpose': 'assurance-receipt-signing',
    },
    body: JSON.stringify({
      schema: 'osoix.assurance-signing-request.v2',
      keyPurpose: `${RECEIPT_CONFIG.issuer}-assurance-receipt`,
      algorithms: ['Ed25519', 'ML-DSA-65'],
      receiptDigest,
      canonicalReceipt: Buffer.from(canonicalReceipt).toString('base64url'),
      sourceRevision: runtimeIdentity.evidence.sourceRevision,
      commandPath: false,
    }),
  });
  if (!response.ok) throw new Error('Signer rejected request');
  const signed = await boundedJson(response, MAX_SIGNER_BYTES);
  const signedAt = Date.parse(signed.signedAt);
  const now = Date.now();
  if (
    signed.receiptDigest !== receiptDigest ||
    signed.signatureAlgorithm !== 'Ed25519' ||
    signed.postQuantumAlgorithm !== 'ML-DSA-65' ||
    signed.commandPath !== false ||
    !isCanonicalBase64Url(signed.signature, ED25519_SIGNATURE_BYTES) ||
    !isCanonicalBase64Url(signed.postQuantumSignature, ML_DSA_65_SIGNATURE_BYTES) ||
    !validIdentifier(signed.keyId) ||
    !validIdentifier(signed.postQuantumKeyId) ||
    !validIdentifier(signed.signingPolicyVersion) ||
    !['hsm', 'cloud-hsm', 'managed-kms', 'mpc'].includes(signed.keyProtection) ||
    !Number.isFinite(signedAt) ||
    Math.abs(signedAt - now) > CLOCK_SKEW_SECONDS * 1000 ||
    signedAt > Date.parse(receipt.expiresAt)
  ) {
    throw new Error('Signer response invalid');
  }
  return {
    receipt,
    receiptDigest,
    signature: signed.signature,
    signatureAlgorithm: 'Ed25519',
    keyId: signed.keyId,
    postQuantumSignature: signed.postQuantumSignature,
    postQuantumAlgorithm: 'ML-DSA-65',
    postQuantumKeyId: signed.postQuantumKeyId,
    keyProtection: signed.keyProtection,
    signingPolicyVersion: signed.signingPolicyVersion,
    signedAt: signed.signedAt,
  };
}

function setResponseHeaders(res) {
  res.setHeader('Cache-Control', 'private, no-store, max-age=0');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Vary', 'Authorization, x-osoix-purpose, x-osoix-challenge');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
}

export default async function handler(req, res) {
  setResponseHeaders(res);
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ status: 'blocked', commandPath: false });
  }
  const challenge = headerValue(req, 'x-osoix-challenge');
  if (!isCanonicalBase64Url(challenge, CHALLENGE_BYTES)) {
    return res.status(400).json({
      status: 'blocked',
      reason: 'invalid_challenge',
      commandPath: false,
    });
  }
  if (!(await authenticateOsoix(req))) {
    return res.status(401).json({ status: 'blocked', commandPath: false });
  }

  const runtimeIdentity = getRuntimeIdentity(req);
  if (!runtimeIdentity.valid) {
    return res.status(503).json({
      status: 'blocked',
      reason: 'runtime_identity_unavailable',
      commandPath: false,
    });
  }

  const controls = getControls(runtimeIdentity);
  const issuedAt = new Date();
  const sourceEvidence = {
    ...RECEIPT_CONFIG.sourceEvidence,
    deployment: runtimeIdentity.evidence,
  };
  const receipt = {
    schema: 'osoix.assurance-receipt.v2',
    receiptId: randomIdentifier(),
    challenge,
    purpose: 'read-only-assurance',
    issuer: RECEIPT_CONFIG.issuer,
    audience: 'OSOIX',
    subject: RECEIPT_CONFIG.subject,
    environment: runtimeIdentity.evidence.environment,
    sourceRevision: runtimeIdentity.evidence.sourceRevision,
    issuedAt: issuedAt.toISOString(),
    expiresAt: new Date(issuedAt.getTime() + 5 * 60_000).toISOString(),
    policyVersion: RECEIPT_CONFIG.policyVersion,
    decision: getDecision(controls),
    evidenceDigest: await sha256(canonicalJson(sourceEvidence)),
    commandPath: false,
    controls,
  };

  try {
    return res.status(200).json(await signReceipt(receipt, runtimeIdentity));
  } catch {
    return res
      .status(503)
      .json({ status: 'blocked', reason: 'signer_unavailable', commandPath: false });
  }
}
