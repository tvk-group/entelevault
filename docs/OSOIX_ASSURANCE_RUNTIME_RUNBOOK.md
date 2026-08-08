# OSOIX Assurance Runtime Runbook

Status: production integration contract; deny-only until all activation prerequisites are independently proven.

## Purpose and authority boundary

The OSOIX assurance fabric may request short-lived, read-only evidence from EnteleVAULT,
EnteleWALLET, EnteleEXCHANGE, and EnteleCLOS. The adapters never accept commands, private keys,
seed phrases, wallet files, orders, withdrawals, transaction payloads, or customer data.

A signed receipt is evidence for an OSOIX decision engine. It is not authorization to deploy,
activate custody, enable trading, sign a transaction, or move assets. Missing identity, revision,
signer, signature, policy, or freshness evidence must produce `401`, `503`, or a signed `deny`.
There is no bypass-to-allow mode.

## Stable Vercel identities

Use Vercel Team issuer mode with owner `tvk-group` and owner ID
`team_MOHi5TFHhsgsCUm8qfCYpnf6`.

| System         | Vercel project     | Project ID                         | Expected Git repository      |
| -------------- | ------------------ | ---------------------------------- | ---------------------------- |
| OSOIX caller   | `osoix`            | `prj_eZx5KHE6d8xPZnJI1TSGHQ711FWb` | `tvk-group/osoix`            |
| EnteleVAULT    | `entelevault`      | `prj_lVL6JHyySLVzkLhG3AmML0y6deZc` | `tvk-group/entelevault`      |
| EnteleWALLET   | `entelewallet-app` | `prj_BzvQEtgeP5oTsWeYxmlhzGMUfwNI` | `tvk-group/entelewallet-app` |
| EnteleEXCHANGE | `enteleexchange`   | `prj_34FPbar6y63CISVsUg1HXnv81dF7` | `tvk-group/enteleexchange`   |
| EnteleCLOS     | `enteleclos`       | `prj_V9rcuB81fJimWQRb46dNjeOpEfb7` | `tvk-group/enteleclos`       |

The adapters accept only the OSOIX production identity:

- issuer: `https://oidc.vercel.com/tvk-group`
- audience: `https://vercel.com/tvk-group`
- subject: `owner:tvk-group:project:osoix:environment:production`
- stable owner ID: `team_MOHi5TFHhsgsCUm8qfCYpnf6`
- stable project ID: `prj_eZx5KHE6d8xPZnJI1TSGHQ711FWb`
- environment: `production`

Names and IDs are both checked. A rename or project replacement therefore fails closed until a
reviewed code and policy update deliberately changes the trust relationship.

## Required Vercel configuration

For every consumer project:

1. In **Project → Settings → Security → Secure backend access with OIDC federation**, select
   **Team issuer mode**.
2. Keep automatic system environment variables available at runtime. The adapter requires:
   `VERCEL_ENV`, `VERCEL_GIT_COMMIT_SHA`, `VERCEL_GIT_REPO_OWNER`,
   `VERCEL_GIT_REPO_SLUG`, and `VERCEL_GIT_COMMIT_REF`.
3. Production receipts are valid only for `main`, the exact expected repository, and a full
   40-character Git commit SHA.
4. Configure encrypted production variables:
   - `ASSURANCE_SIGNER_URL`: exact HTTPS signer endpoint, including its non-root path.
   - `ASSURANCE_SIGNER_ALLOWED_ORIGIN`: origin only, for example
     `https://assurance-signer.example.com`.
5. Do not configure `ASSURANCE_SIGNER_TOKEN`. Persistent signer credentials are prohibited.

The runtime workload token comes from the Vercel-injected `x-vercel-oidc-token` request header.
The adapter forwards it to the signer as both an application bearer token and
`x-vercel-trusted-oidc-idp-token`. It must never be logged, persisted, placed in a response, or
copied into a long-lived environment variable.

## Trusted Sources policy on the signer

Place the signer behind Vercel Deployment Protection or an equivalent zero-trust gateway. Its
Trusted Sources policy must allow only the four source project IDs above, each from
`environment:production` to signer `environment:production`.

Do not authorize preview, development, wildcard owners, wildcard projects, or name-only matches.
The signer must independently verify the Vercel issuer, audience, subject, owner ID, project ID,
environment, token lifetime, signing purpose, receipt issuer, and key purpose.

## Signing request contract

The signer accepts only `POST` with:

- schema `osoix.assurance-signing-request.v1`
- purpose `assurance-receipt-signing`
- `commandPath:false`
- algorithms exactly `Ed25519` and `ML-DSA-65`
- a 64-character lowercase SHA-256 `receiptDigest`
- base64url canonical receipt bytes
- an exact 40-character `sourceRevision`
- a key purpose dedicated to the receipt issuer

Before signing, the signer must decode the canonical receipt, recompute its digest, and require:

- the digest and source revision match the request;
- `issuedAt` is recent and `expiresAt` is no more than five minutes later;
- audience is `OSOIX` and `commandPath` is false;
- environment is production;
- issuer, subject, repository, and policy version are allowlisted;
- decision and controls comply with the signer policy;
- the receipt digest has not already been processed outside the permitted idempotency window.

Reject unknown fields when they would broaden authority. Never normalize or silently repair a
malformed request before signing.

## Key protection and separation

Use a separately administered HSM, Cloud HSM, managed KMS with hardware-backed keys, or reviewed
MPC service. Private keys must never enter GitHub, Vercel environment variables, application
logs, build artifacts, databases, or developer workstations.

Maintain separate key purposes for:

- `custody-assurance-receipt`
- `wallet-assurance-receipt`
- `exchange-assurance-receipt`
- `cloud-assurance-receipt`

Maintain separate Ed25519 and ML-DSA-65 key identifiers for each purpose. The signer response must
contain canonical base64url signatures, key IDs, key-protection class, signing-policy version, and
a fresh `signedAt` time. OSOIX must verify both signatures and the receipt digest before accepting
evidence. A post-quantum signature is migration evidence, not a claim that the whole system is
quantum-safe.

Rotation procedure:

1. Generate replacement keys inside the approved key boundary.
2. Publish new public verification material before first use.
3. Allow a short verification-only overlap for the retiring key.
4. Switch signing to the new key IDs through a four-person-reviewed policy change.
5. Revoke the old signing permission, retain verification material for the evidence-retention
   period, and record the ceremony.
6. Test valid, expired, wrong-key, wrong-project, and revoked-key receipts.

## Availability, rate limiting, and replay protection

Apply per-project and per-key-purpose rate limits at both the gateway and signer. Alert on:

- authentication failures;
- project, environment, or revision mismatches;
- excessive JWKS refreshes;
- signer-origin rejections;
- digest replays;
- invalid signature sizes or algorithms;
- clock skew;
- unexpected `allow` decisions;
- any command method.

Use a bounded idempotency store keyed by receipt digest and key purpose. Store no workload tokens
or canonical receipt bodies when a digest and minimal audit metadata are sufficient.

If the primary signer or its audit sink is unavailable, the adapters return `503` and OSOIX must
deny. A secondary signer may be used only when it has an independently protected key set, the same
policy revision, synchronized revocation state, and a tested failover ceremony. Never fall back to
software keys or persistent bearer tokens.

## Activation prerequisites

An adapter may not produce `allow` until independent evidence proves every control:

1. human quorum and separation of duties;
2. hardware-backed signing keys;
3. transaction simulation where transactions exist;
4. destination and allowlist policy;
5. enforced rate limits;
6. current recovery drill;
7. verified workload identity and exact production revision;
8. complete cryptographic inventory and approved migration plan.

EnteleVAULT remains a synthetic assurance boundary, EnteleWALLET remains external-wallet-only,
EnteleEXCHANGE execution and custody remain disabled, and EnteleCLOS remains observation-only.
Changing those statements requires a separate architecture review, threat model, provider
selection, legal/compliance approval, external assessment, and controlled activation ceremony.

## Verification checklist

For each production adapter:

1. Unauthenticated `GET` is blocked by Deployment Protection or returns `401`.
2. Wrong purpose, issuer, audience, subject, owner ID, project ID, or environment returns `401`.
3. Correct OSOIX identity with missing runtime identity returns `503`.
4. Preview, non-main, wrong repository, or malformed revision returns `503`.
5. Wrong signer origin, redirect, content type, oversized response, stale signer time, wrong key
   ID, or wrong signature size returns `503`.
6. `POST` and every command method return `405` with `commandPath:false`.
7. Fully configured production access returns a short-lived signed `deny` receipt until all eight
   activation controls are independently proven.
8. OSOIX rejects an expired receipt, a changed receipt body, either invalid signature, an unknown
   key ID, an unapproved policy version, or a source-revision mismatch.

Record the exact Git commit, Vercel deployment ID, test evidence, approvers, signer policy version,
and key IDs for every production change. Receipts and audit records must contain no secrets.
