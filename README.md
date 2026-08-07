# EnteleVAULT

EnteleVAULT is the security and privacy vault layer for the EnteleKRON ecosystem. The product direction covers identity, credentials, encrypted records, policy-controlled access, and integration with EnteleCLOS, ChronoSeal, and GraphVAULT.

## Current status

This repository is an early product and assurance foundation. It is not yet a production cryptocurrency custodian, wallet, HSM, MPC signer, password-recovery service, or audited secret-storage product. Do not store production keys, seeds, customer wallet files, recovery phrases, or regulated records in the current implementation.

## VaultLab

[`vaultlab/`](./vaultlab/) is the synthetic and sanitized-metadata-only EnteleVAULT assurance harness. It provides:

- strict synthetic artifact policy and rejection of wallet-shaped inputs;
- scrypt policy bounds and downgrade rejection;
- AES-256-GCM authenticated-encryption checks on generated non-value specimens;
- corruption, parser, error-redaction, and secret-leakage controls;
- a machine-readable CI assurance report;
- explicit rejection of password lists, bulk candidates, targets, wallet imports, mnemonics, seeds, addresses, signing, and network operations.
- production-source exclusion checks for VaultLab imports, fixtures, and test credentials;
- revision-bound, publishable evidence envelopes for future ChronoSeal/GraphVAULT integration;
- recommendation-only security-agent policy with no execution, signing, deployment, or asset authority;
- sanitized signing-intent decisions that always require a human and never receive raw transaction data;
- append-only recovery governance with independent legal, security, and custody quorum;
- a staging-only native-custody readiness gate that exhaustively tests all 4,096 combinations of twelve release controls;
- a sanitized EnteleEXCHANGE withdrawal guard with no hold or withdrawal authority;
- a fourteen-control release-provenance gate with all 16,384 combinations tested;
- a one-way incident lifecycle with monotonic evidence and independent closure quorum.
- a sanitized privileged-access guard for JIT, session, SoD, scope, change-window, and dual-approval evidence;
- a fourteen-control exchange ledger-integrity gate with all 16,384 combinations tested and no solvency claim;
- forward-only break-glass governance that never grants access or starts sessions.
- a sanitized API/session guard for client registration, mTLS, request signing, replay, rate, idempotency, revocation, lifetime, and approval evidence;
- forward-only HSM/MPC signer-ceremony governance that never receives shares or activates a signer;
- a fourteen-control resilience gate with all 16,384 combinations tested and no restoration or failover authority.
- a twelve-control secret-leakage gate with all 4,096 combinations tested and no access to scanned content;
- a fourteen-control immutable-audit gate with all 16,384 combinations tested and no log-read, write, or deletion authority;
- forward-only, time-bounded security-exception governance with no critical-risk waivers or policy-bypass authority.

VaultLab never receives raw production data. It runs in an isolated CI/staging test cell; production-observation policy calls contain only exact sanitized metadata and evidence digests. VaultLab produces redacted assurance results and is excluded from production bundles.

## Security architecture

- EnteleVAULT owns vault and access-control implementations.
- EnteleCLOS owns assurance cases, control evidence, incident workflow, and independent-review records.
- ChronoSeal records approved evidence digests and timestamps.
- GraphVAULT records provenance and authorization relationships without receiving secret material.
- EnteleWALLET and EnteleEXCHANGE consume only independently reviewed custody and signing services; they do not inherit experimental VaultLab code.

See:

- [VaultLab security boundary](./vaultlab/docs/SECURITY_BOUNDARY.md)
- [EnteleVAULT integration contract](./vaultlab/docs/INTEGRATION.md)
- [Wallet and exchange threat model](./vaultlab/docs/THREAT_MODEL.md)
- [Security assurance platform roadmap](./vaultlab/docs/PLATFORM_ROADMAP.md)
- [Security-agent boundary](./vaultlab/docs/AGENT_BOUNDARY.md)
- [Evidence contract](./vaultlab/docs/EVIDENCE_CONTRACT.md)
- [Signing-intent guard](./vaultlab/docs/SIGNING_INTENT_GUARD.md)
- [Recovery governance](./vaultlab/docs/RECOVERY_GOVERNANCE.md)
- [Native-custody readiness](./vaultlab/docs/NATIVE_CUSTODY_READINESS.md)
- [Exchange withdrawal policy guard](./vaultlab/docs/WITHDRAWAL_POLICY_GUARD.md)
- [Release provenance gate](./vaultlab/docs/RELEASE_PROVENANCE_GATE.md)
- [Incident governance](./vaultlab/docs/INCIDENT_GOVERNANCE.md)
- [Privileged-access guard](./vaultlab/docs/PRIVILEGED_ACCESS_GUARD.md)
- [Ledger-integrity gate](./vaultlab/docs/LEDGER_INTEGRITY_GATE.md)
- [Break-glass governance](./vaultlab/docs/BREAK_GLASS_GOVERNANCE.md)
- [API and session security](./vaultlab/docs/API_SESSION_SECURITY.md)
- [Signer-ceremony governance](./vaultlab/docs/SIGNER_CEREMONY_GOVERNANCE.md)
- [Resilience readiness](./vaultlab/docs/RESILIENCE_READINESS.md)
- [Secret-leakage assurance](./vaultlab/docs/SECRET_LEAKAGE_ASSURANCE.md)
- [Immutable-audit integrity readiness](./vaultlab/docs/AUDIT_INTEGRITY_READINESS.md)
- [Security-exception governance](./vaultlab/docs/SECURITY_EXCEPTION_GOVERNANCE.md)
- [Machine-readable control catalog](./vaultlab/controls/vaultlab-controls.json)
- [Security policy](./SECURITY.md)

## Development

```bash
cd vaultlab
npm ci
npm test
npm run assure
npm run policy:assure
npm run verify:production-boundary
```

Node.js 22 or later is required. No runtime dependency is used by VaultLab.

## Production gate

No claim of “unhackable,” “perfect,” guaranteed recovery, or absolute security is permitted. Production readiness requires threat modeling, cryptography review, mobile/web/API penetration testing, HSM/MPC and key-ceremony review, privacy/compliance assessment, incident exercises, signed release provenance, and remediation of all release-blocking findings.
