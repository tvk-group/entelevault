# EnteleVAULT

EnteleVAULT is the security and privacy vault layer for the EnteleKRON ecosystem. The product direction covers identity, credentials, encrypted records, policy-controlled access, and integration with EnteleCLOS, ChronoSeal, and GraphVAULT.

## Current status

This repository is an early product and assurance foundation. It is not yet a production cryptocurrency custodian, wallet, HSM, MPC signer, password-recovery service, or audited secret-storage product. Do not store production keys, seeds, customer wallet files, recovery phrases, or regulated records in the current implementation.

## VaultLab

[`vaultlab/`](./vaultlab/) is the synthetic-only EnteleVAULT cryptographic assurance harness. It provides:

- strict synthetic artifact policy and rejection of wallet-shaped inputs;
- scrypt policy bounds and downgrade rejection;
- AES-256-GCM authenticated-encryption checks on generated non-value specimens;
- corruption, parser, error-redaction, and secret-leakage controls;
- a machine-readable CI assurance report;
- explicit rejection of password lists, bulk candidates, targets, wallet imports, mnemonics, seeds, addresses, signing, and network operations.

VaultLab never receives production data. It runs in an isolated CI/staging test cell, produces a redacted assurance result, and is excluded from production bundles.

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
- [Security policy](./SECURITY.md)

## Development

```bash
cd vaultlab
npm ci
npm test
npm run assure
```

Node.js 22 or later is required. No runtime dependency is used by VaultLab.

## Production gate

No claim of “unhackable,” “perfect,” guaranteed recovery, or absolute security is permitted. Production readiness requires threat modeling, cryptography review, mobile/web/API penetration testing, HSM/MPC and key-ceremony review, privacy/compliance assessment, incident exercises, signed release provenance, and remediation of all release-blocking findings.
