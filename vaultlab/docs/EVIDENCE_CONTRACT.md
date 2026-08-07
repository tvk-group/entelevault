# ChronoSeal and GraphVAULT evidence contract

## Published envelope

VaultLab converts a passing assurance report into a small evidence envelope containing:

- exact Git source revision;
- bounded runner identity;
- canonical SHA-256 digest of the complete report;
- report schema, generation time, control set, scope, and result;
- passed and failed control totals;
- explicit false declarations for fixture, credential, and wallet-material presence.

The envelope excludes the synthetic fixture identifier, fixture ciphertext, credential, decrypted specimen, individual test signals, environment variables, raw logs, wallet material, and exploit detail.

## Trust boundary

The local SHA-256 envelope binds evidence to content but does not prove who ran the job. A production ChronoSeal/GraphVAULT integration must add an independently reviewed identity and signing mechanism, protected signing keys, replay protection, idempotency, trusted time, revocation, retention, and verification procedure.

## Publication sequence

1. CI runs tests and creates a passing report.
2. The structured report policy validates the report.
3. The production-boundary gate confirms VaultLab absence from production source.
4. The evidence command binds the report to `GITHUB_SHA`.
5. A future evidence publisher verifies workload identity and submits only the envelope.
6. ChronoSeal timestamps the approved digest; GraphVAULT records scope and provenance relationships.
7. A human reviewer approves release or records a time-bounded exception.

VaultLab v0.2 creates the envelope but deliberately does not implement step 5 network publication.
