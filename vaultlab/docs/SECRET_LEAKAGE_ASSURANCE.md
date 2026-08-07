# Secret-leakage assurance

This gate evaluates sanitized evidence that secret-detection and redaction controls ran across release artifacts and approved observability surfaces. VaultLab never receives the material that was scanned.

## Required controls

Eligibility requires all twelve controls: structured-log, trace, crash-report, build-artifact, support-export, and client-telemetry scans; high-entropy and secret-pattern detection; redaction verification; canary detection; a pinned scanner ruleset; and independent review.

All credential, token, key-material, wallet-material, and unclassified-entropy finding counts must be zero. The 4,096 possible control combinations are tested; only the all-satisfied set is eligible for independent review.

## Boundary

Inputs contain classifications, counts, revisions, and digests only. Raw logs, traces, crash content, credentials, tokens, keys, wallet data, payloads, identities, addresses, transactions, and commands are rejected.

The decision cannot revoke credentials, delete artifacts, grant access, remediate, deploy, sign, or move assets.
