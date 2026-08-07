# VaultLab control catalog

The authoritative machine-readable catalog is [`controls/vaultlab-controls.json`](../controls/vaultlab-controls.json).

All current controls are release-blocking. They cover authenticated encryption, wrong-credential failure, KDF bounds, parser restrictions, corruption handling, report redaction, production exclusion, recommendation-only agents, prohibited event fields, revision-bound evidence, sanitized signing intent, recovery governance, and native-custody readiness.

VaultLab v0.3 contains 16 controls. The consolidated platform-policy report records three aggregate checks: signing cases, recovery cases, and exhaustive enumeration of all 4,096 custody-control combinations. Aggregate PASS is evidence for review, never permission to sign, deploy, activate custody, or move assets.

Baseline mappings to NIST SSDF, OWASP ASVS, OWASP MASVS, and CCSS identify frameworks for later traceability. They do not claim certification or complete compliance. Exact framework versions, requirement identifiers, applicability, evidence, assessor, exceptions, and retest dates must be added during the independent assurance program.
