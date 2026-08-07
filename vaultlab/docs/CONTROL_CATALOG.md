# VaultLab control catalog

The authoritative machine-readable catalog is [`controls/vaultlab-controls.json`](../controls/vaultlab-controls.json).

All current controls are release-blocking. They cover authenticated encryption, wrong-credential failure, KDF bounds, parser restrictions, corruption handling, report redaction, production exclusion, recommendation-only agents, prohibited event fields, revision-bound evidence, sanitized signing intent, recovery governance, native-custody readiness, withdrawal policy, release provenance, incident governance, privileged access, ledger integrity, break-glass governance, API/session security, signer ceremonies, and resilience.

VaultLab v0.6 contains 34 controls. The consolidated platform-policy report records twelve aggregate checks and exhaustively enumerates 4,096 custody-control plus 16,384 each for release provenance, ledger integrity, and resilience—53,248 combinations total. Aggregate PASS is evidence for review, never proof of solvency or permission to execute API requests, grant access, start sessions, run signer ceremonies, activate signers, restore, fail over, mutate data or balances, trade, hold, contain, revoke, withdraw, sign, deploy, activate custody, or move assets.

Baseline mappings to NIST SSDF, OWASP ASVS, OWASP MASVS, and CCSS identify frameworks for later traceability. They do not claim certification or complete compliance. Exact framework versions, requirement identifiers, applicability, evidence, assessor, exceptions, and retest dates must be added during the independent assurance program.
