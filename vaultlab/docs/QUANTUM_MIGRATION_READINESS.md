# Quantum-migration readiness

This gate verifies migration governance for cryptographic systems that may be affected by future cryptanalytic or quantum-capable adversaries. It does not claim that a system is quantum-safe, select or implement a post-quantum primitive, perform cryptography, or authorize a production migration.

Eligibility requires all fourteen controls: a complete classical-algorithm inventory, long-lived-data exposure assessment, asymmetric-dependency map, approved standards profile, reviewed library roadmap, versioned protocol negotiation, verified crypto-agility interfaces, reviewed hybrid migration plan, rollback/interoperability plan, material lifecycle plan, data-format migration plan, supply-chain compatibility review, independent cryptography review, and an explicit prohibition on custom cryptography.

Critical/high findings, inventory gaps, unreviewed dependencies, and interoperability failures must be zero. Every one of the 16,384 control combinations is evaluated; only the fully satisfied combination is eligible for independent review.

Inputs contain classifications, aggregate counts, source revisions, and SHA-256 digests only. Operational data and secret material are rejected. The decision always records `quantumSafetyClaimed: false` and cannot migrate algorithms, activate custody, deploy, sign, or move assets.
