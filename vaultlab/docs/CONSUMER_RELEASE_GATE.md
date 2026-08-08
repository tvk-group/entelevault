# Consumer release gate

The consumer release gate connects EnteleVAULT assurance evidence to EnteleWALLET and EnteleEXCHANGE CI without placing VaultLab in an application runtime or custody path.

Each consumer pins one immutable EnteleVAULT commit, generates a fresh sanitized platform-policy report, and verifies a strict repository-owned manifest against the exact GitHub revision under test. A passing result creates a digest-bound attestation and makes the revision eligible for human release review. It does not deploy, activate custody, sign, trade, withdraw, or move assets.

The verifier fails closed when the repository, source revision, policy revision, report freshness, report schema, aggregate check set, custody boundary, zero-finding policy, or cryptography-migration governance differs from the manifest. Consumer manifests explicitly prohibit custom cryptography and automatic post-quantum migration. “Governance present” is not a quantum-safety claim.

The report and attestation contain identifiers, revisions, timestamps, aggregate status, and SHA-256 digests only. Consumer CI must never provide keys, seeds, wallet files, credentials, customer data, transaction payloads, or custody material to this gate.
