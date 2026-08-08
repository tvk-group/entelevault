# Assurance signer gateway conformance policy

This VaultLab policy validates sanitized metadata for the future OSOIX assurance-receipt signer boundary. It is a conformance and release-blocking policy, not a signer, gateway, key service, credential verifier, deployment tool, or production runtime.

The policy binds four exact Vercel production workload identities to separate receipt purposes:

- EnteleWALLET → `wallet-assurance-receipt`;
- EnteleEXCHANGE → `exchange-assurance-receipt`;
- EnteleVAULT → `custody-assurance-receipt`;
- EnteleCLOS → `cloud-assurance-receipt`.

Review eligibility requires the fixed `osoix.assurance-signing-request.v2` contract, `POST`, the exact assurance-signing purpose, Ed25519 plus ML-DSA-65 algorithm intent, an exact source revision, evidence that the canonical receipt parsed exactly, a recomputed receipt digest, a canonical 32-byte OSOIX request challenge, a unique 18-byte receipt ID, the exact `read-only-assurance` receipt purpose, a fresh five-minute `osoix.assurance-receipt.v2` deny receipt, no command path, TLS 1.3, redirect rejection, JSON-only bounded bodies, Trusted Sources evidence, fresh challenge and unique receipt-ID state, new idempotency state, enforced rate limits, hardware-backed non-exportable purpose-isolated keys, an available audit sink, and independent provider assessment.

The current policy deliberately permits only `deny` receipts to become review-eligible. A v1 request or receipt, `allow` receipt, malformed/mismatched/replayed challenge, duplicate receipt ID, non-canonical receipt, generic signing purpose, arbitrary payload, key-purpose confusion, source mismatch, provider downgrade, or missing evidence is blocked.

`ELIGIBLE_FOR_SEPARATE_SIGNER_IMPLEMENTATION_REVIEW` is evidence for a separate human and independent review. It does not authorize deployment, request execution, signing, cryptographic operations, key generation, key export, custody, trading, withdrawal, or asset movement.

VaultLab never receives runtime bearer tokens, credentials, private keys, key shares, wallet files, seed phrases, transactions, production signatures, or arbitrary signing payloads. A production signer must be separately hosted and administered behind an approved zero-trust gateway and independently assessed HSM, Cloud HSM, managed KMS, or MPC service.
