# VaultLab security boundary

## Mission

VaultLab gives the EnteleKRON ecosystem a repeatable way to prove that cryptographic, parser, policy, readiness, provenance, and governance controls fail safely. It is an assurance component, not a recovery, custody, signing, deployment, exchange-operations, or incident-response component.

## Allowed inputs

- internally generated VaultLab fixtures bearing the exact synthetic schema;
- one in-memory test credential created for that fixture;
- fixed, allowlisted corruption names;
- bounded KDF-policy configuration maintained in source control.
- exact versioned policy objects containing only sanitized classifications, booleans, counts, pseudonymous identifiers, timestamps, allowlisted enums, source revisions, and SHA-256 evidence digests.

## Rejected inputs

- paths, uploads, URLs, archives, removable media, and arbitrary JSON;
- Ethereum, Bitcoin, Solana, hardware-wallet, browser-wallet, exchange, or vendor keystore formats;
- mnemonics, seeds, private keys, derivation paths, public addresses, signatures, or transaction data;
- arrays, streams, dictionaries, password lists, candidate generators, personal clues, or target profiles;
- GPU kernels, distributed workers, RPC endpoints, chain broadcasters, or signing providers.

## Fail-closed invariants

1. The parser accepts only an exact schema and rejects unknown fields.
2. KDF values below or above policy are rejected before derivation.
3. Only one credential is accepted per API call; arrays are rejected.
4. Authentication, attestation, mutation, and parsing errors expose stable codes, not underlying secrets.
5. Decrypted specimens are zeroed after verification and are never returned.
6. Reports contain no credential, plaintext, key, seed, wallet address, or candidate information.
7. The package has no network or filesystem import API.
8. Policy decisions never activate or distribute clients, execute updates, access devices, store keys, publish prices, trade, execute orders, mutate risk limits, generate traffic, run chaos, execute API requests, grant access, start sessions, run ceremonies, generate keys, activate signers, read/write/delete audit records, revoke credentials, delete artifacts, grant security exceptions, bypass policy, remediate, restore, fail over, mutate data or balances, make financial claims, hold, contain, execute revocation, withdraw, sign, deploy, activate custody, or move assets.
9. Unknown fields, missing evidence, incomplete controls, backward transitions, and prohibited payload shapes fail closed.

## Trust limitation

The embedded fixture attestation detects mutation during a test flow; it is not a production signature and does not establish legal provenance. Production evidence signing belongs in ChronoSeal/GraphVAULT under a separately reviewed key-management design.
