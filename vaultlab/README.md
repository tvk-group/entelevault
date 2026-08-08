# EnteleVAULT VaultLab

VaultLab is a fail-closed, synthetic and sanitized-metadata-only assurance harness for EnteleVAULT and the wider EnteleCLOS security program. It tests defensive controls without accepting, deriving, recovering, or operating blockchain keys.

## What it tests

- authenticated-encryption round trips on generated non-value specimens;
- wrong-credential rejection and redacted errors;
- KDF minimums, maximums, and downgrade resistance;
- corrupted ciphertext, authentication tags, and metadata;
- strict parsing, size limits, nesting limits, and unknown-field rejection;
- rejection of bulk artifacts, password candidate lists, wallet-shaped input, targets, mnemonics, seeds, addresses, and key material;
- secret-free machine-readable assurance reports suitable for CI;
- proof that production source does not import VaultLab or contain fixture markers;
- revision-bound evidence envelopes for ChronoSeal/GraphVAULT publication;
- recommendation-only security-agent decisions with no signing, execution, or asset authority;
- sanitized signing-intent policy that blocks unsafe classifications without receiving raw transactions;
- append-only recovery governance with independent legal, security, and custody quorum;
- a staging-only native-custody readiness gate with exhaustive 12-control evaluation;
- sanitized withdrawal policy for account, device, velocity, compliance, cooldown, and approval classes;
- release provenance with fourteen mandatory controls and exhaustive 16,384-combination testing;
- monotonic incident governance from detection through independently approved closure.
- sanitized privileged-access assurance for JIT, phishing-resistant MFA, reauthentication, session, SoD, scope, change-window, and dual-approval evidence;
- an EnteleEXCHANGE ledger-integrity gate with fourteen mandatory controls and exhaustive 16,384-combination testing;
- forward-only break-glass governance with emergency quorum, immutable time limits, revocation evidence, and independent closure.
- sanitized API/session assurance for registration, mTLS, request signing, replay, rate, idempotency, revocation, lifetime, and approval evidence;
- forward-only signer-ceremony governance for HSM/MPC/device-bound quorum evidence without receiving key material;
- a staging-only resilience gate with fourteen mandatory controls and exhaustive 16,384-combination testing.
- a sanitized secret-leakage gate with twelve mandatory controls and exhaustive 4,096-combination testing;
- an immutable-audit integrity gate with fourteen mandatory controls and exhaustive 16,384-combination testing;
- forward-only security-exception governance with immutable expiry, a 720-hour ceiling, independent quorum, and no critical-risk waiver.
- a wallet/exchange client-integrity gate with fourteen mandatory controls and exhaustive 16,384-combination testing;
- an exchange market-data integrity gate with fourteen mandatory controls and exhaustive 16,384-combination testing;
- an isolated availability/chaos gate with fourteen mandatory controls and exhaustive 16,384-combination testing.
- a vulnerability-remediation lifecycle gate with fourteen mandatory controls and exhaustive 16,384-combination testing;
- an external-assessment authorization and safety gate with fourteen mandatory controls and exhaustive 16,384-combination testing;
- a privacy/data-minimization gate with fourteen mandatory controls and exhaustive 16,384-combination testing.
- a cryptography-review gate with fourteen mandatory controls and exhaustive 16,384-combination testing;
- a quantum-migration governance gate with fourteen mandatory controls and exhaustive 16,384-combination testing, with no quantum-safety claim;
- a security-disclosure/bug-bounty governance gate with fourteen mandatory controls and exhaustive 16,384-combination testing;
- a third-party risk gate with fourteen mandatory controls and exhaustive 16,384-combination testing.
- a revision-bound consumer release gate for EnteleWALLET and EnteleEXCHANGE CI.
- a deny-only assurance-signer gateway conformance gate for exact workload identity, purpose, digest, replay, transport, and hardware-provider evidence.

## What it cannot do

VaultLab has no file-import interface, blockchain library, RPC client, signing operation, key derivation path, address calculation, mnemonic support, password generator, candidate loop, GPU backend, or network operation. These are architectural absences, not optional settings.

It must never be extended to accept arbitrary wallet files, real customer vaults, password lists, target-derived clues, or third-party keys. Real production controls are assessed through separately approved architecture review, code review, HSM/MPC validation, protocol fuzzing, mobile testing, and external penetration testing.

## Run locally

Requirements: Node.js 22 or later.

```bash
npm ci
npm test
npm run assure
npm run policy:assure
```

`npm run assure` creates a fresh credential and specimen in memory. The report contains control results and a fixture identifier, but no credential or decrypted specimen.

`npm run policy:assure` emits a sanitized twenty-six-gate report spanning wallet, exchange, vault, custody, identity, infrastructure, governance, client integrity, market data, availability, vulnerability remediation, external assessment, privacy, cryptography review, quantum migration, security disclosure, third-party risk, and assurance-signer conformance. It exhaustively evaluates 4,096 combinations each for custody and secret leakage plus 16,384 each for release provenance, ledger integrity, resilience, immutable audit, client integrity, market data, availability, remediation, external assessment, privacy, cryptography review, quantum migration, security disclosure, and third-party risk—237,622 evaluated cases total—and always records `authorityGranted: false`.

Additional gates:

```bash
npm run --silent assure > vaultlab-assurance-report.json
npm run validate:report
npm run --silent policy:assure > vaultlab-platform-policy-report.json
npm run validate:policy-report
npm run verify:production-boundary
npm run --silent evidence -- vaultlab-assurance-report.json 0123456789abcdef0123456789abcdef01234567
```

The production-boundary verifier scans production code and configuration while excluding the `vaultlab/` test cell. It reports only paths and rule identifiers—never matching content. The evidence command binds a passing report to an exact 40-character Git revision and emits publishable metadata only.

## Integration rule

Raw EnteleVAULT, EnteleWALLET, and EnteleEXCHANGE production data must never enter VaultLab. A CI or staging job calls VaultLab as an independent test package; it generates its own fixtures, or receives only an exact sanitized policy object, emits a redacted result, and exits. See [INTEGRATION.md](./docs/INTEGRATION.md).

The policy modules consume only sanitized classifications, booleans, counts, pseudonymous identifiers, timestamps, revisions, and evidence digests. They produce recommendations only. The signer conformance boundary is documented in [ASSURANCE_SIGNER_GATEWAY_POLICY.md](./docs/ASSURANCE_SIGNER_GATEWAY_POLICY.md); the complete policy index remains in the [control catalog](./docs/CONTROL_CATALOG.md).

## Security ownership

- EnteleVAULT Security Engineering owns the control contract.
- EnteleCLOS Assurance owns test evidence and control mapping.
- EnteleVAULT Custody Engineering cannot weaken the gate without security approval.
- EnteleCLOS security agents can recommend review, quarantine, blocking, escalation, or rotation, but cannot execute those responses.
- Production operations cannot access fixture credentials because they exist only inside the assurance process.
- Any proposed real-wallet import, candidate processing, or recovery extension is automatically out of scope and requires rejection, not a feature flag.

See [AGENT_BOUNDARY.md](./docs/AGENT_BOUNDARY.md), [EVIDENCE_CONTRACT.md](./docs/EVIDENCE_CONTRACT.md), and the machine-readable [control catalog](./controls/vaultlab-controls.json).
