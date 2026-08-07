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

`npm run policy:assure` emits a sanitized nine-gate report for signing, recovery, custody, withdrawal, release provenance, incident governance, privileged access, ledger integrity, and break-glass governance. It exhaustively evaluates 4,096 custody, 16,384 release-provenance, and 16,384 ledger-control combinations and always records `authorityGranted: false`.

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

The policy modules consume only sanitized classifications, booleans, counts, pseudonymous identifiers, timestamps, and evidence digests. They produce recommendations only. See [SIGNING_INTENT_GUARD.md](./docs/SIGNING_INTENT_GUARD.md), [RECOVERY_GOVERNANCE.md](./docs/RECOVERY_GOVERNANCE.md), [NATIVE_CUSTODY_READINESS.md](./docs/NATIVE_CUSTODY_READINESS.md), [WITHDRAWAL_POLICY_GUARD.md](./docs/WITHDRAWAL_POLICY_GUARD.md), [RELEASE_PROVENANCE_GATE.md](./docs/RELEASE_PROVENANCE_GATE.md), [INCIDENT_GOVERNANCE.md](./docs/INCIDENT_GOVERNANCE.md), [PRIVILEGED_ACCESS_GUARD.md](./docs/PRIVILEGED_ACCESS_GUARD.md), [LEDGER_INTEGRITY_GATE.md](./docs/LEDGER_INTEGRITY_GATE.md), and [BREAK_GLASS_GOVERNANCE.md](./docs/BREAK_GLASS_GOVERNANCE.md).

## Security ownership

- EnteleVAULT Security Engineering owns the control contract.
- EnteleCLOS Assurance owns test evidence and control mapping.
- EnteleVAULT Custody Engineering cannot weaken the gate without security approval.
- EnteleCLOS security agents can recommend review, quarantine, blocking, escalation, or rotation, but cannot execute those responses.
- Production operations cannot access fixture credentials because they exist only inside the assurance process.
- Any proposed real-wallet import, candidate processing, or recovery extension is automatically out of scope and requires rejection, not a feature flag.

See [AGENT_BOUNDARY.md](./docs/AGENT_BOUNDARY.md), [EVIDENCE_CONTRACT.md](./docs/EVIDENCE_CONTRACT.md), and the machine-readable [control catalog](./controls/vaultlab-controls.json).
