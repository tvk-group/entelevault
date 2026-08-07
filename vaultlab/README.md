# EnteleVAULT VaultLab

VaultLab is a fail-closed, synthetic-only cryptographic assurance harness for EnteleVAULT and the wider EnteleCLOS security program. It tests defensive controls without accepting, deriving, recovering, or operating blockchain keys.

## What it tests

- authenticated-encryption round trips on generated non-value specimens;
- wrong-credential rejection and redacted errors;
- KDF minimums, maximums, and downgrade resistance;
- corrupted ciphertext, authentication tags, and metadata;
- strict parsing, size limits, nesting limits, and unknown-field rejection;
- rejection of bulk artifacts, password candidate lists, wallet-shaped input, targets, mnemonics, seeds, addresses, and key material;
- secret-free machine-readable assurance reports suitable for CI.

## What it cannot do

VaultLab has no file-import interface, blockchain library, RPC client, signing operation, key derivation path, address calculation, mnemonic support, password generator, candidate loop, GPU backend, or network operation. These are architectural absences, not optional settings.

It must never be extended to accept arbitrary wallet files, real customer vaults, password lists, target-derived clues, or third-party keys. Real production controls are assessed through separately approved architecture review, code review, HSM/MPC validation, protocol fuzzing, mobile testing, and external penetration testing.

## Run locally

Requirements: Node.js 22 or later.

```bash
npm ci
npm test
npm run assure
```

`npm run assure` creates a fresh credential and specimen in memory. The report contains control results and a fixture identifier, but no credential or decrypted specimen.

## Integration rule

EnteleVAULT production data must never enter VaultLab. A CI or staging job calls VaultLab as an independent test package; it generates its own fixtures, exercises the provider's defensive contract, emits a redacted result, and exits. See [INTEGRATION.md](./docs/INTEGRATION.md).

## Security ownership

- EnteleVAULT Security Engineering owns the control contract.
- EnteleCLOS Assurance owns test evidence and control mapping.
- EnteleVAULT Custody Engineering cannot weaken the gate without security approval.
- Production operations cannot access fixture credentials because they exist only inside the assurance process.
- Any proposed real-wallet import, candidate processing, or recovery extension is automatically out of scope and requires rejection, not a feature flag.
