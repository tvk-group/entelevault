# Recovery governance

The recovery module governs authorization evidence; it does not recover credentials, search passwords, derive keys, import wallets, sign messages, or move assets. A completed case is only a governance record for a separate, independently reviewed custody procedure.

## State machine

```text
intake
  -> authority-verified
  -> cooling-period
  -> quorum-approved
  -> migration-prepared
  -> completed
```

Every active phase may transition to `cancelled`. Fast-forward and backward transitions fail closed.

## Mandatory controls

- authority, subject, scope, and counsel review are all verified;
- legal, security, and custody approvals come from three distinct pseudonymous approver identifiers;
- prior approvals are append-only and verified authority cannot be weakened;
- the required waiting period is 24–720 hours and cannot be shortened after intake;
- claimed elapsed time cannot exceed the observed case timeline;
- emergency override is rejected;
- requester, security, and custody notifications are complete;
- no critical or high finding remains open.

Entering `quorum-approved`, `migration-prepared`, or `completed` re-evaluates all controls. Even a valid transition fixes execution and asset-movement authority to `false`.

## Production separation

The `enteleclos.recovery-governance.v1` object contains identifiers, booleans, counts, timestamps, approval roles, and digests only. Wallet files, addresses, target information, passwords, mnemonics, seeds, private keys, signatures, and transaction material are prohibited. Evidence systems may retain the validated metadata and digest; sensitive identity evidence stays in its approved system of record.

The machine contract is [`recovery-governance.schema.json`](../schemas/recovery-governance.schema.json).
