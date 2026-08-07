# Incident governance

The incident module governs evidence and phase transitions. It does not receive response commands, credentials, infrastructure access, target data, executable payloads, wallet data, or transaction material. It cannot contain a system, revoke access, deploy, sign, or move assets.

## State machine

```text
detected
  -> triaged
  -> contained
  -> access-revoked
  -> assets-reconciled
  -> recovery-reviewed
  -> closed
```

Fast-forward, backward, and same-time transitions fail closed. Incident identity and domain remain fixed; severity may increase but cannot silently decrease. Completed controls cannot revert from true to false, and approval records are append-only.

## Progressive controls

- triage requires an incident commander, preserved evidence, and security/legal/custody notifications;
- containment must be independently verified;
- access revocation must be verified;
- rotation and asset reconciliation must be verified;
- recovery review requires reviewed customer communication, regulatory assessment, root-cause review, an approved remediation plan, and independent closure approval;
- closure requires distinct security, operations, and independent-review approvers plus zero critical, high, or medium findings.

`READY_FOR_SEPARATE_CLOSURE_REVIEW` and `CLOSED` are evidence states, not permissions. Every decision and accepted transition fixes containment, access-revocation, deployment, signing, and asset-movement authority to `false`.

The machine contract is [`incident-governance.schema.json`](../schemas/incident-governance.schema.json).
