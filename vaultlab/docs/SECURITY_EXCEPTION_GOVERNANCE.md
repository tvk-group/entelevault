# Time-bounded security-exception governance

This gate prevents a security waiver from becoming a silent, permanent control bypass. It records sanitized governance evidence through a forward-only lifecycle:

`requested → triaged → compensating-controls-verified → risk-review-approved → monitoring-active → remediated → independently-closed`

## Invariants

- Critical-risk exceptions are prohibited.
- Expiry cannot exceed 720 hours and cannot be extended during the lifecycle.
- Security, risk, and control-owner approvers must be independent.
- Controls are monotonic and approvals are append-only.
- Scope, ownership, customer/regulatory impact, remediation, compensating controls, monitoring, expiry, rollback, remediation evidence, and independent closure are phase-gated.
- Open critical/high findings block authorization review; all findings must be closed before independent closure.

## Boundary

Records contain classifications, pseudonymous approver identifiers, timestamps, counts, and digests only. They reject credentials, tokens, identities, commands, payloads, keys, transactions, and wallet data.

An eligible result only recommends a separate human-controlled review. It cannot grant an exception, bypass policy, remediate, grant access, deploy, sign, or move assets.
