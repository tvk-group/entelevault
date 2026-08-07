# EnteleCLOS security-agent boundary

## Purpose

Security agents convert bounded risk events into explainable recommendations. They are detection and decision-support components, not operators, signers, deployers, recovery actors, or custodians.

## Accepted event model

An event contains only:

- a generated event identifier and timestamp;
- one allowlisted event type and severity;
- a pseudonymous resource identifier, resource class, and environment;
- a SHA-256 evidence digest;
- up to 16 boolean or numeric signals with allowlisted-style codes.

Free text is not accepted. Commands, actions, transactions, addresses, credentials, keys, mnemonics, seeds, signatures, candidate data, targets, and raw payloads are rejected.

## Supported recommendations

| Severity | Recommendation |
| --- | --- |
| Low | `REVIEW` |
| Medium | `REQUIRE_HUMAN_REVIEW` |
| High | `QUARANTINE_AND_REVIEW` |
| Critical | `BLOCK_AND_ESCALATE` |

Every decision permanently states:

- `humanAuthorizationRequired: true`
- `executionAuthorized: false`
- `signingAuthorized: false`
- `assetMovementAuthorized: false`

These fields are security invariants, not configurable settings.

The same authority rule applies to signing-intent, recovery-governance, custody-readiness, withdrawal, release-provenance, incident, privileged-access, ledger-integrity, break-glass, API/session, signer-ceremony, resilience, secret-leakage, audit-integrity, and security-exception decisions. Phrases such as `PROCEED_TO_HUMAN_CONFIRMATION`, `PROCEED_TO_SEPARATE_AUTHORIZATION`, `PROCEED_TO_SEPARATE_ACCESS_AUTHORIZATION`, `PROCEED_TO_SEPARATE_API_AUTHORIZATION`, `READY_FOR_SEPARATE_CUSTODY_REVIEW`, `READY_FOR_SEPARATE_CEREMONY_AUTHORIZATION`, `READY_FOR_SEPARATE_EXCEPTION_AUTHORIZATION`, `ELIGIBLE_FOR_INDEPENDENT_ACTIVATION_REVIEW`, `ELIGIBLE_FOR_INDEPENDENT_PROMOTION_REVIEW`, `ELIGIBLE_FOR_INDEPENDENT_FINANCIAL_CONTROL_REVIEW`, `ELIGIBLE_FOR_INDEPENDENT_RESILIENCE_REVIEW`, `ELIGIBLE_FOR_INDEPENDENT_LEAKAGE_REVIEW`, `ELIGIBLE_FOR_INDEPENDENT_AUDIT_REVIEW`, `READY_FOR_SEPARATE_CLOSURE_REVIEW`, `active-window`, and `CLOSED` are workflow or evidence states—not authorizations or financial claims.

## Deployment rule

The policy kernel may publish a recommendation to a human-reviewed queue. It must not receive cloud administrator credentials, exchange API secrets, HSM/MPC shares, wallet keys, deployment tokens, withdrawal authority, or a generic tool-execution interface.

An independent control service—not the agent—may implement a reversible quarantine or JIT grant after its own authorization policy. API execution, access, session creation, revocation execution, credential rotation, artifact deletion, audit read/write/delete, policy exceptions, remediation, signer ceremonies, key generation, signer activation, restoration, failover, data/balance mutation, trading, signing, deployment, recovery, withdrawal, and asset movement require separate quorum-controlled systems.
