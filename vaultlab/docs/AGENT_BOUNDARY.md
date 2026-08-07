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

The same authority rule applies to the v0.3 signing-intent, recovery-governance, and custody-readiness decisions. Phrases such as `PROCEED_TO_HUMAN_CONFIRMATION`, `READY_FOR_SEPARATE_CUSTODY_REVIEW`, and `ELIGIBLE_FOR_INDEPENDENT_ACTIVATION_REVIEW` are workflow recommendations—not authorizations.

## Deployment rule

The policy kernel may publish a recommendation to a human-reviewed queue. It must not receive cloud administrator credentials, exchange API secrets, HSM/MPC shares, wallet keys, deployment tokens, withdrawal authority, or a generic tool-execution interface.

An independent control service—not the agent—may implement a reversible quarantine after its own authorization policy. Signing, deployment, recovery, and asset movement require separate quorum-controlled systems.
