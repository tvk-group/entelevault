# Native-custody readiness gate

This gate prevents EnteleVAULT from treating planned native custody as production-ready before independent controls exist. It is an assessment mechanism, not a custody implementation, signer, deployment tool, or activation switch.

## Accepted architecture declarations

The staging assessment supports three explicit pairings:

| Custody model | Key-generation boundary |
| --- | --- |
| Non-custodial device-bound | Platform hardware |
| Institutional HSM quorum | Certified HSM |
| MPC quorum | MPC ceremony |

All models require prohibited key export and quorum-governed recovery. The gate rejects production-environment assessments and secret-bearing fields.

## Twelve release-blocking controls

1. Independent cryptography review approved.
2. Hardware boundary reviewed.
3. Mobile platform storage tested.
4. Signing-intent guard enabled.
5. Recovery quorum tested.
6. Key ceremony rehearsed.
7. Incident exercise passed.
8. Dependency provenance verified.
9. Reproducible build verified.
10. External penetration test passed.
11. Privacy review approved.
12. Monitoring and revocation tested.

All twelve must be true and both critical and high open-finding counts must be zero. Tests enumerate every one of the 4,096 Boolean control combinations; only the all-true combination can become `ELIGIBLE_FOR_INDEPENDENT_ACTIVATION_REVIEW`.

Eligibility still requires a separate human activation review. Every result fixes deployment, custody activation, signing, and asset-movement authority to `false`.

The machine contract is [`custody-readiness.schema.json`](../schemas/custody-readiness.schema.json).
