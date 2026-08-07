# Signer-ceremony governance

The signer-ceremony state machine verifies evidence for an HSM, MPC, or device-bound quorum ceremony. It never receives key shares, generates keys, activates signers, exports material, signs, deploys, or moves assets.

## Forward-only phases

```text
planned -> participants-verified -> environment-attested
        -> quorum-rehearsed -> evidence-sealed
        -> independently-reviewed -> closed
```

Controls cannot be recorded before their phase. Architecture is immutable, time moves forward, completed controls cannot be weakened, and approvals are append-only.

## Required evidence

- approved ceremony plan and prohibited export policy;
- independent pseudonymous participants, identity attestation, and separation of duties;
- isolated/restricted environment, device attestation, and entropy-source review;
- backup-policy review, quorum-failure test, and abort-procedure test;
- tamper-evidence verification and sealed transcript digest;
- security, custody, and operations quorum;
- independent approval and zero open critical, high, or medium findings.

Raw keys, shares, seeds, entropy values, transcript content, credentials, signatures, commands, tokens, transactions, and wallet material are rejected. `READY_FOR_SEPARATE_CEREMONY_AUTHORIZATION` is an evidence state, never permission to run a ceremony or activate a signer.
