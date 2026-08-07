# Break-glass governance evidence

The break-glass state machine records emergency-access governance. It does not grant access, authenticate an operator, start a session, issue credentials, execute revocation, run commands, deploy, sign, or move assets.

## Forward-only phases

```text
requested -> authority-verified -> quorum-approved -> active-window
          -> revoked -> reviewed -> closed
```

`active-window` is an evidence state only. A separate identity and access-management system must perform its own human-controlled authorization.

## Required safeguards

- incident linkage, legal-basis review, owner verification, and least-privilege review;
- normal access unavailable and emergency justification reviewed;
- phishing-resistant MFA and hardware-bound identity evidence;
- a 5–60 minute limit, immutable after authority verification;
- security, operations, and custody quorum from independent pseudonymous approvers;
- planned recording, real-time monitoring, automatic revocation, and post-event review;
- verified revocation, sealed session evidence, independent closure approval, and zero open findings.

Controls cannot be completed before their phase. Authority evidence and completed controls cannot be weakened; approvals are append-only; scope is immutable; risk cannot be silently downgraded; and time must move forward.

Raw identities, credentials, tokens, commands, targets, payloads, transactions, wallet files, keys, and secrets are rejected. Every decision records `accessGrantAuthorized: false`, `sessionStartAuthorized: false`, and `revocationExecutionAuthorized: false`.
