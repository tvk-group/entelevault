# Privileged-access assurance guard

The privileged-access guard evaluates a deliberately sanitized snapshot before a separate identity and access-management system considers a grant. It does not authenticate a person, issue a session, create a role, deliver a credential, or execute an administrator action.

## Accepted evidence

- pseudonymous request identifier, timestamp, and environment;
- role, employment-status, and privilege-tier classifications;
- session-assurance, device, network, age, and anomaly classifications;
- allowlisted resource, risk, change-window, and scope classifications;
- booleans for phishing-resistant MFA, fresh reauthentication, ticket binding, JIT access, dual approval, break-glass declaration, and post-action review;
- bounded session/grant lifetime metadata and a SHA-256 evidence digest.

Raw identities, usernames, email addresses, IP addresses, commands, credentials, access tokens, targets, transactions, wallet data, keys, seeds, and payloads are rejected.

## Fail-closed policy

Inactive or unknown employment status, separation-of-duties conflict, degraded sessions, blocked devices, untrusted networks, critical anomalies, expired sessions, missing MFA/reauthentication/ticket/JIT evidence, incomplete dual approval, undeclared break-glass use, missing post-action review, unknown scope, and unapproved change windows block and escalate.

Uncertain, elevated, recently changed, remote, broad, or emergency classifications require human privilege review. A low-risk result may proceed only to a separate access-authorization system.

Every result permanently records `accessGrantAuthorized: false` and `privilegedActionAuthorized: false`.
