# API and session security guard

The API/session guard evaluates sanitized security classifications before a separate gateway or authorization service considers a request. It does not authenticate a client, issue a session, execute an API call, submit an order, change configuration, or initiate a withdrawal.

## Evaluated evidence

- client class, registration, authentication-material age, scope, and owner-status classifications;
- session assurance, device, network, age, and anomaly classifications;
- operation, risk, replay, origin, and rate classifications;
- registration, least-privilege, mTLS, signed-request, nonce, timestamp, rate-limit, schema, idempotency, revocation, lifetime, and dual-approval controls;
- pseudonymous request identifier, timestamp, environment, and SHA-256 evidence digest.

Raw API keys, credentials, tokens, secrets, payloads, identities, addresses, signatures, transactions, commands, and wallet data are rejected.

## Fail-closed behavior

Revoked or unknown clients, inactive owners, expired authentication material, unknown scope, degraded sessions, blocked devices, untrusted networks, unresolved anomalies, expired sessions, replay risk, blocked origins, rate violations, missing mTLS/signature policies, incomplete idempotency/revocation checks, and missing approval evidence block and escalate.

Controlled elevated cases require human API risk review. Low-risk evidence may proceed only to a separate authorization system. Every decision records that request execution, access, session creation, trading, withdrawal, balance mutation, signing, and asset movement are unauthorized.
