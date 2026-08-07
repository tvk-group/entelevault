# EnteleVAULT and EnteleEXCHANGE assurance threat model

This model separates assurance testing from production custody. VaultLab covers only the synthetic test cells marked below; the remaining controls require dedicated services, HSM/MPC review, mobile testing, and external assessment.

| Domain | Representative threat | Required control | Validation owner |
| --- | --- | --- | --- |
| Local vault | weak or downgraded KDF | versioned KDF policy, bounded memory cost, migration plan | VaultLab synthetic KDF gate + cryptography review |
| Local vault | corrupted or malicious vault envelope | strict schema, size limits, authenticated encryption, fail-closed parsing | VaultLab mutation and parser suite |
| Local vault | secrets in logs or errors | structured redaction, no raw exceptions, secret scanning | VaultLab report-leakage checks + application tests |
| Wallet UI | phishing or address substitution | trusted-origin UI, address-book policy, full-address confirmation, transaction simulation | mobile/web penetration test |
| Signing | malicious approvals or blind signing | human-readable intent, simulation, allowlists, spending limits, independent confirmation | signing-policy test harness |
| Recovery | unilateral or fraudulent recovery | two-person control, delay, notification, revocation, evidence trail | recovery tabletop + independent audit |
| Custody | hot-wallet compromise | HSM/MPC, tiered limits, allowlisted withdrawals, anomaly detection | custody architecture and ceremony audit |
| Signing policy | raw transaction or secret leakage into automation | sanitized classifications, strict schemas, fail-closed decisions, no signing authority | VaultLab policy tests + independent decoder review |
| Recovery governance | social engineering or workflow fast-forward | verified authority, independent three-role quorum, immutable waiting policy, append-only evidence | VaultLab state-machine tests + independent audit |
| Custody activation | incomplete controls accepted as ready | staging-only gate, twelve mandatory controls, zero critical/high findings, separate activation review | exhaustive VaultLab gate + external assessment |
| Exchange account | session theft or API-key abuse | phishing-resistant MFA, scoped keys, IP/device policy, rotation | ASVS/mobile/API penetration test |
| Withdrawal | account takeover and laundering | risk scoring, cooling periods, case review, sanctions/KYT controls | scenario simulation and compliance review |
| Supply chain | compromised dependency or build | locked dependencies, provenance, signed releases, isolated builders, SBOM | CI policy and release audit |
| Withdrawal policy | raw identity or destination data entering automation | sanitized classes, phishing-resistant MFA, cooldown, dual approval, compliance availability, separate authorization | VaultLab withdrawal tests + compliance review |
| Release promotion | unbound or compromised artifact promoted | fourteen provenance controls, zero open findings, exhaustive gate, separate human promotion | VaultLab provenance tests + release audit |
| Incident closure | premature closure or silent evidence rollback | forward-only phases, severity floor, monotonic controls, append-only approvals, independent quorum | VaultLab state-machine tests + incident exercise |
| Infrastructure | insider or cloud compromise | least privilege, just-in-time access, immutable audit, dual approval | cloud configuration and red-team review |
| Privileged access | dormant account, session theft, SoD conflict, standing privilege, or unapproved change | active-status classification, phishing-resistant MFA, reauthentication, JIT, ticket binding, bounded session, dual approval | VaultLab privileged-access tests + IAM assessment |
| Exchange ledger | incomplete liabilities, reconciliation drift, commingling, replay, or stale reserve evidence | double entry, segregation, complete snapshots, reconciliations, reviewed method, independent attestation, alert and replay tests | exhaustive VaultLab ledger gate + independent financial audit |
| Emergency access | bypassed quorum, unlimited session, missing monitoring, or premature closure | authority evidence, three-role quorum, 60-minute ceiling, recording, monitoring, automatic revocation, sealed evidence, independent closure | VaultLab break-glass state machine + emergency exercise |
| API and sessions | stolen token, overbroad scope, replay, unsigned write, revoked client, or rate abuse | registration, least privilege, mTLS, request signing, nonce/time window, rate limit, idempotency, revocation check, dual approval | VaultLab API/session tests + API penetration test |
| Signer ceremony | colluding participants, unsafe environment, exportable material, weak quorum, unsealed transcript, or premature approval | immutable architecture, prohibited export, participant independence, isolation, attestation, quorum rehearsal, sealed digest, independent review | VaultLab ceremony state machine + external HSM/MPC assessment |
| Resilience | corrupt or mutable backups, ransomware propagation, dependency-order failure, replay duplication, unreconciled restore, or failed failback | encrypted immutable backups, isolation, integrity, rehearsal, idempotency, reconciliation, failover/failback, monitoring, independent review | exhaustive VaultLab resilience gate + isolated recovery exercise |
| Secret leakage | credentials, tokens, key material, or wallet data appearing in logs, traces, crash reports, artifacts, support exports, or telemetry | multi-surface scanning, entropy and pattern detection, verified redaction, canaries, pinned rules, zero findings, independent review | exhaustive VaultLab leakage gate + approved external scanners |
| Immutable audit | deleted, reordered, duplicated, backdated, forged, or unreadably retained security records | append-only storage, hash chain, sequence/time validation, attested writers, retention lock, replication, export integrity, tamper rehearsal | exhaustive VaultLab audit gate + storage/IAM assessment |
| Security exceptions | permanent waiver, critical-risk bypass, expiry extension, colluding approvers, weak compensation, or premature closure | forward-only phases, no critical waiver, 720-hour ceiling, immutable expiry, independent quorum, monitoring, verified remediation and closure | VaultLab exception state machine + risk/compliance review |
| Client integrity | repackaged application, unsigned update, rooted/jailbroken device, debugger, hook/instrumentation, rollback, or forged attestation | official distribution, signatures, reproducibility, attestation, hardware storage, anti-tamper, secure update, rollback defense | exhaustive VaultLab client gate + MASVS/mobile assessment |
| Market data | compromised source, stale/replayed data, sequence gap, outlier, source divergence, or failed fallback | independent sources, authenticated transport, freshness/sequence, quorum, outlier detection, circuit breakers, replay protection, failover | exhaustive VaultLab market-data gate + feed architecture review |
| Availability | DDoS, queue exhaustion, market volatility | WAF, rate limits, circuit breakers, backpressure, tested recovery | load/chaos testing and incident exercises |
| Availability exercise | production blast radius, real traffic, unsafe target, missing load shedding, unrecovered dependency, or silent data corruption | isolated staging, synthetic traffic, bounded blast radius, queue/backpressure controls, degraded mode, recovery/integrity evidence | exhaustive VaultLab availability gate + isolated chaos program |

## Security agents to build safely

1. Policy Guard — validates build and runtime configuration against signed control policy.
2. Secret Leakage Guard — scans structured logs, traces, crash reports, and build artifacts for prohibited secret classes.
3. Signing Intent Guard — compares user-visible intent with decoded transaction effects before approval.
4. Withdrawal Risk Agent — detects anomalous devices, destinations, velocity, and policy violations; it recommends holds but cannot sign.
5. Dependency Provenance Agent — verifies lockfiles, attestations, SBOMs, and release provenance.
6. Recovery Governance Agent — verifies authorization, dual control, waiting periods, notifications, and evidence completeness; it never receives recovery secrets.
7. VaultLab Agent — runs only generated fixtures and publishes signed pass/fail evidence.
8. Incident Governance Agent — validates evidence, forward-only phases, monotonic controls, and independent closure quorum; it cannot execute response actions.
9. Privileged Access Guard — validates sanitized JIT, session, SoD, scope, change-window, and approval evidence; it cannot grant access.
10. Ledger Integrity Agent — validates digest-only reconciliation and control evidence; it cannot claim solvency or mutate exchange state.
11. Break-Glass Governance Agent — validates emergency quorum, timing, revocation, and closure evidence; it cannot start a session or execute commands.
12. API Session Guard — validates client, session, replay, rate, scope, signature, and revocation evidence; it cannot execute requests or submit orders.
13. Signer Ceremony Agent — validates forward-only HSM/MPC ceremony evidence; it never receives shares and cannot generate keys or activate signers.
14. Resilience Readiness Agent — validates digest-only recovery evidence; it cannot read backups, restore, fail over, or mutate state.
15. Secret Leakage Assurance Agent — validates counts, classifications, ruleset revisions, and evidence digests; it never receives scanned content and cannot revoke or delete.
16. Immutable Audit Integrity Agent — validates digest-only chain, sequence, time, access, retention, replication, and tamper evidence; it cannot read or mutate audit records.
17. Security Exception Governance Agent — enforces forward-only, expiring, independently reviewed exception evidence; it cannot grant a waiver, bypass policy, or remediate.
18. Client Integrity Readiness Agent — validates digest-only build, distribution, attestation, hardware, anti-tamper, and update evidence; it cannot access devices or activate clients.
19. Market Data Integrity Agent — validates sanitized source, freshness, quorum, outlier, breaker, failover, and replay evidence; it cannot receive prices, publish data, or trade.
20. Availability Readiness Agent — validates isolated synthetic exercise evidence; it cannot receive targets, generate traffic, execute chaos, fail over, or remediate.

No agent receives unilateral custody authority. Recommendations and detections are separated from signing and asset movement.
