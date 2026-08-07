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
| Infrastructure | insider or cloud compromise | least privilege, just-in-time access, immutable audit, dual approval | cloud configuration and red-team review |
| Availability | DDoS, queue exhaustion, market volatility | WAF, rate limits, circuit breakers, backpressure, tested recovery | load/chaos testing and incident exercises |

## Security agents to build safely

1. Policy Guard — validates build and runtime configuration against signed control policy.
2. Secret Leakage Guard — scans structured logs, traces, crash reports, and build artifacts for prohibited secret classes.
3. Signing Intent Guard — compares user-visible intent with decoded transaction effects before approval.
4. Withdrawal Risk Agent — detects anomalous devices, destinations, velocity, and policy violations; it recommends holds but cannot sign.
5. Dependency Provenance Agent — verifies lockfiles, attestations, SBOMs, and release provenance.
6. Recovery Governance Agent — verifies authorization, dual control, waiting periods, notifications, and evidence completeness; it never receives recovery secrets.
7. VaultLab Agent — runs only generated fixtures and publishes signed pass/fail evidence.

No agent receives unilateral custody authority. Recommendations and detections are separated from signing and asset movement.
