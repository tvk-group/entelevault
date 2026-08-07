# Resilience and disaster-recovery readiness

The resilience gate evaluates digest-only evidence from isolated staging exercises. It does not read backups, restore data, fail over infrastructure, replay production queues, mutate a ledger, deploy, sign, or move assets.

## Mandatory controls

Eligibility requires all fourteen controls:

1. recovery objectives approved;
2. backup encryption verified;
3. backup immutability verified;
4. geographic separation verified;
5. least-privilege restore access verified;
6. ransomware isolation verified;
7. backup integrity verified;
8. restore rehearsal passed;
9. dependency restore order tested;
10. queue replay and idempotency tested;
11. ledger reconciliation passed;
12. failover and failback tested;
13. monitoring and alerting tested;
14. independent review approved.

Recovery-point and recovery-time classifications must be within objective, and all finding/reconciliation counts must be zero. CI exhaustively evaluates all 16,384 Boolean combinations; only the all-enabled combination is eligible.

VaultLab accepts evidence digests, a source revision, classifications, counts, booleans, and a pseudonymous assessment identifier. Backup payloads, database dumps, raw records, credentials, tokens, secrets, keys, transactions, and wallet files are rejected. Eligibility permits only independent review and grants no restoration or failover authority.
