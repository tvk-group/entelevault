# EnteleVAULT integration contract

## Deployment shape

VaultLab runs as a separate CI/staging assurance job. It is not bundled into the customer wallet, exchange runtime, production vault service, browser extension, or signing path.

```text
source change -> build isolated test package -> generate synthetic fixture
              -> run defensive checks       -> emit redacted report
              -> security gate              -> human-reviewed promotion
```

Sanitized policy inputs follow a separate flow:

```text
reviewed adapter -> remove raw values -> validate exact metadata schema
                 -> evaluate policy  -> publish recommendation-only evidence
                 -> independent human review (never automatic execution)
```

## Adapter contract for a future EnteleVAULT implementation

A production vault provider should expose a test-only adapter compiled only in the isolated assurance build:

- `createSyntheticEnvelope(specimen, policy)`
- `openSyntheticEnvelope(envelope, oneCredential)`
- `describePolicy(envelope)`
- `destroySyntheticEnvelope(envelope)`

The adapter must accept only the VaultLab specimen classification and must not share code paths that import real wallets, mnemonics, seeds, or vendor keystores. The production bundle must fail CI if the adapter or VaultLab package is reachable.

## Promotion gates

- VaultLab control result is `PASS`.
- application unit, integration, and end-to-end tests pass;
- dependency, license, secret, and static-analysis gates pass;
- production build proves absence of VaultLab exports and test credentials;
- `npm run verify:production-boundary` proves that production source contains no VaultLab import, synthetic schema, fixture marker, or test credential marker;
- signing/custody changes receive two security reviewers;
- cryptographic-format or recovery-policy changes require independent external review;
- release has a rollback plan and incident owner.
- signing policy accepts only sanitized classifications and always requires independent human confirmation;
- recovery progression preserves authority evidence, independent quorum, waiting policy, notifications, and finding gates;
- native-custody readiness is evaluated only in staging, with all twelve controls true and no critical or high finding.
- withdrawal metadata contains no identity, address, exact amount, IP, transaction, credential, or key and never directly drives execution;
- release provenance has all fourteen controls true and zero critical, high, or medium findings;
- incident transitions preserve severity, completed controls, approval evidence, phase order, and independent closure quorum.
- privileged-access metadata contains no raw identity, credential, token, command, IP, or target and never grants access;
- ledger-integrity evidence contains digests and aggregate counts only, requires all fourteen controls, and cannot establish solvency or modify exchange state;
- break-glass evidence preserves forward-only phase order, quorum, immutable time limits, revocation, sealed evidence, and independent closure without starting a session.
- API/session metadata contains no keys, credentials, tokens, raw payloads, identities, addresses, signatures, or transactions and never executes a request;
- signer-ceremony evidence contains no key shares, keys, entropy values, transcript content, credentials, or signatures and cannot run a ceremony or activate a signer;
- resilience evidence contains digests, a revision, classifications, and aggregate counts only, requires all fourteen controls, and cannot read backups, restore, fail over, or mutate state.
- secret-leakage evidence contains classifications, aggregate finding counts, revisions, and digests only, requires all twelve controls, and cannot receive scanned content, revoke credentials, or delete artifacts;
- immutable-audit evidence contains classifications, aggregate counts, revisions, and digests only, requires all fourteen controls, and cannot read, write, delete, or repair audit records;
- security exceptions preserve a forward-only lifecycle, independent quorum, monotonic controls, immutable expiry, a 720-hour ceiling, and a prohibition on critical-risk waivers without granting a policy bypass.
- client-integrity evidence contains platform/build classifications, a revision, counts, and digests only, requires all fourteen controls, and cannot activate or distribute a client, execute updates, access devices, or store keys;
- market-data integrity evidence contains feed/market classifications, counts, revisions, and digests only, requires all fourteen controls, and cannot receive price/feed content, publish prices, trade, execute orders, or mutate limits;
- availability evidence comes only from isolated-test or staging exercises, contains scenario/system classifications, counts, revisions, and digests, requires all fourteen controls, and cannot generate traffic, execute chaos, fail over, or remediate.
- vulnerability-remediation evidence contains classifications, revisions, aggregate SLA/ownership/retest counts, and digests only, requires all fourteen controls, and cannot scan, exploit, patch, deploy, or remediate;
- external-assessment evidence contains classifications, revisions, aggregate authorization/scope/safety counts, and digests only, requires all fourteen controls, and cannot conduct testing, generate traffic, access devices, or grant access;
- privacy-minimization evidence contains classifications, revisions, aggregate finding/retention/deletion-verification counts, and digests only, requires all fourteen controls, and cannot receive personal data, access raw records, delete data, or mutate retention.
- cryptography-review evidence contains component classifications, revisions, aggregate finding/exception/failure counts, and digests only, requires all fourteen controls, and cannot receive cryptographic material, perform operations, generate/export keys, migrate, or deploy;
- security-disclosure evidence contains program/system classifications, revisions, aggregate policy/scope/triage/privacy/dispute counts, and digests only, requires all fourteen controls, and cannot receive reports or exploits, activate a program, authorize testing, publish, pay, or remediate;
- third-party evidence contains provider/system classifications, revisions, aggregate finding/review/concentration/exit counts, and digests only, requires all fourteen controls, and cannot identify or onboard providers, inspect contracts, issue credentials, share data, grant access, procure, pay, or deploy.

## Evidence flow

The CI job sends only report digests, control results, source revision, runner identity, timestamps, and aggregate evaluated-case counts to ChronoSeal/GraphVAULT. It does not send the fixture, credential, plaintext specimen, cryptographic material, signing or withdrawal request, API secrets or payloads, signer shares or transcripts, backup content or restored data, client binaries, attestation tokens, device identifiers, market feeds, prices, symbols, orders, trades, traffic, targets, hosts, URLs, vulnerability reports, exploit or proof-of-concept details, researcher or vendor identities, contracts, endpoints, personal data or raw records, raw identity/access evidence, ledger balances or records, audit events, log or trace content, exception justification text, break-glass session content, artifact content, incident payload, environment variables, logs containing raw exceptions, or production data.

The evidence envelope is a transport contract, not a blockchain transaction and not a production signature. ChronoSeal/GraphVAULT integration must add its own independently reviewed service authentication, authorization, idempotency, retention, and signing design.

## EnteleCLOS role

EnteleCLOS owns the assurance case: scope, control mapping, evidence completeness, exceptions, retest status, and independent-review records. EnteleCLOS must not become a wallet-import or credential-search service.
