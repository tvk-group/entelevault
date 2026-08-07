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

## Evidence flow

The CI job sends only report digests, control results, source revision, runner identity, timestamps, and aggregate evaluated-case counts to ChronoSeal/GraphVAULT. It does not send the fixture, credential, plaintext specimen, signing or withdrawal request, identity evidence, artifact content, incident payload, environment variables, logs containing raw exceptions, or production data.

The evidence envelope is a transport contract, not a blockchain transaction and not a production signature. ChronoSeal/GraphVAULT integration must add its own independently reviewed service authentication, authorization, idempotency, retention, and signing design.

## EnteleCLOS role

EnteleCLOS owns the assurance case: scope, control mapping, evidence completeness, exceptions, retest status, and independent-review records. EnteleCLOS must not become a wallet-import or credential-search service.
