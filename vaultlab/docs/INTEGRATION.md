# EnteleVAULT integration contract

## Deployment shape

VaultLab runs as a separate CI/staging assurance job. It is not bundled into the customer wallet, exchange runtime, production vault service, browser extension, or signing path.

```text
source change -> build isolated test package -> generate synthetic fixture
              -> run defensive checks       -> emit redacted report
              -> security gate              -> human-reviewed promotion
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
- signing/custody changes receive two security reviewers;
- cryptographic-format or recovery-policy changes require independent external review;
- release has a rollback plan and incident owner.

## Evidence flow

The CI job sends only the report digest, control result, source revision, runner identity, and timestamp to ChronoSeal/GraphVAULT. It does not send the fixture, credential, plaintext specimen, environment variables, logs containing raw exceptions, or production data.

## EnteleCLOS role

EnteleCLOS owns the assurance case: scope, control mapping, evidence completeness, exceptions, retest status, and independent-review records. EnteleCLOS must not become a wallet-import or credential-search service.
