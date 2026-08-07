# Security policy

## Supported status

EnteleVAULT is under active development and is not yet approved for production custody or storage of cryptocurrency keys, seed phrases, wallet files, identity documents, customer credentials, or regulated personal data.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting or security-advisory feature for this repository. Do not open a public issue containing exploit details, secrets, personal data, wallet material, credentials, or customer information.

A useful report includes the affected revision, component, impact, safe reproduction steps using synthetic data, expected behavior, actual behavior, and suggested containment. Never test against production accounts, third-party wallets, public-chain assets, or systems outside a written scope.

## Research boundary

Authorized research may use generated synthetic fixtures, test accounts, canary assets explicitly created for the assessment, and isolated non-production environments.

The following are outside this repository's acceptable-use boundary:

- importing or attacking arbitrary wallet or keystore files;
- password lists, bulk credential candidates, target-specific guesses, or personal-data-derived candidates;
- seed, mnemonic, private-key, or derivation-path search;
- bypassing wallet security, signing without informed authorization, or broadcasting recovered assets;
- testing any person, organization, account, wallet, device, or service without written authorization and exact technical scope.

## Disclosure handling

Maintain confidentiality until triage and remediation are complete. EnteleVAULT maintainers should acknowledge, classify, contain, reproduce with synthetic data, remediate, independently verify, document affected versions, and publish an advisory when appropriate.
