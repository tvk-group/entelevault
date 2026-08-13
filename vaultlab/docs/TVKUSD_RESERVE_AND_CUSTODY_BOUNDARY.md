# TVKUSD Reserve and Custody Boundary

**Status:** Readiness architecture; no custody, signing, reserve transfer, or activation authority  
**Decision date:** 2026-08-13

## 1. Purpose

This control profile extends EnteleVAULT and VaultLab to the planned TVKUSD, EnteleMINT, EnteleTREASURY, custody, tokenization, and prime-brokerage roadmap. It does not convert the repository into a production custodian, signer, bank, reserve manager, or financial service.

## 2. Mandatory authority separation

The following domains must use separate policy, credentials, roles, quorum design, evidence, recovery, and activation:

| Domain | Authority | Prohibited combination |
| --- | --- | --- |
| Stablecoin mint signer | Sign a previously approved, bounded mint authorisation | Cannot control reserve bank/custodian accounts, customer custody, policy, or ledger |
| Stablecoin burn/redemption signer | Lock/burn under a unique approved redemption order | Cannot release fiat or approve customer/jurisdiction eligibility |
| Reserve banking/custody | Hold and transfer eligible backing assets | Cannot mint, change supply policy, use ENK treasury, or move customer assets |
| Customer digital-asset custody | Hold/operate customer wallets under applicable rules | Cannot access issuer reserve or corporate/ENK treasury |
| Corporate treasury | TVK operating assets | Cannot access TVKUSD reserve or safeguarded customer assets |
| ENK ecosystem treasury | ENK allocation/treasury actions under existing governance | Cannot back TVKUSD, satisfy redemption, or use customer assets |
| Collateral and settlement | Institutional collateral, margin and settlement liquidity | Cannot be treated as unencumbered TVKUSD reserve without explicit lawful classification |
| Policy administration | Define limits, roles, accepted networks/contracts and workflows | Cannot execute asset movement or approve its own changes |
| Recovery/break-glass | Restore a bounded authority after incident | Cannot combine domains, bypass ledger/reconciliation, or silently expand scope |

No person, service account, key, HSM partition, MPC group, cloud role, CI credential, or recovery mechanism should have end-to-end authority across reserve receipt, ledger posting, mint approval, signature, settlement, and reconciliation.

## 3. Key and signer profiles

Each profile records:

```text
profile_id + version
environment
legal_entity
jurisdiction
product + activity
asset + network + contract
allowed transaction types
amount and velocity limits
counterparty and destination policy
required entitlement version
required ledger state
required evidence hashes
quorum and separation of duties
HSM/MPC hardware/software provenance
attestation requirements
not_before + expires_at
pause and revocation
recovery policy
audit sink
```

Default-deny applies to every field not explicitly allowed.

## 4. Signing-intent binding

The signer receives a canonical intent, not an arbitrary transaction. It verifies at minimum:

- expected chain ID and verified canonical contract;
- operation type and exact amount/base units;
- recipient/destination and counterparty policy;
- order, ledger batch, reserve receipt or redemption references;
- jurisdiction entitlement ID/version and effective dates;
- policy version, limits, current supply and expected post-operation supply;
- nonce, expiry, replay protection and prior attempt status;
- code/deployment version and pause state;
- required human/quorum approvals.

Mismatch fails closed. The signer does not accept raw browser-provided transactions, arbitrary calldata, undeclared contracts, blind hashes, mutable URLs, or unsigned policy metadata.

## 5. Reserve-transfer boundary

Reserve transfers require a separate EnteleTREASURY instruction and signer profile from mint/burn.

Controls include:

- approved eligible-asset and counterparty list;
- source/destination ownership and account-purpose verification;
- reserve coverage before and after the transfer;
- settlement finality and intraday liquidity impact;
- concentration, maturity, currency, haircut and encumbrance limits;
- no transfer to corporate, ENK, lending, yield, margin, or proprietary-trading accounts unless an applicable approved mandate explicitly allows it;
- dual/quorum approval independent of proposal and reconciliation;
- pre-positioned emergency redemption liquidity and tested bank/custodian alternatives;
- immutable transfer, approval, settlement and reconciliation evidence.

## 6. Custody models

Supported architecture declarations remain those in the native-custody readiness gate:

- non-custodial device-bound / platform hardware;
- institutional HSM quorum / certified HSM;
- MPC quorum / MPC ceremony.

TVKUSD issuer/reserve and institutional custody should normally use institutional HSM or MPC designs with externally reviewed operational ceremonies. The exact model depends on legal ownership, client-asset rules, asset/network support, recoverability, insolvency treatment, auditability, and licensed-partner requirements.

Native custody eligibility never activates custody. It permits only an independent activation review.

## 7. Prime brokerage and tokenized assets

Prime brokerage introduces additional custody domains:

- customer custody;
- trading venue/settlement wallets;
- collateral control;
- margin or financing accounts;
- corporate house accounts;
- fee accounts;
- tokenized-security issuer/registrar/custody accounts.

These domains must not share omnibus authority merely for operational convenience. Rehypothecation, lending, staking, yield, margin, collateral substitution, or cross-client netting remain disabled unless the exact permission, disclosure, agreement, risk, ledger, and entitlement record enables them.

## 8. Recovery and break-glass

- Recovery quorum differs from normal transaction quorum and cannot unilaterally transact.
- Recovery does not export raw keys or shares.
- Domain separation survives recovery; one recovery cannot restore all authorities.
- Break-glass is purpose-limited, time-bounded, independently approved, monitored, and automatically expires.
- Emergency pause and customer-protection operations are narrower than general transfer authority.
- Every use produces an incident and mandatory post-event review.
- SOVRA may recommend escalation but cannot initiate recovery, break-glass, signing, freeze, seizure, liquidation, or transfer.

## 9. Release-blocking evidence

In addition to existing VaultLab gates:

1. legal ownership and insolvency analysis per asset/account;
2. issuer, custody, treasury and prime-service permission/partner scope;
3. reserve, customer, corporate, ENK and collateral domain maps;
4. HSM/MPC/vendor due diligence and exit plan;
5. key-generation and signer ceremony with independent witnesses;
6. transaction-intent, amount, destination, network, policy and replay tests;
7. recovery, compromise, quorum-member loss and vendor outage tests;
8. chain fork/reorganisation, bridge, pause and contract-upgrade handling;
9. ledger and custodian position reconciliation;
10. incident, complaints, customer asset return and wind-down exercises;
11. external cryptography, architecture and penetration review;
12. zero critical/high open findings and explicit human activation approval.

## 10. Claims boundary

Do not describe EnteleVAULT, VaultLab, EnteleKRON, or any TVK entity as a production custodian, bank-grade certified vault, insured custody provider, qualified custodian, prime broker, or quantum-safe custody service until the exact evidence and authorisation support the exact claim.

