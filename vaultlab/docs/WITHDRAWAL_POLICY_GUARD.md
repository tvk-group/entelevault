# Exchange withdrawal policy guard

The withdrawal guard evaluates sanitized risk classifications for EnteleEXCHANGE. It never receives an account identity, destination address, exact amount, IP address, raw transaction, credential, signature, or key. It cannot place a hold, approve a withdrawal, sign, or move assets.

## Decision flow

1. Separately reviewed account, device, compliance, network, and velocity systems classify the request.
2. An adapter removes raw values and emits the exact `enteleexchange.withdrawal-risk.v1` schema.
3. VaultLab validates all fields and evaluates the classifications fail closed.
4. The result is `HOLD_AND_ESCALATE`, `REQUIRE_HUMAN_RISK_REVIEW`, or `PROCEED_TO_SEPARATE_AUTHORIZATION`.
5. A separate human-controlled withdrawal service repeats its own policy and authorization checks.

`PROCEED_TO_SEPARATE_AUTHORIZATION` is not approval. Every result fixes hold execution, withdrawal, signing, and asset-movement authority to `false`.

## Hold-and-escalate conditions

- suspected account takeover or blocked device;
- blocked destination, limit-exceeding amount, or limit-exceeding velocity;
- blocked or unavailable compliance decision;
- high cross-border or network risk;
- missing phishing-resistant MFA or fresh reauthentication;
- incomplete credential-change cooldown;
- incomplete required dual approval or Travel Rule control.

New, unknown, or elevated classifications require human risk review. Upstream systems must bind their classifier versions, source timestamps, policy version, and evidence to `evidenceDigest`; VaultLab does not establish the truth of an upstream classification.

The machine contract is [`withdrawal-risk.schema.json`](../schemas/withdrawal-risk.schema.json).
