# Signing-intent policy guard

The signing-intent guard is a decision-support boundary for EnteleWALLET. It evaluates a sanitized classification produced by a separately reviewed decoder and simulator. It does not receive a raw transaction, message body, address, recipient, calldata, signature, credential, seed, or private key.

## Decision flow

1. A separately isolated adapter decodes and simulates the request.
2. The adapter removes raw values and emits only the `entelewallet.signing-intent.v1` classifications.
3. VaultLab validates exact fields, enum values, identifiers, and the evidence digest.
4. Policy returns `BLOCK`, `REQUIRE_HUMAN_REVIEW`, or `PROCEED_TO_HUMAN_CONFIRMATION`.
5. A separate trusted user interface must independently render the complete human-readable request and obtain explicit confirmation.
6. A separately reviewed signing service makes its own authorization decision.

`PROCEED_TO_HUMAN_CONFIRMATION` is not approval. Every result fixes `executionAuthorized`, `signingAuthorized`, and `assetMovementAuthorized` to `false`.

## Blocking conditions

The current policy blocks a blocked destination class, risk above policy, missing required decoding, simulation mismatch, unavailable required simulation, disallowed unlimited approval, and a disallowed new destination. Unknown asset/value classifications and near-limit risk require human review.

## Integration constraints

- Never place the guard on a path that has access to a signing key.
- Never use its result as the sole authorization check.
- Bind the evidence digest to decoder version, simulator version, policy version, and source revision outside this package.
- Treat a schema validation failure, timeout, missing field, or unavailable dependency as a block.
- Keep human-readable rendering independent of the sanitized policy object so classification cannot hide material details.

The contract is defined by [`signing-intent.schema.json`](../schemas/signing-intent.schema.json) and enforced by `src/signing-intent-policy.mjs`.
