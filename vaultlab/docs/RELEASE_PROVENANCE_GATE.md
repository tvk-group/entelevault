# Release provenance gate

The release-provenance gate determines whether a CI or staging build has enough evidence to begin an independent promotion review. It does not build, sign, upload, deploy, promote, roll back, or activate software.

## Evidence contract

The `enteleclos.release-provenance.v1` assessment contains an allowlisted component class, one source revision, SHA-256 evidence digests, fourteen Boolean controls, and finding counts. Artifact contents, executables, deployment tokens, credentials, command payloads, signing keys, and wallet data are prohibited.

## Fourteen mandatory controls

1. Source revision is bound.
2. Reproducible build matches.
3. Builder is isolated and ephemeral.
4. Workload identity is verified.
5. Artifact signature is verified.
6. Provenance attestation is verified.
7. SBOM is present.
8. Dependency lock is verified.
9. Secret scan passed.
10. Static analysis passed.
11. Dependency audit passed.
12. Branch protection is verified.
13. Required reviews are verified.
14. Test evidence is bound.

All controls must be true, and critical, high, and medium open-finding counts must all be zero. Tests enumerate every one of the 16,384 Boolean combinations; only the all-true set can become `ELIGIBLE_FOR_INDEPENDENT_PROMOTION_REVIEW`.

Eligibility still requires a separate human promotion system. Every decision fixes deployment, signing, custody activation, and asset-movement authority to `false`.

The machine contract is [`release-provenance.schema.json`](../schemas/release-provenance.schema.json).
