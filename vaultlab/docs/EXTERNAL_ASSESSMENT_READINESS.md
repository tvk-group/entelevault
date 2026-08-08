# External-assessment readiness

This gate verifies whether a proposed independent security assessment has complete authorization and safety governance. It does not conduct penetration testing, scan a target, generate traffic, receive exploit payloads, or grant an assessor access.

## Required controls

Eligibility requires all fourteen controls: written authorization, exact scope boundaries, rules of engagement, safe-harbor terms, assessor independence and competence, conflict checks, an approved window, a production-safety plan, a data-handling plan, emergency contacts, a finding-severity method, evidence-retention rules, and a planned independent closure review.

Authorization gaps, scope ambiguities, safety gaps, data-handling gaps, and unresolved conflicts must all be zero. Every one of the 16,384 control combinations is evaluated; only the fully satisfied combination can proceed to a separate external-assessment authorization.

## Input and authority boundary

Inputs contain only scope and environment classifications, an engagement revision, aggregate counts, and SHA-256 digests. Attacks, exploit code, targets, hosts, URLs, endpoints, credentials, payloads, keys, and wallet material are rejected.

The decision never authorizes scanning, exploitation, traffic generation, device access, access grants, remediation, deployment, signing, or asset movement. The actual engagement requires a separately signed contract, exact asset scope, rules of engagement, and human authorization outside VaultLab.
