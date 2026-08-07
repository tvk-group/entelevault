# Isolated availability and chaos readiness

This gate evaluates evidence from exercises that are structurally restricted to isolated test or staging environments. Production and production-observation exercises are rejected.

## Required controls

Eligibility requires all fourteen controls: environment isolation, synthetic traffic, bounded blast radius, rate limits, backpressure, queue bounds, circuit breakers, load shedding, degraded mode, dependency timeouts, failover rehearsal, recovery objectives, observability, and independent review.

Critical/high findings, availability breaches, unrecovered dependencies, or data-integrity mismatches block readiness. All 16,384 control combinations are tested; only the fully satisfied state is eligible for independent review.

Inputs reject commands, targets, hosts, URLs, raw traffic, credentials, tokens, and payloads. The decision cannot generate traffic, execute chaos, fail over, remediate, mutate data, trade, deploy, sign, or move assets.
