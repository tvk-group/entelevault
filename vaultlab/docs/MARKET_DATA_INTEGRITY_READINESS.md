# Exchange market-data integrity readiness

This gate evaluates classification- and digest-only evidence for spot, derivatives, reference-rate, and risk-pricing data paths. It never receives a feed payload, symbol, price, order, trade, or transaction.

## Required controls

Eligibility requires all fourteen controls: independent sources, source identity, authenticated transport, schema validation, freshness, sequence continuity, outlier detection, cross-source quorum, stale/divergence circuit breakers, failover feed, replay protection, consumer isolation, and independent review.

Critical/high findings, stale or divergent observations, and sequence gaps block readiness. All 16,384 control combinations are tested; only the fully satisfied state is eligible for independent review.

The decision cannot publish prices, trade, execute orders, mutate risk limits, make financial claims, deploy, sign, or move assets.
