# ClawSentry Grafana — PromQL Query Reference

This document provides ready-to-use PromQL queries for building
ClawSentry monitoring dashboards in Grafana.

## Decision Metrics

### Decision rate (per second, 5-minute window)

```promql
rate(clawsentry_decisions_total[5m])
```

Break down by decision type (ALLOW / BLOCK / DEFER):

```promql
sum by (verdict) (rate(clawsentry_decisions_total[5m]))
```

### Latency p95 (seconds)

```promql
histogram_quantile(0.95, rate(clawsentry_decision_latency_seconds_bucket[5m]))
```

### Risk score distribution (p95)

```promql
histogram_quantile(0.95, rate(clawsentry_risk_score_bucket[5m]))
```

## LLM Usage

### LLM cost (cumulative USD)

```promql
clawsentry_llm_cost_usd_total
```

### LLM calls by status (per second)

```promql
rate(clawsentry_llm_calls_total[5m])
```

### Token usage (per second)

```promql
rate(clawsentry_llm_tokens_total[5m])
```

## Session & DEFER

### Active sessions

```promql
clawsentry_active_sessions
```

### Pending defers

```promql
clawsentry_defers_pending
```

## Recommended Dashboard Panels

| Panel              | Query                                                                              | Visualization |
| ------------------ | ---------------------------------------------------------------------------------- | ------------- |
| Decision Rate      | `rate(clawsentry_decisions_total[5m])`                                             | Time series   |
| Latency p95        | `histogram_quantile(0.95, rate(clawsentry_decision_latency_seconds_bucket[5m]))`   | Time series   |
| Risk Score p95     | `histogram_quantile(0.95, rate(clawsentry_risk_score_bucket[5m]))`                 | Time series   |
| LLM Cost           | `clawsentry_llm_cost_usd_total`                                                   | Stat          |
| LLM Calls/s        | `rate(clawsentry_llm_calls_total[5m])`                                             | Time series   |
| Active Sessions    | `clawsentry_active_sessions`                                                       | Stat          |
| Pending Defers     | `clawsentry_defers_pending`                                                        | Stat          |
| Token Usage        | `rate(clawsentry_llm_tokens_total[5m])`                                            | Time series   |
