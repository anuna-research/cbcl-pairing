# Limiter and observability detailed Red Gate

- Date: 2026-08-16
- Command: `cargo test --test limiter_observability`
- Scope: `TEST-014` and `TEST-015`

## Result

Four behavioural tests compiled, ran, and failed at the explicit limiter
constructor stub:

```text
limiter constructs: NotImplemented
```

The tests cover closed non-sensitive log and metric dimensions, 80-percent
capacity alerts, operator-keyed peer dimensions, independent per-operation
budgets, the fixed 300-second cooldown, all eight operations, rotating-address
churn, the configured entry cap, explicit sweep, and automatic periodic sweep.

This evidence is scoped to `limiter-observability` and preserves the prior
recogniser and mailbox results.
