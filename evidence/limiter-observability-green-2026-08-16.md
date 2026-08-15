# Limiter and observability Green Gate

- Date: 2026-08-16
- Scope: `TEST-014`, `TEST-015`, `REQ-006`, `CON-008`, `OBS-001`, and `OBS-002`

## Commands and results

`cargo fmt --check` passed.

`cargo clippy --all-targets --all-features -- -D warnings` passed.

`cargo test --test limiter_observability` passed four tests. An independent
HMAC calculation matches the stored pseudonymous peer key. Per-operation
sliding windows remain independent, the first over-budget attempt fixes a
300-second cooldown that refusals do not extend, every closed operation is
limited, automatic and explicit sweeps remove inactive entries, and rotating
addresses cannot exceed the configured dimension cap.

The tests also drive success, invalid, crowding, expiry, and rate-limit metric
outcomes. Log events accept only closed operation and outcome enums. Metrics
contain only the same closed dimensions and the three aggregate gauges. The
80-percent alerts fire at their exact integer thresholds.

Mailbox, recognition, and exact-dialect regression suites passed.

`cargo test --all-targets` advanced the aggregate behavioural Red Gate to
`cpace-core`.

## Privacy and boundedness

The limiter retains only `{operation, HMAC(operator-key, canonical-address)}`
dimensions, timestamps, and cooldowns. Its `Debug` implementation redacts the
operator key and peer-key debug output is redacted. The raw address is used
only as an HMAC input and is never inserted into state.

The observability accumulator has a fixed 8-by-10 counter matrix. It has no API
for peer, locator, mailbox, token, body, application, identity, or transcript
labels.

This evidence does not accept CPace, endpoint outcomes, relay integration,
interoperability, cryptographic review, or production deployment.
