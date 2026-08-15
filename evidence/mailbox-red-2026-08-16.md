# Mailbox core detailed Red Gate

- Date: 2026-08-16
- Command: `cargo test --test mailbox`
- Scope: `TEST-001`, `TEST-002`, `TEST-003`, `TEST-004`, and `TEST-013`

## Result

The test target compiled and ran five behavioural tests. All five failed at
the same explicit allocation stub:

```text
mailbox allocates: NotImplemented
```

The tests already exercise queued offline delivery and ACK deletion, blind
relay-state inspection, two-membership crowding, immutable/idempotent
sequences, frame-count and body-size bounds, terminal deletion, and complete
reaping at the original expiry.

This is temporal Red Gate evidence for `mailbox-core` only. The existing
canonical-recogniser and exact-dialect suites remain separately accepted.
