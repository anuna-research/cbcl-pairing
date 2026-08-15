# Relay service Red Gate — 2026-08-16

Command:

```text
cargo test --test relay_service
```

Result: 0 passed, 1 failed.

The bounded service API, explicit clock/randomness inputs, connection routing,
privacy-safe metrics boundary, and allocation hold compile. Construction fails
through the real `RelayError::NotImplemented` sentinel before a bind can
produce the required welcome response.
