# Endpoint reducer Red Gate — 2026-08-16

Command:

```text
cargo test --test endpoint
```

Result: expected failure (`exit 101`). All five integration tests compiled and
failed at `ReducerError::NotImplemented`; none was ignored.

The gate fixes these security-state observations before implementation:

- first-peer binding occurs before the online guess; exact resume succeeds and
  an alternate binding permanently spends the invitation;
- a CBCL `Unknown` Finished control emits no frame, performs no confirmation,
  and creates no role cast, then becomes actionable after its predecessor;
- decline closes both endpoints, drops secret-bearing state, and releases zero
  payloads;
- exact decision replay is effect-free while an approval/decline conflict is
  terminal; and
- only one approved payload carrying the accepted intent digest is released.

CBCL remains the choreography authority. The reducer gate covers only durable
consumption, cryptographic activation/erasure, decision uniqueness, and effect
release.

This is non-production conformance evidence, not release approval.
