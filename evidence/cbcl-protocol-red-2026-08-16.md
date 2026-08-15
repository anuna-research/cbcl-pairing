# CBCL protocol adapter Red Gate — 2026-08-16

Command:

```text
cargo test --test cbcl_protocol
```

Result: expected failure (`exit 101`). All 10 focused tests compiled, ran, and
failed at `ProtocolError::NotImplemented`; no test was ignored.

The gate fixes the required observations before implementation:

- exact embedded dialect installation and source/hash mutation rejection;
- invitation-derived ceremony identifiers and canonical Ed25519 controls;
- signature, thread, frame/performative, body, and per-role key pre-store gates;
- `Unknown` Finished fan-in with no store effect, then `Valid` after both CPace
  predecessors exist;
- one exact transcript-key-bound, session-hash-pinned inert `with-roles` root;
- projected sender, recipient, and predecessor violations;
- independent valid causal verdicts for approval and decline siblings; and
- exact replay idempotence.

This is non-production conformance evidence. It is not cryptographic review or
release approval.
