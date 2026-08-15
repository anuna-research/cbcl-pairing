# Secure-channel detailed Red Gate

- Date: 2026-08-16
- Command: `cargo test --test channel`
- Scope: remaining `CON-004` transcript, schedule, Finished, AEAD, and counters

## Result

Five behavioural tests compiled, ran, and failed at the explicit channel stubs.
Four stop at `ChannelError::NotImplemented`; the pure nonce test observes the
stub's all-zero output.

The tests cover independently calculated transcript, HKDF, Finished, and
exporter bytes; corruption of each role's Finished value; both AEAD directions;
independent contiguous counters; replay, gap, wrong-direction, and tag-failure
terminal behavior; exact nonce and deterministic-CBOR AAD encoding; and the
sealed-frame size ceiling.

This evidence is scoped to `secure-channel` and preserves all earlier green
results.
