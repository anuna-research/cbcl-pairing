# Credential/v2 checkpoint Red Gate — 2026-08-24

Authority: SPEC-001 TEST-065 and TEST-066 and Selfsame IMPL-008
`pairing-v2-channel`.

Baseline: `2d017c6`.

Command:

```text
cargo test --test credential_v2_endpoint
```

Observed result: RED. Compilation failed because the endpoint exposed no
one-use CSPRNG nonce, sealed checkpoint, restore operation, or expiry verdict.

The initial test fixes the role/application/ceremony/generation/expiry/key
bindings, nonce-reuse refusal, and retained claimant `payload -> receipt`
behavior. It intentionally begins at the application reducer boundary; the
fresh review must verify how the final checkpoint composes with pre-Finished
admission and live channel state before release.

This evidence authorizes no production allocation, release, or deployment.
