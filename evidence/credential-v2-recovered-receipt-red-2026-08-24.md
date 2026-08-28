# Credential/v2 recovered receipt Red Gate — 2026-08-24

Authority: SPEC-001 TEST-067 and Selfsame IMPL-008
`pairing-v2-channel`.

Baseline: `63520ff`.

Command:

```text
cargo test --test credential_v2_endpoint
```

Observed result: RED. Compilation failed because the endpoint had no registered
verifier path that could mint a private recovered-receipt authority and no
ordinary-reducer recovery method.

The test requires recovery only from claimant `payload -> receipt`, authority
consumption by value, exact receipt binding, mismatch without phase loss, and
survival of an attempted post-payload refusal.

This evidence authorizes no production allocation, release, or deployment.
