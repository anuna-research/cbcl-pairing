# Credential/v2 authenticated display Red Gate — 2026-08-24

Authority: SPEC-001 TEST-062 and Selfsame IMPL-008
`pairing-v2-channel`.

Baseline: `447914f41d33a27293d4dd8c568f9df631235786`.

Command:

```text
cargo test --test credential_v2_display
```

Observed result: RED. Compilation failed with eleven missing credential/v2
display symbols. The channel core had no offer-only parser boundary, separate
authenticated authority input, verdict-only verifier, private typed display,
exact-pair TOFU state, device/account provenance, or closed transition.

The test requires rejection before verifier invocation for every peer versus
authority mismatch and requires the successful display to borrow values copied
only from authenticated authority.

This evidence authorizes no production allocation, release, or deployment.
