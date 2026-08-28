# Credential/v2 recovered receipt Green Gate — 2026-08-24

Authority: SPEC-001 TEST-067 and Selfsame IMPL-008
`pairing-v2-channel`.

Red record:
`evidence/credential-v2-recovered-receipt-red-2026-08-24.md`.

Commands:

```text
cargo test --test credential_v2_endpoint
cargo test --doc
cargo clippy --all-targets --all-features -- -D warnings
```

Result: six endpoint tests, six compile-fail doctests, and strict clippy passed.

Recovery is available only on a claimant retained at `payload -> receipt`.
The registered successor verifier mints one private, non-cloneable authority
binding application, ceremony, intent, payload content hash, final-status
digest, and receipt-body digest. Recovery consumes it by value and reaches the
same terminal edge. A mismatch or attempted post-payload refusal leaves the
receipt wait intact.

This evidence authorizes no production allocation, release, or deployment.
