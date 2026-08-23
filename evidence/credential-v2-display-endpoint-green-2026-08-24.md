# Credential/v2 display and endpoint Green Gate — 2026-08-24

Authority: SPEC-001 TEST-061, TEST-062, and TEST-064 and Selfsame IMPL-008
`pairing-v2-channel`.

Red records:

- `evidence/credential-v2-display-red-2026-08-24.md`
- `evidence/credential-v2-endpoint-red-2026-08-24.md`

Focused commands:

```text
cargo test --test credential_v2_display
cargo test --test credential_v2_endpoint
cargo test --doc
```

Result: four display tests, four endpoint tests, and five compile-fail doctests
passed.

The display evidence covers offer-only input construction, separate authority,
verdict-only verification, pre-display mismatch refusal, private fields,
borrowed accessors, no serialization reconstruction, exact-pair TOFU state,
both transitions, every room symbol, and the constructive 256-room/33,793-byte
maximum.

The endpoint evidence covers the full closed sender/phase projection, both
confirmation branches, intent and predecessor binding, exact latest
retransmission, terminal conflict behavior, consumer-owned successor grammar
verification, and retained `payload -> receipt` state after attempted refusal.

Repository and quality commands:

```text
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
git diff --check
```

Result: all passed after formatting. Credential/v1 behavior and its display
observations remain green through private borrowed accessors.

The test-first pass also found and corrected an implementation mismatch: the
initial carrier code accepted an HTTPS origin where `application-context`
requires a canonical application identifier with a non-empty path. The carrier
and endpoint now reuse that grammar, and the endpoint binds display authority
to the recognised carrier application and ceremony.

Checkpoint, recovered-receipt, and stronger independent-vector evidence remain
open in the same `pairing-v2-channel` task. This evidence authorizes no
production allocation, release, or deployment.
