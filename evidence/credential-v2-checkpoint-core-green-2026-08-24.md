# Credential/v2 checkpoint core Green Gate — 2026-08-24

Authority: the application-reducer portion of SPEC-001 TEST-065 and TEST-066
and Selfsame IMPL-008 `pairing-v2-channel`.

Red record: `evidence/credential-v2-checkpoint-red-2026-08-24.md`.

Commands:

```text
cargo test --test credential_v2_endpoint
cargo test credential_v2::checkpoint::tests::independent_checkpoint_key_vector_is_exact
cargo test --doc
cargo clippy --all-targets --all-features -- -D warnings
```

Result: eight endpoint tests, the independent hard-coded HKDF vector, seven
compile-fail doctests, and strict clippy passed.

The sealed reducer checkpoint uses the exact role-specific deterministic-CBOR
HKDF info, ceremony salt, AES-256-GCM outer shape and seven-member AAD. It binds
role, profile, raw carrier ceremony, positive generation, expiry, nonce,
carrier, phase, intent, predecessor object, and cached retransmission. It
refuses wrong keys, tampering, changed generation, expiry-shape violations, and
nonce reuse. A claimant payload checkpoint uses null expiry and restores after
relay expiry.

This is deliberately not the final CON-030 evidence. The current reducer type
does not own pre-Finished admission secrets, relay membership, or live traffic
keys/counters, so those values are not yet inside this checkpoint. The complete
session composition and crash matrix remain open before the
`pairing-v2-channel` task can be completed.

The hard-coded allocator vector was independently calculated with Python's
standard `hmac`/`hashlib` implementation from the exact deterministic-CBOR info:

```text
info = 83781e6362636c2d70616972696e6720636865636b706f696e74206b65792f763269616c6c6f6361746f7276616e756e612e696f2f63726564656e7469616c2f7632
key  = afb3660ca39fa5c02f6b40422398bfb0487d80a7064a2aa4f00c4458489e82ca
```

This evidence authorizes no production allocation, release, or deployment.
