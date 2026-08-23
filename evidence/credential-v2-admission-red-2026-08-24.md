# Credential/v2 admission Red Gate — 2026-08-24

Authority: SPEC-001 TEST-060 and Selfsame IMPL-008
`pairing-v2-admission`.

Baseline: `87a92a350506d1d0e749b035deda81b828e0cc55`.

Command:

```text
cargo test --test credential_v2_admission
```

Observed result: RED. Compilation failed with 17 missing-surface errors.
The unchanged library had no credential/v2 invitation types, claim token,
commitment constructor, mailbox admission state, v2 allocation, or relay
messages. The failure precedes implementation and proves the new test selects
the intended absent behavior.
