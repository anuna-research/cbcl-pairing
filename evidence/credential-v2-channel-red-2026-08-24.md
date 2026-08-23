# Credential/v2 channel Red Gate — 2026-08-24

Authority: SPEC-001 TEST-061, TEST-063, TEST-064, and TEST-066.

Baseline: `646fa47b228306a7fafd71c9d5b44568d574e0e7`.

Command:

```text
cargo test --test credential_v2_channel
```

Observed result: RED. Compilation failed because the unchanged library exposed
no `credential_v2` carrier, context, channel, frame, or object module.

The test also fixes an implementation-discovered design delta. Credential/v2
uses closed `v = 2` CPace, Finished, and sealed frame arms. The current parent
specifies their transcript use but omits their exact outer grammar. This delta
requires inclusion in the fresh cross-model review before release authority.
