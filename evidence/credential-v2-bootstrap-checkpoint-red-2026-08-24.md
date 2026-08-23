# Credential/v2 allocator bootstrap checkpoint Red Gate — 2026-08-24

Target: [[SPEC-001-reusable-blind-pairing#TEST-065]].

The first run of `cargo test --test credential_v2_bootstrap_checkpoint` failed at
compilation because `CredentialV2AllocatorBootstrap`,
`CredentialV2AllocatorBootstrapPhase`, and `CredentialV2RelayState` did not
exist. The test harness itself compiled through imports and reached the intended
missing protocol boundary; this was not a collection or environment failure.

A deliberate post-implementation mutation removed
`CredentialV2Presence::take_claim_token` from claimant admission. The focused
TEST-065 case failed with `Schema` while attempting to persist the claimed
projection, demonstrating that the suite detects retained claim token `T`.
