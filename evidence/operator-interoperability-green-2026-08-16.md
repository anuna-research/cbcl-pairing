# Operator interoperability implementation evidence

- Date: 2026-08-16
- Test: SPEC-072 TEST-017 local implementer gate
- Commands:
  - `cargo test --test relay_process --features relay`
  - `cargo test --test limiter_observability test_017_operator_keys_separate_peer_pseudonyms -- --exact`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`

## Deployments

The process test starts two separate `cbcl-pairing-relay` operating-system
processes on independent ephemeral listeners. Each reads a different private
32-octet operator key from an owner-only key file and enables allocation only
through the conformance flag. No client or application-profile code changes
between processes.

An additional limiter assertion proves that the same canonical peer address
maps to different pseudonyms under the two operator keys. Debug output for both
pseudonyms remains redacted.

## Profile results

Each process receives two fresh mailboxes and carries a complete agent profile
and credential profile flow:

1. bind, allocate in the profile's required locator mode, and claim;
2. both canonical CPace frames and acknowledgements;
3. both signed Finished frames and the projected R6 role opener;
4. the encrypted, fully profile-recognised intent;
5. explicit approval;
6. the encrypted digest-bound profile payload;
7. exactly one application-authoritative verifier call and one grant effect;
8. explicit mailbox close.

The two processes produce identical `DisplayIntent`, `AuthorisedGrant`, spent-
invitation, verifier-count, delivery-count, and terminal-state results for both
profiles. Every transported channel frame is encoded before `Put`, received
byte-identically, acknowledged, decoded, and then admitted by the endpoint.

Both logs contain only closed operation/outcome labels. They contain none of
the application IDs, claimed principal, agent handle, wallet origin, requested
authority, credential bytes, or grant bytes.

## Scope boundary

This completes the implementation-owned cross-operator assertions and supplies
the full profile-result evidence missing from the earlier opaque-byte smoke
test. The two deployments intentionally share the reference binary, and this
record is authored by the implementer. It does not replace the named integration
reviewer, independent endpoint TEST-018, human cryptography TEST-016, or the
fresh-context adversarial review. Production remains disabled.
