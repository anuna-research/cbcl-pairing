# Credential/v2 allocator bootstrap checkpoint Green Gate — 2026-08-24

Target: [[SPEC-001-reusable-blind-pairing#CON-030]] and
[[SPEC-001-reusable-blind-pairing#TEST-065]].

`cargo test --test credential_v2_bootstrap_checkpoint` passes two tests. The
first seals and restores allocator state at allocation, claimant admission,
CPace-share send, and Finished send. It verifies the same relay membership
bearer and exact cached outbound frame, one-use erasure of `T`, reconstruction
of the pending schedule, and interoperable post-Finished traffic with a
separately constructed claimant. The second refuses wrong wrapping keys,
generations, and expired allocator state.

The shared checkpoint sealing refactor also passes:

- `cargo test --test credential_v2_endpoint`
- `cargo test --test credential_v2_channel`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `git diff --check`

This gate covers pre-Finished allocator state. Application-envelope checkpoint
coverage remains in `credential-v2-checkpoint-core-green-2026-08-24.md`.
