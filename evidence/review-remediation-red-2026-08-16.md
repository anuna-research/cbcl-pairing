# Reviewer remediation Red Gate — 2026-08-16

This record captures failing acceptance evidence before implementation repair.
It covers [[SPEC-001-reusable-blind-pairing#TEST-023]] through
[[SPEC-001-reusable-blind-pairing#TEST-029]].

## Commands and results

- `cargo test --release --test recognition test_023_maximum_adversarial_wire_message_has_bounded_recognition_work -- --exact`
  failed. The 69,729-octet input took 144.848583 milliseconds against a
  100-millisecond ceiling.
- `cargo test --test relay_work_bounds test_024_ping_and_no_expiry_sweep_do_not_copy_queued_bodies -- --exact`
  failed. Ping allocated 223,059,386 bytes with 200 loaded mailboxes.
- `cargo test --test limiter_observability test_02 -- --nocapture` failed.
  Backwards time returned `TimeReversal`, and two IPv6 addresses in one `/64`
  created two dimensions.
- `cargo test --test mailbox test_029_existing_claimant_hash_cannot_reclaim -- --exact`
  failed. The existing claimant hash produced a second `Claimed` effect.
- `cargo test --all-features --test websocket_process test_027_oversize_websocket_message_returns_413_before_close -- --exact`
  failed. The client observed `ConnectionReset` instead of `Error(413)`.

## Requirement attribution

- Recognition latency maps to
  [[SPEC-001-reusable-blind-pairing#NFR-009]].
- Queue-body allocation maps to
  [[SPEC-001-reusable-blind-pairing#NFR-010]].
- Clock refusal maps to [[SPEC-001-reusable-blind-pairing#NFR-011]].
- IPv6 diversity and capacity refusal map to
  [[SPEC-001-reusable-blind-pairing#NFR-012]].
- Transport, sampling, and collision behavior map to
  [[SPEC-001-reusable-blind-pairing#CON-001]],
  [[SPEC-001-reusable-blind-pairing#CON-002]], and
  [[SPEC-001-reusable-blind-pairing#CON-003]].

This evidence records local behavior only. It grants no production approval.
