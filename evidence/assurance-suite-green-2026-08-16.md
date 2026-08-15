# Assurance-suite evidence

- Date: 2026-08-16
- Baseline commit: `578c168`
- Component: `assurance-suite`
- Commands:
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`
  - `tools/run-fuzz-budgets.sh`
  - `tools/run-mutations.sh`

## Deterministic properties

Four property/invariant tests pass. They exercise 4,096 hostile byte strings
against every top-level recogniser and require byte-identical re-encoding after
any acceptance; 256 generated mailbox traces preserve two-member, contiguous,
bounded, terminal-deletion, and fixed-expiry invariants; 48 generated channel
runs preserve directional contiguous counters and terminal authentication
failure; and the endpoint intent record is checked against retention of display
or claim metadata.

## Sanitizer-backed fuzz budgets

Three real `cargo-fuzz`/libFuzzer targets compile with the installed nightly
toolchain and AddressSanitizer. The bounded run completed without a crash,
timeout, sanitizer finding, or assertion failure:

- `wire_recognition`: 10,000 runs, maximum 1,024 octets;
- `mailbox_transitions`: 5,000 runs, maximum 768 octets;
- `channel_receiver`: 1,000 runs, maximum 512 octets.

Generated corpora and artifacts are excluded from Git. The target sources and
exact runner budgets are committed.

## Required mutations

All seven mutants compiled in isolated archives and were killed by an executed
test rather than by a compiler failure:

1. `store-intent-metadata` — killed by
   `assurance_properties::intent_state_retains_no_display_metadata`;
2. `admit-third-membership` — killed by mailbox TEST-003;
3. `accept-sequence-gap` — killed by mailbox TEST-004;
4. `skip-finished-verification` — killed by the corrupt-Finished channel test;
5. `reuse-aead-nonce` — killed by the contiguous directional-counter test;
6. `authorization-is-approval` — killed by endpoint TEST-019;
7. `emit-grant-after-decline` — killed by endpoint TEST-009.

The runner reports `MUTATION GATE OK: 7/7 killed`, and the Forgejo workflow now
runs it after the complete all-feature test suite.

## Scope boundary

Fuzzing and mutation testing increase confidence but do not constitute an
independent endpoint implementation, a cryptographic proof, a fresh-context
adversarial review, or a human cryptography review. They do not approve
production use or invitation allocation.
