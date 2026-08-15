# Secure-channel public-context evidence

- Date: 2026-08-16
- SPEC revision: 0.3.2
- Commands:
  - `cargo test --test context`
  - `cargo test --test endpoint`
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`

## Result

The previously unnamed secure-channel public-context byte string is now one
deterministic `pairing-public-context` array. It binds the protocol/suite,
application identifier, canonical relay origin, resolved mailbox identifier,
and both optional expected ceremony-key digests. A fixed byte vector covers the
encoding.

`PendingChannel::new_pairing` derives that context from a recognised invitation
and resolved mailbox. The migrated endpoint suite uses `start_pairing`,
`new_pairing`, and the same context for durable first-attempt binding; application
fixtures no longer invent CPace or secure-channel context bytes. The raw
`PendingChannel::new` remains only for official vectors and specialised callers.

The normative schema hash advanced to
`c8f7e57a1a944dd999ebeeb20260368d3315ade26748fbab8361de2643240fc9`, and its
profile non-interference pin was deliberately updated. The complete all-feature
suite remains green.

## Scope boundary

This closes an implementation interoperability ambiguity. It does not ratify
the CPace construction or replace TEST-016, TEST-017, TEST-018, or the required
human and fresh-context reviews. Production remains disabled.
