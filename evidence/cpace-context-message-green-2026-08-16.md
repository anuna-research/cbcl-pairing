# CPace application-context and message evidence

- Date: 2026-08-16
- Contracts: `CON-003`, `CON-004`, and deterministic recognition
- Commands:
  - `cargo test --test context`
  - `cargo test --test recognition`
  - `cargo fmt --check`
  - `cargo clippy --all-targets --all-features -- -D warnings`
  - `cargo test --all-targets --all-features`

## Result

The application wrapper now derives the exact CPace `CI`, `sid`, `ADa`, and
`ADb` inputs from the recognised invitation and resolved mailbox. The channel
identifier binds the suite, application identifier, relay origin, mailbox
identifier, and ordered allocator/claimant roles. Each side's associated data
binds its role and optional expected ceremony-key digest. A direct invitation
cannot be used with a different mailbox.

The CPace share is carried in a versioned deterministic-CBOR message with its
role and associated data. Recognition rejects trailing bytes and rejects an
inner role that differs from the signed outer channel-frame role. `finish`
checks the peer's reconstructed associated data before using its share.

Three fixed-vector context tests, all seven canonical-recognition tests, and
the complete all-feature suite pass. The normative schema hash changed to
`40184162a0173e4dd9dd27fd40ff2eaae3a23abd371dc39423761c842ccddbf1` and the
profile non-interference pin was deliberately advanced to that value.

## Scope boundary

The raw `cpace::start` API remains available for draft-21 vector testing and
specialized callers that deliberately supply every CPace input. Applications
implementing SPEC-072 use `cpace::start_pairing`, which removes those choices.
This evidence is implementer-owned and does not replace the mandatory
independent endpoint or human cryptography reviews. Production remains
disabled.
